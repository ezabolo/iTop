#!/usr/bin/env python3
import argparse
import socket
import dns.resolver
import requests
import json
import sys
import csv
from typing import Optional, Dict, List

# Disable SSL verification warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ITopAPI:
    def __init__(self, url: str, username: str, password: str):
        self.url = url
        self.username = username
        self.password = password
        self.auth = (username, password)

    def search_object(self, class_name: str, key: str, value: str) -> Optional[Dict]:
        """Search for an object in iTop"""
        query = {
            'operation': 'core/get',
            'class': class_name,
            'key': f"SELECT {class_name} WHERE {key} = '{value}'",
            'output_fields': '*'
        }
        
        print(f"\nSearching for {class_name} with {key}={value}")
        print("Query:", query)
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post(
            f"{self.url}/webservices/rest.php?version=1.3",
            auth=self.auth,
            headers=headers,
            data={'json_data': json.dumps(query)},
            verify=False
        )
        
        print("Response Status:", response.status_code)
        result = response.json()
        print("Response:", json.dumps(result, indent=2))
        
        if response.status_code == 200:
            if 'objects' in result and result['objects']:
                return next(iter(result['objects'].values()))
            elif 'message' in result:
                print("API Error Message:", result['message'])
            else:
                print("No objects found in response")
        return None

    def update_object(self, class_name: str, object_id: str, data: Dict) -> bool:
        """Update an object in iTop"""
        query = {
            'operation': 'core/update',
            'class': class_name,
            'key': object_id,
            'fields': data,
            'comment': 'Updated owner information via automation script'
        }
        
        print(f"\nUpdating {class_name} with ID {object_id}")
        print("Update query:", json.dumps(query, indent=2))
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post(
            f"{self.url}/webservices/rest.php?version=1.3",
            auth=self.auth,
            headers=headers,
            data={'json_data': json.dumps(query)},
            verify=False
        )
        
        print("Update Response Status:", response.status_code)
        result = response.json()
        print("Update Response:", json.dumps(result, indent=2))
        
        if response.status_code == 200:
            if 'code' in result and result['code'] != 0:
                print("API Error:", result.get('message', 'Unknown error'))
                return False
            return True
        return False

def verify_dns(ip: str, fqdn: str) -> bool:
    """
    Verify if the IP matches the DNS record for the given FQDN
    Returns True if matches, False otherwise
    """
    try:
        # Try forward DNS lookup
        resolved_ips = socket.gethostbyname_ex(fqdn)[2]
        return ip in resolved_ips
    except Exception as e:
        print("Error during DNS resolution: %s" % str(e))
        return False

def process_machine(itop: ITopAPI, ip: str, fqdn: str, owner: str, description: str) -> bool:
    """Process a single machine update"""
    # First verify DNS
    if not verify_dns(ip, fqdn):
        print(f"Error: DNS verification failed. IP {ip} does not match DNS records for {fqdn}")
        return False

    # Search in both Server and VirtualMachine classes
    server = itop.search_object('Server', 'managementip', ip)
    vm = itop.search_object('VirtualMachine', 'managementip', ip)

    target_object = server or vm
    if not target_object:
        print(f"Error: No machine found with IP {ip} in iTop")
        return False

    # Update the owner information
    class_name = 'Server' if server else 'VirtualMachine'
    object_id = target_object['key']
    
    update_data = {
        'ownerorg': owner,
        'description': description
    }

    if itop.update_object(class_name, object_id, update_data):
        print(f"Successfully updated information for {fqdn}")
        return True
    else:
        print(f"Error: Failed to update information in iTop for {fqdn}")
        return False

def read_csv_file(file_path: str) -> List[Dict]:
    """Read the CSV file and return list of machine records"""
    machines = []
    try:
        with open(file_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Verify required fields
                required_fields = ['IP', 'Name', 'Owner', 'Description']
                if not all(field in row for field in required_fields):
                    print(f"Error: CSV must contain columns: {', '.join(required_fields)}")
                    sys.exit(1)
                machines.append(row)
    except Exception as e:
        print(f"Error reading CSV file: {str(e)}")
        sys.exit(1)
    return machines

def main():
    parser = argparse.ArgumentParser(description='Update server information in iTop from CSV file')
    parser.add_argument('--csv-file', required=True, help='Path to CSV file containing machine information')
    parser.add_argument('--itop-url', required=True, help='iTop URL')
    parser.add_argument('--itop-user', required=True, help='iTop username')
    parser.add_argument('--itop-password', required=True, help='iTop password')
    
    args = parser.parse_args()

    # Initialize iTop API client
    itop = ITopAPI(args.itop_url, args.itop_user, args.itop_password)

    # Read and process machines from CSV
    machines = read_csv_file(args.csv_file)
    
    success_count = 0
    total_count = len(machines)
    
    print(f"\nProcessing {total_count} machines...\n")
    
    for machine in machines:
        if process_machine(itop, machine['IP'], machine['Name'], machine['Owner'], machine['Description']):
            success_count += 1
    
    print(f"\nCompleted: Successfully updated {success_count} out of {total_count} machines")

if __name__ == "__main__":
    main()
