#!/usr/bin/env python3
import argparse
import csv
import json
import requests
import sys
from typing import Dict, Optional
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ITopAPI:
    def __init__(self, url: str, user: str, password: str):
        self.url = url
        self.auth = (user, password)
        self.session = requests.Session()
        self.session.verify = False

    def search_machine(self, ip: str, fqdn: str) -> Optional[Dict]:
        """Search for a machine in iTop by IP and FQDN"""
        # Try Server class first
        server = self.search_object('Server', 'managementip', ip)
        if server:
            # Verify FQDN matches
            if server.get('fields', {}).get('name', '').lower() == fqdn.lower():
                return {'class': 'Server', 'object': server}

        # Try VirtualMachine class
        vm = self.search_object('VirtualMachine', 'managementip', ip)
        if vm:
            # Verify FQDN matches
            if vm.get('fields', {}).get('name', '').lower() == fqdn.lower():
                return {'class': 'VirtualMachine', 'object': vm}

        return None

    def search_object(self, class_name: str, field: str, value: str) -> Optional[Dict]:
        """Search for an object in iTop with enhanced validation"""
        query = {
            'operation': 'core/get',
            'class': class_name,
            'key': f"SELECT {class_name} WHERE {field} = '{value}'",
            'output_fields': '*'
        }
        
        print(f"\nSearching for {class_name} with {field}={value}")
        print("Query:", json.dumps(query, indent=2))
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            response = self.session.post(
                f"{self.url}/webservices/rest.php?version=1.3",
                auth=self.auth,
                headers=headers,
                data={'json_data': json.dumps(query)},
                verify=False
            )
            
            print(f"Response Status: {response.status_code}")
            
            # Validate response structure
            try:
                result = response.json()
                print("Response:", json.dumps(result, indent=2))
                
                if not isinstance(result, dict):
                    print("Error: Invalid response format")
                    return None
                    
                if 'objects' in result and result['objects']:
                    if not isinstance(result['objects'], dict):
                        print("Error: Objects should be a dictionary")
                        return None
                    return next(iter(result['objects'].values()))
                
                if 'message' in result:
                    print(f"API Error: {result['message']}")
                else:
                    print("No matching objects found")
                
            except json.JSONDecodeError:
                print(f"Invalid JSON response: {response.text[:200]}")
                
            return None
            
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {str(e)}")
            return None

    def get_first_id_from_query(self, query: str) -> Optional[str]:
        """Execute a query and return the first ID from the results"""
        try:
            response = self.session.post(
                f"{self.url}/webservices/rest.php?version=1.3",
                auth=self.auth,
                data={'json_data': json.dumps({
                    'operation': 'core/get',
                    'key': query,
                    'output_fields': 'id'
                })}
            )
            response.raise_for_status()
            result = response.json()

            if 'objects' in result and result['objects']:
                # Get the first object's key (ID)
                first_id = next(iter(result['objects'].values()))['key']
                if len(result['objects']) > 1:
                    print(f"Note: Multiple results found for query '{query}', using first ID: {first_id}")
                return first_id
            return None

        except Exception as e:
            print(f"Error executing query: {str(e)}")
            return None

    def get_lowest_id_from_query(self, query: str) -> Optional[str]:
        """Execute query and return the lowest ID from results"""
        try:
            response = self.session.post(
                f"{self.url}/webservices/rest.php?version=1.3",
                auth=self.auth,
                data={'json_data': json.dumps({
                    'operation': 'core/get',
                    'key': query,
                    'output_fields': 'id'
                })}
            )
            response.raise_for_status()
            result = response.json()

            if 'objects' in result and result['objects']:
                # Get all IDs and return the lowest one
                ids = [obj['key'] for obj in result['objects'].values()]
                return min(ids)
            return None

        except Exception as e:
            print(f"Error executing query: {str(e)}")
            return None

    def create_machine(self, data: Dict, machine_class: str) -> bool:
        """Create a new machine in iTop"""
        # Handle OS version ID if it's a SELECT query
        if isinstance(data.get('osversion_id'), str) and data['osversion_id'].startswith('SELECT'):
            version_id = self.get_first_id_from_query(data['osversion_id'])
            if version_id:
                data['osversion_id'] = version_id

        payload = {
            'operation': 'core/create',
            'class': machine_class,
            'fields': data,
            'comment': 'Created via import script',
            'output_fields': '*'
        }

        try:
            response = self.session.post(
                f"{self.url}/webservices/rest.php?version=1.3",
                auth=self.auth,
                data={'json_data': json.dumps(payload)}
            )
            response.raise_for_status()
            result = response.json()

            if result.get('code') == 0:
                print(f"Successfully created {machine_class}: {data['name']}")
                return True
            else:
                print(f"Error creating {machine_class}: {result.get('message', 'Unknown error')}")
                return False

        except Exception as e:
            print(f"Error creating {machine_class}: {str(e)}")
            return False

def check_os_exists(itop: ITopAPI, os_name: str, os_version: str) -> bool:
    """Check if both OS Family and Version exist"""
    os_family = itop.get_first_id_from_query(
        f"SELECT OSFamily WHERE name = '{os_name}'"
    )
    if not os_family:
        print(f"OS Family not found: {os_name}")
        return False
        
    os_ver = itop.get_first_id_from_query(
        f"SELECT OSVersion WHERE name = '{os_version}'"
    )
    if not os_ver:
        print(f"OS Version not found: {os_version}")
        return False
        
    return True

def check_or_create_os_family(itop: ITopAPI, os_name: str) -> Optional[str]:
    """Check if OS Family exists, create it if not"""
    # First try to find existing OS Family
    existing = itop.get_first_id_from_query(
        f"SELECT OSFamily WHERE name = '{os_name}'"
    )
    if existing:
        return existing
    
    # If not found, create it
    print(f"Creating new OS Family: {os_name}")
    payload = {
        'operation': 'core/create',
        'class': 'OSFamily',
        'fields': {'name': os_name},
        'comment': 'Created via import script',
        'output_fields': 'id'
    }
    
    try:
        response = itop.session.post(
            f"{itop.url}/webservices/rest.php?version=1.3",
            auth=itop.auth,
            data={'json_data': json.dumps(payload)}
        )
        response.raise_for_status()
        result = response.json()
        return result.get('objects', {}).get('key', None)
    except Exception as e:
        print(f"Error creating OS Family {os_name}: {str(e)}")
        return None

def determine_organization(fqdn: str) -> str:
    """Determine organization based on FQDN"""
    fqdn_lower = fqdn.lower()
    if 'ctho' in fqdn_lower or 'adu.dcn' in fqdn_lower:
        return 'CHNO'
    return 'CMSO'

def determine_machine_class(org: str) -> str:
    """Determine machine class based on organization"""
    if org in ['CHNO', 'ADU']:
        return 'Server'
    return 'VirtualMachine'

def convert_storage_to_mb(storage: str) -> int:
    """Convert storage string to MB"""
    try:
        # Remove any commas and convert to float
        value = float(storage.replace(',', ''))
        # Assuming the input is in GB, convert to MB
        return int(value * 1024)
    except (ValueError, TypeError):
        return 0

def process_csv_file(csv_path: str, itop: ITopAPI):
    """Process the CSV file and create/update machines in iTop"""
    expected_header = [
        "FQDN", "IP_Adress", "AO_Branch", "AO_Application", 
        "OS_Name", "OS_Version", "CPU", "Memory", 
        "Provisioned Storage", "Used Storage"
    ]

    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            
            # Verify header
            if reader.fieldnames != expected_header:
                print(f"Error: CSV header mismatch. Expected: {expected_header}")
                print(f"Got: {reader.fieldnames}")
                sys.exit(1)

            for row in reader:
                fqdn = row['FQDN'].strip()
                ip = row['IP_Adress'].strip()
                
                # Skip if either FQDN or IP is empty
                if not fqdn or not ip:
                    print(f"Skipping row with empty FQDN or IP: {row}")
                    continue

                # Check if machine exists
                existing = itop.search_machine(ip, fqdn)
                if existing:
                    print(f"Machine already exists: {fqdn} ({ip})")
                else:
                    # Only create if machine doesn't exist
                    # Determine organization and machine class
                    org = determine_organization(fqdn)
                    machine_class = determine_machine_class(org)

                    # Get OS IDs (lowest if multiple)
                    os_family_id = itop.get_lowest_id_from_query(
                        f"SELECT OSFamily WHERE name = '{row['OS_Name']}'"
                    )
                    os_version_id = itop.get_lowest_id_from_query(
                        f"SELECT OSVersion WHERE name = '{row['OS_Version']}'"
                    )
                    
                    if not os_family_id or not os_version_id:
                        print(f"Skipping {fqdn} - OS not found")
                        continue
                        
                    # Prepare machine data
                    machine_data = {
                        'name': fqdn,
                        'managementip': ip,
                        'org_id': f"SELECT Organization WHERE name = '{org}'",
                        'osfamily_id': os_family_id,
                        'osversion_id': os_version_id,
                        'cpu': row['CPU'],
                        'ram': row['Memory'],
                        'diskspace': convert_storage_to_mb(row['Provisioned Storage'])
                    }

                    # Create the machine
                    print(f"\nCreating {machine_class}: {fqdn}")
                    itop.create_machine(machine_data, machine_class)

    except FileNotFoundError:
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing CSV file: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Import machines to iTop from CSV')
    parser.add_argument('--csv-file', required=True, help='Path to iTop_Consolidation_Report.csv')
    parser.add_argument('--itop-url', required=True, help='iTop URL')
    parser.add_argument('--itop-user', required=True, help='iTop username')
    parser.add_argument('--itop-password', required=True, help='iTop password')
    
    args = parser.parse_args()

    # Initialize iTop API client
    itop = ITopAPI(args.itop_url, args.itop_user, args.itop_password)

    # Process the CSV file
    process_csv_file(args.csv_file, itop)

if __name__ == "__main__":
    main()
