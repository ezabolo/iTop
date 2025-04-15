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
        """Search for an object in iTop"""
        query = {
            'operation': 'core/get',
            'class': class_name,
            'key': f"SELECT {class_name} WHERE {field} = '{value}'",
            'output_fields': '*'
        }

        try:
            response = self.session.post(
                f"{self.url}/webservices/rest.php?version=1.3",
                auth=self.auth,
                data={'json_data': json.dumps(query)}
            )
            response.raise_for_status()
            result = response.json()

            if 'objects' in result and result['objects']:
                # Return the first matching object
                return next(iter(result['objects'].values()))
            return None

        except Exception as e:
            print(f"Error searching for {class_name}: {str(e)}")
            return None

    def list_available_os_families(self) -> Dict[str, str]:
        """Get all available OS families from iTop"""
        query = {
            'operation': 'core/get',
            'class': 'OSFamily',
            'key': "SELECT OSFamily",
            'output_fields': 'id, name'
        }

        try:
            response = self.session.post(
                f"{self.url}/webservices/rest.php?version=1.3",
                auth=self.auth,
                data={'json_data': json.dumps(query)}
            )
            response.raise_for_status()
            result = response.json()

            os_families = {}
            if 'objects' in result:
                for os in result['objects'].values():
                    os_families[os['fields']['name'].lower()] = os['key']
                print("Available OS Families in iTop:", list(os_families.keys()))
                return os_families
            return {}

        except Exception as e:
            print(f"Error querying OS families: {str(e)}")
            return {}

    def get_os_family_id(self, os_name: str) -> Optional[str]:
        """Get OS family ID from iTop"""
        os_families = self.list_available_os_families()
        os_name_lower = os_name.lower()

        # Try exact match first
        if os_name_lower in os_families:
            return os_families[os_name_lower]

        # If no exact match, try partial match
        for name, id in os_families.items():
            if os_name_lower in name or name in os_name_lower:
                print(f"Note: Using OS family '{name}' for '{os_name}'")
                return id

        print(f"Warning: OS family '{os_name}' not found in iTop. Available options: {list(os_families.keys())}")
        return None

    def list_available_os_versions(self) -> Dict[str, str]:
        """Get all available OS versions from iTop"""
        query = {
            'operation': 'core/get',
            'class': 'OSVersion',
            'key': "SELECT OSVersion",
            'output_fields': 'id, name'
        }

        try:
            response = self.session.post(
                f"{self.url}/webservices/rest.php?version=1.3",
                auth=self.auth,
                data={'json_data': json.dumps(query)}
            )
            response.raise_for_status()
            result = response.json()

            os_versions = {}
            if 'objects' in result:
                for os in result['objects'].values():
                    os_versions[os['fields']['name'].lower()] = os['key']
                print("Available OS Versions in iTop:", list(os_versions.keys()))
                return os_versions
            return {}

        except Exception as e:
            print(f"Error querying OS versions: {str(e)}")
            return {}

    def get_os_version_id(self, os_version: str) -> Optional[str]:
        """Get OS version ID from iTop, taking first if multiple exist"""
        os_versions = self.list_available_os_versions()
        os_version_lower = os_version.lower()

        # Try exact match first
        if os_version_lower in os_versions:
            return os_versions[os_version_lower]

        # If no exact match, try partial match
        matching_versions = []
        for name, id in os_versions.items():
            if os_version_lower in name or name in os_version_lower:
                matching_versions.append((name, id))

        if matching_versions:
            # Use the first matching version
            name, id = matching_versions[0]
            if len(matching_versions) > 1:
                print(f"Note: Multiple matches found for OS version '{os_version}', using '{name}'")
            else:
                print(f"Note: Using OS version '{name}' for '{os_version}'")
            return id

        print(f"Warning: OS version '{os_version}' not found in iTop. Available options: {list(os_versions.keys())}")
        return None

    def create_machine(self, data: Dict, machine_class: str) -> bool:
        """Create a new machine in iTop"""
        # Get OS family and version IDs
        os_family_id = self.get_os_family_id(data.pop('os_name'))
        os_version_id = self.get_os_version_id(data.pop('os_version'))

        if not os_family_id or not os_version_id:
            print(f"Error: Could not find OS information for {data['name']}")
            return False

        # Update data with resolved OS IDs
        data['osfamily_id'] = os_family_id
        data['osversion_id'] = os_version_id

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
                    continue

                # Determine organization and machine class
                org = determine_organization(fqdn)
                machine_class = determine_machine_class(org)

                # Prepare machine data
                machine_data = {
                    'name': fqdn,
                    'managementip': ip,
                    'org_id': f"SELECT Organization WHERE name = '{org}'",
                    'os_name': row['OS_Name'],  # Will be resolved to ID in create_machine
                    'os_version': row['OS_Version'],  # Will be resolved to ID in create_machine
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
