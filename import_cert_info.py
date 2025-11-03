#!/usr/bin/env python3
import argparse
import csv
import json
import requests
import sys
import logging
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class iTOPAPI:
    def __init__(self, url, username, password, version="1.3", verify_ssl=True):
        """
        Initialize the iTOP API client.
        
        Args:
            url (str): The URL to the iTOP API endpoint (e.g., 'https://itop.example.com/webservices/rest.php')
            username (str): iTOP username
            password (str): iTOP password
            version (str): iTOP API version (default: '1.3')
            verify_ssl (bool): Whether to verify SSL certificate
        """
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.version = version
        self.verify_ssl = verify_ssl
        
    def call_operation(self, payload):
        """Post a payload to iTop REST (form-encoded json_data with Basic Auth)."""
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            # Normalize endpoint: ensure we hit /webservices/rest.php
            base = self.url
            if not base.lower().endswith('rest.php'):
                base = base.rstrip('/') + '/webservices/rest.php'
            endpoint = base if ('?version=' in base or '&version=' in base) else f"{base}?version={self.version}"
            response = requests.post(
                endpoint,
                auth=(self.username, self.password),
                headers=headers,
                data={
                    'auth_user': self.username,
                    'auth_pwd': self.password,
                    'json_data': json.dumps(payload),
                },
                verify=self.verify_ssl,
                timeout=60,
            )
            # Try JSON first; if HTML or other, log a concise preview
            try:
                return response.json()
            except Exception:
                ctype = response.headers.get('Content-Type')
                preview = (response.text or '')[:500]
                logger.error(f"Non-JSON response (status {response.status_code}, content-type {ctype}) from {endpoint}: {preview}")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return None
            
    def search_machine(self, ip=None, fqdn=None):
        """
        Search for a machine by IP address or FQDN.
        Searches both Server and VirtualMachine types.
        
        Args:
            ip (str, optional): IP address to search for
            fqdn (str, optional): FQDN to search for
            
        Returns:
            dict: Dictionary of matching machine objects with their class type
        """
        if not ip and not fqdn:
            logger.error("Either IP or FQDN must be provided")
            return {}
        
        results = {}
        
        # Search for both Server and VirtualMachine types
        for machine_class in ['Server', 'VirtualMachine']:
            # Prepare the OQL query based on provided parameters
            if ip and fqdn:
                oql = f"SELECT {machine_class} WHERE ip_address = '{ip}' OR fqdn = '{fqdn}'"
            elif ip:
                oql = f"SELECT {machine_class} WHERE ip_address = '{ip}'"
            else:  # fqdn only
                oql = f"SELECT {machine_class} WHERE fqdn = '{fqdn}'"
                
            data = {
                'operation': 'core/get',
                'class': machine_class,
                'key': oql,
                'output_fields': 'id, friendlyname, ip_address, fqdn, owner_name, project_name'
            }
                
            response = self.call_operation(data)
            
            if response and response.get('code') == 0:
                objects = response.get('objects', {})
                # Add the class type to each object for later use
                for obj_id, obj in objects.items():
                    obj['class_type'] = machine_class
                    results[obj_id] = obj
            else:
                msg = response.get('message') if response else 'No response'
                logger.warning(f"Failed to search {machine_class}: {msg}")
                
        return results

    def search_by_name(self, name):
        results = {}
        if not name:
            return results
        for machine_class in ['Server', 'VirtualMachine']:
            oql = f"SELECT {machine_class} WHERE name = '{name}'"
            data = {
                'operation': 'core/get',
                'class': machine_class,
                'key': oql,
                'output_fields': 'id, name'
            }
            response = self.call_operation(data)
            if response and response.get('code') == 0:
                objects = response.get('objects', {})
                for obj_id, obj in objects.items():
                    obj['class_type'] = machine_class
                    results[obj_id] = obj
        return results
        
    def update_machine(self, machine_id, machine_class, certrenewaldate=None, currentstartdate=None, currentcertenddate=None):
        """
        Update the owner and project of a machine.
        
        Args:
            machine_id (str): The ID of the machine to update
            machine_class (str): The class of the machine ('Server' or 'VirtualMachine')
            owner (str): The new owner value
            project (str): The new project value
            
        Returns:
            bool: True if successful, False otherwise
        """
        fields = {}

        # Add optional certificate-related fields if provided
        if certrenewaldate:
            fields['certrenewaldate'] = certrenewaldate
        if currentstartdate:
            fields['currentstartdate'] = currentstartdate
        if currentcertenddate:
            fields['currentcertenddate'] = currentcertenddate

        data = {
            'operation': 'core/update',
            'comment': 'Updated via automation script',
            'class': machine_class,
            'key': machine_id,
            'fields': fields
        }
        
        response = self.call_operation(data)
        
        if not response or response.get('code') != 0:
            logger.error(f"Failed to update {machine_class} {machine_id}: {response.get('message') if response else 'No response'}")
            return False
            
        logger.info(f"Successfully updated {machine_class} {machine_id}")
        return True

def process_csv(csv_file, itop_api):
    """
    Process the CSV file and update machines in iTOP.
    
    Args:
        csv_file (str): Path to the CSV file
        itop_api (iTOPAPI): Instance of the iTOP API client
        
    Returns:
        tuple: (success_count, error_count)
    """
    success_count = 0
    error_count = 0
    
    logger.info(f"Processing CSV file: {csv_file}")
    
    try:
        with open(csv_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            
            # Validate required columns
            required_cols = ['Name']
            missing_cols = [col for col in required_cols if col not in reader.fieldnames]
            
            if missing_cols:
                logger.error(f"Missing required columns in CSV: {', '.join(missing_cols)}")
                return 0, 1
                
            for row_num, row in enumerate(reader, start=2):
                name = row.get('Name', '').strip()
                cert_renewal_date = row.get('Cert Renewal  Date', '').strip()
                current_cert_start = row.get('Current Cert Start Date', '').strip()
                current_cert_end = row.get('Current Cert End Date', row.get('Current cert End Date', '')).strip()

                if not name:
                    logger.warning(f"Row {row_num}: Name is required - skipping")
                    error_count += 1
                    continue

                machines = itop_api.search_by_name(name)
                
                if not machines:
                    logger.warning(f"Row {row_num}: No machines found with Name={name}")
                    error_count += 1
                    continue
                    
                for machine_id, machine in machines.items():
                    machine_class = machine.get('class_type', 'Server')
                    if itop_api.update_machine(
                        machine_id,
                        machine_class,
                        certrenewaldate=cert_renewal_date,
                        currentstartdate=current_cert_start,
                        currentcertenddate=current_cert_end
                    ):
                        success_count += 1
                    else:
                        error_count += 1
                        
    except FileNotFoundError:
        logger.error(f"CSV file not found: {csv_file}")
        return 0, 1
    except Exception as e:
        logger.error(f"Error processing CSV: {e}")
        return success_count, error_count + 1
        
    return success_count, error_count

def main():
    parser = argparse.ArgumentParser(description='Update machine owners and projects in iTOP based on a CSV file')
    parser.add_argument('csv_file', help='Path to the CSV file containing machine information')
    parser.add_argument('--url', required=True, help='iTOP API URL (e.g., https://itop.example.com/webservices/rest.php)')
    parser.add_argument('--username', required=True, help='iTOP username')
    parser.add_argument('--password', required=True, help='iTOP password')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL certificate verification')
    
    args = parser.parse_args()
    
    # Initialize the iTOP API client
    itop_api = iTOPAPI(
        url=args.url,
        username=args.username,
        password=args.password,
        verify_ssl=not args.no_verify
    )
    
    # Process the CSV file
    success_count, error_count = process_csv(args.csv_file, itop_api)
    
    logger.info(f"Completed: {success_count} successful updates, {error_count} errors")
    
    # Return a non-zero exit code if there were any errors
    if error_count > 0:
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
