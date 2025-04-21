import csv
import os
import socket
import requests
import logging
import urllib3
import json
import sys

# Suppress SSL warnings if verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Environment variables for iTop API
ITOP_API_URL = os.getenv('ITOP_API_URL', '[https://myitop.example.com/itop/webservices/rest.php')](https://myitop.example.com/itop/webservices/rest.php'))
ITOP_API_USER = os.getenv('ITOP_API_USER', '')
ITOP_API_PASSWORD = os.getenv('ITOP_API_PASSWORD', '')

# Logging setup
logging.basicConfig(filename='itop_import_log.txt', level=logging.INFO, 
                   format='%(asctime)s %(levelname)s:%(message)s')

def fqdn_matches_ip(fqdn, ip):
    try:
        resolved_ip = socket.gethostbyname(fqdn)
        return resolved_ip == ip
    except Exception as e:
        logging.error(f"DNS resolution failed for {fqdn}: {e}")
        return False

def itop_api_request(operation, class_name=None, key=None, output_fields=None, 
                   filter_criteria=None, data=None):
    """
    Make a request to iTop REST API 1.3
    
    :param operation: 'core/get', 'core/create', 'core/update', etc.
    :param class_name: The class of objects to work with
    :param key: For operations that require an object key
    :param output_fields: Fields to output for 'get' operations
    :param filter_criteria: Filter criteria for 'get' operations
    :param data: Data for 'create' or 'update' operations
    :return: JSON response
    """
    payload = {
        'operation': operation,
        'version': '1.3',
        'auth_user': ITOP_API_USER,
        'auth_pwd': ITOP_API_PASSWORD,
    }
    
    if class_name:
        payload['class'] = class_name
    
    if key:
        payload['key'] = key
        
    if output_fields:
        payload['output_fields'] = output_fields
        
    if filter_criteria:
        payload['filter'] = filter_criteria
        
    if data:
        payload['fields'] = data
    
    try:
        response = requests.post(
            ITOP_API_URL, 
            data={'json_data': json.dumps(payload)},
            verify=False  # Skip SSL verification - remove in production if possible
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"API request failed: {e}")
        if hasattr(response, 'text'):
            logging.error(f"Response: {response.text}")
        raise

def check_exists_in_itop(fqdn, ip):
    """Check if server or VM exists in iTop by FQDN or IP"""
    # Check in Server class
    server_filter = f"SELECT Server WHERE name = '{fqdn}' OR managementip = '{ip}'"
    resp = itop_api_request('core/get', 'Server', filter_criteria=server_filter)
    
    if resp.get('objects') and len(resp.get('objects', {})) > 0:
        return True
        
    # Check in VirtualMachine class
    vm_filter = f"SELECT VirtualMachine WHERE name = '{fqdn}' OR managementip = '{ip}'"
    resp = itop_api_request('core/get', 'VirtualMachine', filter_criteria=vm_filter)
    
    return resp.get('objects') and len(resp.get('objects', {})) > 0

def get_lowest_id(class_name, field_name, field_value):
    """Get the lowest ID from a list of matching objects"""
    query = f"SELECT {class_name} WHERE {field_name} = '{field_value}'"
    resp = itop_api_request('core/get', class_name, filter_criteria=query)
    
    if not resp.get('objects'):
        logging.warning(f"No {class_name} found with {field_name}='{field_value}'")
        return None
        
    # Extract IDs and find the lowest
    ids = []
    for obj_key, obj_data in resp.get('objects', {}).items():
        try:
            # Extract the ID part from the key (format is usually "ClassName::ID")
            id_part = obj_key.split('::')[1]
            ids.append(int(id_part))
        except (IndexError, ValueError) as e:
            logging.error(f"Failed to parse ID from {obj_key}: {e}")
    
    if not ids:
        return None
        
    return min(ids)

def create_machine_in_itop(class_name, machine_data):
    """Create a new machine in iTop"""
    resp = itop_api_request('core/create', class_name, data=machine_data)
    
    if resp.get('code') != 0:
        error_msg = resp.get('message', 'Unknown error')
        logging.error(f"Failed to create {class_name}: {error_msg}")
        return False
        
    return True

def main(csv_filename):
    if not os.path.exists(csv_filename):
        logging.error(f"CSV file not found: {csv_filename}")
        print(f"Error: CSV file not found: {csv_filename}")
        return
        
    logging.info(f"Starting import from {csv_filename}")
    
    try:
        with open(csv_filename, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            
            # Verify CSV header
            expected_headers = [
                'FQDN', 'IP_Address', 'AO_Branch', 'AO_Application', 
                'OS_NAME', 'OS_version', 'CPU', 'Memory', 
                'Provisioned_storage', 'Used_storage'
            ]
            
            if reader.fieldnames != expected_headers:
                logging.error(f"CSV headers do not match expected format: {reader.fieldnames}")
                print("Error: CSV headers do not match expected format")
                return
                
            for row in reader:
                fqdn = row['FQDN']
                ip = row['IP_Address']
                
                # Step 1: Verify FQDN matches IP
                if not fqdn_matches_ip(fqdn, ip):
                    msg = f"FQDN/IP mismatch: {fqdn} <-> {ip}, skipping"
                    logging.warning(msg)
                    print(msg)
                    continue
                    
                # Step 2: Check if machine exists in iTop
                if check_exists_in_itop(fqdn, ip):
                    msg = f"Machine already exists in iTop: {fqdn} ({ip}), skipping"
                    logging.info(msg)
                    print(msg)
                    continue
                    
                # Step 3: Determine class and organization based on FQDN
                if 'ctho.asbn' in fqdn.lower() or 'adu.dcn' in fqdn.lower():
                    class_name = 'Server'
                    org_name = 'CTHO'
                else:
                    class_name = 'VirtualMachine'
                    org_name = 'CMSO'
                    
                # Step 4: Get required IDs
                org_id = get_lowest_id('Organization', 'name', org_name)
                os_family_id = get_lowest_id('OSFamily', 'name', row['OS_NAME'])
                os_version_id = get_lowest_id('OSVersion', 'name', row['OS_version'])
                
                if not all([org_id, os_family_id, os_version_id]):
                    msg = f"Missing required IDs for {fqdn}, skipping"
                    logging.error(msg)
                    print(msg)
                    continue
                    
                # Step 5: Create machine in iTop
                machine_data = {
                    'name': fqdn,
                    'managementip': ip,
                    'org_id': org_id,
                    'osfamily_id': os_family_id, 
                    'osversion_id': os_version_id,
                    'cpu': row['CPU'],
                    'ram': row['Memory'],
                    'diskspace': row['Provisioned_storage']
                }
                
                try:
                    if create_machine_in_itop(class_name, machine_data):
                        msg = f"Successfully created {class_name} in iTop: {fqdn} ({ip})"
                        logging.info(msg)
                        print(msg)
                    else:
                        msg = f"Failed to create {class_name} in iTop: {fqdn} ({ip})"
                        logging.error(msg)
                        print(msg)
                except Exception as e:
                    msg = f"Error creating {class_name} in iTop for {fqdn}: {e}"
                    logging.error(msg)
                    print(msg)
    
    except Exception as e:
        logging.error(f"Error processing CSV: {e}")
        print(f"Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python import_to_itop.py <csv_filename>")
    else:
        main(sys.argv[1])
