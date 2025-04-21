import csv
import os
import socket
import requests
import logging
from dotenv import load_dotenv

# Load environment variables (optional: if using a .env file)
load_dotenv()

# Environment variables for iTop API
ITOP_API_URL = os.getenv('ITOP_API_URL')
ITOP_API_USER = os.getenv('ITOP_API_USER')
ITOP_API_PASSWORD = os.getenv('ITOP_API_PASSWORD')

# Logging setup
logging.basicConfig(filename='itop_import_log.txt', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

def fqdn_matches_ip(fqdn, ip):
    try:
        resolved_ip = socket.gethostbyname(fqdn)
        return resolved_ip == ip
    except Exception as e:
        logging.error(f"DNS resolution failed for {fqdn}: {e}")
        return False

def itop_api_request(endpoint, params=None, method='GET', data=None):
    url = f"{ITOP_API_URL}{endpoint}"
    auth = (ITOP_API_USER, ITOP_API_PASSWORD)
    headers = {'Content-Type': 'application/json'}
    if method == 'GET':
        resp = requests.get(url, params=params, auth=auth, headers=headers)
    elif method == 'POST':
        resp = requests.post(url, json=data, auth=auth, headers=headers)
    else:
        raise ValueError("Unsupported HTTP method")
    resp.raise_for_status()
    return resp.json()

def get_id_from_itop(classname, field, value):
    # Example: /api/{classname}?{field}=value
    resp = itop_api_request(f"/api/{classname}", params={field: value})
    items = resp.get('objects', [])
    if not items:
        return None
    # Return the lowest ID if multiple
    ids = [int(item['id']) for item in items]
    return str(min(ids))

def server_exists_in_itop(fqdn, ip):
    # You may need to adjust the endpoint and query parameters for your iTop API
    resp = itop_api_request("/api/Server", params={'name': fqdn})
    if resp.get('objects'):
        return True
    resp = itop_api_request("/api/VirtualMachine", params={'name': fqdn})
    if resp.get('objects'):
        return True
    resp = itop_api_request("/api/Server", params={'managementip': ip})
    if resp.get('objects'):
        return True
    resp = itop_api_request("/api/VirtualMachine", params={'managementip': ip})
    if resp.get('objects'):
        return True
    return False

def create_machine_in_itop(classname, data):
    # Example: /api/{classname} POST
    return itop_api_request(f"/api/{classname}", method='POST', data=data)

def main(csv_filename):
    with open(csv_filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            fqdn = row['FQDN']
            ip = row['IP_Address']
            if not fqdn_matches_ip(fqdn, ip):
                logging.warning(f"FQDN/IP mismatch: {fqdn} <-> {ip}")
                continue
            if server_exists_in_itop(fqdn, ip):
                logging.info(f"Server/VM already exists in iTop: {fqdn} ({ip})")
                continue
            # Determine class and organization
            if 'ctho.asbn' in fqdn or 'adu.dcn' in fqdn:
                classname = 'Server'
                org_name = 'CTHO'
            else:
                classname = 'VirtualMachine'
                org_name = 'CMSO'
            org_id = get_id_from_itop('Organization', 'name', org_name)
            osfamily_id = get_id_from_itop('OSFamily', 'name', row['OS_NAME'])
            osversion_id = get_id_from_itop('OSVersion', 'name', row['OS_version'])
            if not all([org_id, osfamily_id, osversion_id]):
                logging.error(f"Missing IDs for {fqdn}: org={org_id}, osfamily={osfamily_id}, osversion={osversion_id}")
                continue
            # Prepare data for creation
            machine_data = {
                'name': fqdn,
                'managementip': ip,
                'org_id': org_id,
                'osfamily_id': osfamily_id,
                'osversion_id': osversion_id,
                'cpu': row['CPU'],
                'ram': row['Memory'],
                'diskspace': row['Provisioned_storage'],
            }
            try:
                create_machine_in_itop(classname, machine_data)
                logging.info(f"Created {classname} in iTop: {fqdn} ({ip})")
            except Exception as e:
                logging.error(f"Failed to create {classname} for {fqdn} ({ip}): {e}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("Usage: python import_to_itop.py <csv_filename>")
    else:
        main(sys.argv[1])
