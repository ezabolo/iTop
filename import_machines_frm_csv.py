#!/usr/bin/env python3
"""
iTop Server Import Tool

This script reads server information from a CSV file and imports it into iTop.
It verifies FQDN-IP matches and checks if servers already exist in iTop before creating them.
"""

import csv
import sys
import json
import dns.resolver
import requests
import socket
import logging
import warnings
from typing import Dict, List, Tuple, Optional

# Disable InsecureRequestWarning
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Change to DEBUG for more verbose output
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("itop_import.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# iTop API configuration
ITOP_URL = "https://my-itop.example.com/itop/weservices/rest.php"
ITOP_USER = "admin"
ITOP_PWD = "password"  # Consider using environment variables for credentials
ITOP_VERSION = "1.3"  # iTop API version

# Fallback IDs for common entities when search fails
FALLBACK_IDS = {
    "organizations": {
        "CHNO": "3",  # As specified
        "CMSO": "2"    # As specified
    },
    "os_families": {
        "RHEL": "1",    # As specified
        "Windows": "2"  # As specified
    },
    "os_versions": {
        "8.10": "211"  # As specified
    }
}

# Organization mapping
ORG_MAPPING = {
    "CHNO": {"ctho.asbn", "adu.dcn"},  # Renamed from CTHO to CHNO
    "CMSO": set()  # Default organization
}

class iTopAPI:
    """Class for interacting with the iTop REST API"""
    
    def __init__(self, url: str, username: str, password: str, version: str = "1.3"):
        self.url = url
        self.username = username
        self.password = password
        self.version = version
        self.auth_params = {
            'auth_user': username,
            'auth_pwd': password,
            'version': version,
        }
        # Ensure warnings about insecure requests are suppressed
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.info(f"Initialized iTopAPI with URL: {url}, version: {version}")
        
    def search(self, object_type: str, query: Dict) -> Dict:
        """Search for objects in iTop based on query criteria"""
        # Handle LIKE queries with % wildcard
        using_like = False
        for key, value in query.items():
            if isinstance(value, str) and '%' in value:
                using_like = True
                break
        
        operation = 'core/get'
        if using_like:
            # Use OQL for LIKE queries
            # Convert dict query to OQL format
            oql_conditions = []
            for key, value in query.items():
                if isinstance(value, str) and '%' in value:
                    # Remove % for OQL LIKE syntax
                    cleaned_value = value.replace('%', '')
                    oql_conditions.append(f"{key} LIKE '{cleaned_value}'")
                else:
                    oql_conditions.append(f"{key} = '{value}'")
                    
            oql_where = ' AND '.join(oql_conditions)
            key = f"SELECT {object_type} WHERE {oql_where}"
        else:
            key = query
        
        # Format like curl would - POST with json_data as a parameter    
        json_data = {
            'operation': operation,
            'class': object_type,
            'key': key,
            'output_fields': 'id, name, managementip',
        }
        
        # Debug the JSON data being sent
        logger.debug(f"Search query for {object_type}: {json.dumps(json_data, indent=2)}")
        
        # Use POST with form data like curl would
        form_data = {**self.auth_params, 'json_data': json.dumps(json_data)}
        
        try:
            # SSL verification explicitly disabled as requested
            headers = {'User-Agent': 'Python iTop Client'}
            response = requests.post(self.url, data=form_data, headers=headers, verify=False)
            
            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {response.headers}")
            
            if response.status_code != 200:
                logger.error(f"Error searching iTop: {response.text}")
                return {"objects": {}}
            
            result = response.json()
            logger.debug(f"Search result: {json.dumps(result, indent=2)}")
            return result
            
        except Exception as e:
            logger.error(f"Exception during iTop search: {str(e)}")
            return {"objects": {}}
    
    def create(self, object_type: str, data: Dict) -> Dict:
        """Create a new object in iTop"""
        json_data = {
            'operation': 'core/create',
            'class': object_type,
            'fields': data,
            'comment': 'Created via CSV import script',
        }
        
        # Debug the JSON data being sent
        logger.debug(f"Create request for {object_type}: {json.dumps(json_data, indent=2)}")
        
        # Use POST with form data like curl would
        form_data = {**self.auth_params, 'json_data': json.dumps(json_data)}
        
        try:
            # SSL verification explicitly disabled as requested
            headers = {'User-Agent': 'Python iTop Client'}
            response = requests.post(self.url, data=form_data, headers=headers, verify=False)
            
            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {response.headers}")
            
            if response.status_code != 200:
                logger.error(f"Error creating object in iTop: {response.text}")
                return {"code": 99, "message": response.text}
            
            result = response.json()
            logger.debug(f"Create result: {json.dumps(result, indent=2)}")
            return result
            
        except Exception as e:
            logger.error(f"Exception during iTop create: {str(e)}")
            return {"code": 99, "message": str(e)}
    
    def get_os_family_id(self, os_name: str) -> str:
        """Get the ID of an OS family by name, using hardcoded values for known OS families"""
        # Check fallback IDs first for known OS families
        if os_name in FALLBACK_IDS['os_families']:
            logger.info(f"Using hardcoded ID for OS Family '{os_name}'")
            return FALLBACK_IDS['os_families'][os_name]
        
        # For unknown OS families, attempt to find them in iTop
        # Try exact match
        result = self.search('OSFamily', {'name': os_name})
        
        if 'objects' in result and result['objects']:
            # Sort by ID and take the lowest
            os_ids = [int(obj_id.split('::')[1]) for obj_id in result['objects']]
            return str(min(os_ids))
            
        # Try partial match
        result = self.search('OSFamily', {'name': f'%{os_name}%'})
        
        if 'objects' in result and result['objects']:
            # Sort by ID and take the lowest
            os_ids = [int(obj_id.split('::')[1]) for obj_id in result['objects']]
            return str(min(os_ids))
            
        logger.warning(f"OS Family '{os_name}' not found in iTop and no hardcoded ID available")
        return ""
    
    def get_os_version_id(self, os_version: str) -> str:
        """Get the ID of an OS version by name, or use hardcoded ID for specific versions"""
        # Check fallback IDs first for known OS versions
        if os_version in FALLBACK_IDS['os_versions']:
            logger.info(f"Using hardcoded ID for OS Version '{os_version}'")
            return FALLBACK_IDS['os_versions'][os_version]
        
        # Special case for version 8.10 as requested (redundant since it's in fallbacks but kept for clarity)
        if os_version == "8.10":
            logger.info(f"Using specified ID 211 for OS Version '{os_version}'")
            return "211"
            
        # For other versions, use dynamic lookup via OQL query
        # Try exact match first
        result = self.search('OSVersion', {'name': os_version})
        
        if 'objects' in result and result['objects']:
            # Sort by ID and take the lowest
            version_ids = [int(obj_id.split('::')[1]) for obj_id in result['objects']]
            return str(min(version_ids))
            
        # Try partial match
        result = self.search('OSVersion', {'name': f'%{os_version}%'})
        
        if 'objects' in result and result['objects']:
            # Sort by ID and take the lowest
            version_ids = [int(obj_id.split('::')[1]) for obj_id in result['objects']]
            return str(min(version_ids))
        
        logger.warning(f"OS Version '{os_version}' not found in iTop and no hardcoded ID available")
        return ""
    
    def get_organization_id(self, org_name: str) -> str:
        """Get the ID of an organization by name, using hardcoded values for known organizations"""
        # Check fallback IDs first for known organizations
        if org_name in FALLBACK_IDS['organizations']:
            logger.info(f"Using hardcoded ID for Organization '{org_name}'")
            return FALLBACK_IDS['organizations'][org_name]
            
        # For unknown organizations, attempt to find them in iTop
        # Try exact match
        result = self.search('Organization', {'name': org_name})
        
        if 'objects' in result and result['objects']:
            # Return the first organization ID found
            return list(result['objects'].keys())[0].split('::')[1]
            
        # Try partial match
        result = self.search('Organization', {'name': f'%{org_name}%'})
        
        if 'objects' in result and result['objects']:
            # Return the first organization ID found
            return list(result['objects'].keys())[0].split('::')[1]
        
        logger.warning(f"Organization '{org_name}' not found in iTop and no hardcoded ID available")
        return ""


def verify_fqdn_ip_match(fqdn: str, ip: str) -> bool:
    """Verify if the FQDN resolves to the given IP address"""
    try:
        # Try forward DNS lookup
        resolved_ips = socket.gethostbyname_ex(fqdn)[2]
        if ip in resolved_ips:
            return True
        
        # Try reverse DNS lookup
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname.lower() == fqdn.lower()
    except (socket.gaierror, socket.herror):
        # DNS resolution failed
        logger.warning(f"DNS resolution failed for {fqdn} - {ip}")
        return False


def determine_server_type(fqdn: str) -> str:
    """Determine if the machine is a Server or VirtualMachine based on FQDN"""
    if any(domain in fqdn.lower() for domain in ["ctho.asbn", "adu.dcn"]):
        return "Server"
    return "VirtualMachine"


def determine_organization(fqdn: str) -> str:
    """Determine the organization based on FQDN"""
    fqdn_lower = fqdn.lower()
    
    for org_name, domains in ORG_MAPPING.items():
        if any(domain in fqdn_lower for domain in domains):
            return org_name
    
    return "CMSO"  # Default organization


def process_csv(csv_file_path: str, itop_api: iTopAPI) -> None:
    """Process the CSV file and import servers into iTop"""
    skipped_count = 0
    created_count = 0
    already_exists_count = 0
    
    with open(csv_file_path, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        
        # Validate CSV headers
        expected_headers = ['FQDN', 'IP_Address', 'AO_Branch', 'AO_Application', 
                           'OS_Name', 'OS_Version', 'CPU', 'Memory', 
                           'Provisioned_Storage', 'Used_Storage']
        if reader.fieldnames != expected_headers:
            logger.error(f"CSV headers do not match expected format: {expected_headers}")
            sys.exit(1)
        
        # Process each row
        for row in reader:
            fqdn = row['FQDN'].strip()
            ip = row['IP_Address'].strip()
            
            # Step 1: Verify FQDN-IP match
            if not verify_fqdn_ip_match(fqdn, ip):
                logger.warning(f"FQDN-IP mismatch: {fqdn} - {ip}, skipping")
                skipped_count += 1
                continue
            
            # Step 2: Check if server exists in iTop
            server_type = determine_server_type(fqdn)
            search_result = itop_api.search(server_type, {'name': fqdn})
            
            if search_result.get('objects'):
                logger.info(f"Server {fqdn} already exists in iTop, skipping")
                already_exists_count += 1
                continue
            
            # Step 3: Create server in iTop
            organization = determine_organization(fqdn)
            logger.info(f"Determined organization: {organization} for {fqdn}")
            org_id = itop_api.get_organization_id(organization)
            
            logger.info(f"Using OS Name: {row['OS_Name']} for {fqdn}")
            os_family_id = itop_api.get_os_family_id(row['OS_Name'])
            
            logger.info(f"Using OS Version: {row['OS_Version']} for {fqdn}")
            os_version_id = itop_api.get_os_version_id(row['OS_Version'])
            
            logger.info(f"Retrieved IDs - Org: {org_id}, OS Family: {os_family_id}, OS Version: {os_version_id}")
            
            if not org_id:
                logger.error(f"Failed to get organization ID for {organization}, skipping {fqdn}")
                skipped_count += 1
                continue
            
            if not os_family_id:
                logger.error(f"Failed to get OS Family ID for {row['OS_Name']}, skipping {fqdn}")
                skipped_count += 1
                continue
            
            if not os_version_id:
                logger.error(f"Failed to get OS Version ID for {row['OS_Version']}, skipping {fqdn}")
                skipped_count += 1
                continue
            
            # Prepare data for iTop
            server_data = {
                'name': fqdn,
                'org_id': org_id,
                'managementip': ip,
                'osfamily_id': os_family_id,
                'osversion_id': os_version_id,
                'cpu': row['CPU'],
                'ram': row['Memory'],
                'diskspace': row['Provisioned_Storage']
            }
            
            # Log the data being sent to iTop for debugging
            logger.info(f"Creating {server_type} with data: {json.dumps(server_data)}")
            
            # Create server in iTop
            create_result = itop_api.create(server_type, server_data)
            
            if create_result.get('code') == 0:
                logger.info(f"Successfully created {server_type} {fqdn} in iTop")
                created_count += 1
            else:
                logger.error(f"Failed to create {server_type} {fqdn} in iTop: {create_result.get('message')}")
                skipped_count += 1
    
    # Report summary
    logger.info(f"Import complete: {created_count} servers created, {already_exists_count} already exist, {skipped_count} skipped")


def test_itop_connection(itop_api):
    """Test the connection to iTop"""
    logger.info("Testing connection to iTop server...")
    try:
        # Try a simple query to test the connection
        result = itop_api.search('Organization', {'id': '1'})
        logger.info(f"Connection test result: {result}")
        if 'objects' in result:
            logger.info("Successfully connected to iTop!")
            return True
        else:
            logger.error("Failed to connect to iTop properly")
            return False
    except Exception as e:
        logger.exception(f"Connection test failed: {e}")
        return False

def main():
    """Main function"""
    # Warning about disabled SSL verification
    logger.warning("SSL certificate verification is disabled. This is insecure and should only be used in test environments.")
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <csv_file_path>")
        sys.exit(1)
    
    csv_file_path = sys.argv[1]
    
    try:
        # Initialize iTop API with specified version
        itop_api = iTopAPI(ITOP_URL, ITOP_USER, ITOP_PWD, ITOP_VERSION)
        
        # Test connection first
        if test_itop_connection(itop_api):
            # Process CSV
            process_csv(csv_file_path, itop_api)
        else:
            logger.error("Unable to continue due to iTop connection issues")
            sys.exit(1)
        
    except Exception as e:
        logger.exception(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
