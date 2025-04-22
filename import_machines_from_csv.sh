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
ITOP_URL = "https://myitop.example.com" # Base URL
ITOP_API_ENDPOINT = f"{ITOP_URL}/webservices/rest.php" # REST API endpoint
ITOP_USER = "itopuser"
ITOP_PWD = "XXXX"  # Replace with your actual password
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

def call_itop_api(operation: str, class_name: str = None, key=None, fields=None, output_fields=None, comment=None) -> Dict:
    """
    Helper function to make calls to the iTop REST API.
    Implements the API structure according to official iTop documentation.
    """
    # Suppress insecure request warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Build the JSON payload
    json_data = {
        'operation': operation
    }
    
    # Add operation-specific parameters
    if class_name is not None:
        json_data['class'] = class_name
    
    if key is not None:
        json_data['key'] = key
    
    if fields is not None:
        json_data['fields'] = fields
        
    if output_fields is not None:
        json_data['output_fields'] = output_fields
        
    if comment is not None:
        json_data['comment'] = comment

    # Form data parameters (as expected by iTop REST API)
    form_data = {
        'version': ITOP_VERSION,
        'auth_user': ITOP_USER,
        'auth_pwd': ITOP_PWD,
        'json_data': json.dumps(json_data)
    }
    
    # Log the request details
    logger.debug(f"API Request to {ITOP_API_ENDPOINT}")
    logger.debug(f"Operation: {operation}, Class: {class_name}")
    logger.debug(f"JSON Data: {json.dumps(json_data, indent=2, default=str)}")
    
    try:
        # Make the API request with SSL verification disabled
        # Using POST with form data as per iTop documentation
        response = requests.post(
            ITOP_API_ENDPOINT,
            data=form_data,  # Use form data, not JSON payload
            verify=False
        )
        
        # Log response details
        logger.debug(f"Response status: {response.status_code}")
        logger.debug(f"Response headers: {response.headers}")
        logger.debug(f"Response text: {response.text[:200]}..." if len(response.text) > 200 else response.text)
        
        # Raise exception for bad status codes
        response.raise_for_status()
        
        # Parse and return JSON response
        result = response.json()
        if result.get('code') != 0:
            logger.error(f"API error: {result.get('message')}")
            logger.error(f"Full response: {json.dumps(result, indent=2)}")
        else:
            logger.debug(f"Success response: {result.get('message')}")
            
        return result
    
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON response: {e}")
        logger.error(f"Raw response: {response.text[:500]}" if 'response' in locals() else "No response")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during API call: {str(e)}")
        return None


def search_itop(name: str, ip: str = None) -> Dict:
    """
    Searches for a machine in iTop by name or IP.
    Returns the iTop object data if found, None otherwise.
    """
    logger.info(f"Searching iTop for machine: {name} {f'({ip})' if ip else ''}")
    
    # Build OQL query to search by name or IP
    conditions = []
    if name:
        # Use LIKE for case-insensitive search
        conditions.append(f"name LIKE '{name}'")
    if ip:
        conditions.append(f"managementip = '{ip}'")
    
    if not conditions:
        logger.warning("No search criteria provided")
        return None
        
    # Use OR to match either condition
    condition_str = ' OR '.join(conditions)
    
    # Try Server class first
    logger.debug(f"Searching in Server class")
    oql_query = f"SELECT Server WHERE {condition_str}"
    logger.debug(f"OQL Query: {oql_query}")
    
    # Call the API
    result = call_itop_api(
        operation='core/get',
        class_name='Server',
        key=oql_query,
        output_fields='id, name, managementip, org_id, osfamily_id, osversion_id'
    )
    
    # If not found as Server, try VirtualMachine
    if not result or not result.get('objects') or len(result.get('objects', {})) == 0:
        logger.debug("Not found as Server, trying VirtualMachine")
        oql_query = f"SELECT VirtualMachine WHERE {condition_str}"
        result = call_itop_api(
            operation='core/get',
            class_name='VirtualMachine',
            key=oql_query,
            output_fields='id, name, managementip, org_id, osfamily_id, osversion_id'
        )
    
    # Check if any objects were found
    if result and result.get('objects') and len(result.get('objects', {})) > 0:
        found_objects = result['objects']
        # Return the first object found
        first_object_id = list(found_objects.keys())[0]
        logger.info(f"Machine '{name}' found in iTop with ID: {first_object_id}")
        return found_objects[first_object_id]
    
    logger.info(f"Machine '{name}' not found in iTop")
    return None


def create_itop_server(server_type: str, server_data: Dict) -> Dict:
    """
    Creates a new server or virtual machine in iTop.
    """
    logger.info(f"Creating {server_type} in iTop: {server_data['name']}")
    
    # Call the API to create the object
    result = call_itop_api(
        operation='core/create',
        class_name=server_type,
        fields=server_data,
        comment='Created via CSV import script',
        output_fields='id, name, managementip, org_id, osfamily_id, osversion_id'
    )
    
    if result and result.get('code') == 0:
        if 'objects' in result and result['objects']:
            # Get the ID of the created object
            created_id = list(result['objects'].keys())[0]
            logger.info(f"Successfully created {server_type} with ID: {created_id}")
            return result
        else:
            logger.warning(f"Creation succeeded but no object ID returned")
            return result
    else:
        error_msg = result.get('message', 'Unknown error') if result else 'API call failed'
        logger.error(f"Failed to create {server_type}: {error_msg}")
        return None


def get_organization_id(org_name: str) -> str:
    """
    Get the ID of an organization by name, using hardcoded values for known organizations.
    """
    # Check fallback IDs first for known organizations
    if org_name in FALLBACK_IDS['organizations']:
        logger.info(f"Using hardcoded ID for Organization '{org_name}'")
        return FALLBACK_IDS['organizations'][org_name]
        
    # For unknown organizations, attempt to find them in iTop
    # Use LIKE for case-insensitive matching
    oql_query = f"SELECT Organization WHERE name LIKE '{org_name}'"
    result = call_itop_api(
        operation='core/get',
        class_name='Organization',
        key=oql_query
    )
    
    if result and result.get('code') == 0 and result.get('objects'):
        # Return the first organization ID found
        first_object_id = list(result['objects'].keys())[0]
        org_id = first_object_id.split('::')[1]
        logger.info(f"Found organization '{org_name}' with ID: {org_id}")
        return org_id
    
    # Try with wildcard search if exact match fails
    oql_query = f"SELECT Organization WHERE name LIKE '%{org_name}%'"
    result = call_itop_api(
        operation='core/get',
        class_name='Organization',
        key=oql_query
    )
    
    if result and result.get('code') == 0 and result.get('objects'):
        # Return the first organization ID found
        first_object_id = list(result['objects'].keys())[0]
        org_id = first_object_id.split('::')[1]
        logger.info(f"Found organization matching '{org_name}' with ID: {org_id}")
        return org_id
    
    logger.warning(f"Organization '{org_name}' not found in iTop and no hardcoded ID available")
    return ""


def get_os_family_id(os_name: str) -> str:
    """
    Get the ID of an OS family by name, using hardcoded values for known OS families.
    """
    # Check fallback IDs first for known OS families
    if os_name in FALLBACK_IDS['os_families']:
        logger.info(f"Using hardcoded ID for OS Family '{os_name}'")
        return FALLBACK_IDS['os_families'][os_name]
    
    # For unknown OS families, attempt to find them in iTop
    oql_query = f"SELECT OSFamily WHERE name = '{os_name}'"
    result = call_itop_api(
        operation='core/get',
        class_name='OSFamily',
        key=oql_query
    )
    
    if result and result.get('objects'):
        # Sort by ID and take the lowest
        os_ids = [int(obj_id.split('::')[1]) for obj_id in result['objects']]
        return str(min(os_ids))
    
    # Try partial match if exact match failed
    oql_query = f"SELECT OSFamily WHERE name LIKE '%{os_name}%'"
    result = call_itop_api(
        operation='core/get',
        class_name='OSFamily',
        key=oql_query
    )
    
    if result and result.get('objects'):
        # Sort by ID and take the lowest
        os_ids = [int(obj_id.split('::')[1]) for obj_id in result['objects']]
        return str(min(os_ids))
        
    logger.warning(f"OS Family '{os_name}' not found in iTop and no hardcoded ID available")
    return ""


def get_os_version_id(os_version: str) -> str:
    """
    Get the ID of an OS version by name, or use hardcoded ID for specific versions.
    """
    # Check fallback IDs first for known OS versions (including 8.10)
    if os_version in FALLBACK_IDS['os_versions']:
        logger.info(f"Using hardcoded ID for OS Version '{os_version}'")
        return FALLBACK_IDS['os_versions'][os_version]
    
    # For other versions, use dynamic lookup via OQL query
    oql_query = f"SELECT OSVersion WHERE name = '{os_version}'"
    result = call_itop_api(
        operation='core/get',
        class_name='OSVersion',
        key=oql_query
    )
    
    if result and result.get('objects'):
        # Sort by ID and take the lowest
        version_ids = [int(obj_id.split('::')[1]) for obj_id in result['objects']]
        return str(min(version_ids))
        
    # Try partial match if exact match failed
    oql_query = f"SELECT OSVersion WHERE name LIKE '%{os_version}%'"
    result = call_itop_api(
        operation='core/get',
        class_name='OSVersion',
        key=oql_query
    )
    
    if result and result.get('objects'):
        # Sort by ID and take the lowest
        version_ids = [int(obj_id.split('::')[1]) for obj_id in result['objects']]
        return str(min(version_ids))
    
    logger.warning(f"OS Version '{os_version}' not found in iTop and no hardcoded ID available")
    return ""


def verify_fqdn_ip_match(fqdn: str, ip: str) -> bool:
    """
    DNS verification has been disabled - always returns True
    """
    # DNS verification has been disabled as requested
    logger.info(f"DNS verification disabled - accepting {fqdn} - {ip} without verification")
    return True


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


def process_csv(csv_file_path: str) -> None:
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
            
            # Step 1: Verify FQDN-IP match - Always returns True now as DNS verification is disabled
            if not verify_fqdn_ip_match(fqdn, ip):
                logger.warning(f"FQDN-IP mismatch: {fqdn} - {ip}, skipping")
                skipped_count += 1
                continue
            
            # Step 2: Check if server exists in iTop
            existing_server = search_itop(fqdn, ip)
            
            if existing_server:
                logger.info(f"Server {fqdn} already exists in iTop, skipping")
                already_exists_count += 1
                continue
            
            # Step 3: Create server in iTop
            server_type = determine_server_type(fqdn)
            organization = determine_organization(fqdn)
            logger.info(f"Determined organization: {organization} for {fqdn}")
            org_id = get_organization_id(organization)
            
            logger.info(f"Using OS Name: {row['OS_Name']} for {fqdn}")
            os_family_id = get_os_family_id(row['OS_Name'])
            
            logger.info(f"Using OS Version: {row['OS_Version']} for {fqdn}")
            os_version_id = get_os_version_id(row['OS_Version'])
            
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
            
            # Add VirtualHost for VirtualMachine type only
            if server_type == "VirtualMachine":
                # Determine the correct VirtualHost based on name and OS
                virtualhost_name = ""
                is_windows = row['OS_Name'].lower() == "windows"
                has_aocms = "aocms" in fqdn.lower()
                
                if has_aocms and is_windows:
                    virtualhost_name = "CMSO-CMECF-W"
                elif has_aocms and not is_windows:
                    virtualhost_name = "CMSO-CMECF-E"
                elif not has_aocms and not is_windows:
                    virtualhost_name = "CMSO-PPS-E"
                elif not has_aocms and is_windows:
                    virtualhost_name = "CMSO-PPS-W"
                
                # Add virtualhost_id to server_data using OQL query
                if virtualhost_name:
                    logger.info(f"Using VirtualHost: {virtualhost_name} for {fqdn}")
                    server_data['virtualhost_id'] = f"SELECT VirtualHost WHERE name = '{virtualhost_name}'"
            
            # Log the data being sent to iTop for debugging
            logger.info(f"Creating {server_type} with data: {json.dumps(server_data)}")
            
            # Create server in iTop
            create_result = create_itop_server(server_type, server_data)
            
            if create_result and create_result.get('code') == 0:
                logger.info(f"Successfully created {server_type} {fqdn} in iTop")
                created_count += 1
            else:
                error_msg = create_result.get('message', 'Unknown error') if create_result else 'API call failed'
                logger.error(f"Failed to create {server_type} {fqdn} in iTop: {error_msg}")
                skipped_count += 1
    
    # Report summary
    logger.info(f"Import complete: {created_count} servers created, {already_exists_count} already exist, {skipped_count} skipped")


def test_itop_connection():
    """Test the connection to iTop"""
    logger.info("Testing connection to iTop server...")
    try:
        # Try list_operations first - this is the simplest operation that doesn't require class parameters
        result = call_itop_api(operation='list_operations')
        
        if result and result.get('code') == 0:
            logger.info(f"Successfully connected to iTop! Available operations: {len(result.get('operations', []))}")
            logger.debug(f"Available operations: {[op.get('verb') for op in result.get('operations', [])]}")
            return True
            
        # Fallback to a simple query if list_operations is not available
        if not result or result.get('code') != 0:
            logger.debug("Trying fallback connection test with Organization query")
            result = call_itop_api(
                operation='core/get',
                class_name='Organization',
                key="SELECT Organization LIMIT 1"
            )
            
            if result and result.get('code') == 0:
                logger.info("Successfully connected to iTop using Organization query!")
                return True
                
        # If we get here, both connection tests failed
        logger.error(f"Failed to connect to iTop: {result.get('message') if result else 'No response'}")
        return False
    except Exception as e:
        logger.exception(f"Connection test failed: {e}")
        return False

def main():
    """Main function"""
    # Warning about disabled SSL verification
    logger.warning("SSL certificate verification is disabled. This is insecure and should only be used in test environments.")
    logger.warning("DNS verification has been disabled. Machine names and IPs are not being validated.")
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <csv_file_path>")
        sys.exit(1)
    
    csv_file_path = sys.argv[1]
    
    try:
        # Log important configuration
        logger.info(f"Using iTop REST API at: {ITOP_API_ENDPOINT}")
        logger.info(f"API version: {ITOP_VERSION}")
        logger.info(f"Using username: {ITOP_USER}")
        
        # Test connection first using the new API structure
        if test_itop_connection():
            # Process CSV using the new API functions
            process_csv(csv_file_path)
        else:
            logger.error("Unable to continue due to iTop connection issues")
            sys.exit(1)
        
    except Exception as e:
        logger.exception(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
