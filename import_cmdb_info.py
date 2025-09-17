#!/usr/bin/env python3
"""
iTop Advanced Server Import/Update Tool

This script reads server information from an Excel file and imports/updates it into iTop.
It can update existing servers or create new ones if they don't exist.
"""

import sys
import json
import logging
import argparse
import pandas as pd
import dns.resolver
import requests
import socket
from typing import Dict, List, Tuple, Optional, Union, Any

# Disable InsecureRequestWarning
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Change to DEBUG for more verbose output
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("itop_import_advanced.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# iTop API configuration - will be overridden by command line args
ITOP_URL = "https://myitop.example.com"  # Base URL
ITOP_API_ENDPOINT = f"{ITOP_URL}/webservices/rest.php"  # REST API endpoint
ITOP_USER = "itopuser"
ITOP_PWD = "XXXX"  # Replace with your actual password
ITOP_VERSION = "1.3"  # iTop API version

# Fallback IDs for common entities when search fails
FALLBACK_IDS = {
    "organizations": {
        "CHNO": "3",  # As specified
        "CMSO": "2"   # As specified
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

# Custom field mappings
CUSTOM_FIELDS = [
    "AO_Program",
    "AO_CMECF_Circuit",
    "AO_CMECF_Court_TYpe",
    "Environment",
    "Function"
]

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
        output_fields='id, name, managementip, org_id, osfamily_id, osversion_id, owner_id, description'
    )
    
    # If not found as Server, try VirtualMachine
    if not result or not result.get('objects') or len(result.get('objects', {})) == 0:
        logger.debug("Not found as Server, trying VirtualMachine")
        oql_query = f"SELECT VirtualMachine WHERE {condition_str}"
        result = call_itop_api(
            operation='core/get',
            class_name='VirtualMachine',
            key=oql_query,
            output_fields='id, name, managementip, org_id, osfamily_id, osversion_id, owner_id, description'
        )
    
    # Check if any objects were found
    if result and result.get('objects') and len(result.get('objects', {})) > 0:
        found_objects = result['objects']
        # Return the first object found
        first_object_id = list(found_objects.keys())[0]
        logger.info(f"Machine '{name}' found in iTop with ID: {first_object_id}")
        found_object = found_objects[first_object_id]
        # Extract the class name from the key (format is "ClassType::ID")
        class_name = first_object_id.split('::')[0]
        found_object['class'] = class_name  # Add the class name to the returned object
        found_object['itop_key'] = first_object_id  # Add the full key to the returned object
        return found_object
    
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
        comment='Created via Excel import script',
        output_fields='id, name, managementip, org_id, osfamily_id, osversion_id, owner_id'
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


def update_itop_server(server_class: str, server_id: str, update_data: Dict) -> Dict:
    """
    Updates an existing server or virtual machine in iTop.
    """
    logger.info(f"Updating {server_class} in iTop with ID: {server_id}")
    logger.debug(f"Update data: {json.dumps(update_data, indent=2, default=str)}")
    
    # Call the API to update the object
    result = call_itop_api(
        operation='core/update',
        class_name=server_class,
        key=server_id,
        fields=update_data,
        comment='Updated via Excel import script',
        output_fields='id, name, managementip, org_id, osfamily_id, osversion_id, owner_id'
    )
    
    if result and result.get('code') == 0:
        logger.info(f"Successfully updated {server_class} with ID: {server_id}")
        return result
    else:
        error_msg = result.get('message', 'Unknown error') if result else 'API call failed'
        logger.error(f"Failed to update {server_class}: {error_msg}")
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
    # Check fallback IDs first for known OS versions
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


def get_person_id(owner_name: str) -> str:
    """
    Get the ID of a person by name
    """
    if not owner_name:
        return ""
        
    # For person lookup via OQL query
    # We search by both first name and last name
    oql_query = f"SELECT Person WHERE name LIKE '%{owner_name}%' OR first_name LIKE '%{owner_name}%'"
    result = call_itop_api(
        operation='core/get',
        class_name='Person',
        key=oql_query
    )
    
    if result and result.get('objects'):
        # Sort by ID and take the lowest
        person_ids = [int(obj_id.split('::')[1]) for obj_id in result['objects']]
        found_id = str(min(person_ids))
        logger.info(f"Found person '{owner_name}' with ID: {found_id}")
        return found_id
    
    logger.warning(f"Person '{owner_name}' not found in iTop")
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


def validate_excel_data(df: pd.DataFrame) -> bool:
    """
    Validate the Excel data to ensure it has all required columns
    """
    required_columns = [
        'FQDN', 'IP', 'OS Name', 'OS Version', 
        'Organization', 'Owner', 'Environment', 'Function'
    ]
    
    # Check if all required columns are present
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        logger.error(f"Missing required columns in Excel file: {missing_columns}")
        return False
    
    # Check for empty values in critical columns
    empty_fqdn = df['FQDN'].isna().sum()
    empty_ip = df['IP'].isna().sum()
    
    if empty_fqdn > 0 or empty_ip > 0:
        logger.error(f"Found {empty_fqdn} empty FQDN values and {empty_ip} empty IP values")
        logger.error("FQDN and IP are required fields and cannot be empty")
        return False
    
    logger.info("Excel data validation passed")
    return True


def process_excel(excel_file_path: str, sheet_name: str = None) -> None:
    """
    Process the Excel file and import/update servers in iTop
    """
    try:
        # Read Excel file
        if sheet_name:
            df = pd.read_excel(excel_file_path, sheet_name=sheet_name)
        else:
            df = pd.read_excel(excel_file_path)
            
        logger.info(f"Read {len(df)} rows from Excel file")
        
        # Validate data
        if not validate_excel_data(df):
            logger.error("Excel data validation failed, aborting import")
            return
        
        # Initialize counters
        created_count = 0
        updated_count = 0
        skipped_count = 0
        error_count = 0
        
        # Process each row
        for index, row in df.iterrows():
            try:
                logger.info(f"Processing row {index + 1}: {row['FQDN']}")
                
                fqdn = row['FQDN'].strip()
                ip = row['IP'].strip()
                
                # Step 1: Verify FQDN-IP match - Always returns True now as DNS verification is disabled
                if not verify_fqdn_ip_match(fqdn, ip):
                    logger.warning(f"FQDN-IP mismatch: {fqdn} - {ip}, skipping")
                    skipped_count += 1
                    continue
                
                # Step 2: Check if server exists in iTop
                existing_server = search_itop(fqdn, ip)
                
                # Get the required IDs
                organization_name = row.get('Organization', determine_organization(fqdn))
                org_id = get_organization_id(organization_name)
                
                os_name = row.get('OS Name', '')
                os_family_id = get_os_family_id(os_name)
                
                os_version = row.get('OS Version', '')
                os_version_id = get_os_version_id(os_version)
                
                owner_name = row.get('Owner', '')
                owner_id = get_person_id(owner_name)
                
                # Check for required IDs
                if not org_id:
                    logger.error(f"Failed to get organization ID for {organization_name}, skipping {fqdn}")
                    error_count += 1
                    continue
                
                if not os_family_id and os_name:
                    logger.error(f"Failed to get OS Family ID for {os_name}, skipping {fqdn}")
                    error_count += 1
                    continue
                
                if not os_version_id and os_version:
                    logger.error(f"Failed to get OS Version ID for {os_version}, skipping {fqdn}")
                    error_count += 1
                    continue
                
                # Prepare common data for both create and update
                server_data = {
                    'name': fqdn,
                    'managementip': ip
                }
                
                # Add organization if available
                if org_id:
                    server_data['org_id'] = org_id
                
                # Add OS family and version if available
                if os_family_id:
                    server_data['osfamily_id'] = os_family_id
                if os_version_id:
                    server_data['osversion_id'] = os_version_id
                
                # Add owner if available
                if owner_id:
                    server_data['owner_id'] = owner_id
                
                # Add description from Function field if available
                if 'Function' in row and not pd.isna(row['Function']):
                    server_data['description'] = str(row['Function'])
                
                # Add custom fields if they exist in the row
                for field_name in CUSTOM_FIELDS:
                    if field_name in row and not pd.isna(row[field_name]):
                        # Convert custom field name to lowercase for iTop API compatibility
                        itop_field_name = field_name.lower()
                        server_data[itop_field_name] = str(row[field_name])
                
                # If server exists, update it
                if existing_server:
                    server_class = existing_server['class']
                    server_key = existing_server['itop_key']
                    
                    # Call update function
                    update_result = update_itop_server(server_class, server_key, server_data)
                    
                    if update_result and update_result.get('code') == 0:
                        logger.info(f"Successfully updated {server_class} {fqdn} in iTop")
                        updated_count += 1
                    else:
                        logger.error(f"Failed to update {server_class} {fqdn} in iTop")
                        error_count += 1
                else:
                    # Server doesn't exist, create it
                    # Determine server type
                    server_type = determine_server_type(fqdn)
                    
                    # Add CPU, Memory, and Storage if available for new servers
                    if 'CPU' in row and not pd.isna(row['CPU']):
                        server_data['cpu'] = str(row['CPU'])
                    if 'Memory' in row and not pd.isna(row['Memory']):
                        server_data['ram'] = str(row['Memory'])
                    if 'Storage' in row and not pd.isna(row['Storage']):
                        server_data['diskspace'] = str(row['Storage'])
                    
                    # Add VirtualHost for VirtualMachine type only
                    if server_type == "VirtualMachine" and 'VirtualHost' in row and not pd.isna(row['VirtualHost']):
                        virtualhost_name = row['VirtualHost']
                        server_data['virtualhost_id'] = f"SELECT VirtualHost WHERE name = '{virtualhost_name}'"
                    
                    # Create server in iTop
                    create_result = create_itop_server(server_type, server_data)
                    
                    if create_result and create_result.get('code') == 0:
                        logger.info(f"Successfully created {server_type} {fqdn} in iTop")
                        created_count += 1
                    else:
                        error_msg = create_result.get('message', 'Unknown error') if create_result else 'API call failed'
                        logger.error(f"Failed to create {server_type} {fqdn} in iTop: {error_msg}")
                        error_count += 1
            
            except Exception as e:
                logger.exception(f"Error processing row {index + 1}: {e}")
                error_count += 1
        
        # Report summary
        logger.info(f"Import complete: {created_count} servers created, {updated_count} servers updated, "
                    f"{skipped_count} skipped, {error_count} errors")
        
    except Exception as e:
        logger.exception(f"Failed to process Excel file: {e}")


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


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='iTop Server Import/Update Tool')
    
    # Required arguments
    parser.add_argument('excel_file', help='Path to Excel file containing server data')
    
    # Optional arguments
    parser.add_argument('--sheet', help='Excel sheet name to read data from')
    parser.add_argument('--url', help='iTop URL (e.g., https://itop.example.com)')
    parser.add_argument('--user', help='iTop API username')
    parser.add_argument('--password', help='iTop API password')
    parser.add_argument('--verify-dns', action='store_true', help='Enable DNS verification')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    return parser.parse_args()


def main():
    """Main function"""
    global ITOP_URL, ITOP_API_ENDPOINT, ITOP_USER, ITOP_PWD
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Update global variables from command line arguments if provided
    if args.url:
        ITOP_URL = args.url
        ITOP_API_ENDPOINT = f"{ITOP_URL}/webservices/rest.php"
    
    if args.user:
        ITOP_USER = args.user
    
    if args.password:
        ITOP_PWD = args.password
    
    # Warning about disabled SSL verification
    logger.warning("SSL certificate verification is disabled. This is insecure and should only be used in test environments.")
    
    # Warning about disabled DNS verification
    if not args.verify_dns:
        logger.warning("DNS verification has been disabled. Machine names and IPs are not being validated.")
    
    try:
        # Log important configuration
        logger.info(f"Using iTop REST API at: {ITOP_API_ENDPOINT}")
        logger.info(f"API version: {ITOP_VERSION}")
        logger.info(f"Using username: {ITOP_USER}")
        logger.info(f"Processing Excel file: {args.excel_file}")
        
        # Test connection first
        if test_itop_connection():
            # Process Excel file
            process_excel(args.excel_file, args.sheet)
        else:
            logger.error("Unable to continue due to iTop connection issues")
            sys.exit(1)
        
    except Exception as e:
        logger.exception(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
