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


def search_itop_by_ip(ip: str) -> Dict:
    """
    Searches for a machine in iTop by IP only.
    Returns the iTop object data if found, None otherwise.
    """
    logger.info(f"Searching iTop for machine with IP: {ip}")
    
    if not ip:
        logger.warning("No IP address provided for search")
        return None
    
    # Create query to search by IP only
    condition_str = f"managementip = '{ip}'"
    
    # Try Server class first
    logger.debug(f"Searching in Server class with IP: {ip}")
    oql_query = f"SELECT Server WHERE {condition_str}"
    
    # Call the API
    result = call_itop_api(
        operation='core/get',
        class_name='Server',
        key=oql_query,
        output_fields='id, name, managementip'
    )
    
    # If not found as Server, try VirtualMachine
    if not result or not result.get('objects') or len(result.get('objects', {})) == 0:
        logger.debug(f"Not found as Server, trying VirtualMachine with IP: {ip}")
        oql_query = f"SELECT VirtualMachine WHERE {condition_str}"
        result = call_itop_api(
            operation='core/get',
            class_name='VirtualMachine',
            key=oql_query,
            output_fields='id, name, managementip'
        )
    
    # Check if any objects were found
    if result and result.get('objects') and len(result.get('objects', {})) > 0:
        found_objects = result['objects']
        # Return the first object found
        first_object_id = list(found_objects.keys())[0]
        logger.info(f"Machine with IP '{ip}' found in iTop with ID: {first_object_id}")
        found_object = found_objects[first_object_id]
        # Extract the class name from the key (format is "ClassType::ID")
        class_name = first_object_id.split('::')[0]
        found_object['class'] = class_name  # Add the class name to the returned object
        found_object['itop_key'] = first_object_id  # Add the full key to the returned object
        return found_object
    
    logger.info(f"Machine with IP '{ip}' not found in iTop")
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
    Simplified validation - only check for IP column
    """
    # Only check for IP column
    if 'IP' not in df.columns:
        logger.error("Missing required IP column in Excel file")
        return False
    
    # Check for empty IP values
    empty_ip = df['IP'].isna().sum()
    if empty_ip > 0:
        logger.error(f"Found {empty_ip} empty IP values")
        logger.error("IP is a required field and cannot be empty")
        return False
    
    logger.info("Excel data validation passed")
    return True


def process_excel(excel_file_path: str, sheet_name: str = None) -> None:
    """
    Process the Excel file and import/update servers in iTop
    Simplified to just check if machine exists by IP and update all fields
    """
    try:
        # Read Excel file
        if sheet_name:
            df = pd.read_excel(excel_file_path, sheet_name=sheet_name)
        else:
            df = pd.read_excel(excel_file_path)
            
        logger.info(f"Read {len(df)} rows from Excel file")
        
        # Validate data - only checks for IP column
        if not validate_excel_data(df):
            logger.error("Excel data validation failed, aborting import")
            return
        
        # Initialize counters
        created_count = 0
        updated_count = 0
        skipped_count = 0
        
        # Process each row
        for index, row in df.iterrows():
            try:
                # Get IP address from row
                if pd.isna(row['IP']):
                    logger.warning(f"Skipping row {index + 1} - missing IP address")
                    skipped_count += 1
                    continue
                    
                ip = row['IP'].strip()
                logger.info(f"Processing row {index + 1} with IP: {ip}")
                
                # Check if machine exists by IP
                existing_server = search_itop_by_ip(ip)
                
                # Prepare data dictionary from all available columns
                server_data = {}
                
                # Add all columns from Excel as fields, skipping empty values
                for col in df.columns:
                    if col != 'IP' and not pd.isna(row[col]):  # Skip IP as we already have it
                        # Map Excel column names to iTop field names
                        itop_field = col.lower().replace(' ', '_')  # Convert spaces to underscores
                        server_data[itop_field] = str(row[col])
                
                # Always include IP address
                server_data['managementip'] = ip
                
                # If FQDN exists, use it for name
                if 'FQDN' in df.columns and not pd.isna(row['FQDN']):
                    server_data['name'] = row['FQDN'].strip()
                
                # Handle special fields that need ID lookups
                if 'Organization' in df.columns and not pd.isna(row['Organization']):
                    org_id = get_organization_id(row['Organization'])
                    if org_id:
                        server_data['org_id'] = org_id
                
                if 'OS Name' in df.columns and not pd.isna(row['OS Name']):
                    os_family_id = get_os_family_id(row['OS Name'])
                    if os_family_id:
                        server_data['osfamily_id'] = os_family_id
                
                if 'OS Version' in df.columns and not pd.isna(row['OS Version']):
                    os_version_id = get_os_version_id(row['OS Version'])
                    if os_version_id:
                        server_data['osversion_id'] = os_version_id
                
                if 'Owner' in df.columns and not pd.isna(row['Owner']):
                    owner_id = get_person_id(row['Owner'])
                    if owner_id:
                        server_data['owner_id'] = owner_id
                
                # If machine exists, update it
                if existing_server:
                    server_class = existing_server['class']
                    server_key = existing_server['itop_key']
                    
                    logger.info(f"Updating {server_class} with IP {ip}")
                    update_result = update_itop_server(server_class, server_key, server_data)
                    
                    if update_result and update_result.get('code') == 0:
                        logger.info(f"Successfully updated machine with IP {ip} in iTop")
                        updated_count += 1
                    else:
                        logger.error(f"Failed to update machine with IP {ip} in iTop")
                        skipped_count += 1
                else:
                    # If machine doesn't exist, determine the server type based on FQDN if available
                    server_type = "Server"  # Default type
                    if 'FQDN' in df.columns and not pd.isna(row['FQDN']):
                        server_type = determine_server_type(row['FQDN'])
                    
                    logger.info(f"Creating new {server_type} with IP {ip}")
                    create_result = create_itop_server(server_type, server_data)
                    
                    if create_result and create_result.get('code') == 0:
                        logger.info(f"Successfully created {server_type} with IP {ip} in iTop")
                        created_count += 1
                    else:
                        logger.error(f"Failed to create machine with IP {ip} in iTop")
                        skipped_count += 1
            
            except Exception as e:
                logger.exception(f"Error processing row {index + 1}: {e}")
                skipped_count += 1
        
        # Report summary
        logger.info(f"Import complete: {created_count} machines created, {updated_count} machines updated, "
                    f"{skipped_count} skipped")
        
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
    """Parse command line arguments - simplified version"""
    parser = argparse.ArgumentParser(description='iTop Server Import/Update Tool')
    
    # Required arguments
    parser.add_argument('excel_file', help='Path to Excel file containing server data')
    
    # Essential optional arguments
    parser.add_argument('--url', help='iTop URL (e.g., https://itop.example.com)')
    parser.add_argument('--user', help='iTop API username')
    parser.add_argument('--password', help='iTop API password')
    parser.add_argument('--sheet', help='Excel sheet name to read data from')
    
    return parser.parse_args()


def main():
    """Main function - simplified to focus on essential steps"""
    global ITOP_URL, ITOP_API_ENDPOINT, ITOP_USER, ITOP_PWD
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Update global variables from command line arguments if provided
    if args.url:
        ITOP_URL = args.url
        ITOP_API_ENDPOINT = f"{ITOP_URL}/webservices/rest.php"
    
    if args.user:
        ITOP_USER = args.user
    
    if args.password:
        ITOP_PWD = args.password
    
    try:
        logger.info(f"Using iTop REST API at: {ITOP_API_ENDPOINT}")
        logger.info(f"Using username: {ITOP_USER}")
        logger.info(f"Processing Excel file: {args.excel_file}")
        
        # Process Excel file directly - minimal controls
        process_excel(args.excel_file, args.sheet)
        
    except Exception as e:
        logger.exception(f"Error processing Excel file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
