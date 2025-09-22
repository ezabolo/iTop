#!/usr/bin/env python3
"""
iTop Advanced Server Import/Update Tool

This script reads server information from a CSV file and imports/updates it into iTop.
It checks if machines exist in iTop by IP address and updates all fields from the file.
"""

import sys
import json
import logging
import argparse
import pandas as pd
import csv
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

# Custom field mappings - map CSV column names to iTop database fields
FIELD_MAPPINGS = {
    "AO_Program": "aoprogram",
    "AO_CMECF_Circuit": "aocmecfcirtcuit", 
    "AO_CMECF_Court_Type": "aocmecfcourttype",
    "Function": "functionpurpose",
    "Environment": "cmsofunction",
    "OS Name": "osfamily_id",  # These will be mapped to IDs
    "OS Version": "osversion_id",
    "Owner": "ownerorg",
    "Organization": "org_id",
    "FQDN": "name",
    "IP": "managementip",
    "VirtualHost": "virtualhost_id"  # Mandatory field for VirtualMachine objects
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
    logger.info(f"API Request to {ITOP_API_ENDPOINT}")
    logger.info(f"Operation: {operation}, Class: {class_name}")
    if operation == 'core/update':
        logger.info(f"Update key: {key}")
        logger.info(f"Update fields: {json.dumps(fields, indent=2, default=str)}")
    logger.info(f"JSON Data: {json.dumps(json_data, indent=2, default=str)}")
    
    try:
        # Make the API request with SSL verification disabled
        # Using POST with form data as per iTop documentation
        response = requests.post(
            ITOP_API_ENDPOINT,
            data=form_data,  # Use form data, not JSON payload
            verify=False
        )
        
        # Log response details
        logger.info(f"Response status: {response.status_code}")
        logger.debug(f"Response headers: {response.headers}")
        logger.info(f"Response text: {response.text[:500]}..." if len(response.text) > 500 else response.text)
        
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
    logger.info(f"Searching in Server class with IP: {ip}")
    oql_query = f"SELECT Server WHERE {condition_str}"
    
    # Get all important fields
    output_fields = 'id, name, managementip, org_id, osfamily_id, osversion_id, ownerorg, description, brand_id, model_id'
    
    # Call the API
    result = call_itop_api(
        operation='core/get',
        class_name='Server',
        key=oql_query,
        output_fields=output_fields
    )
    
    # If not found as Server, try VirtualMachine
    if not result or not result.get('objects') or len(result.get('objects', {})) == 0:
        logger.info(f"Not found as Server, trying VirtualMachine with IP: {ip}")
        oql_query = f"SELECT VirtualMachine WHERE {condition_str}"
        result = call_itop_api(
            operation='core/get',
            class_name='VirtualMachine',
            key=oql_query,
            output_fields=output_fields
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
        comment='Created via CSV import script',
        output_fields='id, name, managementip, org_id, osfamily_id, osversion_id, ownerorg'
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
    logger.info(f"Original update data: {json.dumps(update_data, indent=2, default=str)}")
    
    # Clean up the update data to avoid format issues
    cleaned_data = {}
    for key, value in update_data.items():
        # Skip empty values
        if value is None or value == "":
            continue
            
        # Ensure all values are strings to avoid JSON formatting issues
        cleaned_data[key] = str(value).strip()
    
    # Extract numeric ID from the server_id string (format is typically 'ClassType::ID')
    try:
        if '::' in server_id:
            numeric_id = int(server_id.split('::')[1])
        else:
            # If we already have just the numeric ID, convert it to int
            numeric_id = int(server_id)
            
        logger.info(f"Cleaned update data: {json.dumps(cleaned_data, indent=2)}")
        
        # Call the API to update the object using the cleaned data
        result = call_itop_api(
            operation='core/update',
            class_name=server_class,
            key=numeric_id,  # Use numeric ID for the key
            fields=cleaned_data,
            comment='Updated via CSV import script',
            output_fields='id, name, managementip, org_id, osfamily_id, osversion_id, ownerorg'
        )
    except ValueError as e:
        logger.error(f"Invalid server ID format: {server_id}. Error: {e}")
        return None
    
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


def get_virtualhost_id(virtualhost_name: str) -> str:
    """
    Get the ID of a VirtualHost by name.
    Returns the ID if found, empty string otherwise.
    """
    if not virtualhost_name:
        return ""
    
    logger.info(f"Looking up VirtualHost ID for: {virtualhost_name}")
    
    # Query for VirtualHost by name
    oql_query = f"SELECT VirtualHost WHERE name = '{virtualhost_name}'"
    result = call_itop_api(
        operation='core/get',
        class_name='VirtualHost',
        key=oql_query,
        output_fields='id, name'
    )
    
    if result and result.get('objects'):
        # Get the first VirtualHost found
        first_object_id = list(result['objects'].keys())[0]
        virtualhost_id = first_object_id.split('::')[1]
        logger.info(f"Found VirtualHost '{virtualhost_name}' with ID: {virtualhost_id}")
        return virtualhost_id
    
    # Try partial match if exact match failed
    oql_query = f"SELECT VirtualHost WHERE name LIKE '%{virtualhost_name}%'"
    result = call_itop_api(
        operation='core/get',
        class_name='VirtualHost',
        key=oql_query,
        output_fields='id, name'
    )
    
    if result and result.get('objects'):
        # Get the first VirtualHost found
        first_object_id = list(result['objects'].keys())[0]
        virtualhost_id = first_object_id.split('::')[1]
        logger.info(f"Found VirtualHost containing '{virtualhost_name}' with ID: {virtualhost_id}")
        return virtualhost_id
    
    logger.warning(f"VirtualHost '{virtualhost_name}' not found in iTop")
    return ""


# Note: The get_person_id function has been removed as we now use ownerorg instead of owner_id
# Owner field in CSV now refers to an organization, not a person


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


def validate_csv_data(df: pd.DataFrame) -> bool:
    """
    Simplified validation - only check for IP column
    """
    # Only check for IP column
    if 'IP' not in df.columns:
        logger.error("Missing required IP column in CSV file")
        return False
    
    # Check for empty IP values
    empty_ip = df['IP'].isna().sum()
    if empty_ip > 0:
        logger.error(f"Found {empty_ip} empty IP values")
        logger.error("IP is a required field and cannot be empty")
        return False
    
    logger.info("CSV data validation passed")
    return True


def process_csv(file_path: str) -> None:
    """
    Process the CSV file and import/update servers in iTop
    Simplified to just check if machine exists by IP and update all fields
    """
    try:
        # Read CSV file
        try:
            df = pd.read_csv(file_path)
            logger.info(f"Read {len(df)} rows from CSV file")
        except Exception as e:
            logger.error(f"Failed to read CSV file: {e}")
            return
        
        # Validate data - only checks for IP column
        if not validate_csv_data(df):
            logger.error("CSV data validation failed, aborting import")
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
                
                # Log available fields in CSV row for debugging
                logger.info(f"CSV fields available in row: {list(df.columns)}")
                
                # Process each column in the CSV row based on field mappings
                for csv_field, itop_field in FIELD_MAPPINGS.items():
                    # Skip processing if the field isn't in the CSV or value is empty
                    if csv_field not in df.columns:
                        logger.debug(f"Field '{csv_field}' not found in CSV, skipping")
                        continue
                    
                    if pd.isna(row[csv_field]):
                        logger.debug(f"Field '{csv_field}' is empty, skipping")
                        continue
                        
                    # Get the value and sanitize it
                    value = str(row[csv_field]).strip()
                    if not value:  # Skip empty values
                        logger.debug(f"Field '{csv_field}' has empty value after stripping, skipping")
                        continue
                        
                    logger.info(f"Processing field '{csv_field}' with value '{value}' -> iTop field '{itop_field}'")

                        
                    # Handle special fields that need ID lookups
                    if csv_field == 'Organization':
                        org_id = get_organization_id(value)
                        if org_id:
                            server_data['org_id'] = org_id
                    elif csv_field == 'Owner':
                        owner_org_id = get_organization_id(value)
                        if owner_org_id:
                            server_data['ownerorg'] = owner_org_id
                    elif csv_field == 'OS Name':
                        os_family_id = get_os_family_id(value)
                        if os_family_id:
                            server_data['osfamily_id'] = os_family_id
                    elif csv_field == 'OS Version':
                        os_version_id = get_os_version_id(value)
                        if os_version_id:
                            server_data['osversion_id'] = os_version_id
                    elif csv_field == 'IP':  # IP is handled separately
                        continue  # Skip as we already have it
                    elif csv_field == 'FQDN':  # FQDN maps to name
                        server_data['name'] = value
                    elif csv_field == 'VirtualHost':
                        # Try to get the numeric ID for the VirtualHost
                        virtualhost_id = get_virtualhost_id(value)
                        if virtualhost_id:
                            # Use the numeric ID directly
                            server_data['virtualhost_id'] = virtualhost_id
                            logger.info(f"Set virtualhost_id to: {virtualhost_id}")
                        else:
                            # Fallback to OQL reference if lookup fails
                            server_data['virtualhost_id'] = f"SELECT VirtualHost WHERE name = '{value}'"
                            logger.info(f"Set virtualhost_id to OQL reference: {server_data['virtualhost_id']}")
                    else:  # For all other mapped fields
                        # Use the mapping to get the correct iTop field name
                        server_data[itop_field] = value
                        
                # Always include IP address
                server_data['managementip'] = ip
                
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
    """Parse command line arguments - CSV version"""
    parser = argparse.ArgumentParser(description='iTop Server Import/Update Tool - CSV Version')
    
    # Required arguments
    parser.add_argument('csv_file', help='Path to CSV file containing server data')
    
    # Essential optional arguments
    parser.add_argument('--url', help='iTop URL (e.g., https://itop.example.com)')
    parser.add_argument('--user', help='iTop API username')
    parser.add_argument('--password', help='iTop API password')
    
    return parser.parse_args()


def main():
    """Main function - simplified for CSV processing only"""
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
        logger.info(f"Processing CSV file: {args.csv_file}")
        
        # Process CSV file directly - minimal controls
        process_csv(args.csv_file)
        
    except Exception as e:
        logger.exception(f"Error processing CSV file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
