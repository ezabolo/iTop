#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
iTop Hostname Update Script

This script reads a CSV file containing machine data and updates only the hostname
field of existing machines in iTop. It searches for machines by name and updates 
their hostname if they are found. If a machine is not found, it skips to the next one.

CSV file structure:
name,hostname
"""

import argparse
import csv
import json
import logging
import os
import sys
from datetime import datetime
import requests

# Set up logging
logger = logging.getLogger('itop_hostname_update')

def configure_logging():
    """
    Configure logging to output to both console and a log file
    """
    # Create logs directory if it doesn't exist
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Create a timestamped log file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f'itop_hostname_update_{timestamp}.log')
    
    # Configure logging
    logger.setLevel(logging.INFO)
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Format
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info("Starting iTop hostname update")
    logger.info(f"Logging to {log_file}")
    
    return log_file

# Initialize logging at module level
configure_logging()

# --- iTop API Functions ---

def call_itop_api(url, username, password, operation, class_name, key=None, fields=None, version='1.3', verify_ssl=False):
    """
    Helper function to make calls to the iTop REST API.
    
    Args:
        url (str): iTop API URL
        username (str): iTop username
        password (str): iTop password
        operation (str): API operation to perform
        class_name (str): iTop class name
        key: Search key or object ID
        fields (dict): Fields to update
        version (str): API version
        verify_ssl (bool): Whether to verify SSL certificate
    """
    payload = {
        'version': version,
        'auth': {
            'user': username,
            'password': password
        },
        'operation': operation,
        'class': class_name,
    }
    
    if key:
        payload['key'] = key
    
    if fields:
        payload['fields'] = fields
        
    if operation == 'core/update':
        payload['comment'] = 'Updated hostname via CSV import script'
    
    # Log the API request for debugging
    logger.info(f"API Request to {url}")
    logger.info(f"Payload: {json.dumps(payload)[:500]}..." if len(json.dumps(payload)) > 500 else json.dumps(payload))
    
    try:
        response = requests.post(url, json=payload, verify=verify_ssl)
        # Log the raw response for debugging
        logger.debug(f"Raw API response: {response.text[:500]}..." if len(response.text) > 500 else response.text)
        response.raise_for_status()
        json_response = response.json()
        return json_response
    except requests.exceptions.RequestException as e:
        logger.error(f"API call failed: {e}")
        logger.error(f"URL: {url}")
        # Try to get the response content if available
        try:
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response status code: {e.response.status_code}")
                logger.error(f"Response content: {e.response.text[:500]}")
        except:
            pass
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON response from iTop: {e}")
        logger.error(f"Response text: {response.text[:500]}..." if len(response.text) > 500 else response.text)
        return None

def check_api_connection(url, username, password, verify_ssl=False):
    """
    Check if we can connect to the iTop API before attempting any updates
    
    Args:
        url (str): iTop API URL
        username (str): iTop username
        password (str): iTop password
        verify_ssl (bool): Whether to verify SSL certificate
    
    Returns:
        bool: True if connection is successful, False otherwise
    """
    logger.info("Testing API connectivity...")
    
    # Try a very simple API call to test connectivity
    test_query = "SELECT Organization LIMIT 1"
    
    result = call_itop_api(
        url=url,
        username=username,
        password=password,
        operation='core/get',
        class_name='Organization',
        key=test_query,
        verify_ssl=verify_ssl
    )
    
    if result is None:
        logger.error("API connection test failed - could not connect to iTop")
        return False
    
    if 'code' in result and result['code'] != 0:
        logger.error(f"API connection test failed with error code {result['code']}: {result.get('message', 'Unknown error')}")
        return False
        
    logger.info("✓ API connection test successful!")
    
    # As an additional test, check if the expected classes exist
    for class_name in ['Server', 'VirtualMachine']:
        logger.info(f"Checking if class '{class_name}' exists...")
        class_query = f"SELECT {class_name} LIMIT 1"
        class_result = call_itop_api(
            url=url,
            username=username,
            password=password,
            operation='core/get',
            class_name=class_name,
            key=class_query,
            verify_ssl=verify_ssl
        )
        
        if class_result is None or ('code' in class_result and class_result['code'] != 0):
            logger.warning(f"Class '{class_name}' may not exist in this iTop instance or you may not have access to it")
        else:
            logger.info(f"✓ Class '{class_name}' exists and is accessible")
    
    return True

def search_machine_by_name(url, username, password, machine_type, name, verify_ssl=False):
    """
    Search for a machine in iTop by name
    
    Args:
        url (str): iTop API URL
        username (str): iTop username
        password (str): iTop password
        machine_type (str): Type of machine ('Server' or 'VirtualMachine')
        name (str): Machine name
        verify_ssl (bool): Whether to verify SSL certificate
    
    Returns:
        dict: Machine data if found, None otherwise
    """
    logger.info(f"Searching for {machine_type}: {name}")
    
    # Search by name only
    name_query = f"SELECT {machine_type} WHERE name = '{name}'"
    logger.info(f"Executing query: {name_query}")
    
    result = call_itop_api(
        url=url,
        username=username,
        password=password,
        operation='core/get',
        class_name=machine_type,
        key=name_query,
        verify_ssl=verify_ssl
    )
    
    # Check if we got results
    if result and isinstance(result, dict) and result.get('objects'):
        found_objects = result['objects']
        if found_objects:
            first_object_id = list(found_objects.keys())[0]
            logger.info(f"Found {machine_type} with ID: {first_object_id}")
            return found_objects[first_object_id]
    
    logger.warning(f"No {machine_type} found with name '{name}'")
    return None

def update_hostname(url, username, password, machine_type, name, hostname, verify_ssl=False):
    """
    Update a machine's hostname in iTop
    
    Args:
        url (str): iTop API URL
        username (str): iTop username
        password (str): iTop password
        machine_type (str): Type of machine ('Server' or 'VirtualMachine')
        name (str): Machine name
        hostname (str): New hostname value
        verify_ssl (bool): Whether to verify SSL certificate
    
    Returns:
        bool: True if update succeeded, False otherwise
    """
    # Use an OQL query to identify the machine by name
    key = f"SELECT {machine_type} WHERE name = '{name}'"
    
    # Prepare fields to update - only hostname
    fields = {'hostname': hostname}
    
    logger.info(f"Updating {machine_type} '{name}' hostname to '{hostname}'")
    
    result = call_itop_api(
        url=url,
        username=username,
        password=password,
        operation='core/update',
        class_name=machine_type,
        key=key,
        fields=fields,
        verify_ssl=verify_ssl
    )
    
    # Safely check the result
    success = False
    if result and isinstance(result, dict):
        # Check for successful update
        if result.get('code') == 0 or result.get('message') == 'Object updated':
            logger.info(f"Successfully updated hostname for {machine_type} '{name}'")
            success = True
        else:
            # Log any error message
            error_msg = result.get('message', 'Unknown error')
            logger.warning(f"Failed to update hostname for {machine_type} '{name}': {error_msg}")
    else:
        logger.warning(f"Failed to update hostname for {machine_type} '{name}': No valid response from API")
        
    return success

def process_csv(file_path, url, username, password, verify_ssl=False):
    """
    Process a CSV file and update hostnames in iTop
    
    Args:
        file_path (str): Path to the CSV file
        url (str): iTop API URL
        username (str): iTop username
        password (str): iTop password
        verify_ssl (bool): Whether to verify SSL certificate
    
    Returns:
        tuple: Number of processed, updated, and skipped records
    """
    processed = 0
    updated = 0
    skipped = 0
    
    try:
        logger.info(f"Opening CSV file: {file_path}")
        # Try different encodings if needed
        encodings = ['utf-8', 'utf-8-sig', 'latin1', 'ISO-8859-1']
        for encoding in encodings:
            try:
                with open(file_path, 'r', newline='', encoding=encoding) as test_file:
                    test_file.read(1024)
                logger.info(f"Successfully opened file with encoding: {encoding}")
                break
            except UnicodeDecodeError:
                logger.warning(f"Failed to open file with encoding: {encoding}")
                if encoding == encodings[-1]:
                    logger.error("Unable to open file with any supported encoding")
                    return processed, updated, skipped
                continue
        
        # Open with the successful encoding
        with open(file_path, 'r', newline='', encoding=encoding) as csvfile:
            # Try to determine the CSV format
            try:
                dialect = csv.Sniffer().sniff(csvfile.read(1024))
                csvfile.seek(0)  # Go back to beginning of file
            except csv.Error:
                logger.info("Could not determine CSV dialect, using default")
                dialect = csv.excel
            
            # Read the CSV file
            reader = csv.DictReader(csvfile, dialect=dialect)
            field_names = reader.fieldnames if reader.fieldnames else []
            logger.info(f"CSV field names: {field_names}")
            
            # Check for required fields
            has_type = 'type' in field_names or 'machineType' in field_names
            has_name = 'name' in field_names
            has_hostname = 'hostname' in field_names
            
            if not has_type:
                logger.error("CSV is missing required field 'type' or 'machineType'. Cannot continue.")
                return processed, updated, skipped
                
            if not has_name:
                logger.error("CSV is missing required field 'name'. Cannot continue.")
                return processed, updated, skipped
                
            if not has_hostname:
                logger.error("CSV is missing required field 'hostname'. Cannot continue.")
                return processed, updated, skipped
            
            # Determine which field name to use for machine type
            type_field = 'machineType' if 'machineType' in field_names else 'type'
            logger.info(f"Using '{type_field}' for machine type field")
            
            # Process each row
            for row_num, row in enumerate(reader, start=1):
                try:
                    processed += 1
                    logger.info(f"Processing row {row_num}: {row}")
                    
                    # Extract and validate required fields
                    machine_type = row.get(type_field, '').strip() if row.get(type_field) else ''
                    name = row.get('name', '').strip() if row.get('name') else ''
                    hostname = row.get('hostname', '').strip() if row.get('hostname') else ''
                    
                    # Validate required fields
                    if not machine_type:
                        logger.warning(f"Row {row_num}: Missing machine type. Skipping.")
                        skipped += 1
                        continue
                    
                    if not name:
                        logger.warning(f"Row {row_num}: Missing machine name. Skipping.")
                        skipped += 1
                        continue
                    
                    if not hostname:
                        logger.warning(f"Row {row_num}: Missing hostname. Skipping.")
                        skipped += 1
                        continue
                    
                    # Validate machine type
                    if machine_type not in ['Server', 'VirtualMachine']:
                        logger.warning(f"Row {row_num}: Invalid machine type '{machine_type}'. Skipping.")
                        skipped += 1
                        continue
                    
                    logger.info(f"Processing {machine_type}: {name}")
                    
                    try:
                        # Search for the machine in iTop
                        machine = search_machine_by_name(
                            url=url,
                            username=username,
                            password=password,
                            machine_type=machine_type,
                            name=name,
                            verify_ssl=verify_ssl
                        )
                        
                        if not machine:
                            logger.warning(f"Row {row_num}: {machine_type} '{name}' not found in iTop. Skipping.")
                            skipped += 1
                            continue
                        
                        logger.info(f"Machine '{name}' found in iTop. Proceeding to update hostname.")
                        
                        # Update the hostname in iTop
                        success = update_hostname(
                            url=url,
                            username=username,
                            password=password,
                            machine_type=machine_type,
                            name=name,
                            hostname=hostname,
                            verify_ssl=verify_ssl
                        )
                        
                        if success:
                            updated += 1
                            logger.info(f"Successfully updated hostname for {machine_type} '{name}' to '{hostname}'")
                        else:
                            skipped += 1
                            logger.warning(f"Failed to update hostname for {machine_type} '{name}'")
                    
                    except Exception as e:
                        logger.error(f"Error processing row {row_num}: {e}")
                        skipped += 1
                        continue
                
                except Exception as row_error:
                    logger.error(f"Error processing row {row_num}: {row_error}")
                    skipped += 1
                    continue
        
        logger.info(f"CSV processing complete. Processed: {processed}, Updated: {updated}, Skipped: {skipped}")
        return processed, updated, skipped
    
    except FileNotFoundError:
        logger.error(f"CSV file not found: {file_path}")
        return processed, updated, skipped
    except csv.Error as e:
        logger.error(f"CSV error: {e}")
        return processed, updated, skipped
    except Exception as e:
        logger.error(f"Error processing CSV: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return processed, updated, skipped

def main():
    """
    Main entry point
    """
    parser = argparse.ArgumentParser(description='Update machine hostnames in iTop from a CSV file')
    parser.add_argument('csv_file', help='Path to the CSV file')
    parser.add_argument('--url', required=True, help='iTop REST API URL (e.g., https://itop.example.com/webservices/rest.php)')
    parser.add_argument('--user', required=True, help='iTop username')
    parser.add_argument('--password', required=True, help='iTop password')
    parser.add_argument('--verify-ssl', action='store_true', help='Enable SSL certificate verification (disabled by default)')
    
    args = parser.parse_args()
    
    # Check if the CSV file exists
    if not os.path.isfile(args.csv_file):
        logger.error(f"CSV file not found: {args.csv_file}")
        return 1
    
    # First check if we can connect to the API
    if not check_api_connection(args.url, args.user, args.password, args.verify_ssl):
        logger.error("API connectivity check failed. Aborting import.")
        return 1
    
    logger.info("API connectivity check passed. Proceeding with hostname updates...\n")
    
    try:
        # Display SSL verification status
        if args.verify_ssl:
            logger.info("SSL certificate verification is enabled")
        else:
            logger.info("SSL certificate verification is disabled")
            
        # Process the CSV file
        processed, updated, skipped = process_csv(
            file_path=args.csv_file,
            url=args.url,
            username=args.user,
            password=args.password,
            verify_ssl=args.verify_ssl
        )
        
        # Print summary
        logger.info("\nSummary:")
        logger.info(f"Processed: {processed}")
        logger.info(f"Updated: {updated}")
        logger.info(f"Skipped: {skipped}")
        
        return 0
    except Exception as e:
        logger.exception(f"An error occurred: {e}")
        return 1

if __name__ == "__main__":
    main()
