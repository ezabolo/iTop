import csv
import socket
# import random # No longer needed for real API calls
import requests
import json # Needed for working with JSON payloads

# --- Configuration ---
# Replace with the actual path to your CSV file
csv_file_path = 'machines.csv'

# iTop API Configuration
itop_url = 'https://myitop.example.com' # Your iTop base URL
itop_api_endpoint = f'{itop_url}/webservices/rest.php' # Common REST API endpoint
itop_api_version = '1.3' # Check your iTop version and API documentation
itop_user = 'itopuser'
itop_password = 'XXXX' # Replace with your actual password or a secure method

# --- iTop API Functions ---
# IMPORTANT: You might need to adjust the endpoint, API version,
# authentication method, and payload structure based on your specific iTop setup.

def call_itop_api(operation, class_name, key=None, fields=None):
    """
    Helper function to make calls to the iTop REST API.
    Adjust the payload structure if your iTop API requires a different format.
    """
    payload = {
        'version': itop_api_version,
        'auth': {
            'user': itop_user,
            'password': itop_password
        },
        'operation': operation,
        'class': class_name,
    }
    if key:
        payload['key'] = key
    if fields:
        payload['fields'] = fields

    try:
        # Use verify=False if you have SSL certificate issues (NOT recommended for production)
        response = requests.post(itop_api_endpoint, json=payload, verify=True)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"  [API ERROR] Request failed: {e}")
        return None
    except json.JSONDecodeError:
        print(f"  [API ERROR] Failed to decode JSON response from iTop.")
        return None


def search_itop(name, ip):
    """
    Searches for a machine in iTop by name or IP using the iTop REST API.
    Returns the iTop object data if found, None otherwise.
    Adjust the OQL query ('key' parameter) if needed for your iTop data model.
    """
    print(f"  Searching iTop for machine: {name} ({ip})")
    # Example OQL query to search for Server by name or IP
    # Adjust 'Server' if your CI class is different
    oql_query = f"SELECT Server WHERE name = '{name}' OR ipaddress = '{ip}'"

    # Using 'core/get' operation to search
    # The 'key' parameter here is the OQL query for 'core/get'
    result = call_itop_api(
        operation='core/get',
        class_name='Server', # Adjust if your CI class is different
        key=oql_query
    )

    if result and result.get('objects'):
        # iTop API 'core/get' returns objects keyed by their object ID
        # We just need to check if any objects were returned
        found_objects = result['objects']
        if found_objects:
            # Return the first found object's data
            first_object_id = list(found_objects.keys())[0]
            print(f"  Machine '{name}' found in iTop with ID: {first_object_id}")
            return found_objects[first_object_id]
        else:
            print(f"  Machine '{name}' not found in iTop.")
            return None
    elif result is not None:
         # API call was successful but returned no objects key or empty objects
         print(f"  Machine '{name}' not found in iTop.")
         return None
    else:
        # API call failed
        print(f"  Failed to search iTop for '{name}'.")
        return None


def update_itop(name, owner, description):
    """
    Updates a machine's owner and description in iTop using the iTop REST API.
    Assumes you can identify the object to update by its 'name'.
    Adjust the 'class', 'key', and 'fields' parameters as needed.
    """
    print(f"  Attempting to update iTop for machine: {name}")
    print(f"    Setting Owner to: {owner}")
    print(f"    Setting Description to: {description}")

    # Using 'core/update' operation
    # The 'key' parameter here identifies the object to update (using OQL)
    # The 'fields' parameter contains the data to update
    # Assuming 'owner_id' is the field name for the owner and 'description' for description
    # You might need to map the 'owner' name from CSV to an iTop owner_id if needed
    result = call_itop_api(
        operation='core/update',
        class_name='Server', # Adjust if your CI class is different
        key=f"SELECT Server WHERE name = '{name}'", # Identify object by name
        fields={
            # Assuming 'owner_id' is the field name for the owner.
            # If 'owner' in your CSV is a name and iTop expects an ID,
            # you'll need an extra step to look up the owner ID in iTop first.
            'owner_id': owner,
            'description': description
        }
    )

    if result and result.get('message') == 'Object updated':
        print(f"  Successfully updated '{name}' in iTop.")
        return True
    elif result is not None:
        # API call was successful but update failed (check iTop API response details)
        print(f"  Update failed for '{name}'. iTop response: {result.get('message', 'No message')}")
        # Print full result for debugging if needed: print(json.dumps(result, indent=2))
        return False
    else:
        # API call failed
        print(f"  Failed to update '{name}' in iTop.")
        return False


# --- Main Script Logic ---

def process_machines_from_csv(file_path):
    """
    Reads machine data from a CSV, performs checks, and interacts with iTop.
    """
    print(f"Starting to process CSV file: {file_path}")

    try:
        with open(file_path, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)

            # Check if required headers are present
            required_headers = ['Name', 'IP', 'Owner', 'Description']
            if not all(header in csv_reader.fieldnames for header in required_headers):
                print(f"Error: CSV file must contain the following headers: {', '.join(required_headers)}")
                return

            line_num = 1 # Start line number after header

            for row in csv_reader:
                line_num += 1
                name = row.get('Name', '').strip()
                ip = row.get('IP', '').strip()
                owner = row.get('Owner', '').strip()
                description = row.get('Description', '').strip()

                print(f"\nProcessing line {line_num}: Name='{name}', IP='{ip}'")

                if not name or not ip:
                    print(f"  Skipping line {line_num}: Missing Name or IP.")
                    continue

                # 1. Verify if the IP matches the name using DNS lookup
                try:
                    resolved_ip = socket.gethostbyname(name)
                    if resolved_ip != ip:
                        print(f"  Skipping line {line_num}: IP mismatch. DNS resolved '{name}' to '{resolved_ip}', but CSV has '{ip}'.")
                        continue
                    else:
                        print(f"  DNS match: '{name}' resolved to '{resolved_ip}'.")

                except socket.gaierror as e:
                    print(f"  Skipping line {line_num}: Could not resolve hostname '{name}'. Error: {e}")
                    continue
                except Exception as e:
                    print(f"  Skipping line {line_num}: An unexpected error occurred during DNS lookup for '{name}'. Error: {e}")
                    continue

                # 2. Search the machine in iTop
                itop_object = search_itop(name, ip)

                if itop_object:
                    # 3. If the machine exists, update the Owner and Description
                    print(f"  Machine '{name}' found in iTop. Proceeding to update.")
                    if update_itop(name, owner, description):
                        print(f"  Successfully processed and updated '{name}'.")
                    else:
                         print(f"  Failed to update '{name}'. Check update_itop function and iTop API response.")
                else:
                    print(f"  Machine '{name}' not found in iTop or search failed. Skipping update.")

    except FileNotFoundError:
        print(f"Error: CSV file not found at {file_path}")
    except Exception as e:
        print(f"An unexpected error occurred while processing the CSV: {e}")

# --- Run the script ---
if __name__ == "__main__":
    process_machines_from_csv(csv_file_path)
    print("\nScript finished.")
