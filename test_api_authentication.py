import requests
import json

# --- iTop API Configuration ---
# Use the same details you provided earlier
itop_url = 'https://myitop.example.com' # Your iTop base URL
itop_api_endpoint = f'{itop_url}/webservices/rest.php' # Common REST API endpoint
itop_api_version = '1.3' # Check your iTop version and API documentation
itop_user = 'itopuser'
itop_password = 'XXXX' # Replace with your actual password

# --- Test API Call ---
# This payload attempts to get the first 5 Organization objects.
# This operation requires authentication and basic read access.
# If your iTop version/config is different, you might need a different operation
# or a different class name (e.g., 'core/getVersion' if available).
test_payload = {
    'version': itop_api_version,
    'auth': {
        'user': itop_user,
        'password': itop_password
    },
    'operation': 'core/get',
    'class': 'Organization', # A common, usually accessible class
    'key': 'SELECT Organization LIMIT 5', # Get a small number of objects
    'output_fields': 'name' # Just get the name field for simplicity
}

print(f"Attempting to connect to iTop API at: {itop_api_endpoint}")
print(f"Using user: {itop_user}")

try:
    # Use verify=False if you have SSL certificate issues (NOT recommended for production)
    response = requests.post(itop_api_endpoint, json=test_payload, verify=True)

    print(f"HTTP Status Code: {response.status_code}")

    # Check HTTP status code first
    if response.status_code == 200:
        try:
            result = response.json()

            # Check the iTop API response for errors
            # iTop API usually returns an 'code' field in case of errors (e.g., 100 for authentication failure)
            if result and result.get('code', 0) == 0:
                print("\nAuthentication successful!")
                print("Successfully received a valid response from iTop.")
                # Optionally print part of the result to confirm data is coming back
                # print("Sample result objects:", result.get('objects', {}))
            else:
                print("\nAuthentication likely failed or iTop returned an error.")
                print(f"iTop API Error Code: {result.get('code')}")
                print(f"iTop API Message: {result.get('message', 'No message provided')}")
                # Print the full response for debugging if needed
                # print("Full iTop API Response:", json.dumps(result, indent=2))

        except json.JSONDecodeError:
            print("\nError: Failed to decode JSON response from iTop.")
            print("Response body:", response.text)
        except Exception as e:
            print(f"\nAn unexpected error occurred while processing iTop response: {e}")

    elif response.status_code == 401:
        print("\nAuthentication Failed: HTTP 401 Unauthorized.")
        print("Please check your iTop username and password.")
    elif response.status_code == 403:
        print("\nAuthentication Failed: HTTP 403 Forbidden.")
        print("The user has authenticated but does not have permission for this operation.")
        print("Check user permissions in iTop.")
    else:
        print(f"\nAPI request failed with HTTP status code: {response.status_code}")
        print("Response body:", response.text)

except requests.exceptions.ConnectionError:
    print(f"\nError: Could not connect to iTop API at {itop_api_endpoint}.")
    print("Please check the iTop URL and ensure the server is reachable.")
except requests.exceptions.Timeout:
    print("\nError: The request to the iTop API timed out.")
    print("This could indicate network issues or a slow server.")
except requests.exceptions.RequestException as e:
    print(f"\nAn unexpected error occurred during the API request: {e}")

print("\nTest finished.")
