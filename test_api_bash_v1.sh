#!/bin/bash

# --- iTop API Configuration ---
# Use the same details you provided earlier
ITOP_URL="https://myitop.example.com" # Your iTop base URL
ITOP_API_ENDPOINT="${ITOP_URL}/webservices/rest.php" # Common REST API endpoint
ITOP_API_VERSION="1.3" # Check your iTop version and API documentation
ITOP_USER="itopuser"
ITOP_PASSWORD="XXXX" # Replace with your actual password

# --- Test API Call Payload ---
# This JSON payload attempts to get the first 5 Organization objects.
# This operation requires authentication and basic read access.
# If your iTop version/config is different, you might need a different operation
# or a different class name (e.g., 'core/getVersion' if available).
JSON_PAYLOAD='{
    "version": "'"${ITOP_API_VERSION}"'",
    "auth": {
        "user": "'"${ITOP_USER}"'",
        "password": "'"${ITOP_PASSWORD}"'"
    },
    "operation": "core/get",
    "class": "Organization",
    "key": "SELECT Organization LIMIT 5",
    "output_fields": "name"
}'

echo "Attempting to connect to iTop API at: ${ITOP_API_ENDPOINT}"
echo "Using user: ${ITOP_USER}"

# --- Make the API Request using curl ---
# -X POST: Specify POST method
# -H "Content-Type: application/json": Set the content type header
# -d "$JSON_PAYLOAD": Send the JSON payload as request body
# -k: Allow insecure server connections (like SSL certificate issues) - WARNING: INSECURE!
# -s: Silent mode (don't show progress)
# -w "%{http_code}": Print the HTTP status code after the response
# Capture both the response body and the status code

# Use process substitution to capture body and status separately
read HTTP_STATUS RESPONSE_BODY < <(curl -s -k -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d "$JSON_PAYLOAD" \
    "$ITOP_API_ENDPOINT")

echo "HTTP Status Code: ${HTTP_STATUS}"

# --- Process the Response ---

if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "Received HTTP 200 OK."
    # Attempt to parse the JSON response body using jq
    if command -v jq &> /dev/null; then
        ITOP_API_CODE=$(echo "$RESPONSE_BODY" | jq -r '.code')
        ITOP_API_MESSAGE=$(echo "$RESPONSE_BODY" | jq -r '.message')

        if [ "$ITOP_API_CODE" -eq 0 ]; then
            echo ""
            echo "Authentication successful!"
            echo "Successfully received a valid response from iTop."
            # Optionally print part of the result:
            # echo "Sample result objects:"
            # echo "$RESPONSE_BODY" | jq '.objects'
        else
            echo ""
            echo "Authentication likely failed or iTop returned an error."
            echo "iTop API Error Code: ${ITOP_API_CODE}"
            echo "iTop API Message: ${ITOP_API_MESSAGE}"
            # Print the full response for debugging if needed:
            # echo "Full iTop API Response:"
            # echo "$RESPONSE_BODY" | jq '.'
        fi
    else
        echo ""
        echo "jq command not found. Cannot parse JSON response."
        echo "Response Body (raw):"
        echo "$RESPONSE_BODY"
        echo "Please install jq (e.g., sudo apt-get install jq) to automatically parse the response."
    fi

elif [ "$HTTP_STATUS" -eq 401 ]; then
    echo ""
    echo "Authentication Failed: HTTP 401 Unauthorized."
    echo "Please check your iTop username and password."
    echo "Response Body (raw):"
    echo "$RESPONSE_BODY"

elif [ "$HTTP_STATUS" -eq 403 ]; then
    echo ""
    echo "Authentication Failed: HTTP 403 Forbidden."
    echo "The user has authenticated but does not have permission for this operation."
    echo "Check user permissions in iTop."
    echo "Response Body (raw):"
    echo "$RESPONSE_BODY"

else
    echo ""
    echo "API request failed with HTTP status code: ${HTTP_STATUS}"
    echo "Response Body (raw):"
    echo "$RESPONSE_BODY"
fi

echo ""
echo "Test finished."
