#!/bin/bash

# Usage: ./update_server_owner.sh <ip> <fqdn> <owner_id> <description> <itop_url> <username> <password>
# Example: ./update_server_owner.sh 192.168.1.10 server1.domain.com 1234 "Test description" [https://itop.example.com](https://itop.example.com) user pass

set -e

IP="$1"
FQDN="$2"
OWNER_ID="$3"
DESCRIPTION="$4"
ITOP_URL="$5"
USERNAME="$6"
PASSWORD="$7"

if [ $# -ne 7 ]; then
  echo "Usage: $0 <ip> <fqdn> <owner_id> <description> <itop_url> <username> <password>"
  exit 1
fi

# --- DNS Verification ---
echo "Verifying DNS for $FQDN matches IP $IP..."
RESOLVED_IPS=$(host "$FQDN" | awk '/has address/ {print $4}')
MATCH=0
for resolved in $RESOLVED_IPS; do
  if [ "$resolved" == "$IP" ]; then
    MATCH=1
    break
  fi
done

if [ $MATCH -eq 0 ]; then
  echo "Error: DNS verification failed. IP $IP does not match DNS records for $FQDN"
  exit 2
fi

# --- Search for machine in iTop ---
search_object() {
  local class="$1"
  local field="$2"
  local value="$3"
  local query="{\"operation\":\"core/get\",\"class\":\"$class\",\"key\":\"$field = \\\"$value\\\"\"}"
  local response=$(curl -sk -u "$USERNAME:$PASSWORD" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "json_data=$query" \
    "$ITOP_URL/webservices/rest.php?version=1.3")
  echo "$response"
}

echo "Searching for Server or VirtualMachine with IP $IP in iTop..."
SERVER_JSON=$(search_object "Server" "managementip" "$IP")
VM_JSON=$(search_object "VirtualMachine" "managementip" "$IP")

SERVER_ID=$(echo "$SERVER_JSON" | jq -r '.objects | to_entries[0].value.id // empty')
VM_ID=$(echo "$VM_JSON" | jq -r '.objects | to_entries[0].value.id // empty')

TARGET_CLASS=""
TARGET_ID=""

if [ -n "$SERVER_ID" ]; then
  TARGET_CLASS="Server"
  TARGET_ID="$SERVER_ID"
elif [ -n "$VM_ID" ]; then
  TARGET_CLASS="VirtualMachine"
  TARGET_ID="$VM_ID"
else
  echo "Error: No machine found with IP $IP in iTop"
  exit 3
fi

echo "Found $TARGET_CLASS with ID $TARGET_ID"

# --- Update owner ---
FIELDS="{\"owner_id\":$OWNER_ID, \"description\":\"$DESCRIPTION\"}"
UPDATE_QUERY="{\"operation\":\"core/update\",\"class\":\"$TARGET_CLASS\",\"key\":$TARGET_ID,\"fields\":$FIELDS,\"comment\":\"Updated owner information via automation script\"}"

echo "Updating $TARGET_CLASS with ID $TARGET_ID"
echo "Update query:"
echo "$UPDATE_QUERY" | jq .

UPDATE_RESPONSE=$(curl -sk -u "$USERNAME:$PASSWORD" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "json_data=$UPDATE_QUERY" \
  "$ITOP_URL/webservices/rest.php?version=1.3")

echo "Update Response:"
echo "$UPDATE_RESPONSE" | jq .

CODE=$(echo "$UPDATE_RESPONSE" | jq -r '.code // empty')
if [ "$CODE" != "0" ]; then
  MESSAGE=$(echo "$UPDATE_RESPONSE" | jq -r '.message // "Unknown error"')
  echo "API Error: $MESSAGE"
  exit 4
fi

echo "Update successful!"
exit 0
