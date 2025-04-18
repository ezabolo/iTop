#!/bin/bash

# Usage: ./import_machines.sh <csv_file> <itop_url> <itop_user> <itop_password>
CSV_FILE="$1"
ITOP_URL="$2"
ITOP_USER="$3"
ITOP_PWD="$4"

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <csv_file> <itop_url> <itop_user> <itop_password>"
  exit 1
fi

# Function to search for a machine by IP
search_machine() {
  local ip="$1"
  local fqdn="$2"
  local class="$3"
  local query="{\"operation\":\"core/get\",\"class\":\"$class\",\"key\":\"SELECT $class WHERE managementip = '$ip'\",\"output_fields\":\"*\"}"
  local response=$(curl -sk -X POST "$ITOP_URL/webservices/rest.php?version=1.3" \
    -u "$ITOP_USER:$ITOP_PWD" \
    -d "json_data=$query")
  echo "$response" | jq ".objects | to_entries[] | select(.value.fields.name | ascii_downcase == \"$fqdn\")"
}

# Function to create a machine
create_machine() {
  local fqdn="$1"
  local ip="$2"
  local org="$3"
  local os_name="$4"
  local os_version="$5"
  local cpu="$6"
  local ram="$7"
  local diskspace="$8"
  local payload="{
    \"operation\": \"core/create\",
    \"class\": \"VirtualMachine\",
    \"fields\": {
      \"name\": \"$fqdn\",
      \"managementip\": \"$ip\",
      \"org_id\": \"SELECT Organization WHERE name = '$org'\",
      \"osfamily_id\": \"SELECT OSFamily WHERE name = '$os_name'\",
      \"osversion_id\": \"SELECT OSVersion WHERE name = '$os_version'\",
      \"cpu\": \"$cpu\",
      \"ram\": \"$ram\",
      \"diskspace\": \"$diskspace\",
      \"status\": \"production\",
      \"currentstatus\": \"on\"
    },
    \"comment\": \"Created via Bash script\",
    \"output_fields\": \"id, name, status\"
  }"
  curl -sk -X POST "$ITOP_URL/webservices/rest.php?version=1.3" \
    -u "$ITOP_USER:$ITOP_PWD" \
    -d "json_data=$payload"
}

# Read CSV (skip header)
tail -n +2 "$CSV_FILE" | while IFS=, read -r FQDN IP_ADDR AO_BRANCH AO_APP OS_NAME OS_VERSION CPU MEM PROV_STORAGE USED_STORAGE; do
  fqdn=$(echo "$FQDN" | tr -d '"')
  ip=$(echo "$IP_ADDR" | tr -d '"')
  os_name=$(echo "$OS_NAME" | tr -d '"')
  os_version=$(echo "$OS_VERSION" | tr -d '"')
  cpu=$(echo "$CPU" | tr -d '"')
  ram=$(echo "$MEM" | tr -d '"')
  diskspace=$(echo "$PROV_STORAGE" | tr -d '"')
  org="CMSO"

  # Search for existing machine
  found=$(search_machine "$ip" "$fqdn" "VirtualMachine")
  if [[ -n "$found" ]]; then
    echo "Machine $fqdn ($ip) already exists."
  else
    echo "Creating machine $fqdn ($ip)..."
    create_machine "$fqdn" "$ip" "$org" "$os_name" "$os_version" "$cpu" "$ram" "$diskspace"
  fi
done
