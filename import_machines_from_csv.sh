#!/usr/bin/env bash

# --- Configuration ---
ITOP_URL="https://myitop.example.com" # CHANGE THIS: Base URL of your iTop instance
ITOP_API_ENDPOINT="${ITOP_URL}/webservices/rest.php" # REST API endpoint
ITOP_USER="itopuser"                 # CHANGE THIS: Your iTop API username
ITOP_PWD="XXXXXX"                    # CHANGE THIS: Your iTop API password
ITOP_VERSION="1.3"                   # iTop API version to use
LOG_FILE="itop_import_$(date +%Y%m%d_%H%M%S).log"

# CSV Header expected order (for reference)
# FQDN,IP_Address,AO_Branch,AO_Application,OS_Name,OS_Version,CPU,Memory,Provisioned_Storage,Used_Storage

# --- Logging ---
# Function to log messages to both stdout/stderr and the log file
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_line="${timestamp} - ${level^^} - ${message}"

    # Log to file
    echo "${log_line}" >> "$LOG_FILE"
    # Log to console (INFO to stdout, others to stderr)
    if [[ "$level" == "INFO" ]]; then
        echo "${log_line}"
    else
        echo "${log_line}" >&2
    fi
}

# --- Helper Functions ---

# Function to make calls to the iTop REST API using curl and jq
# Usage: call_itop_api <operation> <class_name> [key_json] [fields_json] [output_fields_json]
# Returns JSON response on stdout if successful, empty string and logs error on failure. Returns non-zero exit code on curl/jq errors.
call_itop_api() {
    local operation="$1"
    local class_name="$2"
    local key_json="${3:-null}"
    local fields_json="${4:-null}"
    local output_fields_json="${5:-null}"
    local payload
    local response
    local curl_exit_code

    # Construct the JSON payload using jq
    payload=$(jq -n \
        --arg version "$ITOP_VERSION" \
        --arg user "$ITOP_USER" \
        --arg password "$ITOP_PWD" \
        --arg op "$operation" \
        --arg class "$class_name" \
        --argjson key "$key_json" \
        --argjson fields "$fields_json" \
        --argjson output_fields "$output_fields_json" \
        '{
            version: $version,
            auth: { user: $user, password: $password },
            operation: $op,
            class: $class,
            key: (if $key == null then null else $key end),
            fields: (if $fields == null then null else $fields end),
            output_fields: (if $output_fields == null then null else $output_fields end)
        } | del(..|nulls)') # Remove keys with null values

    if [[ -z "$payload" ]]; then
        log "ERROR" "Failed to construct JSON payload for ${operation} ${class_name}"
        return 1
    fi

    log "DEBUG" "API Request to ${ITOP_API_ENDPOINT}"
    log "DEBUG" "Operation: ${operation}, Class: ${class_name}"
    log "DEBUG" "Payload: $(echo "$payload" | jq -c .)"

    # Make the API request with curl, disable SSL verification (-k)
    response=$(curl -k -s -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$ITOP_API_ENDPOINT")
    curl_exit_code=$?

    if [[ $curl_exit_code -ne 0 ]]; then
        log "ERROR" "API request failed (curl error code: $curl_exit_code) for ${operation} ${class_name}"
        return 1
    fi

    if ! echo "$response" | jq -e . > /dev/null; then
         log "ERROR" "Failed to decode JSON response from iTop for ${operation} ${class_name}. Response was: ${response}"
         return 1
    fi

    log "DEBUG" "Response status: $(echo "$response" | jq -r '.code // "N/A"')"
    log "DEBUG" "Response data: $(echo "$response" | jq -c .)"

    echo "$response"
    return 0
}

# Verify if the FQDN resolves to the given IP address using dig
# Usage: verify_fqdn_ip_match <fqdn> <ip>
# Returns 0 if match, 1 if mismatch or resolution error.
verify_fqdn_ip_match() {
    local fqdn="$1"
    local ip="$2"
    local resolved_ips
    local resolved_hostname
    local match=1 # 0 = match, 1 = no match

    # Try forward DNS lookup (A record)
    resolved_ips=$(dig +short "$fqdn" A @8.8.8.8) # Using Google DNS for consistency, remove @8.8.8.8 to use local resolver
    if [[ $? -eq 0 && -n "$resolved_ips" ]]; then
        if echo "$resolved_ips" | grep -q -w "$ip"; then
            log "DEBUG" "Forward DNS match: ${fqdn} resolves to ${ip}"
            match=0
        fi
    else
        log "DEBUG" "Forward DNS resolution failed or returned no A records for ${fqdn}"
    fi

    # If forward didn't match, try reverse DNS lookup (PTR record)
    if [[ $match -ne 0 ]]; then
        resolved_hostname=$(dig +short -x "$ip" @8.8.8.8 | head -n 1 | sed 's/\.$//') # Using Google DNS
         if [[ $? -eq 0 && -n "$resolved_hostname" ]]; then
            # Case-insensitive comparison
            if [[ "$(echo "$resolved_hostname" | tr '[:upper:]' '[:lower:]')" == "$(echo "$fqdn" | tr '[:upper:]' '[:lower:]')" ]]; then
                 log "DEBUG" "Reverse DNS match: ${ip} resolves to ${fqdn}"
                match=0
            fi
        else
             log "DEBUG" "Reverse DNS resolution failed or returned no PTR record for ${ip}"
        fi
    fi

    if [[ $match -ne 0 ]]; then
         log "WARN" "DNS Verification FAILED: FQDN-IP mismatch or resolution error for FQDN='${fqdn}' IP='${ip}'"
    fi

    return $match
}

# Searches for a machine in iTop by name or IP.
# Usage: search_itop <name> [ip]
# Returns 0 if found, 1 if not found, >1 on API error. Outputs found object JSON on stdout if found.
search_itop() {
    local name="$1"
    local ip="$2"
    local oql_query
    local conditions=()
    local result_json
    local found_object_json

    log "INFO" "Searching iTop for machine: ${name} ${ip:+($ip)}"

    # Build OQL query conditions
    conditions+=("name = '${name}'")
    if [[ -n "$ip" ]]; then
        conditions+=("managementip = '${ip}'")
    fi
    local joined_conditions
    printf -v joined_conditions " OR %s" "${conditions[@]}"
    joined_conditions="${joined_conditions:4}" # Remove leading " OR "

    local search_classes=("Server" "VirtualMachine")
    for class in "${search_classes[@]}"; do
        oql_query="SELECT ${class} WHERE ${joined_conditions}"
        log "DEBUG" "OQL Query (${class}): ${oql_query}"

        local key_jq; key_jq=$(jq -n --arg q "$oql_query" '$q')
        local output_fields_jq; output_fields_jq=$(jq -n --arg f 'id, name' '$f') # Only need ID/name to confirm existence

        result_json=$(call_itop_api 'core/get' "$class" "$key_jq" null "$output_fields_jq")
        if [[ $? -ne 0 ]]; then return 2; fi # Propagate API call error

        found_object_json=$(echo "$result_json" | jq -c '.objects | select(. != null and . != {}) | to_entries[0].value // empty')

        if [[ -n "$found_object_json" ]]; then
             local found_id; found_id=$(echo "$found_object_json" | jq -r '.id // "unknown"')
             log "INFO" "Machine '${name}' found in iTop (as ${class}) with ID: ${found_id}. Skipping."
             echo "$found_object_json" # Output JSON for potential use (though we just skip)
             return 0 # Found
        fi
    done

    log "INFO" "Machine '${name}' not found in iTop. Proceeding to creation."
    return 1 # Not found
}

# Gets the ID for an entity (Org, OS Family, OS Version) by name from iTop.
# Usage: get_itop_id <Entity Name for logs> <iTop Class Name> <Name to Search>
# Special handling for OS Family/Version: returns the *lowest* ID if multiple found.
# Returns ID on stdout if found, empty string if not. Returns non-zero on API errors or if not found.
get_itop_id() {
    local entity_log_name="$1" # e.g., "Organization"
    local class_name="$2"      # e.g., "Organization"
    local name_to_search="$3"
    local id=""
    local result_json
    local oql_query

    if [[ -z "$name_to_search" ]]; then
        log "ERROR" "Cannot search for empty ${entity_log_name} name."
        return 1
    fi

    log "DEBUG" "Querying iTop for ${entity_log_name} ID for name: '${name_to_search}'"
    oql_query="SELECT ${class_name} WHERE name = '${name_to_search}'"
    local key_jq; key_jq=$(jq -n --arg q "$oql_query" '$q')
    local output_fields_jq; output_fields_jq=$(jq -n --arg f 'id' '$f') # Only need the ID

    result_json=$(call_itop_api 'core/get' "$class_name" "$key_jq" null "$output_fields_jq")
    if [[ $? -ne 0 ]]; then
        log "ERROR" "API error while querying ID for ${entity_log_name} '${name_to_search}'."
        return 2 # API error
    fi

    # Extract ID(s)
    if [[ "$class_name" == "OSFamily" || "$class_name" == "OSVersion" ]]; then
        # For OSFamily/OSVersion, find the *lowest* numeric ID if multiple matches
        id=$(echo "$result_json" | jq -r '[.objects | select(. != null and . != {}) | keys[]? | split("::")[1] | tonumber] | sort | .[0] // empty')
         if [[ -n "$id" ]]; then
             log "INFO" "Found lowest ID '${id}' for ${entity_log_name} '${name_to_search}'."
         fi
    else
        # For Organization (assume unique name), take the first one found
        id=$(echo "$result_json" | jq -r '.objects | select(. != null and . != {}) | keys[0]? | split("::")[1] // empty')
         if [[ -n "$id" ]]; then
             log "INFO" "Found ID '${id}' for ${entity_log_name} '${name_to_search}'."
         fi
    fi

    if [[ -z "$id" ]]; then
        log "ERROR" "Could not find ID for ${entity_log_name} with name '${name_to_search}' in iTop."
        return 1 # Not found
    fi

    echo "$id" # Output the found ID
    return 0  # Success
}

# Creates a new server or virtual machine in iTop.
# Usage: create_itop_server <server_type> <fields_json>
# Returns 0 on success, 1 on failure.
create_itop_server() {
    local server_type="$1"
    local fields_json="$2"
    local name
    name=$(echo "$fields_json" | jq -r '.name // "unknown"')
    local result_json

    log "INFO" "Attempting to create ${server_type} in iTop: ${name}"
    log "DEBUG" "Creation fields: $(echo "$fields_json" | jq -c .)"

    result_json=$(call_itop_api 'core/create' "$server_type" null "$fields_json")
    local api_call_status=$?

    if [[ $api_call_status -ne 0 ]]; then
        log "ERROR" "Failed to create ${server_type} ${name}: API call failed during creation."
        return 1
    fi

    local result_code; result_code=$(echo "$result_json" | jq -r '.code // -1')
    local created_id_key; created_id_key=$(echo "$result_json" | jq -r '.objects | select(. != null) | keys[0]? // empty')

    if [[ "$result_code" == "0" && -n "$created_id_key" ]]; then
        log "INFO" "Successfully created ${server_type} ${name} with ID: ${created_id_key}"
        return 0
    else
        local error_msg; error_msg=$(echo "$result_json" | jq -r '.message // "Unknown creation error"')
        log "ERROR" "Failed to create ${server_type} ${name} in iTop. Code: ${result_code}, Message: ${error_msg}"
        return 1
    fi
}

# Determine iTop class based on FQDN
# Usage: determine_server_type <fqdn>
# Returns "Server" or "VirtualMachine" on stdout
determine_server_type() {
    local fqdn="$1"
    local fqdn_lower
    fqdn_lower=$(echo "$fqdn" | tr '[:upper:]' '[:lower:]')

    if [[ "$fqdn_lower" == *ctho.asbn* || "$fqdn_lower" == *adu.dcn* ]]; then
        echo "Server"
    else
        echo "VirtualMachine"
    fi
}

# Determine Organization Name based on FQDN
# Usage: determine_organization_name <fqdn>
# Returns "CTHO" or "CMSO" on stdout
determine_organization_name() {
    local fqdn="$1"
    local fqdn_lower
    fqdn_lower=$(echo "$fqdn" | tr '[:upper:]' '[:lower:]')

    if [[ "$fqdn_lower" == *ctho.asbn* || "$fqdn_lower" == *adu.dcn* ]]; then
        echo "CTHO"
    else
        echo "CMSO"
    fi
}


# --- Main Script ---
log "INFO" "Starting iTop import script..."
log "WARN" "SSL certificate verification is disabled via curl '-k'. This is insecure for production."

# Check for dependencies
if ! command -v jq &> /dev/null; then
    log "ERROR" "jq command could not be found. Please install jq."
    exit 1
fi
if ! command -v dig &> /dev/null; then
    log "ERROR" "dig command could not be found. Please install DNS utilities (e.g., dnsutils, bind-utils)."
    exit 1
fi
if ! command -v curl &> /dev/null; then
    log "ERROR" "curl command could not be found. Please install curl."
    exit 1
fi

# Check command line arguments
if [[ "$#" -ne 1 ]]; then
    log "ERROR" "Usage: $0 <csv_file_path>"
    exit 1
fi

csv_file_path="$1"
if [[ ! -f "$csv_file_path" ]]; then
    log "ERROR" "CSV file not found: ${csv_file_path}"
    exit 1
fi

# Counters
skipped_dns_mismatch=0
skipped_already_exists=0
skipped_id_lookup_error=0
skipped_creation_error=0
created_count=0
processed_count=0

# --- Process the CSV file ---
log "INFO" "Processing CSV file: ${csv_file_path}"

# Read header line (optional: validate it)
IFS=',' read -r header < "$csv_file_path"
log "DEBUG" "CSV Header: $header"
expected_header="FQDN,IP_Address,AO_Branch,AO_Application,OS_Name,OS_Version,CPU,Memory,Provisioned_Storage,Used_Storage"
if [[ "$header" != "$expected_header" ]]; then
    log "WARN" "CSV header does not exactly match expected format."
    log "WARN" "Expected: $expected_header"
    log "WARN" "Got:      $header"
    log "WARN" "Attempting to process anyway, assuming column order is correct."
fi

# Process data rows (skip header line with tail)
# Use process substitution <(...) to read file line by line skipping header
# Allows counters to persist outside the loop
while IFS=',' read -r fqdn ip_address ao_branch ao_application os_name os_version cpu memory provisioned_storage used_storage || [[ -n "$fqdn" ]]; do
    ((processed_count++))

    # Trim whitespace (basic trim) - Important for names and IPs
    fqdn=$(echo "$fqdn" | xargs)
    ip_address=$(echo "$ip_address" | xargs)
    os_name=$(echo "$os_name" | xargs)
    os_version=$(echo "$os_version" | xargs)
    cpu=$(echo "$cpu" | xargs)
    memory=$(echo "$memory" | xargs)
    provisioned_storage=$(echo "$provisioned_storage" | xargs)

    # Skip blank lines or lines without FQDN
    if [[ -z "$fqdn" ]]; then
        log "WARN" "Skipping row ${processed_count}: FQDN is empty."
        continue
    fi

    log "INFO" "--- Processing Row ${processed_count}: FQDN=${fqdn}, IP=${ip_address} ---"

    # 1. Verify FQDN-IP match
    if ! verify_fqdn_ip_match "$fqdn" "$ip_address"; then
        ((skipped_dns_mismatch++))
        continue # Skip this server
    fi
    log "INFO" "DNS verification successful for ${fqdn} <-> ${ip_address}"

    # 2. Check if server exists in iTop
    search_result=$(search_itop "$fqdn" "$ip_address")
    search_status=$?
    if [[ $search_status -eq 0 ]]; then
        # Found in iTop
        ((skipped_already_exists++))
        continue # Skip this server
    elif [[ $search_status -ne 1 ]]; then
        # API error during search
        log "ERROR" "Skipping row ${processed_count} due to error searching iTop for ${fqdn}."
        ((skipped_id_lookup_error++)) # Count as ID lookup error for simplicity
        continue
    fi
    # Not found, proceed to creation logic

    # 3. Gather information for creation
    itop_class=$(determine_server_type "$fqdn")
    itop_org_name=$(determine_organization_name "$fqdn")
    log "INFO" "Determined Class: ${itop_class}, Organization Name: ${itop_org_name}"

    # Get IDs from iTop
    org_id=$(get_itop_id "Organization" "Organization" "$itop_org_name")
    if [[ $? -ne 0 ]]; then ((skipped_id_lookup_error++)); continue; fi

    osfamily_id=$(get_itop_id "OS Family" "OSFamily" "$os_name")
    if [[ $? -ne 0 ]]; then ((skipped_id_lookup_error++)); continue; fi

    osversion_id=$(get_itop_id "OS Version" "OSVersion" "$os_version")
    if [[ $? -ne 0 ]]; then ((skipped_id_lookup_error++)); continue; fi

    log "INFO" "Retrieved IDs - Org: ${org_id}, OS Family: ${osfamily_id}, OS Version: ${osversion_id}"

    # 4. Prepare fields and create machine
    # Map CSV fields to iTop fields using the retrieved IDs
    fields_json=$(jq -n \
        --arg name "$fqdn" \
        --arg org_id "$org_id" \
        --arg managementip "$ip_address" \
        --arg osfamily_id "$osfamily_id" \
        --arg osversion_id "$osversion_id" \
        --arg cpu "$cpu" \
        --arg ram "$memory" \
        --arg diskspace "$provisioned_storage" \
        '{
            "name": $name,
            "org_id": $org_id,
            "managementip": $managementip,
            "osfamily_id": $osfamily_id,
            "osversion_id": $osversion_id,
            "cpu": $cpu,
            "ram": $ram,
            "diskspace": $diskspace
        }')

    if ! create_itop_server "$itop_class" "$fields_json"; then
        ((skipped_creation_error++))
    else
        ((created_count++))
    fi

done < <(tail -n +2 "$csv_file_path") # Read from 2nd line onwards

# --- Report Summary ---
log "INFO" "==================== Import Summary ===================="
log "INFO" "Total rows processed (excluding header): ${processed_count}"
log "INFO" "Servers CREATED: ${created_count}"
log "INFO" "Servers SKIPPED (Already Exists): ${skipped_already_exists}"
log "INFO" "Servers SKIPPED (DNS Mismatch/Error): ${skipped_dns_mismatch}"
log "INFO" "Servers SKIPPED (ID Lookup Error): ${skipped_id_lookup_error}"
log "INFO" "Servers SKIPPED (Creation API Error): ${skipped_creation_error}"
log "INFO" "========================================================"
log "INFO" "Log file: ${LOG_FILE}"
log "INFO" "Script finished."

exit 0
