#!/usr/bin/env python3
import argparse
import csv
import json
import re
import sys
from typing import Dict, Optional, Tuple

import requests
from urllib3.exceptions import InsecureRequestWarning

# Disable TLS verification warnings (insecure connection by request)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ITopAPI:
    def __init__(self, url: str, user: str, password: str):
        self.url = url.rstrip('/')
        self.auth = (user, password)

    def _post(self, payload: Dict) -> requests.Response:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        return requests.post(
            f"{self.url}/webservices/rest.php?version=1.3",
            auth=self.auth,
            headers=headers,
            data={'json_data': json.dumps(payload)},
            verify=False,  # insecure per request
            timeout=60,
        )

    def search_by_name(self, fqdn: str) -> Optional[Dict]:
        """Search for a machine by name (FQDN) in Server or VirtualMachine."""
        for cls in ("Server", "VirtualMachine"):
            payload = {
                'operation': 'core/get',
                'class': cls,
                'key': f"SELECT {cls} WHERE name = '{fqdn}'",
                'output_fields': '*',
            }
            print(f"Searching for {cls} by name='{fqdn}'")
            resp = self._post(payload)
            print(f"Response Status: {resp.status_code}")
            try:
                result = resp.json()
                print("Response:", json.dumps(result, indent=2))
            except Exception:
                print("Non-JSON response:", resp.text[:500])
                result = {}

            if resp.status_code == 200 and result.get('objects'):
                first_obj = next(iter(result['objects'].values()))
                return {'class': cls, 'object': first_obj}
        return None

    def get_lowest_id_from_query(self, query: str) -> Optional[str]:
        """Execute an OQL query and return the lowest object ID from the result set."""
        payload = {
            'operation': 'core/get',
            'key': query,
            'output_fields': 'id',
        }
        resp = self._post(payload)
        print(f"Query: {query}")
        print(f"Response Status: {resp.status_code}")
        if resp.status_code == 200:
            try:
                result = resp.json()
            except Exception:
                print("Non-JSON response:", resp.text[:500])
                return None
            if result.get('objects'):
                ids = [obj['key'] for obj in result['objects'].values()]
                return min(ids)
        return None

    def create_machine(self, data: Dict, machine_class: str) -> bool:
        """Create a new Server/VirtualMachine with provided fields."""
        payload = {
            'operation': 'core/create',
            'class': machine_class,
            'fields': data,
            'comment': 'Created via reconcile_itop_script.py',
            'output_fields': '*',
        }
        resp = self._post(payload)
        print(f"Creation response status: {resp.status_code}")
        try:
            result = resp.json()
            print("Creation response:", json.dumps(result, indent=2))
        except Exception:
            print("Non-JSON response:", resp.text[:500])
            return False

        if resp.status_code == 200 and result.get('code') == 0:
            print(f"Successfully created {machine_class}: {data.get('name')}")
            return True
        print(f"Error creating {machine_class}: {result.get('message', 'Unknown error')}")
        return False


# Organization will be taken directly from AO_Branch column in the CSV


def convert_storage_to_mb(storage: str) -> int:
    """Convert Provisioned_Storage to MB. Accepts plain numbers as GB by default."""
    if storage is None:
        return 0
    s = str(storage).strip()
    if not s:
        return 0
    try:
        # Try to parse units if present (e.g., "500 GB", "10240 MB")
        m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]*)$", s)
        if m:
            val = float(m.group(1))
            unit = m.group(2).lower()
            if unit in ('mb', 'mib'):
                return int(val)
            if unit in ('gb', 'gib', ''):
                return int(val * 1024)
            if unit in ('tb', 'tib'):
                return int(val * 1024 * 1024)
        # Fallback: treat as GB
        return int(float(s.replace(',', '')) * 1024)
    except Exception:
        return 0


def normalize_key(k: str) -> str:
    """Normalize CSV header keys for robust matching."""
    return re.sub(r"[^a-z0-9]", "", k.lower())


def resolve_csv_mappings(fieldnames: Tuple[str, ...]) -> Dict[str, str]:
    """Map various possible column names to canonical keys we need.

    Returns a mapping of canonical -> actual field name found in CSV.
    """
    norm_to_actual = {normalize_key(fn): fn for fn in fieldnames}

    def pick(*candidates: str) -> Optional[str]:
        for c in candidates:
            if c in norm_to_actual:
                return norm_to_actual[c]
        return None

    mapping = {
        'fqdn': pick('fqdn'),
        'ip_address': pick('ipaddress', 'ip_addr', 'ip_adress', 'ipaddresss', 'ip'),
        'ao_branch': pick('aobranch', 'ao_branch'),
        # Handle AO_Applocation misspelling as per request
        'ao_application': pick('aoapplication', 'aoapplocation'),
        'os_name': pick('osname', 'os_name'),
        'os_version': pick('osversion', 'os_version'),
        'cpu': pick('cpu'),
        'memory': pick('memory', 'ram'),
        'provisioned_storage': pick('provisioned_storage', 'provisionedstorage'),
    }

    required_keys = ['fqdn', 'ip_address', 'ao_branch', 'ao_application', 'os_name', 'os_version', 'cpu', 'memory', 'provisioned_storage']
    missing = [k for k in required_keys if mapping.get(k) is None]
    if missing:
        print("Error: Missing required CSV columns:", missing)
        print("Detected columns:", list(fieldnames))
        sys.exit(1)

    return mapping


def process_csv_file(csv_path: str, itop: ITopAPI):
    """Process CSV and reconcile machines into iTop."""
    try:
        with open(csv_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                print("Error: CSV appears to have no header row.")
                sys.exit(1)

            mapping = resolve_csv_mappings(tuple(reader.fieldnames))

            for row in reader:
                fqdn = (row.get(mapping['fqdn']) or '').strip()
                ip = (row.get(mapping['ip_address']) or '').strip()
                ao_branch = (row.get(mapping['ao_branch']) or '').strip()
                ao_app = (row.get(mapping['ao_application']) or '').strip()
                os_name = (row.get(mapping['os_name']) or '').strip()
                os_version = (row.get(mapping['os_version']) or '').strip()
                cpu = (row.get(mapping['cpu']) or '').strip()
                memory = (row.get(mapping['memory']) or '').strip()
                prov_storage_raw = (row.get(mapping['provisioned_storage']) or '').strip()

                if not fqdn:
                    print(f"Skipping row without FQDN: {row}")
                    continue

                # Check existence by name
                existing = itop.search_by_name(fqdn)
                if existing:
                    print(f"Exists, skipping: {fqdn}")
                    continue

                # Resolve OS family and version IDs (lowest ID when multiple)
                os_family_id = itop.get_lowest_id_from_query(
                    f"SELECT OSFamily WHERE name = '{os_name}'"
                ) if os_name else None
                os_version_id = itop.get_lowest_id_from_query(
                    f"SELECT OSVersion WHERE name = '{os_version}'"
                ) if os_version else None

                if not os_family_id or not os_version_id:
                    print(f"Skipping {fqdn} - OS not found (family='{os_name}', version='{os_version}')")
                    continue

                # Organization comes from AO_Branch; class defaults to Server
                org = ao_branch
                machine_class = 'Server'

                machine_data = {
                    'name': fqdn,  # FQDN -> name
                    'managementip': ip,  # IP_Address -> managementip
                    'org_id': f"SELECT Organization WHERE name = '{org}'",
                    'osfamily_id': os_family_id,
                    'osversion_id': os_version_id,
                    'cpu': cpu,
                    'ram': memory,
                    'diskspace': convert_storage_to_mb(prov_storage_raw),
                    # Additional custom fields
                    'aoapplication': ao_app,
                }

                print(f"\nCreating {machine_class}: {fqdn}")
                itop.create_machine(machine_data, machine_class)

    except FileNotFoundError:
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing CSV: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Reconcile machines in iTop from CSV (create missing)')
    parser.add_argument('--csv-file', required=True, help='Path to CSV with headers: FQDN,IP_Address,AO_Branch,AO_Applocation,OS_NAME,OS_Version,CPU,Memory,Provisioned_Storage')
    parser.add_argument('--itop-url', required=True, help='iTop base URL, e.g. https://itop.example.com')
    parser.add_argument('--itop-user', required=True, help='iTop username')
    parser.add_argument('--itop-password', required=True, help='iTop password')

    args = parser.parse_args()
    print(f"Connecting to iTop at {args.itop_url} as {args.itop_user}")

    itop = ITopAPI(args.itop_url, args.itop_user, args.itop_password)
    process_csv_file(args.csv_file, itop)


if __name__ == '__main__':
    main()
