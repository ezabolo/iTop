#!/usr/bin/env python3
"""Convert selected VirtualMachine objects into Server objects in iTop.

Selection criteria:
  - Class: VirtualMachine
  - management IP is NOT:
      10.34.*
      10.44.*
      1.1.1.1

For each matching VirtualMachine:
  - Create a new Server object with copied fields.
  - If creation succeeds, delete the original VirtualMachine.

IMPORTANT:
  - This script assumes the management IP attribute is called "managementip".
    If your datamodel uses a different code, change MANAGEMENT_IP_ATTR below.
  - The set of fields copied from VirtualMachine to Server is controlled by
    COMMON_FIELDS. Adjust this list to match attributes that exist on both
    classes in your iTop instance.
  - Run first with --dry-run to see what *would* change.
"""

import argparse
import json
import logging
import sys
from typing import Any, Dict, List

import requests
from urllib3.exceptions import InsecureRequestWarning

# ---------------------------------------------------------------------------
# Logging & SSL
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Suppress only the InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Configuration – adjust to your environment
# ---------------------------------------------------------------------------

ITOP_URL_DEFAULT = "https://your-itop-server/webservices/rest.php?version=1.3"
ITOP_USER_DEFAULT = "your_itop_username"
ITOP_PWD_DEFAULT = "your_itop_password"

# Attribute code for the management IP on VirtualMachine/Server
MANAGEMENT_IP_ATTR = "managementip"

# Fields that should NEVER be copied from VM to Server, even if they exist
# on both classes. Typically id/finalclass/internal flags and derived
# read-only name fields.
FIELD_BLACKLIST = {
    "id",
    "friendlyname",
    "finalclass",
    "obsolescence_flag",
    "obsolescence_date",
    "obsolescense_date",
}

# Field name suffixes that indicate read-only or derived attributes in iTop
# (e.g. organization_name, org_id_friendlyname, *_obsolescence_flag).
FIELD_SUFFIX_BLACKLIST = (
    "_name",
    "_friendlyname",
    "_obsolescence_flag",
    "_obsolescence_date",
    "_finalclass_recall",
)


class ITOPClient:
    def __init__(self, url: str, username: str, password: str, version: str = "1.3", verify_ssl: bool = True) -> None:
        self.base_url = url.rstrip("/")
        self.username = username
        self.password = password
        self.version = version
        self.verify_ssl = verify_ssl

    def _endpoint(self) -> str:
        base = self.base_url
        if not base.lower().endswith("rest.php"):
            base = base.rstrip("/") + "/webservices/rest.php"
        if "?version=" in base or "&version=" in base:
            return base
        return f"{base}?version={self.version}"

    def call(self, operation: str, params: Dict[str, Any]) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"operation": operation, **params}
        data = {
            "auth_user": self.username,
            "auth_pwd": self.password,
            "json_data": json.dumps(payload),
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        endpoint = self._endpoint()
        logger.info("Calling iTop operation=%s at %s", operation, endpoint)

        resp = requests.post(
            endpoint,
            auth=(self.username, self.password),
            headers=headers,
            data=data,
            verify=self.verify_ssl,
            timeout=60,
        )

        try:
            result = resp.json()
        except Exception:
            ctype = resp.headers.get("Content-Type")
            preview = (resp.text or "")[:500]
            logger.error(
                "Non-JSON response (status %s, content-type %s) from %s: %s",
                resp.status_code,
                ctype,
                endpoint,
                preview,
            )
            raise RuntimeError("Non-JSON response from iTop API")

        logger.info("iTop response code=%s, message=%s", result.get("code"), result.get("message"))

        if result.get("code") != 0:
            raise RuntimeError(f"iTop error {result.get('code')}: {result.get('message')}")

        return result


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def fetch_virtual_machines_to_convert(client: ITOPClient) -> List[Dict[str, Any]]:
    """Fetch VirtualMachine objects whose management IP is NOT in the allowed ranges.

    Criteria (OQL):
      managementip NOT LIKE '10.34.%'
      AND managementip NOT LIKE '10.44.%'
      AND managementip != '1.1.1.1'
    """
    attr = MANAGEMENT_IP_ATTR
    oql = (
        "SELECT VirtualMachine WHERE "
        f"{attr} NOT LIKE '10.34.%' AND "
        f"{attr} NOT LIKE '10.44.%' AND "
        f"{attr} != '1.1.1.1'"
    )

    result = client.call(
        "core/get",
        {
            "class": "VirtualMachine",
            "key": oql,
            "output_fields": "*",
        },
    )

    objects = result.get("objects") or {}
    vms: List[Dict[str, Any]] = []
    for obj in objects.values():
        fields = obj.get("fields", {})
        # The true numeric id is carried in the object's 'key' field.
        # Some datamodels do not include a valid 'id' inside 'fields',
        # which can leave id=None and cause Missing parameter 'key' on delete.
        key_val = obj.get("key")
        try:
            numeric_id = int(key_val) if key_val is not None else None
        except Exception:
            numeric_id = key_val
        # Store it explicitly so downstream logic can rely on it.
        fields["_numeric_id"] = numeric_id
        vms.append(fields)

    logger.info("Found %d VirtualMachine objects to convert", len(vms))
    return vms


def get_server_field_names(client: ITOPClient) -> set:
    """Return the set of attribute names defined on the Server class.

    We fetch a single Server object (any one) with output_fields='*' and
    inspect its fields dict. This is used to determine which VM fields can
    safely be copied over when creating a Server.
    """
    result = client.call(
        "core/get",
        {
            "class": "Server",
            "key": "SELECT Server",
            "output_fields": "*",
        },
    )

    objects = result.get("objects") or {}
    for obj in objects.values():
        fields = obj.get("fields", {})
        return set(fields.keys())

    # If no Server objects exist yet, fall back to an empty set; the caller
    # can decide how to handle this situation.
    logger.warning("No existing Server objects found to infer field names.")
    return set()


def build_server_fields_from_vm(vm_fields: Dict[str, Any], server_field_names: set) -> Dict[str, Any]:
    """Construct the fields dict for the new Server from VM fields.

    Copies all VM attributes that also exist on Server, excluding a small
    blacklist of internal fields.
    """
    fields: Dict[str, Any] = {}
    for key, value in vm_fields.items():
        if key in FIELD_BLACKLIST:
            continue
        if any(key.endswith(sfx) for sfx in FIELD_SUFFIX_BLACKLIST):
            continue
        if key not in server_field_names:
            continue
        fields[key] = value
    return fields


def create_server_from_vm(client: ITOPClient, vm_fields: Dict[str, Any], server_field_names: set, comment: str) -> int:
    """Create a Server object from the given VM fields.

    Returns the new Server id.
    """
    server_fields = build_server_fields_from_vm(vm_fields, server_field_names)
    name = server_fields.get("name", vm_fields.get("name", ""))
    logger.info("Creating Server from VM name=%r with fields=%r", name, server_fields)

    result = client.call(
        "core/create",
        {
            "class": "Server",
            "fields": server_fields,
            "comment": comment,
        },
    )

    objects = result.get("objects") or {}
    # Expect a single created object
    for _, obj in objects.items():
        new_id = int(obj.get("key"))
        logger.info("Created Server id=%s from VM name=%r", new_id, name)
        return new_id

    raise RuntimeError("Unexpected core/create response: no objects returned")


def delete_virtual_machine(client: ITOPClient, vm_id: int, name: str, comment: str) -> None:
    """Delete the original VirtualMachine after successful migration."""
    logger.info("Deleting VirtualMachine id=%s, name=%r", vm_id, name)
    client.call(
        "core/delete",
        {
            "class": "VirtualMachine",
            "key": vm_id,
            "comment": comment,
        },
    )


def migrate_virtual_machines(client: ITOPClient, dry_run: bool, no_delete: bool, comment: str) -> None:
    vms = fetch_virtual_machines_to_convert(client)

    # Determine which attributes are valid on Server so we only copy
    # overlapping fields from the VM.
    server_field_names = get_server_field_names(client)
    if not server_field_names:
        logger.warning("Server field list is empty; no attributes will be copied.")

    for vm in vms:
        # Prefer the numeric id we captured from the API object's 'key'.
        vm_id = vm.get("_numeric_id", vm.get("id"))
        name = vm.get("name", "")
        mgmt_ip = vm.get(MANAGEMENT_IP_ATTR, "")

        try:
            numeric_id = int(vm_id) if vm_id is not None else None
        except Exception:
            numeric_id = vm_id

        logger.info(
            "Processing VM id=%s, name=%r, %s=%r",
            vm_id,
            name,
            MANAGEMENT_IP_ATTR,
            mgmt_ip,
        )

        if dry_run:
            logger.info("(dry-run) Would create Server and %s VirtualMachine id=%s",
                        "NOT delete" if no_delete else "delete", vm_id)
            continue

        # Create Server
        new_server_id = create_server_from_vm(client, vm, server_field_names, comment)

        # Optionally delete original VM
        if no_delete:
            logger.info("--no-delete specified; keeping original VirtualMachine id=%s", vm_id)
        else:
            delete_virtual_machine(client, numeric_id, name, comment)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert selected VirtualMachines into Servers in iTop.")
    parser.add_argument("--url", default=ITOP_URL_DEFAULT, help="iTop REST URL (default: %(default)s)")
    parser.add_argument("--user", default=ITOP_USER_DEFAULT, help="iTop username (default: %(default)s)")
    parser.add_argument("--password", default=ITOP_PWD_DEFAULT, help="iTop password (default: %(default)s)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument(
        "--comment",
        default="Converted VirtualMachine to Server via convert_vm_to_server.py",
        help="Top-level iTop update comment (default: %(default)s)",
    )
    parser.add_argument(
        "--no-delete",
        action="store_true",
        help="Create Server objects but do NOT delete original VirtualMachines",
    )
    parser.add_argument("--dry-run", action="store_true", help="Only show what would change; do not modify iTop")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    client = ITOPClient(
        url=args.url,
        username=args.user,
        password=args.password,
        version="1.3",
        verify_ssl=not args.no_verify_ssl,
    )

    logger.info(
        "Starting VirtualMachine -> Server migration (dry_run=%s, no_delete=%s)",
        args.dry_run,
        args.no_delete,
    )
    migrate_virtual_machines(
        client,
        dry_run=args.dry_run,
        no_delete=args.no_delete,
        comment=args.comment,
    )
    logger.info("Done.")


if __name__ == "__main__":
    main()
