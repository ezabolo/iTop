#!/usr/bin/env python3
"""Export certificate information from iTop into a CSV file.

This script reuses the iTOPAPI client from import_cert_info.py to:
- Query both Server and VirtualMachine objects.
- Extract: name, IP address, certrenewaldate, currentcertstartdate, currentcertenddate.
- Optionally filter out machines without any cert info or with a specific IP.

The output CSV columns are:
    Name,IP,certrenewaldate,currentcertstartdate,currentcertenddate

Usage example:

    python3 export_cert_info.py \
        --url "https://your-itop-server/webservices/rest.php" \
        --user your_itop_username \
        --password your_itop_password \
        --output all_machines_cert_info.csv
"""

import argparse
import csv
import logging
import sys
from typing import Any, Dict, List

from import_cert_info import iTOPAPI  # reuse existing API client

logger = logging.getLogger(__name__)


def fetch_cert_info(api: iTOPAPI, class_name: str) -> List[Dict[str, Any]]:
    """Fetch cert-related info for all objects of a given class.

    Different iTop datamodels spell the IP field differently
    (e.g. managementip, ip_address, ip_adress). To avoid
    "invalid attribute" errors, we request all fields (*) and
    then pick the first IP-like attribute that exists per object.
    """

    oql = f"SELECT {class_name}"
    data = {
        "operation": "core/get",
        "class": class_name,
        "key": oql,
        # Request all fields; we'll pick out what we need.
        "output_fields": "*",
    }

    response = api.call_operation(data)
    results: List[Dict[str, Any]] = []

    if not response or response.get("code") != 0:
        msg = response.get("message") if response else "No response"
        logger.error("Failed to fetch %s objects: %s", class_name, msg)
        return results

    objects = response.get("objects") or {}
    for obj in objects.values():
        fields = obj.get("fields", {})
        name = fields.get("name", "")

        # Try a few common IP attributes; fall back to empty string.
        ip = ""
        for candidate in ("managementip", "ip_address", "ip_adress", "ip"):
            val = fields.get(candidate)
            if val:
                ip = val
                break

        certrenewal = (fields.get("certrenewaldate") or "").strip()
        cert_start = (fields.get("currentcertstartdate") or "").strip()
        cert_end = (fields.get("currentcertenddate") or "").strip()

        # Filter 1: skip machines with no cert info at all in iTop.
        if not (certrenewal or cert_start or cert_end):
            continue

        # Filter 2: skip decommissioned machines (IP 1.1.1.1).
        if ip == "1.1.1.1":
            continue

        row = {
            "Name": name,
            "IP": ip,
            "certrenewaldate": certrenewal,
            "currentcertstartdate": cert_start,
            "currentcertenddate": cert_end,
        }
        results.append(row)

    logger.info("Fetched %d %s objects", len(results), class_name)
    return results


def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    fieldnames = [
        "Name",
        "IP",
        "certrenewaldate",
        "currentcertstartdate",
        "currentcertenddate",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export cert info from iTop to CSV.")
    parser.add_argument("--url", required=True, help="iTop base URL (same as used by import_cert_info.py)")
    parser.add_argument("--user", required=True, help="iTop username")
    parser.add_argument("--password", required=True, help="iTop password")
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates (default: disabled)",
    )
    parser.add_argument(
        "--output",
        default="cert_export.csv",
        help="Output CSV file path (default: %(default)s)",
    )
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    args = parse_args()

    api = iTOPAPI(
        url=args.url,
        username=args.user,
        password=args.password,
        version="1.3",
        verify_ssl=args.verify_ssl,
    )

    all_rows: List[Dict[str, Any]] = []
    for cls in ("Server", "VirtualMachine"):
        all_rows.extend(fetch_cert_info(api, cls))

    write_csv(args.output, all_rows)
    logger.info("Wrote %d rows to %s", len(all_rows), args.output)


if __name__ == "__main__":
    main()


