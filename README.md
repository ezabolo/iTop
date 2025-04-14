# iTop Server Owner Update Tool

A Python script to update server owner information in iTop after DNS verification.

## Features

- Verifies DNS records match the provided IP and FQDN
- Searches for machines in both Server and VirtualMachine classes
- Updates the owner information in iTop
- Supports SSL verification disable for internal environments

## Requirements

- Python 3.6+
- Required packages listed in requirements.txt

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python update_server_owner.py --ip <server_ip> --fqdn <server_fqdn> --owner <new_owner> --itop-url <itop_url> --itop-user <username> --itop-password <password>
```

### Arguments

- `--ip`: Server IP address
- `--fqdn`: Server FQDN
- `--owner`: New owner information
- `--itop-url`: iTop URL
- `--itop-user`: iTop username
- `--itop-password`: iTop password
