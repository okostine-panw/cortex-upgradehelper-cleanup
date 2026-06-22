"""
Cortex Bulk Key Provisioner

This script automates the bulk creation of "Standard" security level API keys.
It parses user details from an input CSV, combines the first and last name to
create an audit comment, and allows the operator to select both a custom role
and an optional token expiration deadline at runtime.

Example Input CSV File (e.g., users.csv):
----------------------------------------
Firstname,Lastname,Department
Oleg,Kostine,PSO

Note: Column headers are case-insensitive and handles hidden BOM markers.
"""

import configparser
import csv
import os
import sys
import requests
from datetime import datetime, timezone, timedelta

# ==============================================================================
# REPOSITORY CONFIGURATION METHOD Alignment
# ==============================================================================
API_CONFIG_PATH = 'API_config-x5.ini'
SSL_VERIFY = False  # Matches your repository's security verify flag


def read_api_config():
    """
    Reads configuration properties precisely mirroring your repo's standard setup.
    """
    config = configparser.ConfigParser()
    config.read(API_CONFIG_PATH)
    try:
        baseurl = config.get('URL', 'BaseURL')
        api_key_id = config.get('AUTHENTICATION', 'ACCESS_KEY_ID')
        api_key = config.get('AUTHENTICATION', 'SECRET_KEY')
        return baseurl, api_key_id, api_key
    except (configparser.NoSectionError, configparser.NoOptionError) as err:
        print(f"[-] Configuration Error: Could not parse {API_CONFIG_PATH}. Details: {err}")
        sys.exit(1)


class CortexBulkKeyProvisioner:
    """
    Handles connection to the Cortex API gateway using credentials matching
    your workspace configuration parameters.
    """
    def __init__(self, baseurl, api_key_id, api_key):
        self.baseurl = baseurl.strip("/")
        self.api_key_id = api_key_id
        self.api_key = api_key

    def _get_headers(self):
        """
        Builds the standard request context required by your platform tenant.
        """
        return {
            'x-xdr-auth-id': self.api_key_id,
            'Authorization': self.api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def generate_api_key(self, first_name, last_name, role, expiration_ms=None):
        """
        Dispatches a POST request to programmatically spin up a Standard key
        assigned to the user-selected role.
        """
        url = f"{self.baseurl}/public_api/v1/api_keys/generate"

        payload = {
            "request_data": {
                "roles": [role],               # Dynamically assigned role from prompt
                "security_level": "standard",  # Enforces Standard security level
                "comment": f"Assigned to user: {first_name} {last_name}"
            }
        }

        if expiration_ms:
            payload["request_data"]["expiration"] = expiration_ms

        try:
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=payload,
                verify=SSL_VERIFY,
                timeout=15
            )
            response.raise_for_status()
            res_json = response.json()

            reply = res_json.get("reply", {})
            key_id = reply.get("id")
            api_key = reply.get("key")

            if key_id and api_key:
                return key_id, api_key
            return None, None

        except Exception as err:
            print(f"[-] API failure for user '{first_name} {last_name}': {err}")
            return None, None


def run_provisioning_workflow(input_path, output_path, provisioner_client, role, expiration_ms=None):
    """
    Parses the updated CSV structure, handles hidden BOM signatures,
    maps fields, and generates keys sequentially.
    """
    if not os.path.exists(input_path):
        print(f"[!] Target input file '{input_path}' not found in the current folder.")
        sys.exit(1)

    target_records = []

    # Using 'utf-8-sig' cleanly swallows hidden BOM markers from Excel/Text editors
    with open(input_path, mode='r', newline='', encoding='utf-8-sig') as infile:
        reader = csv.DictReader(infile)
        headers = {f.lower().strip(): f for f in reader.fieldnames} if reader.fieldnames else {}

        fname_key = headers.get('firstname')
        lname_key = headers.get('lastname')
        dept_key = headers.get('department')

        if not fname_key or not lname_key:
            print(f"[!] File format error: CSV requires distinct 'Firstname' and 'Lastname' headers.")
            print(f"    Detected fields in your file: {reader.fieldnames}")
            sys.exit(1)

        for row in reader:
            first = row.get(fname_key, "").strip()
            last = row.get(lname_key, "").strip()
            dept = row.get(dept_key, "").strip() if dept_key else "N/A"

            if first or last:
                target_records.append({'first': first, 'last': last, 'dept': dept})

    if not target_records:
        print("[!] Execution halted: Ingest user records file is empty.")
        return

    print(f"[+] Loaded {len(target_records)} personnel records. Mapping assignments...")

    # Track the selected role in the output file for auditing sanity
    csv_headers = ['Firstname', 'Lastname', 'Department', 'Assigned_Role', 'api_key_id', 'api_key', 'status']

    with open(output_path, mode='w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=csv_headers)
        writer.writeheader()

        for idx, record in enumerate(target_records, start=1):
            f_name = record['first']
            l_name = record['last']
            dept_name = record['dept']

            print(f"[{idx}/{len(target_records)}] Generating Standard '{role}' key for: {f_name} {l_name}")
            key_id, secret = provisioner_client.generate_api_key(f_name, l_name, role, expiration_ms)

            if key_id and secret:
                writer.writerow({
                    'Firstname': f_name,
                    'Lastname': l_name,
                    'Department': dept_name,
                    'Assigned_Role': role,
                    'api_key_id': key_id,
                    'api_key': secret,
                    'status': 'SUCCESS'
                })
            else:
                writer.writerow({
                    'Firstname': f_name,
                    'Lastname': l_name,
                    'Department': dept_name,
                    'Assigned_Role': role,
                    'api_key_id': 'FAILED',
                    'api_key': 'FAILED',
                    'status': 'ERROR'
                })

    print(f"[+] Operational run finished. Generated keys exported to: {output_path}")


if __name__ == "__main__":
    # 1. Ingest repo configuration using the parser definition matching your example
    baseurl, api_key_id, api_key = read_api_config()

    # 2. Instantiate client bridge
    cortex_client = CortexBulkKeyProvisioner(baseurl, api_key_id, api_key)

    print("\n--- Cortex Role & Policy Configurations ---")

    # NEW: Prompt the operator for the desired role assignment scope
    selected_role = input("Enter Cortex Role name to provision (Default: Developer): ").strip()
    if not selected_role:
        selected_role = "Developer"

    print(f"[+] Configured to provision all keys with the role: {selected_role}\n")

    # 3. Handle custom expiration date timelines
    print("--- Cortex Token Expiration Configuration ---")
    user_input = input("Enter API key lifetime in days (Default: 7 days, Max: 180): ").strip()

    expiration_ms = None
    if user_input:
        try:
            days = int(user_input)
            if 0 < days <= 180:
                future_date = datetime.now(timezone.utc) + timedelta(days=days)
                expiration_ms = int(future_date.timestamp() * 1000)
                print(f"[+] Keys will lock/expire on: {future_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            else:
                print("[!] Boundary alert: Out of scope (1-180). Using system baseline default.")
        except ValueError:
            print("[!] Syntax fallback: Invalid count given. Processing standard baseline default.")

    INPUT_FILE_CSV = "users.csv"
    OUTPUT_FILE_CSV = "generated_developer_keys.csv"

    run_provisioning_workflow(INPUT_FILE_CSV, OUTPUT_FILE_CSV, cortex_client, selected_role, expiration_ms)