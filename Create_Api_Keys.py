"""
Cortex Bulk Key Provisioner (Multi-Cloud Secret Engine)

This script automates the bulk creation of "Standard" security level API keys.
It parses user details from an input CSV, combines the first and last name to
create an audit comment, and provides runtime options to customize roles,
expiration dates, and push directly to AWS, Azure, or GCP Secret Managers.

Example Input CSV File (e.g., users.csv):
----------------------------------------
Firstname,Lastname,Department
Oleg,Kostine,PSO
"""

import configparser
import csv
import json
import os
import sys
import time
import requests
from datetime import datetime, timezone, timedelta

# Conditional Cloud SDK Imports to keep script execution lightweight
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.cloud import secretmanager
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

# ==============================================================================
# REPOSITORY CONFIGURATION METHOD Alignment
# ==============================================================================
API_CONFIG_PATH = 'API_config-x5.ini'
SSL_VERIFY = False


def read_api_config():
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
    def __init__(self, baseurl, api_key_id, api_key):
        self.baseurl = baseurl.strip("/")
        self.api_key_id = api_key_id
        self.api_key = api_key

    def _get_headers(self):
        return {
            'x-xdr-auth-id': self.api_key_id,
            'Authorization': self.api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def get_existing_comments(self):
        """
        Queries the gateway to extract comments of all active keys for duplicate checking.
        """
        url = f"{self.baseurl}/public_api/v1/api_keys/get_api_keys"
        payload = {"request_data": {}}
        try:
            response = requests.post(url, headers=self._get_headers(), json=payload, verify=SSL_VERIFY, timeout=15)
            response.raise_for_status()
            res_json = response.json()
            reply = res_json.get("reply", {})
            keys_list = reply.get("DATA", []) or reply.get("data", [])

            comments = []
            for k in keys_list:
                comment = k.get("comment")
                if comment:
                    comments.append(str(comment).strip())
            return comments
        except Exception as err:
            print(f"[!] Warning: Failed to retrieve existing keys for deduplication check: {err}")
            return []

    def generate_api_key(self, first_name, last_name, role, expiration_ms=None):
        url = f"{self.baseurl}/public_api/v1/api_keys/generate"
        payload = {
            "request_data": {
                "roles": [role],
                "security_level": "standard",
                "comment": f"Assigned to user: {first_name} {last_name}"
            }
        }
        print(f"payload: {payload}")
        if expiration_ms:
            payload["request_data"]["expiration"] = expiration_ms

        try:
            response = requests.post(url, headers=self._get_headers(), json=payload, verify=SSL_VERIFY, timeout=15)
            response.raise_for_status()
            res_json = response.json()
            reply = res_json.get("reply", {})
            return reply.get("id"), reply.get("key")
        except Exception as err:
            print(f"[-] API failure for user '{first_name} {last_name}': {err}")
            return None, None

# ==============================================================================
# CLOUD VAULT PROVIDER ENGINES
# ==============================================================================
def store_in_aws(secret_name, payload, region):
    client = boto3.client('secretsmanager', region_name=region)
    try:
        client.create_secret(Name=secret_name, SecretString=json.dumps(payload))
        return "SUCCESS (Created)"
    except client.exceptions.ResourceExistsException:
        try:
            client.put_secret_value(SecretId=secret_name, SecretString=json.dumps(payload))
            return "SUCCESS (Updated)"
        except ClientError as e:
            return f"AWS Error: {e.response['Error']['Message']}"


def store_in_azure(vault_url, secret_name, payload):
    # Azure allows only alphanumerics and hyphens
    sanitized_name = secret_name.replace("/", "-").replace("_", "-").strip("-")
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        client.set_secret(sanitized_name, json.dumps(payload))
        return "SUCCESS (Synced)"
    except Exception as e:
        return f"Azure Error: {str(e)}"


def store_in_gcp(project_id, secret_id, payload):
    # GCP allows only letters, numbers, underscores, and hyphens
    sanitized_id = secret_id.replace("/", "-").strip("-")
    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{project_id}"
    secret_path = f"{parent}/secrets/{sanitized_id}"

    try:
        try:
            client.get_secret(request={"name": secret_path})
        except Exception:
            # Create secret container if absent
            client.create_secret(request={"parent": parent, "secret_id": sanitized_id, "secret": {"replication": {"automatic": {}}}})

        client.add_secret_version(request={"parent": secret_path, "payload": {"data": json.dumps(payload).encode("utf-8")}})
        return "SUCCESS (Synced)"
    except Exception as e:
        return f"GCP Error: {str(e)}"


def run_provisioning_workflow(input_path, output_path, provisioner_client, role, expiration_ms=None, save_csv=True, cloud_config=None):
    if not os.path.exists(input_path):
        print(f"[!] Input file '{input_path}' missing.")
        sys.exit(1)

    target_records = []
    with open(input_path, mode='r', newline='', encoding='utf-8-sig') as infile:
        reader = csv.DictReader(infile)
        headers = {f.lower().strip(): f for f in reader.fieldnames} if reader.fieldnames else {}
        fname_key, lname_key, dept_key = headers.get('firstname'), headers.get('lastname'), headers.get('department')

        if not fname_key or not lname_key:
            print(f"[!] Format error: CSV requires 'Firstname' and 'Lastname' headers.")
            sys.exit(1)

        for row in reader:
            first, last = row.get(fname_key, "").strip(), row.get(lname_key, "").strip()
            if first or last:
                target_records.append({'first': first, 'last': last, 'dept': row.get(dept_key, "").strip() or "N/A"})

    if not target_records:
        print("[!] Ingest manifest is empty.")
        return

    print("[*] Gathering existing platform metadata for safety crosscheck...")
    existing_comments = provisioner_client.get_existing_comments()

    print(f"[+] Processing {len(target_records)} personnel records...")
    results_ledger = []
    creation_count = 0

    for idx, record in enumerate(target_records, start=1):
        f_name, l_name, dept_name = record['first'], record['last'], record['dept']
        cloud_status = "NOT REQUESTED"

        # Check for matching structural audit comment
        target_comment = f"Assigned to user: {f_name} {l_name}"
        if target_comment in existing_comments:
            print(f"\n[!] Duplicate Detected: An active key already exists for '{f_name} {l_name}'.")
            confirm = input("    Do you want to skip this user? (Y/n): ").strip().lower()
            if confirm != 'n':
                print(f"    [→] Skipping token creation for {f_name} {l_name}.")
                results_ledger.append({
                    'Firstname': f_name, 'Lastname': l_name, 'Department': dept_name,
                    'Assigned_Role': role, 'api_key_id': 'SKIPPED', 'api_key': 'SKIPPED',
                    'cortex_status': 'SKIPPED', 'cloud_vault_status': 'SKIPPED'
                })
                continue

        # If we are creating a key, evaluate if a throttle cooldown is required
        if creation_count > 0:
            print(f"[*] Rate Limit Guard: Pausing for 15 seconds before next task...")
            time.sleep(15)

        print(f"[{idx}/{len(target_records)}] Generating Key for: {f_name} {l_name}")
        key_id, secret = provisioner_client.generate_api_key(f_name, l_name, role, expiration_ms)

        if key_id and secret:
            secret_payload = {
                "CORTEX_API_KEY_ID": key_id, "CORTEX_API_KEY": secret,
                "ROLE": role, "DEPARTMENT": dept_name, "SYNC_DATE": datetime.now(timezone.utc).isoformat()
            }

            # Cloud Provisioning Orchestration
            if cloud_config and cloud_config['provider'] != 'none':
                provider = cloud_config['provider']
                base_name = f"{f_name.lower().replace(' ', '_')}_{l_name.lower().replace(' ', '_')}"

                if provider == 'aws':
                    secret_path = f"{cloud_config['prefix'].strip('/')}/{base_name}"
                    cloud_status = store_in_aws(secret_path, secret_payload, cloud_config['target'])
                elif provider == 'azure':
                    secret_path = f"{cloud_config['prefix']}-{base_name}" if cloud_config['prefix'] else base_name
                    cloud_status = store_in_azure(cloud_config['target'], secret_path, secret_payload)
                elif provider == 'gcp':
                    secret_path = f"{cloud_config['prefix']}-{base_name}" if cloud_config['prefix'] else base_name
                    cloud_status = store_in_gcp(cloud_config['target'], secret_path, secret_payload)

            results_ledger.append({
                'Firstname': f_name, 'Lastname': l_name, 'Department': dept_name,
                'Assigned_Role': role, 'api_key_id': key_id, 'api_key': secret,
                'cortex_status': 'SUCCESS', 'cloud_vault_status': cloud_status
            })
        else:
            results_ledger.append({
                'Firstname': f_name, 'Lastname': l_name, 'Department': dept_name,
                'Assigned_Role': role, 'api_key_id': 'FAILED', 'api_key': 'FAILED',
                'cortex_status': 'FAILED', 'cloud_vault_status': 'SKIPPED'
            })

    if save_csv:
        csv_headers = ['Firstname', 'Lastname', 'Department', 'Assigned_Role', 'api_key_id', 'api_key', 'cortex_status', 'cloud_vault_status']
        with open(output_path, mode='w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=csv_headers)
            writer.writeheader()
            writer.writerows(results_ledger)
        print(f"[+] Saved local transaction copy to: {output_path}")


if __name__ == "__main__":
    baseurl, api_key_id, api_key = read_api_config()
    cortex_client = CortexBulkKeyProvisioner(baseurl, api_key_id, api_key)

    # 1. Configs & Expirations
    selected_role = input("Enter Cortex Role name (Default: Developer): ").strip() or "Developer"
    user_input = input("Enter API key lifetime in days (Default: 7): ").strip()
    expiration_ms = int((datetime.now(timezone.utc) + timedelta(days=int(user_input or 7))).timestamp() * 1000)

    # 2. Storage Selection Menu
    print("\n--- Key Storage Configuration ---")
    print("0. Local Storage Only (No Cloud Vault)")
    print("1. AWS Secrets Manager")
    print("2. Azure Key Vault")
    print("3. GCP Secret Manager")
    choice = input("Select Storage Provider (0-3, Default: 0): ").strip() or "0"

    cloud_config = {"provider": "none", "target": "", "prefix": ""}

    if choice == "1":
        if not AWS_AVAILABLE: print("[!] Run via: uv run --with boto3 ..."); sys.exit(1)
        cloud_config.update({"provider": "aws", "target": input("AWS Region (Default: us-east-1): ").strip() or "us-east-1", "prefix": input("Secret Path Prefix (Default: cortex/api_keys): ").strip() or "cortex/api_keys"})
    elif choice == "2":
        if not AZURE_AVAILABLE: print("[!] Run via: uv run --with azure-keyvault-secrets --with azure-identity ..."); sys.exit(1)
        cloud_config.update({"provider": "azure", "target": input("Azure Key Vault URL (https://<vault>.vault.azure.net/): ").strip(), "prefix": input("Secret Prefix (Optional): ").strip()})
        if not cloud_config["target"]: print("[!] Error: Azure Vault URL required."); sys.exit(1)
    elif choice == "3":
        if not GCP_AVAILABLE: print("[!] Run via: uv run --with google-cloud-secret-manager ..."); sys.exit(1)
        cloud_config.update({"provider": "gcp", "target": input("GCP Project ID: ").strip(), "prefix": input("Secret Prefix (Optional): ").strip()})
        if not cloud_config["target"]: print("[!] Error: GCP Project ID required."); sys.exit(1)

    save_local_csv = input("\nDo you also want to save a local backup CSV ledger? (Y/n): ").strip().lower() != 'n'

    run_provisioning_workflow("users.csv", "generated_developer_keys.csv", cortex_client, selected_role, expiration_ms, save_local_csv, cloud_config)