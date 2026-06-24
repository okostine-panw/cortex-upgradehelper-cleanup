"""
Cortex Bulk Key Provisioner (Multi-Cloud Secret Engine)

This script automates the bulk creation of "Standard" security level API keys.
It parses user details from an input CSV, combines the first and last name to
create an audit comment, and provides runtime options to customize roles,
expiration dates, and push directly to AWS, Azure, or GCP Secret Managers.

Example Input CSV File (e.g., users.csv):
----------------------------------------
Firstname,Lastname,Department
John,Doe,PSO
"""

import configparser
import csv
import json
import os
import sys
import time
import requests
from datetime import datetime, timezone, timedelta

# Conditional Cloud & Vault SDK Imports
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

try:
    from pykeepass import PyKeePass, create_database
    KEEPASS_AVAILABLE = True
except ImportError:
    KEEPASS_AVAILABLE = False

# ==============================================================================
# REPOSITORY CONFIGURATION
# ==============================================================================
API_CONFIG_PATH = 'API_config-x5.ini'
# SSL_VERIFY = False
SSL_VERIFY = True


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

    def get_active_cortex_emails(self):
        """
        Queries the Cortex RBAC User Directory API to map verified platform accounts.
        """
        url = f"{self.baseurl}/public_api/v1/rbac/get_users"
        payload = {"request_data": {}}
        try:
            response = requests.post(url, headers=self._get_headers(), json=payload, verify=SSL_VERIFY, timeout=15)
            response.raise_for_status()

            # The API returns an array/list of objects directly or inside a reply envelope
            res_json = response.json()

            # Accommodates flat array replies and standard dictionary object wraps safely
            reply = res_json.get("reply", [])
            user_list = reply if isinstance(reply, list) else reply.get("data", reply.get("DATA", []))

            active_emails = set()
            for user in user_list:
                email = user.get("user_email")
                if email:
                    active_emails.add(email.strip().lower())
            return active_emails
        except Exception as err:
            print(f"[!] Critical Error: Failed to fetch active user directory from Cortex RBAC endpoint: {err}")
            sys.exit(1)

    def get_existing_keys_lifecycle(self):
        """
        Queries the platform to build an expiration timeline map indexed by key comments.
        UPDATED: Group entries into an array list to handle users holding multiple active keys.
        """
        url = f"{self.baseurl}/public_api/v1/api_keys/get_api_keys"
        payload = {"request_data": {"filters": []}}
        lifecycle_map = {}
        try:
            response = requests.post(url, headers=self._get_headers(), json=payload, verify=SSL_VERIFY, timeout=15)
            response.raise_for_status()
            res_json = response.json()
            reply = res_json.get("reply", {})
            keys_list = reply.get("DATA", []) or reply.get("data", [])

            for k in keys_list:
                comment = k.get("comment")
                expiration = k.get("expiration")
                key_id = k.get("id")
                if comment:
                    comment_str = str(comment).strip()
                    if comment_str not in lifecycle_map:
                        lifecycle_map[comment_str] = []
                    lifecycle_map[comment_str].append({
                        "expiration": expiration,
                        "id": key_id
                    })
            return lifecycle_map
        except Exception as err:
            print(f"[!] Warning: Failed to retrieve API key lifecycle data: {err}")
            return {}

    def generate_api_key(self, first_name, last_name, email, role, expiration_ms=None):
        url = f"{self.baseurl}/public_api/v1/api_keys/generate"
        payload = {
            "request_data": {
                "roles": [role],
                "security_level": "standard",
                "comment": f"Assigned to user: {first_name} {last_name} ({email})"
            }
        }
        # print(f"payload: {payload}")
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
# SECRETS STORAGE ENGINES
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
    sanitized_name = secret_name.replace("/", "-").replace("_", "-").strip("-")
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        client.set_secret(sanitized_name, json.dumps(payload))
        return "SUCCESS (Synced)"
    except Exception as e:
        return f"Azure Error: {str(e)}"


def store_in_gcp(project_id, secret_id, payload):
    sanitized_id = secret_id.replace("/", "-").strip("-")
    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{project_id}"
    secret_path = f"{parent}/secrets/{sanitized_id}"
    try:
        try:
            client.get_secret(request={"name": secret_path})
        except Exception:
            client.create_secret(request={"parent": parent, "secret_id": sanitized_id, "secret": {"replication": {"automatic": {}}}})
        client.add_secret_version(request={"parent": secret_path, "payload": {"data": json.dumps(payload).encode("utf-8")}})
        return "SUCCESS (Synced)"
    except Exception as e:
        return f"GCP Error: {str(e)}"


def store_in_keepass(kdbx_path, kdbx_password, group_name, title, username, api_key, key_id, role, dept):
    try:
        if os.path.exists(kdbx_path):
            kp = PyKeePass(kdbx_path, password=kdbx_password)
        else:
            kp = create_database(kdbx_path, password=kdbx_password)

        group = kp.find_groups(name=group_name, first=True)
        if not group:
            group = kp.add_group(kp.root_group, group_name)

        entry = kp.find_entries(title=title, group=group, first=True)
        notes_content = f"Role: {role}\nDepartment: {dept}\nSync Date: {datetime.now(timezone.utc).isoformat()}"

        if entry:
            entry.password = api_key
            entry.username = username
            entry.notes = notes_content
            entry.set_custom_property("CORTEX_API_KEY_ID", str(key_id), protect=False)
        else:
            # VERIFIED: Strictly positional parameters bypasses Cython keyword mapping bugs completely
            new_entry = kp.add_entry(group, title, username, api_key)
            new_entry.notes = notes_content
            new_entry.set_custom_property("CORTEX_API_KEY_ID", str(key_id), protect=False)

        kp.save()
        return "SUCCESS (KeePass)"
    except Exception as e:
        return f"KeePass Error: {str(e)}"


def store_secret_payload(provider_config, base_name, payload):
    provider = provider_config['provider']
    if provider == 'none': return "NOT REQUESTED"

    if provider == 'aws':
        secret_path = f"{provider_config['prefix'].strip('/')}/{base_name}"
        return store_in_aws(secret_path, payload, provider_config['target'])
    elif provider == 'azure':
        secret_path = f"{provider_config['prefix']}-{base_name}" if provider_config['prefix'] else base_name
        return store_in_azure(provider_config['target'], secret_path, payload)
    elif provider == 'gcp':
        secret_path = f"{provider_config['prefix']}-{base_name}" if provider_config['prefix'] else base_name
        return store_in_gcp(provider_config['target'], secret_path, payload)
    elif provider == 'keepass':
        entry_title = f"Cortex - {base_name.replace('_', ' ').title()}"
        return store_in_keepass(
            provider_config['target'], provider_config['password'], provider_config['prefix'],
            entry_title, base_name, payload["CORTEX_API_KEY"], payload["CORTEX_API_KEY_ID"],
            payload["ROLE"], payload["DEPARTMENT"]
        )
    return "SKIPPED"


# ==============================================================================
# MAIN WORKFLOW RUNNER WITH ROTATION MANAGEMENT
# ==============================================================================
def run_provisioning_workflow(input_path, output_path, provisioner_client, role, expiration_ms=None, save_csv=True, target_config=None):
    if not os.path.exists(input_path):
        print(f"[!] Input file '{input_path}' missing.")
        sys.exit(1)

    target_records = []
    with open(input_path, mode='r', newline='', encoding='utf-8-sig') as infile:
        reader = csv.DictReader(infile)
        headers = {f.lower().strip(): f for f in reader.fieldnames} if reader.fieldnames else {}

        fname_key = headers.get('firstname')
        lname_key = headers.get('lastname')
        dept_key = headers.get('department')
        email_key = headers.get('email')

        if not all([fname_key, lname_key, email_key]):
            print(f"[!] Format error: CSV requires 'Firstname', 'Lastname', and 'Email' headers.")
            sys.exit(1)

        for row in reader:
            first = row.get(fname_key, "").strip()
            last = row.get(lname_key, "").strip()
            email = row.get(email_key, "").strip().lower()
            dept = row.get(dept_key, "").strip() or "N/A"
            if email:
                target_records.append({'first': first, 'last': last, 'email': email, 'dept': dept})

    # Step 1: Pre-fetch Cortex Directory map
    print("[*] Syncing live account records from Cortex User Directory...")
    active_cortex_emails = provisioner_client.get_active_cortex_emails()

    # Step 2: Pre-fetch Existing Key Lifecycles
    print("[*] Syncing live token map from Cortex Gateway...")
    keys_lifecycle = provisioner_client.get_existing_keys_lifecycle()

    print(f"[+] Processing {len(target_records)} personnel rows under account rotation checks...")
    results_ledger = []
    creation_count = 0
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    seven_days_ms = 7 * 24 * 60 * 60 * 1000

    for idx, record in enumerate(target_records, start=1):
        f_name, l_name, email, dept_name = record['first'], record['last'], record['email'], record['dept']
        vault_status = "NOT REQUESTED"

        # Rule Check 1: Verify presence inside Core Identity Directory
        if email not in active_cortex_emails:
            print(f"[-] Skipped: User '{f_name} {l_name}' ({email}) has no profile account registered in Cortex.")
            results_ledger.append({
                'Firstname': f_name, 'Lastname': l_name, 'Email': email, 'Department': dept_name,
                'old_api_key_id': 'N/A', 'new_api_key_id': 'SKIPPED_NO_ACCOUNT', 'new_api_key': 'SKIPPED',
                'cortex_comment': 'N/A', 'cortex_status': 'SKIPPED', 'storage_vault_status': 'SKIPPED'
            })
            continue

        # Rule Check 2: Evaluate Timeline Lease using Email-scoped unique comment structures
        target_comment = f"Assigned to user: {f_name} {l_name} ({email})"
        existing_keys = keys_lifecycle.get(target_comment, [])

        should_rotate = False
        reason = "No matching key comment footprint found for this specific email address."
        old_key_ids_str = "N/A"

        # UPDATED: Inspect all keys tracked under the user's specific comment envelope
        if existing_keys:
            old_key_ids_str = ", ".join([str(k["id"]) for k in existing_keys])
            print(f"\n[*] Found {len(existing_keys)} existing key(s) for {f_name} {l_name} ({email}):")

            expiring_count = 0
            for k in existing_keys:
                key_expiration = k["expiration"]
                k_id = k["id"]
                if key_expiration is None:
                    print(f"    - Key ID {k_id}: Configured to never expire.")
                else:
                    ms_until_expiration = key_expiration - now_ms
                    days_left = round(ms_until_expiration / (1000 * 60 * 60 * 24), 1)
                    if ms_until_expiration <= seven_days_ms:
                        expiring_count += 1
                        print(f"    - Key ID {k_id}: Expires in {days_left} days. -> FLAGS FOR ROTATION")
                    else:
                        print(f"    - Key ID {k_id}: Expires in {days_left} days. (Healthy)")

            if expiring_count > 0 or len(existing_keys) > 1:
                should_rotate = True
                if len(existing_keys) > 1:
                    reason = f"User holds multiple keys ({len(existing_keys)} found) on the instance."
                else:
                    reason = "An existing key falls within the 7-day pre-expiration window."
            else:
                should_rotate = False
                reason = "All active keys associated with this profile are currently healthy."
        else:
            # No matching comment profile found on instance
            should_rotate = True
            reason = "No active key registered under this exact user and email comment signature block."

        # Action Phase based on policy execution outputs
        if not should_rotate:
            print(f"[=] Healthy: Skipping rotation for {f_name} {l_name}. Reason: {reason}")
            results_ledger.append({
                'Firstname': f_name, 'Lastname': l_name, 'Email': email, 'Department': dept_name,
                'old_api_key_id': old_key_ids_str, 'new_api_key_id': 'CURRENT_KEY_VALID', 'new_api_key': 'SKIPPED',
                'cortex_comment': target_comment, 'cortex_status': 'SKIPPED_HEALTHY', 'storage_vault_status': 'SKIPPED'
            })
            continue

        # NEW: Force an explicit confirmation prompt if keys already exist for the user
        if existing_keys:
            print(f"[!] Policy recommends rotation for {f_name} {l_name}. Reason: {reason}")
            confirm_choice = input(f"    Proceed with creating a replacement key for this user? (y/N): ").strip().lower()
            if confirm_choice != 'y':
                print(f"    [→] Rotation canceled by operator request.")
                results_ledger.append({
                    'Firstname': f_name, 'Lastname': l_name, 'Email': email, 'Department': dept_name,
                    'old_api_key_id': old_key_ids_str, 'new_api_key_id': 'SKIPPED_BY_OPERATOR', 'new_api_key': 'SKIPPED',
                    'cortex_comment': target_comment, 'cortex_status': 'SKIPPED_BY_OPERATOR', 'storage_vault_status': 'SKIPPED'
                })
                continue

        print(f"\n[!] Triggering rotation cycle for: {f_name} {l_name}. Reason: {reason}")

        # Safe Multi-Tier Pacing Delays to protect platform from throwing 500s
        if creation_count > 0:
            if creation_count % 10 == 0:
                print(f"[*] Batch Interval: Completed {creation_count} tokens. Halting thread for 60 seconds...")
                time.sleep(60)
            else:
                print(f"[*] Throttling delay: Pausing 15 seconds before processing next entity...")
                time.sleep(15)

        # Pass the email straight to the key creation block
        key_id, secret = provisioner_client.generate_api_key(f_name, l_name, email, role, expiration_ms)

        if key_id and secret:
            creation_count += 1
            secret_payload = {
                "CORTEX_API_KEY_ID": key_id, "CORTEX_API_KEY": secret,
                "ROLE": role, "DEPARTMENT": dept_name, "EMAIL": email, "SYNC_DATE": datetime.now(timezone.utc).isoformat()
            }

            base_name = f"{f_name.lower().replace(' ', '_')}_{l_name.lower().replace(' ', '_')}"
            vault_status = store_secret_payload(target_config, base_name, secret_payload)

            print(f"    [✓] Rotation processed successfully for User: {f_name} {l_name}")
            print(f"        Identity Contact: {email} | Department Group: {dept_name}")
            print(f"        Old Key ID(s): {old_key_ids_str} -> New Key ID Reference: {key_id} | Storage Sync Status: {vault_status}")
            print(f"        [!] REMINDER: The old key references ({old_key_ids_str}) should be tracked and deleted after their grace period.")

            results_ledger.append({
                'Firstname': f_name, 'Lastname': l_name, 'Email': email, 'Department': dept_name,
                'old_api_key_id': old_key_ids_str, 'new_api_key_id': key_id, 'new_api_key': secret,
                'cortex_comment': target_comment, 'cortex_status': 'ROTATED', 'storage_vault_status': vault_status
            })
        else:
            results_ledger.append({
                'Firstname': f_name, 'Lastname': l_name, 'Email': email, 'Department': dept_name,
                'old_api_key_id': old_key_ids_str, 'new_api_key_id': 'FAILED', 'new_api_key': 'FAILED',
                'cortex_comment': target_comment, 'cortex_status': 'FAILED', 'storage_vault_status': 'SKIPPED'
            })

    if save_csv:
        # UPDATED: Re-ordered layout mapping tracking metrics safely inside tracking configurations
        csv_headers = [
            'Firstname', 'Lastname', 'Email', 'Department',
            'old_api_key_id', 'new_api_key_id', 'new_api_key',
            'cortex_comment', 'cortex_status', 'storage_vault_status'
        ]
        with open(output_path, mode='w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=csv_headers)
            writer.writeheader()
            writer.writerows(results_ledger)
        print(f"\n[+] Processing run finished. Log ledger written out to: {output_path}")


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
    print("4. KeePass Database (.kdbx)")
    choice = input("Select Storage Provider (0-4, Default: 0): ").strip() or "0"

    target_config = {"provider": "none", "target": "", "prefix": "", "password": ""}

    if choice == "1":
        target_config.update({"provider": "aws", "target": input("AWS Region (Default: us-east-1): ").strip() or "us-east-1", "prefix": input("Secret Path Prefix (Default: cortex/api_keys): ").strip() or "cortex/api_keys"})
    elif choice == "2":
        target_config.update({"provider": "azure", "target": input("Azure Key Vault URL: ").strip(), "prefix": input("Secret Prefix (Optional): ").strip()})
    elif choice == "3":
        target_config.update({"provider": "gcp", "target": input("GCP Project ID: ").strip(), "prefix": input("Secret Prefix (Optional): ").strip()})
    elif choice == "4":
        if not KEEPASS_AVAILABLE:
            print("[!] Execution Aborted: 'pykeepass' module missing from local environment path.")
            print("    Please launch this execution stream utilizing the package manager:")
            print("    uv run --with pykeepass Create_Api_Keys.py")
            sys.exit(1)

        target_config.update({
            "provider": "keepass",
            "target": input("KeePass Database File Path (Default: cortex_keys.kdbx): ").strip() or "cortex_keys.kdbx",
            "password": input("Enter KeePass Master Password: ").strip(),
            "prefix": input("Database Group Name (Default: Cortex Keys): ").strip() or "Cortex Keys"
        })
        if not target_config["password"]:
            print("[!] Error: KeePass master password cannot be empty.")
            sys.exit(1)

    save_local_csv = input("\nDo you also want to save a local backup CSV ledger? (Y/n): ").strip().lower() != 'n'

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"generated_developer_keys_{timestamp_str}.csv"

    run_provisioning_workflow("users.csv", output_filename, cortex_client, selected_role, expiration_ms, save_local_csv, target_config)