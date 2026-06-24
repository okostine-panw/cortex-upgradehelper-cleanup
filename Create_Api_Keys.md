# Cortex Bulk Key Provisioner & Rotation Utility

An automated enterprise utility script designed to bulk-provision, audit, and rotate **Standard** security level API keys on the Palo Alto Networks Cortex platform. 

The script reads identity targets from an input CSV, matches them against the live Cortex RBAC user directory via email, evaluates **all** existing active credential profiles for each user, maps out their respective timelines, and dynamically steps through interactive operator validation gates before executing target rotations.

---

## 🚀 Key Features

* **Multi-Key Inventory Verification:** Scans the target tenant for *all* active keys registered under a user's specific comment envelope, ensuring multiple distinct access tokens are handled simultaneously.
* **Interactive Operator Validation Gates:** Detects any impending expiration (within **7 days**) or multi-key footprints and forces an explicit interactive prompt (`y/N`) allowing you to confirm or cancel the replacement request on the fly.
* **Live Identity Verification:** Queries the active Cortex RBAC directory (`/public_api/v1/rbac/get_users`) to confirm the user has an active platform account before provisioning any credentials.
* **Email-Bound Audit Footprint:** Enforces strict compliance tracking by encoding the owner's email address directly into the key metadata comment: `Assigned to user: First Last (email)`.
* **Aggressive Rate-Limit Protections:** Mitigates gateway `500 Internal Server Errors` by enforcing a mandatory 15-second individual delay between tasks, paired with an extended 60-second cool-down block after every 10 successful creations.
* **Lineage Tracking Reminders:** Displays old key references (`old_api_key_id`) on screen and outputs them as a comma-separated list inside your output ledger, alongside an explicit reminder notice to clean up expired resources.
* **Multi-Vault Storage Architectures:** Native, variable-sanitized runtime execution mapping directly to **AWS Secrets Manager**, **Azure Key Vault**, **GCP Secret Manager**, **KeePass encrypted databases (`.kdbx`)** using positional parameter safety, or local ledgers.

---

## 📋 Prerequisites & Local Setup

### 1. API Configuration File
The automation runtime reads platform authentication vectors from a standard initialization block. Keep a file named `API_config-x5.ini` inside your root workspace containing:

```ini
[URL]
BaseURL = [https://your-tenant-fqdn.paloaltonetworks.com](https://your-tenant-fqdn.paloaltonetworks.com)

[AUTHENTICATION]
ACCESS_KEY_ID = your_master_key_id
SECRET_KEY = your_master_high_privilege_secret_key
```

### 2. Ingestion Manifest Setup (`users.csv`)
Your ingestion file must be named `users.csv` and **must include the explicit `Email` column header** used to associate platform assets. Headers are case-insensitive and leading/trailing whitespace is trimmed dynamically.

```csv
Firstname,Lastname,Department,Email
Oleg,Kostine,PSO,okostine@example.com
Jane,Doe,Engineering,jdoe@example.com
John,Smith,Platform-Ops,jsmith@example.com
```

---

## 🛠️ Installation & Dependency Management

### Option A: Isolated Ephemeral Run via `uv` (Recommended)
If you leverage the `uv` package manager, you can spin up the utility and dynamically inject all cloud/vault system SDKs on-the-fly without dirtying your global Python environment:

```bash
uv run --with boto3 --with azure-keyvault-secrets --with azure-identity --with google-cloud-secret-manager --with pykeepass Create_Api_Keys.py
```

### Option B: Traditional Pipeline Virtual Environment
For classic environments, save the following tracking manifest as `requirements.txt`:

```text
requests>=2.31.0
boto3>=1.34.0
botocore>=1.34.0
azure-identity>=1.15.0
azure-keyvault-secrets>=4.7.0
google-cloud-secret-manager>=2.20.0
pykeepass>=4.0.7
```

Install packages and call the automation engine:
```bash
pip install -r requirements.txt
python Create_Api_Keys.py
```

---

## 🕹️ Interactive Runtime Configuration

When calling `Create_Api_Keys.py`, the CLI interactive prompt guides deployment profiling:

1. **Cortex Role Allocation:** Provide the authorization group mapping string. Pressing **Enter** assigns the default safe baseline `Developer`.
2. **Expiration Bounds:** Define lease validity in days (Accepts boundary scopes between 1-180). Pressing **Enter** sets a `7` day expiration timeline.
3. **Storage Engine Target Selection:**
   * `0`: Local CSV backup ledger only.
   * `1`: Push credentials to **AWS Secrets Manager** (Requires an active `aws sso` session or matching terminal profile keys).
   * `2`: Push credentials to **Azure Key Vault** (Requires local identity binding using active `az login` context).
   * `3`: Push credentials to **GCP Secret Manager** (Requires active Application Default Credentials).
   * `4`: Write to an encrypted **KeePass Database (`.kdbx`)** (Prompts for filename and master database key; updates entries seamlessly using compliant keyword calls or builds a fresh container if not present).
   * `5`: **Interactive Rotation Intercepts:** If a user possesses keys expiring within 7 days or maintains multiple distinct active tokens on the instance, the console halts execution, showcases an inventory of current keys with their remaining lifespans, and requests a confirmation:
        `Proceed with creating a replacement key for this user? (y/N):`
---

## 🔐 Vault Object Data Schema

When committing credentials to cloud keychains or local encrypted password managers, the structured object is committed as a single stringified JSON document:

```json
{
  "CORTEX_API_KEY_ID": "1405",
  "CORTEX_API_KEY": "d7A8k2...f8B9",
  "ROLE": "Developer",
  "DEPARTMENT": "PSO",
  "EMAIL": "okostine@example.com",
  "SYNC_DATE": "2026-06-24T16:30:00Z"
}
```

## ⏱️ Output File Integrity
When a local ledger backup is requested, the runtime compiles results into an explicitly timestamped tracking sheet matching the context profile format:  
`generated_developer_keys_YYYYMMDD_HHMMSS.csv`

The log columns utilize the following alignment schema to preserve token lineage records:
* `old_api_key_id`: Contains a comma-separated string mapping out all key IDs discovered for the profile prior to execution.
* `new_api_key_id`: The ID of the newly provisioned standard key.
* `cortex_comment`: The exact email-bound audit string injected into the platform asset.

> ⚠️ **Security Operations Ledger Warning:** Treating the output local logs as highly sensitive cryptographic material is required. Ensure processing automation chains scrub the working block directory clean upon confirmation of ingestion. **Never commit raw generated key sheets back into git history standard version control.**
```