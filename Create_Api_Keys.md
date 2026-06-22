# Cortex Bulk Key Provisioner

An automated utility script designed to bulk-provision **Standard** security level API keys on the Palo Alto Networks Cortex platform. The script reads employee names from an input CSV file, maps them to a specified role, calculates optional custom expiration tokens, and securely syncs the output across your choice of storage backends (**Local CSV**, **AWS Secrets Manager**, **Azure Key Vault**, or **GCP Secret Manager**).

---

## 🚀 Features

* **Multi-Cloud Integration:** Seamlessly push secrets to AWS, Azure, or GCP vaults natively.
* **Smart Name Sanitization:** Automatically adjusts secret naming conventions to match strict cloud provider requirements (e.g., handles forward slashes and underscores dynamically).
* **BOM-Resistant Ingestion:** Uses `utf-8-sig` encoding to prevent hidden Byte Order Marks (BOM) from Excel breaking column reads.
* **Uniform Configuration:** Hooks directly into your existing `API_config.ini` configuration framework.

---

## 📋 Prerequisites & Setup

### 1. API Configuration File
The script reads your active master gateway credentials directly from your local `.ini` configuration file. Ensure a file named `API_config.ini` sits in your execution directory with the following structure:

```ini
[URL]
BaseURL = [https://your-tenant-fqdn.paloaltonetworks.com](https://your-tenant-fqdn.paloaltonetworks.com)

[AUTHENTICATION]
ACCESS_KEY_ID = your_master_key_id
SECRET_KEY = your_master_high_privilege_secret_key
```

### 2. Prepare the Input CSV (`users.csv`)
Create an ingestion manifest named `users.csv` in the same execution folder:

```csv
Firstname,Lastname,Department
Oleg,Kostine,PSO
Jane,Doe,Engineering
John,Smith,Platform-Ops
```

---

## 🛠️ Installation & Dependency Management

### Option A: Fast Execution via `uv` (Recommended)
If you are using `uv`, you can execute the script instantly without mutating your global environment by letting `uv` inject the dependencies on-the-fly:

```bash
uv run --with boto3 --with azure-keyvault-secrets --with azure-identity --with google-cloud-secret-manager create_api_keys.py
```

### Option B: Standard `requirements.txt` Installation
If you prefer a standard environment, install the following dependencies:

```text
requests>=2.31.0
boto3>=1.34.0
botocore>=1.34.0
azure-identity>=1.15.0
azure-keyvault-secrets>=4.7.0
google-cloud-secret-manager>=2.20.0
```

Run installation and execute:
```bash
pip install -r requirements.txt
python create_api_keys.py
```

---

## 🕹️ Usage & Runtime Menu

Execute the script from your terminal. During execution, you will be prompted to customize your batch deployment:

1. **Cortex Role Allocation:** Enter any valid system role (e.g., `Developer`, `Security Admin`). Pressing **Enter** defaults to `Developer`.
2. **Expiration Lifespan:** Define token viability in days (Cortex parameters accept 1 to 180 days). Pressing **Enter** defaults to a `7` day lease.
3. **Storage Engine Destination:**
   * `0`: Local CSV backup ledger only.
   * `1`: Push directly to **AWS Secrets Manager** (Requires active `aws sso` or local env keys).
   * `2`: Push directly to **Azure Key Vault** (Requires active `az login` context).
   * `3`: Push directly to **GCP Secret Manager** (Requires active Application Default Credentials).


---

## 🔐 Vault Secret Payload Model

When syncing tokens with corporate vaults, each user's credential structure is committed as an isolated JSON map:

```json
{
  "CORTEX_API_KEY_ID": "104",
  "CORTEX_API_KEY": "d7A8k2...f8B9",
  "ROLE": "Developer",
  "DEPARTMENT": "PSO",
  "SYNC_DATE": "2026-06-22T15:00:00Z"
}
```

> ⚠️ **Security Policy Ledger Warning:** If you choose to generate a local copy (`generated_developer_keys.csv`), treat that file as highly privileged data. Ensure your pipeline acts on it immediately and deletes it safely. **Do not commit raw secret sheets back to source code version tracking.**