"""
Copyright 2025-Present Palo Alto Networks, Inc.
"""

import aiohttp
import asyncio
import configparser
import sys
from colorama import Fore, Style

# ── Configuration ────────────────────────────────────────────────────────────
# API_CONFIG_PATH = 'API_config-x5.ini'
# API_CONFIG_PATH = 'API_config-c3.ini'
API_CONFIG_PATH = 'API_config-c1.ini'
SSL_VERIFY = False

# Prefix to match against IAM role pretty names.
NAME_PREFIX = "prisma_copy_"

semaphore = asyncio.Semaphore(32)
# ─────────────────────────────────────────────────────────────────────────────


def read_api_config():
    config = configparser.ConfigParser()
    config.read(API_CONFIG_PATH)
    baseurl = config.get('URL', 'BaseURL')
    api_key_id = config.get('AUTHENTICATION', 'ACCESS_KEY_ID')
    api_key = config.get('AUTHENTICATION', 'SECRET_KEY')
    return baseurl, api_key_id, api_key


def _headers(api_key_id: str, api_key: str) -> dict:
    return {
        'x-xdr-auth-id': api_key_id,
        'Authorization': api_key,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }


async def _get(url, api_key_id, api_key, session, sem, max_retries=3, backoff=5):
    """GET with retry; returns {'success': bool, 'data': …} or {'success': False, 'error': …}"""
    async with sem:
        for attempt in range(1, max_retries + 1):
            try:
                async with session.get(url, headers=_headers(api_key_id, api_key),
                                       ssl=SSL_VERIFY) as resp:
                    if resp.status == 200:
                        return {'success': True, 'data': await resp.json()}
                    try:
                        err = await resp.json()
                    except Exception:
                        err = {'error': await resp.text()}
                    if attempt == max_retries:
                        return {'success': False, 'status': resp.status, 'error': err}
                    await asyncio.sleep(backoff ** (attempt - 1))
            except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as exc:
                if attempt == max_retries:
                    return {'success': False, 'error': str(exc)}
                await asyncio.sleep(backoff ** (attempt - 1))


async def _delete(url, api_key_id, api_key, session, sem, max_retries=3, backoff=5):
    """DELETE with retry; returns {'success': bool, 'error': …}"""
    async with sem:
        for attempt in range(1, max_retries + 1):
            try:
                async with session.delete(url, headers=_headers(api_key_id, api_key),
                                          ssl=SSL_VERIFY) as resp:
                    # Cortex typically responds with 200 or 204 on successful drops
                    if resp.status in (200, 204):
                        return {'success': True}
                    try:
                        err = await resp.json()
                    except Exception:
                        err = {'error': await resp.text()}
                    if attempt == max_retries:
                        return {'success': False, 'status': resp.status, 'error': err}
                    await asyncio.sleep(backoff ** (attempt - 1))
            except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as exc:
                if attempt == max_retries:
                    return {'success': False, 'error': str(exc)}
                await asyncio.sleep(backoff ** (attempt - 1))


async def fetch_roles_with_prefix(baseurl, api_key_id, api_key, session, sem, prefix: str) -> list:
    """
    Fetches all IAM roles from /platform/iam/v1/role.
    Returns a list of role dicts whose pretty_name starts with the prefix.
    """
    roles_url = f"{baseurl}/platform/iam/v1/role"
    collected: list[dict] = []

    print(f"Fetching IAM roles to find names starting with '{prefix}' …")

    resp = await _get(roles_url, api_key_id, api_key, session, sem)
    if not resp or not resp.get('success'):
        err = resp.get('error') if resp else 'No response'
        print(Fore.RED + f"Retrieve roles failed: {err}" + Style.RESET_ALL)
        return collected

    body = resp['data']
    
    # Handle response envelope variability (either a list or dict wrapper)
    roles_list = []
    if isinstance(body, list):
        roles_list = body
    elif isinstance(body, dict):
        roles_list = body.get("data", body.get("roles", []))

    for role in roles_list:
        if isinstance(role, dict) and role.get('pretty_name', '').startswith(prefix):
            collected.append(role)

    print(f"   -> Found {len(collected)} custom matching roles out of {len(roles_list)} total roles.")
    return collected


async def delete_role(baseurl, api_key_id, api_key, role_id: str,
                      session, sem) -> tuple[bool, str | None]:
    """Delete a single IAM role by ID. Returns (success, error_message)."""
    url = f"{baseurl}/platform/iam/v1/role/{role_id}"
    result = await _delete(url, api_key_id, api_key, session, sem)

    if result.get('success'):
        return True, None

    err_data = result.get('error', {})
    if isinstance(err_data, dict):
        err_msg = (err_data.get('err_msg')
                   or err_data.get('metadata', {}).get('err_extra', [{}])[0].get('message')
                   or 'Unknown error')
    else:
        err_msg = str(err_data)

    return False, err_msg


async def main():
    baseurl, api_key_id, api_key = read_api_config()

    async with aiohttp.ClientSession() as session:
        matching = await fetch_roles_with_prefix(
            baseurl, api_key_id, api_key, session, semaphore, NAME_PREFIX
        )

        if not matching:
            print(Fore.YELLOW + f"\nNo roles found starting with '{NAME_PREFIX}'." + Style.RESET_ALL)
            return

        # ── Display matches ───────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}Found {len(matching)} role(s) starting with '{NAME_PREFIX}':{Style.RESET_ALL}")
        for idx, role in enumerate(matching, start=1):
            pretty_name = role.get('pretty_name', 'Unknown')
            role_id = role.get('role_id', 'Unknown')
            role_type = role.get('role_type', 'Unknown')

            print(f"{idx}. {Fore.GREEN}{pretty_name}{Style.RESET_ALL}")
            print(f"   Role ID  : {role_id}")
            print(f"   Type     : {role_type}")

        # ── Confirmation ──────────────────────────────────────────────────────
        print(f"\n{Fore.YELLOW}WARNING: This will permanently delete "
              f"{len(matching)} custom IAM role(s) from your tenant!{Style.RESET_ALL}")
        confirmation = input("Type 'DELETE' to confirm: ").strip()

        if confirmation != 'DELETE':
            print(Fore.YELLOW + "Deletion cancelled." + Style.RESET_ALL)
            return

        # ── Delete loop ───────────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}Starting deletion …{Style.RESET_ALL}")
        deleted_count = 0
        failed_count = 0
        failed_roles: list[dict] = []

        for role in matching:
            pretty_name = role.get('pretty_name', 'Unknown')
            role_id = role.get('role_id', 'Unknown')

            print(f"Deleting: {pretty_name} …", end=' ')
            success, error_msg = await delete_role(
                baseurl, api_key_id, api_key, role_id, session, semaphore
            )

            if success:
                print(Fore.GREEN + "✓ Deleted" + Style.RESET_ALL)
                deleted_count += 1
            else:
                print(Fore.RED + f"✗ Failed: {error_msg}" + Style.RESET_ALL)
                failed_roles.append({'name': pretty_name, 'id': role_id, 'error': error_msg})
                failed_count += 1

        # ── Summary ───────────────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Deletion Summary:{Style.RESET_ALL}")
        print(f"  Successfully deleted : {Fore.GREEN}{deleted_count}{Style.RESET_ALL}")
        print(f"  Failed               : {Fore.RED}{failed_count}{Style.RESET_ALL}")
        print(f"  Total matched        : {len(matching)}")

        if failed_rules := failed_roles:
            print(f"\n{Fore.RED}Failed deletions:{Style.RESET_ALL}")
            for f in failed_rules:
                print(f"  - {f['name']} (ID: {f['id']})")
                print(f"    Error: {f['error']}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)