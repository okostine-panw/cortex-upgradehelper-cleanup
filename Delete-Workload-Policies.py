import aiohttp
import asyncio
import configparser
import sys
from colorama import Fore, Style

# ── Configuration ────────────────────────────────────────────────────────────
# API_CONFIG_PATH = 'API_config-x5.ini'
API_CONFIG_PATH = 'API_config-c3.ini'
# API_CONFIG_PATH = 'API_config-c1.ini'
SSL_VERIFY = False

NAME_SUFFIX = "prisma_"

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
                    if resp.status in (200, 201):
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


async def fetch_cwp_policies(baseurl, api_key_id, api_key, session, sem) -> list | None:
    """
    Fetch all CWP policies via GET /public_api/v2/cwp/policies.
    Returns None on API error (vs empty list for no results).
    """
    url = f"{baseurl}/public_api/v2/cwp/policies"
    print("Fetching all CWP (workload) policies …")

    resp = await _get(url, api_key_id, api_key, session, sem)
    if not resp or not resp.get('success'):
        status = resp.get('status', '?') if resp else '?'
        err = resp.get('error') if resp else 'No response'
        print(Fore.RED + f"  API error (HTTP {status}): {err}" + Style.RESET_ALL)
        if status in (401, 403, '?'):
            print(Fore.RED + f"  Check API_CONFIG_PATH ({API_CONFIG_PATH}), ACCESS_KEY_ID, and SECRET_KEY" + Style.RESET_ALL)
        return None

    data = resp['data']
    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        policies = data.get('data', data.get('policies', data.get('reply', [])))
        if isinstance(policies, dict):
            policies = policies.get('policies', [])
    else:
        policies = []

    print(f"   -> Retrieved {len(policies)} total CWP policies")
    return policies


async def delete_cwp_policy(baseurl, api_key_id, api_key, policy_id: str,
                            session, sem) -> tuple[bool, str | None]:
    """Delete a single CWP policy via DELETE /public_api/v1/cwp/policies/{id}."""
    url = f"{baseurl}/public_api/v1/cwp/policies/{policy_id}"
    result = await _delete(url, api_key_id, api_key, session, sem)

    if result.get('success'):
        return True, None

    err_data = result.get('error', {})
    if isinstance(err_data, dict):
        err_msg = (err_data.get('err_msg')
                   or err_data.get('reply', {}).get('err_extra')
                   or err_data.get('reply', {}).get('err_msg')
                   or 'Unknown error')
    else:
        err_msg = str(err_data)

    return False, err_msg


async def main():
    baseurl, api_key_id, api_key = read_api_config()

    async with aiohttp.ClientSession() as session:
        all_policies = await fetch_cwp_policies(baseurl, api_key_id, api_key, session, semaphore)

        if all_policies is None:
            return

        if not all_policies:
            print(Fore.YELLOW + "No CWP policies returned from API." + Style.RESET_ALL)
            return

        # Client-side filter by name suffix
        suffix_lower = NAME_SUFFIX.lower()
        matching = [
            p for p in all_policies
            if suffix_lower in p.get('name', '').lower()
        ]

        if not matching:
            print(Fore.YELLOW + f"\nNo CWP policies found containing '{NAME_SUFFIX}' "
                  f"(out of {len(all_policies)} total)." + Style.RESET_ALL)
            print(f"\n{Fore.CYAN}Sample policy names (first 20):{Style.RESET_ALL}")
            for p in all_policies[:20]:
                print(f"  - {p.get('name', 'Unknown')}")
            if len(all_policies) > 20:
                print(f"  … and {len(all_policies) - 20} more")
            return

        # ── Display matches ───────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}Found {len(matching)} CWP policy/policies "
              f"containing '{NAME_SUFFIX}':{Style.RESET_ALL}")

        for idx, policy in enumerate(matching, start=1):
            name = policy.get('name', 'Unknown')
            policy_id = policy.get('id', policy.get('_id', 'Unknown'))
            enabled = policy.get('enabled', False)
            policy_type = policy.get('type', policy.get('policyType', ''))
            owner = policy.get('owner', policy.get('created_by', ''))

            print(f"{idx}. {Fore.GREEN}{name}{Style.RESET_ALL}")
            print(f"   ID      : {policy_id}")
            print(f"   Type    : {policy_type}  |  Enabled: {enabled}")
            if owner:
                print(f"   Owner   : {owner}")

        # ── Confirmation ──────────────────────────────────────────────────────
        print(f"\n{Fore.YELLOW}WARNING: This will permanently delete "
              f"{len(matching)} CWP workload policy/policies!{Style.RESET_ALL}")
        confirmation = input("Type 'DELETE' to confirm: ").strip()

        if confirmation != 'DELETE':
            print(Fore.YELLOW + "Deletion cancelled." + Style.RESET_ALL)
            return

        # ── Delete loop ───────────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}Starting deletion …{Style.RESET_ALL}")
        deleted_count = 0
        failed_count = 0
        failed_policies: list[dict] = []

        for policy in matching:
            name = policy.get('name', 'Unknown')
            policy_id = policy.get('id', policy.get('_id', 'Unknown'))

            print(f"Deleting: {name} …", end=' ')
            success, error_msg = await delete_cwp_policy(
                baseurl, api_key_id, api_key, policy_id, session, semaphore
            )

            if success:
                print(Fore.GREEN + "✓ Deleted" + Style.RESET_ALL)
                deleted_count += 1
            else:
                print(Fore.RED + f"✗ Failed: {error_msg}" + Style.RESET_ALL)
                failed_policies.append({'name': name, 'id': policy_id, 'error': error_msg})
                failed_count += 1

        # ── Summary ───────────────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Deletion Summary:{Style.RESET_ALL}")
        print(f"  Successfully deleted : {Fore.GREEN}{deleted_count}{Style.RESET_ALL}")
        print(f"  Failed               : {Fore.RED}{failed_count}{Style.RESET_ALL}")
        print(f"  Total matched        : {len(matching)}")

        if failed_policies:
            print(f"\n{Fore.RED}Failed deletions:{Style.RESET_ALL}")
            for f in failed_policies:
                print(f"  - {f['name']}")
                print(f"    Error: {f['error']}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
