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

NAME_SUFFIX = "-prisma_cloud_copy"

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


async def _post(url, payload, api_key_id, api_key, session, sem, max_retries=3, backoff=5):
    """POST with retry; returns {'success': bool, 'data': …} or {'success': False, 'error': …}"""
    async with sem:
        for attempt in range(1, max_retries + 1):
            try:
                async with session.post(url, headers=_headers(api_key_id, api_key),
                                        json=payload, ssl=SSL_VERIFY) as resp:
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


async def fetch_policies_with_suffix(baseurl, api_key_id, api_key, session, sem, suffix: str) -> list | None:
    """
    Page through /public_api/v1/policy/search filtering by name CONTAINS suffix.
    Returns None on API error (vs empty list for no matches).
    """
    search_url = f"{baseurl}/public_api/v1/policy/search"
    page_size = 100
    search_from = 0
    search_to = page_size
    collected: list[dict] = []

    print(f"Searching for policies whose name contains '{suffix}' …")

    while True:
        payload = {
            "filter": {
                "AND": [
                    {
                        "SEARCH_FIELD": "name",
                        "SEARCH_TYPE": "CONTAINS",
                        "SEARCH_VALUE": suffix,
                    }
                ]
            },
            "search_from": search_from,
            "search_to": search_to,
            "sort": [{"FIELD": "name", "ORDER": "ASC"}],
        }

        resp = await _post(search_url, payload, api_key_id, api_key, session, sem)
        if not resp or not resp.get('success'):
            status = resp.get('status', '?') if resp else '?'
            err = resp.get('error') if resp else 'No response'
            print(Fore.RED + f"  API error (HTTP {status}): {err}" + Style.RESET_ALL)
            if status in (401, 403, '?'):
                print(Fore.RED + f"  Check API_CONFIG_PATH ({API_CONFIG_PATH}), ACCESS_KEY_ID, and SECRET_KEY" + Style.RESET_ALL)
            return None

        body = resp['data']
        page_items: list[dict] = body.get('data', [])
        meta = body.get('metadata', {})
        total_count: int = meta.get('total_count', 0)

        if not page_items:
            break

        collected.extend(page_items)

        print(f"   -> Retrieved {len(collected)} of {total_count} policies …")

        if total_count > 0 and len(collected) >= total_count:
            break

        if len(page_items) < page_size:
            break

        search_from += page_size
        search_to += page_size

    return collected


async def delete_policy(baseurl, api_key_id, api_key, policy_id: str,
                        session, sem) -> tuple[bool, str | None]:
    """Delete a single cloud security policy by ID via DELETE /public_api/v1/policy/{policy_id}."""
    url = f"{baseurl}/public_api/v1/policy/{policy_id}"
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
        matching = await fetch_policies_with_suffix(
            baseurl, api_key_id, api_key, session, semaphore, NAME_SUFFIX
        )

        if matching is None:
            return

        if not matching:
            print(Fore.YELLOW + f"\nNo policies found whose name contains '{NAME_SUFFIX}'." + Style.RESET_ALL)
            return

        # ── Display matches ───────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}Found {len(matching)} policy/policies containing '{NAME_SUFFIX}':{Style.RESET_ALL}")
        for idx, policy in enumerate(matching, start=1):
            name = policy.get('name', 'Unknown')
            policy_id = policy.get('id', 'Unknown')
            severity = policy.get('severity', '')
            enabled = policy.get('enabled', False)
            mode = policy.get('mode', 'Unknown')
            policy_type = policy.get('type', '')
            providers = ', '.join(p for p in policy.get('providers', []) if p)

            print(f"{idx}. {Fore.GREEN}{name}{Style.RESET_ALL}")
            print(f"   ID       : {policy_id}")
            print(f"   Type     : {policy_type}  |  Severity: {severity}")
            print(f"   Enabled  : {enabled}  |  Mode: {mode}")
            if providers:
                print(f"   Providers: {providers}")

        # ── Confirmation ──────────────────────────────────────────────────────
        print(f"\n{Fore.YELLOW}WARNING: This will permanently delete "
              f"{len(matching)} cloud security policy/policies!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Non-custom policies will be skipped.{Style.RESET_ALL}")
        confirmation = input("Type 'DELETE' to confirm: ").strip()

        if confirmation != 'DELETE':
            print(Fore.YELLOW + "Deletion cancelled." + Style.RESET_ALL)
            return

        # ── Delete loop ───────────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}Starting deletion …{Style.RESET_ALL}")
        deleted_count = 0
        failed_count = 0
        skipped_system = 0
        failed_policies: list[dict] = []

        for policy in matching:
            name = policy.get('name', 'Unknown')
            policy_id = policy.get('id', 'Unknown')
            mode = policy.get('mode', 'Unknown')

            if mode != 'CUSTOM':
                print(f"Skipping (mode={mode}): {Fore.YELLOW}{name}{Style.RESET_ALL}")
                skipped_system += 1
                continue

            print(f"Deleting: {name} …", end=' ')
            success, error_msg = await delete_policy(
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
        print(f"  Skipped (non-custom) : {Fore.YELLOW}{skipped_system}{Style.RESET_ALL}")
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
