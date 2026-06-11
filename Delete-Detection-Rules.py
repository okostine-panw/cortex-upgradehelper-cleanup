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

# Suffix to match against rule names.  Change this before running.
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
                    if resp.status == 204:
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


async def fetch_rules_with_suffix(baseurl, api_key_id, api_key, session, sem, suffix: str) -> list:
    """
    Page through /public_api/v1/rule/search filtering by name CONTAINS suffix.
    Returns a list of rule dicts whose names actually end with the suffix.
    """
    search_url = f"{baseurl}/public_api/v1/rule/search"
    page_size = 100
    search_from = 0
    search_to = page_size
    collected: list[dict] = []

    print(f"Searching for rules whose name contains '{suffix}' …")

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
            err = resp.get('error') if resp else 'No response'
            print(Fore.RED + f"Search failed: {err}" + Style.RESET_ALL)
            break

        body = resp['data']
        page_rules: list[dict] = body.get('data', [])
        meta = body.get('metadata', {})
        total_count: int = meta.get('total_count', 0)

        if not page_rules:
            break

        # Keep only rules whose name truly ends with the suffix
        for rule in page_rules:
            if rule.get('name', '').endswith(suffix):
                collected.append(rule)

        print(f"   -> Scanned {search_from + len(page_rules)} of {total_count} rules, "
              f"{len(collected)} match suffix so far …")

        if total_count > 0 and len(collected) >= total_count:
            break

        if len(page_rules) < page_size:
            break

        search_from += page_size
        search_to += page_size

    return collected


async def delete_rule(baseurl, api_key_id, api_key, rule_id: str,
                      session, sem) -> tuple[bool, str | None]:
    """Delete a single detection rule by ID. Returns (success, error_message)."""
    url = f"{baseurl}/public_api/v1/rule/{rule_id}"
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
        matching = await fetch_rules_with_suffix(
            baseurl, api_key_id, api_key, session, semaphore, NAME_SUFFIX
        )

        if not matching:
            print(Fore.YELLOW + f"\nNo rules found whose name ends with '{NAME_SUFFIX}'." + Style.RESET_ALL)
            return

        # ── Display matches ───────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}Found {len(matching)} rule(s) ending with '{NAME_SUFFIX}':{Style.RESET_ALL}")
        for idx, rule in enumerate(matching, start=1):
            name = rule.get('name', 'Unknown')
            rule_id = rule.get('id', 'Unknown')
            severity = rule.get('severity', '')
            enabled = rule.get('enabled', False)
            system_default = rule.get('system_default', True)

            print(f"{idx}. {Fore.GREEN}{name}{Style.RESET_ALL}")
            print(f"   ID       : {rule_id}")
            print(f"   Severity : {severity}  |  Enabled: {enabled}  |  System default: {system_default}")

        # ── Confirmation ──────────────────────────────────────────────────────
        print(f"\n{Fore.YELLOW}WARNING: This will permanently delete "
              f"{len(matching)} detection rule(s)!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Only custom rules can be deleted; system-default rules will be skipped.{Style.RESET_ALL}")
        confirmation = input("Type 'DELETE' to confirm: ").strip()

        if confirmation != 'DELETE':
            print(Fore.YELLOW + "Deletion cancelled." + Style.RESET_ALL)
            return

        # ── Delete loop ───────────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}Starting deletion …{Style.RESET_ALL}")
        deleted_count = 0
        failed_count = 0
        skipped_system = 0
        failed_rules: list[dict] = []

        for rule in matching:
            name = rule.get('name', 'Unknown')
            rule_id = rule.get('id', 'Unknown')
            system_default = rule.get('system_default', True)

            if system_default:
                print(f"Skipping (system default): {Fore.YELLOW}{name}{Style.RESET_ALL}")
                skipped_system += 1
                continue

            print(f"Deleting: {name} …", end=' ')
            success, error_msg = await delete_rule(
                baseurl, api_key_id, api_key, rule_id, session, semaphore
            )

            if success:
                print(Fore.GREEN + "✓ Deleted" + Style.RESET_ALL)
                deleted_count += 1
            else:
                print(Fore.RED + f"✗ Failed: {error_msg}" + Style.RESET_ALL)
                failed_rules.append({'name': name, 'id': rule_id, 'error': error_msg})
                failed_count += 1

        # ── Summary ───────────────────────────────────────────────────────────
        print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Deletion Summary:{Style.RESET_ALL}")
        print(f"  Successfully deleted : {Fore.GREEN}{deleted_count}{Style.RESET_ALL}")
        print(f"  Skipped (system)     : {Fore.YELLOW}{skipped_system}{Style.RESET_ALL}")
        print(f"  Failed               : {Fore.RED}{failed_count}{Style.RESET_ALL}")
        print(f"  Total matched        : {len(matching)}")

        if failed_rules:
            print(f"\n{Fore.RED}Failed deletions:{Style.RESET_ALL}")
            for f in failed_rules:
                print(f"  - {f['name']}")
                print(f"    Error: {f['error']}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
