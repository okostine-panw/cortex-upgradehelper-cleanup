import json
import aiohttp
import asyncio
import configparser
import sys
from collections import defaultdict
from colorama import Fore, Style

# ── Configuration ────────────────────────────────────────────────────────────
API_CONFIG_PATH = 'API_config-x5.ini'
SSL_VERIFY = False

semaphore = asyncio.Semaphore(8)


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


async def fetch_all_correlation_rules(baseurl, api_key_id, api_key, session, sem) -> list[dict]:
    url = f"{baseurl}/public_api/v1/correlations/get"
    page_size = 100
    search_from = 0
    search_to = page_size
    all_rules: list[dict] = []

    print("Fetching all correlation rules …")

    while True:
        payload = {
            "request_data": {
                "extended_view": False,
                "filters": [],
                "search_from": search_from,
                "search_to": search_to,
            }
        }

        resp = await _post(url, payload, api_key_id, api_key, session, sem)
        if not resp or not resp.get('success'):
            err = resp.get('error') if resp else 'No response'
            print(Fore.RED + f"API request failed: {err}" + Style.RESET_ALL)
            break

        reply = resp['data'].get('reply', resp['data'])
        page_rules = (reply.get('objects')
                      or reply.get('data')
                      or reply.get('result')
                      or [])

        if not page_rules:
            break

        all_rules.extend(page_rules)
        print(f"   -> Retrieved {len(all_rules)} rules …")

        if len(page_rules) < page_size:
            break

        search_from += page_size
        search_to += page_size

    return all_rules


def find_duplicates(rules: list[dict]) -> tuple[dict[str, int], list[int]]:
    """
    Group rules by name, keep the lowest rule_id per group.
    Returns (keepers {name: rule_id}, ids_to_delete [unique]).
    """
    by_name: dict[str, list[int]] = defaultdict(list)
    for r in rules:
        name = r.get('name', '')
        rule_id = r.get('rule_id')
        if name and rule_id is not None:
            by_name[name].append(rule_id)

    keepers: dict[str, int] = {}
    to_delete: set[int] = set()
    for name, ids in sorted(by_name.items()):
        unique_ids = sorted(set(ids))
        keepers[name] = unique_ids[0]
        if len(unique_ids) > 1:
            to_delete.update(unique_ids[1:])

    return keepers, sorted(to_delete)


async def delete_correlation_rule(baseurl, api_key_id, api_key, rule_id: int,
                                  session, sem) -> tuple[bool, str | None]:
    url = f"{baseurl}/public_api/v1/correlations/delete"
    payload = {
        "request_data": {
            "filters": [
                {
                    "field": "rule_id",
                    "operator": "EQ",
                    "value": rule_id,
                }
            ]
        }
    }

    resp = await _post(url, payload, api_key_id, api_key, session, sem)
    if resp and resp.get('success'):
        return True, None

    err = resp.get('error', 'Unknown error') if resp else 'No response'
    return False, str(err)


async def main():
    print(Fore.CYAN + "═" * 80 + Style.RESET_ALL)
    print(Fore.CYAN + " Correlation Rules — Duplicate Cleanup" + Style.RESET_ALL)
    print(Fore.CYAN + "═" * 80 + Style.RESET_ALL)

    baseurl, api_key_id, api_key = read_api_config()

    async with aiohttp.ClientSession() as session:
        rules = await fetch_all_correlation_rules(
            baseurl, api_key_id, api_key, session, semaphore
        )

    if not rules:
        print(Fore.YELLOW + "No correlation rules found." + Style.RESET_ALL)
        return

    # Identify duplicates
    by_name: dict[str, list[dict]] = defaultdict(list)
    for r in rules:
        by_name[r.get('name', '')].append(r)

    dup_names = {n: rs for n, rs in by_name.items()
                 if len(set(r['rule_id'] for r in rs)) > 1}
    keepers, ids_to_delete = find_duplicates(rules)

    if not ids_to_delete:
        print(Fore.GREEN + f"\nNo duplicates found among {len(rules)} rules." + Style.RESET_ALL)
        return

    # Summary
    print(f"\n{Fore.CYAN}Total rules on tenant  : {len(rules)}{Style.RESET_ALL}")
    print(f"  Unique names          : {len(by_name)}")
    print(f"  Names with duplicates : {Fore.YELLOW}{len(dup_names)}{Style.RESET_ALL}")
    print(f"  Unique IDs to delete  : {Fore.RED}{len(ids_to_delete)}{Style.RESET_ALL}")

    # Show details
    print(f"\n{Fore.CYAN}Duplicates (keeping lowest ID):{Style.RESET_ALL}")
    for name in sorted(dup_names.keys()):
        unique_ids = sorted(set(r['rule_id'] for r in dup_names[name]))
        keep = unique_ids[0]
        remove = unique_ids[1:]
        print(f"  {Fore.GREEN}{name}{Style.RESET_ALL}")
        print(f"    Keep   : {Fore.GREEN}{keep}{Style.RESET_ALL}")
        print(f"    Delete : {remove}")

    # Confirm
    print(f"\n{Fore.YELLOW}WARNING: This will permanently delete {len(ids_to_delete)} duplicate correlation rules!{Style.RESET_ALL}")
    confirmation = input("Type 'DELETE' to confirm: ").strip()

    if confirmation != 'DELETE':
        print(Fore.YELLOW + "Deletion cancelled." + Style.RESET_ALL)
        return

    # Delete
    print(f"\n{Fore.CYAN}Deleting duplicates …{Style.RESET_ALL}")
    deleted = 0
    failed = 0

    # Build a lookup from rule_id → name for display
    id_to_name = {r['rule_id']: r.get('name', '?') for r in rules}

    async with aiohttp.ClientSession() as session:
        for rule_id in ids_to_delete:
            name = id_to_name.get(rule_id, '?')
            print(f"  Deleting rule_id={rule_id} ({name}) …", end=' ')

            success, error = await delete_correlation_rule(
                baseurl, api_key_id, api_key, rule_id, session, semaphore
            )

            if success:
                print(Fore.GREEN + "✓" + Style.RESET_ALL)
                deleted += 1
            else:
                print(Fore.RED + f"✗ {error}" + Style.RESET_ALL)
                failed += 1

    # Summary
    print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Cleanup Summary:{Style.RESET_ALL}")
    print(f"  Deleted   : {Fore.GREEN}{deleted}{Style.RESET_ALL}")
    print(f"  Failed    : {Fore.RED}{failed}{Style.RESET_ALL}")
    print(f"  Remaining : {len(rules) - deleted}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
