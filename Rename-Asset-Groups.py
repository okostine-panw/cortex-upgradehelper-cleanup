import aiohttp
import asyncio
import configparser
import sys
from colorama import Fore, Style

# Configuration
API_CONFIG_PATH = 'API_config-x5.ini'
# API_CONFIG_PATH = 'API_config-c3.ini'
# API_CONFIG_PATH = 'API_config-c1.ini'
SSL_VERIFY      = False
semaphore       = asyncio.Semaphore(32)

STRIP_PREFIX    = "Asset group for "


def read_api_config():
    config = configparser.ConfigParser()
    config.read(API_CONFIG_PATH)
    baseurl    = config.get('URL', 'BaseURL')
    api_key_id = config.get('AUTHENTICATION', 'ACCESS_KEY_ID')
    api_key    = config.get('AUTHENTICATION', 'SECRET_KEY')
    return baseurl, api_key_id, api_key


async def make_post_request(url, payload, api_key_id, api_key, session, semaphore,
                            max_retries=3, backoff_factor=5):
    headers = {
        'x-xdr-auth-id':  api_key_id,
        'Authorization':  api_key,
        'Content-Type':   'application/json',
        'Accept':         'application/json'
    }
    async with semaphore:
        for attempt in range(1, max_retries + 1):
            try:
                async with session.post(
                    url, headers=headers, json=payload, ssl=SSL_VERIFY
                ) as response:
                    response_text = await response.text()
                    if response.status in [200, 201]:
                        return {'success': True, 'data': await response.json()}
                    try:
                        error_data = await response.json()
                    except Exception:
                        error_data = {'error': response_text}
                    if attempt == max_retries:
                        return {'success': False, 'status': response.status,
                                'error': error_data}
                    await asyncio.sleep(backoff_factor ** (attempt - 1))
            except aiohttp.ClientError as e:
                if attempt == max_retries:
                    return {'success': False, 'error': str(e)}
                await asyncio.sleep(backoff_factor ** (attempt - 1))
            except asyncio.TimeoutError:
                if attempt == max_retries:
                    return {'success': False, 'error': 'Request timed out'}
                await asyncio.sleep(backoff_factor ** (attempt - 1))
            except Exception as e:
                if attempt == max_retries:
                    return {'success': False, 'error': str(e)}
                await asyncio.sleep(backoff_factor ** (attempt - 1))


async def fetch_all_assetgroups(baseurl, api_key_id, api_key, session, semaphore):
    """
    Fetch all Dynamic asset groups, paginating via filter_count.
    Returns list of group dicts with keys XDM.ASSET_GROUP.ID, XDM.ASSET_GROUP.NAME, etc.
    """
    url          = f"{baseurl}/public_api/v1/asset-groups"
    all_groups   = []
    page_size    = 1000
    search_from  = 0
    filter_count = None

    print("Fetching all Dynamic asset groups...")

    while True:
        payload = {
            "request_data": {
                "filters": {
                    "AND": [{
                        "SEARCH_FIELD": "XDM.ASSET_GROUP.TYPE",
                        "SEARCH_TYPE":  "EQ",
                        "SEARCH_VALUE": "Dynamic"
                    }]
                },
                "sort": [{
                    "FIELD": "XDM.ASSET_GROUP.NAME",
                    "ORDER": "ASC"
                }],
                "search_from": search_from,
                "search_to":   search_from + page_size
            }
        }

        response = await make_post_request(
            url, payload, api_key_id, api_key, session, semaphore
        )

        if not response or not response.get('success'):
            print(f"  -> Fetch failed at offset {search_from}: {response}")
            break

        reply    = response.get('data', {}).get('reply', {})
        metadata = reply.get('metadata', {})
        page     = reply.get('data', [])

        if filter_count is None:
            filter_count = metadata.get('filter_count', 0)
            print(f"  -> {filter_count} Dynamic groups found "
                  f"(system total: {metadata.get('total_count')})")

        if not page:
            break

        all_groups.extend(page)
        print(f"  -> Fetched {len(all_groups)}/{filter_count}")

        search_from += page_size
        if search_from >= filter_count:
            break

    return all_groups


async def rename_assetgroup(baseurl, api_key_id, api_key, group_id, new_name,
                            group_type, description, predicate,
                            session, semaphore):
    """
    Rename an asset group via POST /public_api/v1/asset-groups/update/{group_id}.
    Must send the full existing config (type, description, predicate) alongside
    the new name — partial payloads overwrite omitted fields with nulls.
    Returns (success: bool, error_msg: str|None)
    """
    url          = f"{baseurl}/public_api/v1/asset-groups/update/{group_id}"
    asset_group  = {
        "group_name": new_name,
        "group_type": group_type,
    }
    if description is not None:
        asset_group["group_description"] = description
    if predicate is not None:
        asset_group["membership_predicate"] = predicate

    payload = {"request_data": {"asset_group": asset_group}}

    response = await make_post_request(
        url, payload, api_key_id, api_key, session, semaphore
    )

    if not response:
        return False, "No response from API"

    if response.get('success'):
        return True, None

    error_data = response.get('error', {})
    status     = response.get('status', 'unknown')
    if isinstance(error_data, dict):
        reply     = error_data.get('reply', {})
        error_msg = (
            reply.get('err_extra')
            or reply.get('err_msg')
            or f"HTTP {status} | raw: {error_data}"
        )
    else:
        error_msg = f"HTTP {status} | raw: {error_data}"

    return False, error_msg


async def main():
    baseurl, api_key_id, api_key = read_api_config()

    async with aiohttp.ClientSession() as session:
        all_groups = await fetch_all_assetgroups(
            baseurl, api_key_id, api_key, session, semaphore
        )

        if not all_groups:
            print(Fore.YELLOW + "No Dynamic asset groups found." + Style.RESET_ALL)
            return

        # Find groups whose name starts with the prefix
        to_rename = []
        for g in all_groups:
            name = g.get('XDM.ASSET_GROUP.NAME', '')
            if name.startswith(STRIP_PREFIX):
                to_rename.append({
                    'id':          g.get('XDM.ASSET_GROUP.ID'),
                    'old_name':    name,
                    'new_name':    name[len(STRIP_PREFIX):],
                    # Preserve full config for the update payload
                    'type':        g.get('XDM.ASSET_GROUP.TYPE', 'Dynamic'),
                    'description': g.get('XDM.ASSET_GROUP.DESCRIPTION'),
                    'predicate':   g.get('XDM.ASSET_GROUP.MEMBERSHIP_PREDICATE'),
                })

        if not to_rename:
            print(Fore.YELLOW
                  + f"No groups found with prefix '{STRIP_PREFIX}'"
                  + Style.RESET_ALL)
            return

        # Preview
        print(f"\n{Fore.CYAN}Found {len(to_rename)} groups to rename:{Style.RESET_ALL}")
        for idx, r in enumerate(to_rename, 1):
            print(f"  {idx}. {Fore.YELLOW}{r['old_name']}{Style.RESET_ALL}")
            print(f"      -> {Fore.GREEN}{r['new_name']}{Style.RESET_ALL}  (id={r['id']})")

        # Confirm
        print(f"\n{Fore.YELLOW}This will rename {len(to_rename)} asset groups.{Style.RESET_ALL}")
        confirmation = input("Type 'RENAME' to confirm: ").strip()

        if confirmation != 'RENAME':
            print(Fore.YELLOW + "Cancelled." + Style.RESET_ALL)
            return

        # Execute renames
        print(f"\n{Fore.CYAN}Renaming...{Style.RESET_ALL}")
        renamed_count = 0
        failed_count  = 0
        failed_list   = []

        for r in to_rename:
            print(f"  {r['old_name'][:60]}", end=' ... ', flush=True)

            success, error_msg = await rename_assetgroup(
                baseurl, api_key_id, api_key,
                r['id'], r['new_name'],
                r['type'], r['description'], r['predicate'],
                session, semaphore
            )

            if success:
                print(Fore.GREEN + "✓" + Style.RESET_ALL)
                renamed_count += 1
            else:
                print(Fore.RED + f"✗ {error_msg}" + Style.RESET_ALL)
                failed_count += 1
                failed_list.append({**r, 'error': error_msg})

        # Summary
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"  Renamed: {Fore.GREEN}{renamed_count}{Style.RESET_ALL}")
        print(f"  Failed:  {Fore.RED}{failed_count}{Style.RESET_ALL}")
        print(f"  Total:   {len(to_rename)}")

        if failed_list:
            print(f"\n{Fore.RED}Failed renames:{Style.RESET_ALL}")
            for f in failed_list:
                print(f"  - {f['old_name']} -> {f['new_name']}: {f['error']}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
