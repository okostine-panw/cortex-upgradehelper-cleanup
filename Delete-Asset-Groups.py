import aiohttp
import asyncio
import configparser
import sys
from colorama import Fore, Style

# Configuration
API_CONFIG_PATH = 'API_config-x5.ini'
# API_CONFIG_PATH = 'API_config-c3.ini'
# API_CONFIG_PATH = 'API_config-c1.ini'
SSL_VERIFY = False
semaphore = asyncio.Semaphore(32)


def read_api_config():
    config = configparser.ConfigParser()
    config.read(API_CONFIG_PATH)
    baseurl   = config.get('URL', 'BaseURL')
    api_key_id = config.get('AUTHENTICATION', 'ACCESS_KEY_ID')
    api_key   = config.get('AUTHENTICATION', 'SECRET_KEY')
    return baseurl, api_key_id, api_key


async def make_post_request(url, payload, api_key_id, api_key, session, semaphore, max_retries=3, backoff_factor=5):
    headers = {
        'x-xdr-auth-id': api_key_id,
        'Authorization': api_key,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    async with semaphore:
        for attempt in range(1, max_retries + 1):
            try:
                async with session.post(url, headers=headers, json=payload, ssl=SSL_VERIFY) as response:
                    response_text = await response.text()
                    if response.status in [200, 201]:
                        return {'success': True, 'data': await response.json()}
                    else:
                        try:
                            error_data = await response.json()
                        except Exception:
                            error_data = {'error': response_text}
                        if attempt == max_retries:
                            return {'success': False, 'status': response.status, 'error': error_data}
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
    Fetch all Dynamic asset groups using pagination.

    API response structure:
        reply.data[]              — list of group dicts
        reply.metadata.filter_count — count matching the filter
        reply.metadata.total_count  — total groups in system

    Group fields:
        XDM.ASSET_GROUP.ID
        XDM.ASSET_GROUP.NAME
        XDM.ASSET_GROUP.TYPE
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
                    "FIELD": "XDM.ASSET_GROUP.LAST_UPDATE_TIME",
                    "ORDER": "DESC"
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
        page     = reply.get('data', [])   # actual group list

        # Capture filter_count on first page
        if filter_count is None:
            filter_count = metadata.get('filter_count', 0)
            print(f"  -> Total matching groups: {filter_count} "
                  f"(system total: {metadata.get('total_count')})")

        if not page:
            break

        all_groups.extend(page)
        print(f"  -> Fetched {len(all_groups)}/{filter_count} groups")

        search_from += page_size
        if search_from >= filter_count:
            break

    return all_groups


async def delete_assetgroup(baseurl, api_key_id, api_key, group_id, session, semaphore):
    """
    Delete an asset group by ID.
    Endpoint: POST /public_api/v1/asset-groups/delete/
    Payload:  { "request_data": { "id": <int> } }
    Returns (success: bool, error_msg: str|None)
    """
    url     = f"{baseurl}/public_api/v1/asset-groups/delete/{group_id}"
    payload = {}

    response = await make_post_request(
        url, payload, api_key_id, api_key, session, semaphore
    )

    if not response:
        return False, "No response from API"

    if response.get('success'):
        return True, None

    # Surface the full raw error for debugging
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

        # ---------------------------------------------------------------
        # Filter: groups matching any of these rules will be deleted.
        # ---------------------------------------------------------------
        STARTSWITH_PATTERNS = [
            'hostVulnerability_',
            'serverlessVulnerability_',
            'vmVulnerability_',
            'vmCompliance_',
            'hostCompliance_',
            'ciImagesVulnerability_',
            'containerCompliance_',
            'containerVulnerability_',
        ]
        CONTAINS_PATTERNS = [
            '-prisma_cloud_copy-',
        ]

        def matches_delete_filter(name: str) -> bool:
            for prefix in STARTSWITH_PATTERNS:
                if name.startswith(prefix):
                    return True
            for substring in CONTAINS_PATTERNS:
                if substring in name:
                    return True
            return False

        matching = [
            g for g in all_groups
            if matches_delete_filter(g.get('XDM.ASSET_GROUP.NAME', ''))
        ]

        if not matching:
            print(Fore.YELLOW
                  + "No asset groups found matching any delete filter."
                  + Style.RESET_ALL)
            return

        # Display matches
        print(f"\n{Fore.CYAN}Found {len(matching)} groups matching delete filters:{Style.RESET_ALL}")
        for idx, g in enumerate(matching, start=1):
            name       = g.get('XDM.ASSET_GROUP.NAME', 'Unknown')
            group_id   = g.get('XDM.ASSET_GROUP.ID', 'Unknown')
            created_by = g.get('XDM.ASSET_GROUP.CREATED_BY_PRETTY', 'Unknown')
            print(f"  {idx}. {Fore.GREEN}{name}{Style.RESET_ALL}")
            print(f"       ID: {group_id}  |  Created by: {created_by}")

        # Confirm
        print(f"\n{Fore.YELLOW}WARNING: This will permanently delete "
              f"{len(matching)} asset groups!{Style.RESET_ALL}")
        confirmation = input("Type 'DELETE' to confirm: ").strip()

        if confirmation != 'DELETE':
            print(Fore.YELLOW + "Deletion cancelled." + Style.RESET_ALL)
            return

        # Delete
        print(f"\n{Fore.CYAN}Starting deletion...{Style.RESET_ALL}")
        deleted_count  = 0
        failed_count   = 0
        in_use_count   = 0
        failed_details = []

        for g in matching:
            name     = g.get('XDM.ASSET_GROUP.NAME', 'Unknown')
            group_id = g.get('XDM.ASSET_GROUP.ID')

            print(f"  Deleting: {name} (id={group_id})...", end=' ', flush=True)

            success, error_msg = await delete_assetgroup(
                baseurl, api_key_id, api_key, group_id, session, semaphore
            )

            if success:
                print(Fore.GREEN + "✓ Deleted" + Style.RESET_ALL)
                deleted_count += 1
            else:
                print(Fore.RED + f"✗ Failed: {error_msg}" + Style.RESET_ALL)
                failed_details.append({'name': name, 'id': group_id, 'error': error_msg})
                failed_count += 1

        # Summary
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"  Deleted:  {Fore.GREEN}{deleted_count}{Style.RESET_ALL}")
        print(f"  Failed:   {Fore.RED}{failed_count}{Style.RESET_ALL}")
        print(f"  Total:    {len(matching)}")



if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)