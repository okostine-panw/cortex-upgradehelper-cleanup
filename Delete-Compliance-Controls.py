import aiohttp
import asyncio
import configparser
import sys
from colorama import Fore, Style

# Configuration
# API_CONFIG_PATH = 'API_config-x5.ini'
# API_CONFIG_PATH = 'API_config-c3.ini'
API_CONFIG_PATH = 'API_config-c1.ini'
SSL_VERIFY = False
semaphore = asyncio.Semaphore(32)


def read_api_config():
    """Read API configuration from config file"""
    config = configparser.ConfigParser()
    config.read(API_CONFIG_PATH)
    baseurl = config.get('URL', 'BaseURL')
    api_key_id = config.get('AUTHENTICATION', 'ACCESS_KEY_ID')
    api_key = config.get('AUTHENTICATION', 'SECRET_KEY')
    return baseurl, api_key_id, api_key


async def make_post_request(url, payload, api_key_id, api_key, session, semaphore, max_retries=3, backoff_factor=5):
    """Send a POST request with retry logic and return the JSON response asynchronously."""
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
                        # Return error details instead of printing repeatedly
                        error_data = None
                        try:
                            error_data = await response.json()
                        except:
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


async def fetch_matching_controls(baseurl, api_key_id, api_key, session, semaphore, search_pattern):
    """Fetch controls whose names contain the search pattern using server-side filtering + pagination"""
    controls_url = f"{baseurl}/public_api/v1/compliance/get_controls"
    controls_data = []
    page_size = 100
    search_from = 0
    search_to = page_size

    print(f"Fetching controls matching '{search_pattern}'...")

    while True:
        controls_payload = {
            "request_data": {
                "filters": [
                    {
                        "field": "name",
                        "operator": "contains",
                        "value": search_pattern
                    }
                ],
                "search_from": search_from,
                "search_to": search_to
            }
        }

        response = await make_post_request(controls_url, controls_payload, api_key_id, api_key, session, semaphore)
        if not response or not response.get('success'):
            status = response.get('status', '?') if response else '?'
            error_info = response.get('error', 'Unknown') if response else 'No response'
            print(Fore.RED + f"  API error (HTTP {status}): {error_info}" + Style.RESET_ALL)
            if status in (401, 403, '?'):
                print(Fore.RED + f"  Check API_CONFIG_PATH ({API_CONFIG_PATH}), ACCESS_KEY_ID, and SECRET_KEY" + Style.RESET_ALL)
            return None

        controls_response = response.get('data', {})
        reply_block = controls_response.get("reply", {})
        page_controls = reply_block.get("controls", [])
        total_count = reply_block.get("total_count", 0)

        if not page_controls:
            break

        controls_data.extend(page_controls)
        print(f"   -> Retrieved {len(controls_data)} of {total_count} controls...")

        if total_count > 0 and len(controls_data) >= total_count:
            break

        if len(page_controls) < page_size:
            break

        search_from += page_size
        search_to += page_size

    return controls_data


async def delete_control(baseurl, api_key_id, api_key, control_id, session, semaphore):
    """Delete a compliance control by ID. Returns (success, error_message)"""
    delete_url = f"{baseurl}/public_api/v1/compliance/delete_control"
    payload = {
        "request_data": {
            "id": control_id
        }
    }
    
    response = await make_post_request(delete_url, payload, api_key_id, api_key, session, semaphore)
    
    if not response:
        return False, "No response from API"
    
    if response.get('success'):
        return True, None
    
    # Extract error message
    error_data = response.get('error', {})
    if isinstance(error_data, dict):
        reply = error_data.get('reply', {})
        error_msg = reply.get('err_extra') or reply.get('err_msg', 'Unknown error')
    else:
        error_msg = str(error_data)
    
    return False, error_msg


async def main():
    baseurl, api_key_id, api_key = read_api_config()
    
    search_pattern = "-prisma_cloud_copy"
    if len(sys.argv) > 1:
        search_pattern = sys.argv[1]
    
    async with aiohttp.ClientSession() as session:
        matching_controls = await fetch_matching_controls(baseurl, api_key_id, api_key, session, semaphore, search_pattern)
        
        if matching_controls is None:
            return
        
        if not matching_controls:
            print(Fore.YELLOW + f"No controls found matching pattern '*{search_pattern}*'" + Style.RESET_ALL)
            return
        
        # Display matching controls
        print(f"\n{Fore.CYAN}Found {len(matching_controls)} controls matching pattern '*{search_pattern}*':{Style.RESET_ALL}")
        for idx, control in enumerate(matching_controls, start=1):
            name = control.get('CONTROL_NAME', 'Unknown')
            control_id = control.get('CONTROL_ID', 'Unknown')
            category = control.get('CATEGORY', '')
            rules_count = control.get('RULES', 0)
            created_by = control.get('CREATED_BY', 'Unknown')
            is_custom = control.get('IS_CUSTOM', False)
            standards = control.get('STANDARDS', [])
            standards_str = ', '.join(standards) if standards else 'None'
            
            print(f"{idx}. {Fore.GREEN}{name}{Style.RESET_ALL}")
            print(f"   ID: {control_id}")
            print(f"   Category: {category}")
            print(f"   Rules: {rules_count}, Custom: {is_custom}, Created by: {created_by}")
            print(f"   Associated Standards: {standards_str}")
        
        # Ask for confirmation
        print(f"\n{Fore.YELLOW}WARNING: This will permanently delete {len(matching_controls)} compliance controls!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Note: Controls associated with standards may need to be removed from those standards first.{Style.RESET_ALL}")
        confirmation = input(f"Type 'DELETE' to confirm deletion: ").strip()
        
        if confirmation != 'DELETE':
            print(Fore.YELLOW + "Deletion cancelled." + Style.RESET_ALL)
            return
        
        # Delete each control
        print(f"\n{Fore.CYAN}Starting deletion process...{Style.RESET_ALL}")
        deleted_count = 0
        failed_count = 0
        failed_controls = []
        standard_associated_count = 0
        
        for control in matching_controls:
            name = control.get('CONTROL_NAME', 'Unknown')
            control_id = control.get('CONTROL_ID', 'Unknown')
            
            print(f"Deleting: {name}...", end=' ')
            
            success, error_msg = await delete_control(baseurl, api_key_id, api_key, control_id, session, semaphore)
            
            if success:
                print(Fore.GREEN + "✓ Deleted" + Style.RESET_ALL)
                deleted_count += 1
            else:
                # Check if it's the standard association error
                if error_msg and ('standard' in error_msg.lower() or 'associated' in error_msg.lower()):
                    print(Fore.YELLOW + "⚠ Skipped (in use by standard)" + Style.RESET_ALL)
                    standard_associated_count += 1
                else:
                    print(Fore.RED + f"✗ Failed: {error_msg}" + Style.RESET_ALL)
                
                failed_controls.append({'name': name, 'id': control_id, 'error': error_msg})
                failed_count += 1
        
        # Summary
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Deletion Summary:{Style.RESET_ALL}")
        print(f"  Successfully deleted: {Fore.GREEN}{deleted_count}{Style.RESET_ALL}")
        print(f"  Failed: {Fore.RED}{failed_count}{Style.RESET_ALL}")
        if standard_associated_count > 0:
            print(f"    └─ Associated with standards: {Fore.YELLOW}{standard_associated_count}{Style.RESET_ALL}")
        print(f"  Total processed: {len(matching_controls)}")
        
        # Show details of failed controls
        if failed_controls and standard_associated_count > 0:
            print(f"\n{Fore.YELLOW}Note: {standard_associated_count} control(s) could not be deleted because they are")
            print(f"associated with compliance standards. To delete these controls:{Style.RESET_ALL}")
            print(f"  1. Remove the control from all associated standards first")
            print(f"  2. Or delete the associated standards")
            print(f"  3. Then run this script again")
            print(f"\n{Fore.YELLOW}Controls associated with standards:{Style.RESET_ALL}")
            for failed in failed_controls:
                if 'standard' in failed['error'].lower() or 'associated' in failed['error'].lower():
                    print(f"  - {failed['name']}")
                    print(f"    Error: {failed['error']}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
