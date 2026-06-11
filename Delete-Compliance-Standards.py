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


async def fetch_all_standards(baseurl, api_key_id, api_key, session, semaphore):
    """Fetch all custom compliance standards using pagination"""
    standards_url = f"{baseurl}/public_api/v1/compliance/get_standards"
    standards_data = []
    page_size = 100
    search_from = 0
    search_to = page_size
    
    print("Fetching all custom compliance standards...")
    
    while True:
        standards_payload = {
            "request_data": {
                "filters": [
                    {
                        "field": "is_custom",
                        "operator": "in",
                        "value": ["yes"]
                    }
                ],
                "search_from": search_from,
                "search_to": search_to
            }
        }
        
        response = await make_post_request(standards_url, standards_payload, api_key_id, api_key, session, semaphore)
        if not response or not response.get('success'):
            break
        standards_response = response.get('data', {})
        reply_block = standards_response.get("reply", {})
        page_standards = reply_block.get("standards", [])
        total_count = reply_block.get("total_count", 0)
        
        if not page_standards:
            break
        
        standards_data.extend(page_standards)
        print(f"   -> Retrieved {len(standards_data)} of {total_count} standards...")
        
        if total_count > 0 and len(standards_data) >= total_count:
            break
        
        if len(page_standards) < page_size:
            break
        
        search_from += page_size
        search_to += page_size
    
    return standards_data


async def delete_standard(baseurl, api_key_id, api_key, standard_id, session, semaphore):
    """Delete a compliance standard by ID. Returns (success, error_message)"""
    delete_url = f"{baseurl}/public_api/v1/compliance/delete_standard"
    payload = {
        "request_data": {
            "id": standard_id
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
    
    async with aiohttp.ClientSession() as session:
        # Fetch all custom standards
        all_standards = await fetch_all_standards(baseurl, api_key_id, api_key, session, semaphore)
        
        if not all_standards:
            print(Fore.YELLOW + "No custom compliance standards found." + Style.RESET_ALL)
            return
        
        # Filter standards ending with "-prisma_cloud_copy"
        matching_standards = [
            std for std in all_standards 
            if std.get('name', '').endswith('-prisma_cloud_copy')
        ]
        
        if not matching_standards:
            print(Fore.YELLOW + "No standards found matching pattern '*-prisma_cloud_copy'" + Style.RESET_ALL)
            return
        
        # Display matching standards
        print(f"\n{Fore.CYAN}Found {len(matching_standards)} standards matching pattern '*-prisma_cloud_copy':{Style.RESET_ALL}")
        for idx, standard in enumerate(matching_standards, start=1):
            name = standard.get('name', 'Unknown')
            std_id = standard.get('id', 'Unknown')
            controls_count = len(standard.get('controls_ids') or [])
            created_by = standard.get('created_by', 'Unknown')
            print(f"{idx}. {Fore.GREEN}{name}{Style.RESET_ALL}")
            print(f"   ID: {std_id}")
            print(f"   Controls: {controls_count}, Created by: {created_by}")
        
        # Ask for confirmation
        print(f"\n{Fore.YELLOW}WARNING: This will permanently delete {len(matching_standards)} compliance standards!{Style.RESET_ALL}")
        confirmation = input(f"Type 'DELETE' to confirm deletion: ").strip()
        
        if confirmation != 'DELETE':
            print(Fore.YELLOW + "Deletion cancelled." + Style.RESET_ALL)
            return
        
        # Delete each standard
        print(f"\n{Fore.CYAN}Starting deletion process...{Style.RESET_ALL}")
        deleted_count = 0
        failed_count = 0
        failed_standards = []
        profile_associated_count = 0
        
        for standard in matching_standards:
            name = standard.get('name', 'Unknown')
            std_id = standard.get('id', 'Unknown')
            
            print(f"Deleting: {name}...", end=' ')
            
            success, error_msg = await delete_standard(baseurl, api_key_id, api_key, std_id, session, semaphore)
            
            if success:
                print(Fore.GREEN + "✓ Deleted" + Style.RESET_ALL)
                deleted_count += 1
            else:
                # Check if it's the assessment profile error
                if error_msg and 'assessment profile' in error_msg.lower():
                    print(Fore.YELLOW + "⚠ Skipped (in use by assessment profile)" + Style.RESET_ALL)
                    profile_associated_count += 1
                else:
                    print(Fore.RED + f"✗ Failed: {error_msg}" + Style.RESET_ALL)
                
                failed_standards.append({'name': name, 'id': std_id, 'error': error_msg})
                failed_count += 1
        
        # Summary
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Deletion Summary:{Style.RESET_ALL}")
        print(f"  Successfully deleted: {Fore.GREEN}{deleted_count}{Style.RESET_ALL}")
        print(f"  Failed: {Fore.RED}{failed_count}{Style.RESET_ALL}")
        if profile_associated_count > 0:
            print(f"    └─ Associated with assessment profiles: {Fore.YELLOW}{profile_associated_count}{Style.RESET_ALL}")
        print(f"  Total processed: {len(matching_standards)}")
        
        # Show details of failed standards
        if failed_standards and profile_associated_count > 0:
            print(f"\n{Fore.YELLOW}Note: {profile_associated_count} standard(s) could not be deleted because they are")
            print(f"associated with assessment profiles. To delete these standards:{Style.RESET_ALL}")
            print(f"  1. Go to Cortex > Compliance > Assessment Profiles")
            print(f"  2. Remove the standard from all associated profiles")
            print(f"  3. Run this script again")
            print(f"\n{Fore.YELLOW}Standards associated with assessment profiles:{Style.RESET_ALL}")
            for failed in failed_standards:
                if 'assessment profile' in failed['error'].lower():
                    print(f"  - {failed['name']}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
