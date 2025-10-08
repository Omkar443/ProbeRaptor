#This module check whether a domain exist or not by making request to it

import requests
from utils import helpers
from config import settings
import concurrent.futures
from modules.port_scanner import common_ports_scan


def enumerate_with_port_scan(domain, wordlist_path=None):
    from modules.api_enumerator import comprehensive_api_scan
    print(f"Starting full scan for {domain}")
    all_results = []
    api_subdomains=comprehensive_api_scan(domain)

    verified_subdomains=[]
    for subdomain in api_subdomains:
        if domain in subdomain:
            sub_part = subdomain.replace(f".{domain}", "")
            result=check_subdomains(sub_part, domain)
            if result.get('exist') and result.get('ip_address') not in ['Not Resolved', None]:
                verified_subdomains.append(result)

    print(f"\n Starting port scan on {len(verified_subdomains)} discovered subdomains...")
    
    wordlist_results = []
    if wordlist_path:
        print(f"\n Starting wordlist enumeration... ")
        wordlist_results = enumerate_from_wordlists(domain, wordlist_path)
        print(f"\n Wordlist complete: {len(wordlist_results)} subdomains found")
    all_results = wordlist_results + verified_subdomains
    unique_subdomains = remove_duplicate_subdomains(all_results)
    print(f"\n Total unique subdoamins: {len(unique_subdomains)} for port scanning ")

    for i, subdomain_result in enumerate(unique_subdomains,1):
        ip = subdomain_result.get('ip_address')
        subdomain_name = subdomain_result.get('subdomain')
        print(f"\n [{i}/{len(unique_subdomains)}] Scanning {subdomain_name} ({ip})...")

        open_ports = []
        if ip and ip not in ['Not Resolved']:
            open_ports = common_ports_scan(ip, scan_type='web')
        subdomain_result['open_ports'] = open_ports
        
        if i % 10 == 0:
            print(f"\n Port scan progress: {i}/{len(unique_subdomains)}")
    print(f"\n Full reconnaissance complete! processed: {len(unique_subdomains)} unique targets")
    return unique_subdomains




def check_subdomains(domain,subdomain,timeout=10):
    full_domain=f"{domain}.{subdomain}"

    result={
        "subdomain":full_domain,
        "exist":False,
        "ip_address":None,
        "error":None,
        "status_code":None,
    }

    try:
        response = requests.get(
            f"http://{full_domain}",
            timeout=timeout,
            headers={"User-Agent": settings.get_user_agent()}
        )
        
        result["exist"]=True
        result["status_code"]=response.status_code

        import socket
        try:
            ip = socket.gethostbyname(full_domain)
            result["ip_address"]=ip
        except socket.gaierror:
            result["ip_address"]="Not Resolved"

    except requests.exceptions.RequestException as e:
        result["error"]=str(e)
        
    return result


def enumerate_from_wordlists(domain, wordlist, max_workers=50, timeout=5):
    found_subdomain = []
    
    # Rate limiting to avoid being blocked
    import time
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    try:
        print(f"📁 Loading wordlist: {wordlist}")
        
        # Read and clean the wordlist
        with open(wordlist, 'r') as lines:
            raw_subdomains = [line.strip() for line in lines if line.strip()]
            subdomains = list(set(raw_subdomains))
        
        print(f"🔍 Checking {len(subdomains)} unique subdomains for {domain}")
        print(f"⚡ Using {max_workers} concurrent workers")
        print(f"⏱️  Timeout: {timeout} seconds per request")
        print("⏳ This may take several minutes for large wordlists...")
        print("-" * 70)

        total = len(subdomains)
        processed = 0
        found_count = 0
        error_count = 0
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Process ENTIRE wordlist
            future_to_subdomain = {
                executor.submit(check_subdomains, subdomain, domain, timeout): subdomain
                for subdomain in subdomains
            }

            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                processed += 1

                try:
                    result = future.result()
                    if result['exist']:
                        found_count += 1
                        print(f"[{found_count}] {result['subdomain']} (IP: {result['ip_address']})")
                        found_subdomain.append(result)
                    elif result.get('error'):
                        error_count += 1
                    
                    # Detailed progress every 50 subdomains or 5%
                    if processed % 50 == 0 or processed == total:
                        elapsed = time.time() - start_time
                        progress_percent = (processed / total) * 100
                        items_per_second = processed / elapsed if elapsed > 0 else 0
                        remaining = total - processed
                        eta_seconds = remaining / items_per_second if items_per_second > 0 else 0
                        
                        print(f"Progress: {processed}/{total} ({progress_percent:.1f}%) | "
                              f"Found: {found_count} | "
                              f"Errors: {error_count} | "
                              f"Speed: {items_per_second:.1f}/sec | "
                              f"ETA: {eta_seconds/60:.1f} min")
                        
                except Exception as e:
                    error_count += 1
                    if error_count <= 10:  # Only show first 10 errors to avoid spam
                        print(f"⚠️ Error checking {subdomain}.{domain}: {e}")

        elapsed_total = time.time() - start_time
        success_rate = (processed - error_count) / processed * 100 if processed > 0 else 0
        
        print("-" * 70)
        print(f"🎉 SCAN COMPLETE!")
        print(f"📊 Results:")
        print(f"   ✅ Subdomains found: {found_count}")
        print(f"   📁 Total checked: {processed}")
        print(f"   ❌ Errors: {error_count}")
        print(f"   📈 Success rate: {success_rate:.1f}%")
        print(f"⏱️  Performance:")
        print(f"   🕒 Total time: {elapsed_total/60:.1f} minutes")
        print(f"   🚀 Speed: {total/elapsed_total:.1f} subdomains/second")
        print(f"   📦 Coverage: {found_count/len(subdomains)*100:.1f}% of wordlist")

    except FileNotFoundError:
        print(f"❌ Wordlist file not found: {wordlist}")
        return []
    except Exception as e:
        print(f"❌ Critical error: {e}")
        return []

    return found_subdomain

def comprehensive_enumeration(domain, wordlist_path=None):

    print(f"Starting comprehensive enumeration on {domain}")
    all_results=[]
    from modules.api_enumerator import comprehensive_api_scan
    api_subdomains=comprehensive_api_scan(domain)

    print(f"Verifying API found subdomains")
    for subdomain in api_subdomains:
        if domain in subdomain:
            sub_part=subdomain.replace(f".{domain}", "")
            result=check_subdomains(sub_part, domain)
            if(result['exist']):
                all_results.append(result)

    if wordlist_path:
        wordlist_results = enumerate_from_wordlists(domain, wordlist_path)
        all_results.extend(wordlist_results)

    unique_results=remove_duplicate_subdomains(all_results)
    print(f"Comprehensive scan complete found {len(unique_results)} unique live subdomains")
    return  unique_results


def remove_duplicate_subdomains(results):
    seen = set()
    unique_results=[]
    for result in results:
        if result['subdomain'] not in seen:
            seen.add(result['subdomain'])
            unique_results.append(result)
    return unique_results


