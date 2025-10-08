#This module will be including all the api based subdomain enumerator

import requests
import json
import time
from config import settings
from requests.exceptions import RequestException



def cert_transparency_scan(domain, retries=3, timeout=None, backoff_factor=1):

    print(f"Checking certificate transparency for {domain}...")

    if timeout is None:
        try:
            timeout = settings.get_default_timeout()
        except Exception:
            timeout = 10

    subdomains = set()

    query_variants = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]

    for url in query_variants:
        for attempt in range(1, retries + 1):
            try:
                resp = requests.get(url, timeout=timeout, headers={'User-Agent': settings.get_user_agent()})
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except ValueError:
                        print(f"⚠️ crt.sh returned non-json for url {url}")
                        break
                    for certificate in data:
                        names = certificate.get('name_value') or certificate.get('common_name') or ''
                        if not names:
                            continue
                        for name in str(names).splitlines():
                            name = name.strip()
                            if not name:
                                continue
                            if name.startswith("*."):
                                name = name[2:]
                            if domain in name:
                                subdomains.add(name)
                    break
                else:
                    print(f"⚠️ crt.sh returned status {resp.status_code} for url {url} (attempt {attempt})")
                    if attempt < retries:
                        time.sleep(backoff_factor * attempt)
                    else:
                        break
            except RequestException as e:
                print(f"crt.sh request failed for url {url} (attempt {attempt}/{retries}): {e}")
                if attempt < retries:
                    time.sleep(backoff_factor * attempt)
                else:
                    break

        if subdomains:
            break

    if not subdomains:
        print("⚠️ crt.sh returned no subdomains (try other sources or increase timeout)")

    return sorted(subdomains)




def hackertarget_scan(domain):

    print(f"Checking HackerTarget for {domain}..")
    subdomains=[]
    try:
        url=f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response=requests.get(
            url,
            timeout = settings.get_default_timeout(),
            headers={"User-Agent" : settings.get_user_agent()}
        )

        if response.status_code == 200 and 'error' not in response.text.lower():
            lines=response.text.strip().split('\n')
            for line in lines:
                if ',' in  line:
                    subdomain=line.split(',')[0]
                    subdomains.append(subdomain)
    except Exception as e:
        print(f"HackerTarget API error: {e}")

    return subdomains


def comprehensive_api_scan(domain):

    all_subdomains = set()
    print(f"Starting comprehensive API scan on target: {domain}")

    ct_subdomains=set(cert_transparency_scan(domain) or [])
    ht_subdomains=set(hackertarget_scan(domain) or [])
    
    all_subdomains.update(ct_subdomains)
    all_subdomains.update(ht_subdomains)

    print(f"API scan found: {len(all_subdomains)} unique subdomains")
    return list(all_subdomains)
