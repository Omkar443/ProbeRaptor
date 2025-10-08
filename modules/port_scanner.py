# It will scan and find open ports and services running on it

import socket
import concurrent.futures
from config import settings

def port_check(target_ip,port,timeout=1):
    
    result = {
        'port': port,
        'is_open': False,
        'service': 'unknown',
        'banner': None,
        'error': None
    }

    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            connection_result = sock.connect_ex((target_ip, port))
            if(connection_result == 0):
                result['is_open'] = True
                try:
                    sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    result['banner'] = banner[:500]
                except:
                    pass
                result['service'] = identify_service(port, result['banner'])
    
    except Exception as e:
        result['error'] = str(e)


    return result

def identify_service(port, banner=None):
    
    common_services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        27017: 'MongoDB'
    }

    if port in common_services:
        return common_services[port]

    if banner:
        banner_lower = banner.lower()
        if 'apache' in banner_lower or 'nginx' in banner_lower:
            return 'Web Server'
        elif 'mysql' in banner_lower:
            return 'MySql'
        elif 'ssh' in banner.lower:
            return 'SSH'

    return 'unknown'

def scan_ports(target_ip, ports_to_scan, max_workers=50, timeout=1):
    
    open_ports=[]
    print(f"Scanning {len(ports_to_scan)} ports on target {target_ip}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(port_check, target_ip, port, timeout): port
            for port in ports_to_scan
        }

    for future in concurrent.futures.as_completed(future_to_port):
        port = future_to_port[future]
        try:
            result = future.result()
            if result.get('is_open'):
                print(f"Port {port}/tcp open - {result.get('service')}")
                open_ports.append(result)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    
    print(f"Port scan complete! Found {len(open_ports)} open ports")
    return open_ports

def common_ports_scan(target_ip, scan_type="common"):
    if scan_type == 'common':
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    elif scan_type == 'web':
        ports = [80, 443, 8080, 8443, 8000, 3000, 5000, 9000]
    elif scan_type == 'full':
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389]
    else:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389]

    return scan_ports(target_ip, ports)
