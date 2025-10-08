#!/usr/bin/env python3
"""
ProbeRaptor - Bug Bounty Reconnaissance Tool
🦅 Fast, precise reconnaissance for security researchers
"""

import argparse
import sys
import time
import json
import os
from datetime import datetime

# Import our ACTUAL modules that exist
from modules.subdomain_enum import comprehensive_enumeration, enumerate_with_port_scan
from modules.port_scanner import common_ports_scan
from utils.helpers import validate_url
from config.settings import get_version, get_user_agent

class ProbeRaptor:
    def __init__(self):
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {
            'metadata': {
                'tool': 'ProbeRaptor',
                'version': get_version(),
                'scan_id': self.scan_id,
                'start_time': None,
                'end_time': None,
                'duration': None
            },
            'targets': []
        }
    
    def print_banner(self):
        """Display the awesome ProbeRaptor banner"""
        banner = """
🦅 \033[1;33mPROBE RAPTOR\033[0m
\033[1;34m╔═────═════════════════════════════──────════╗
║    Bug Bounty Reconnaissance Tool          │
│    Created by Omkar sahni                  ║
╚═════════════════════════════════──────────═╝\033[0m
        """
        print(banner)
        print(f"🔧 Version {get_version()} | 📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
    
    def run_scan(self, target_domain, scan_type="standard", output_format="console", output_dir="outputs", wordlist_path="wordlists/common_subdomains.txt"):
        """Main scan controller"""
        
        start_time = time.time()
        self.results['metadata']['start_time'] = datetime.now().isoformat()
        self.results['metadata']['target'] = target_domain
        self.results['metadata']['scan_type'] = scan_type
        self.results['metadata']['wordlist'] = wordlist_path
        
        print(f"🎯 Target: \033[1;36m{target_domain}\033[0m")
        print(f"🔍 Scan Type: \033[1;33m{scan_type.upper()}\033[0m")
        print(f"📁 Wordlist: {wordlist_path}")
        print(f"🕒 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        try:
            # Create output directory
            os.makedirs(output_dir, exist_ok=True)
            
            if scan_type == "subdomains":
                self._run_subdomain_scan(target_domain, wordlist_path)
            elif scan_type == "ports":
                self._run_port_scan(target_domain)
            elif scan_type == "standard":
                self._run_standard_scan(target_domain, wordlist_path)
            elif scan_type == "full":
                self._run_full_scan(target_domain, wordlist_path)
            else:
                print(f"❌ Unknown scan type: {scan_type}")
                return False
            
            # Calculate duration
            end_time = time.time()
            duration = end_time - start_time
            self.results['metadata']['end_time'] = datetime.now().isoformat()
            self.results['metadata']['duration'] = f"{duration:.2f}s"
            
            # Generate output
            self._generate_output(target_domain, output_format, output_dir, duration)
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n❌ Scan interrupted by user")
            return False
        except Exception as e:
            print(f"❌ Scan failed: {e}")
            return False
    
    def _run_subdomain_scan(self, domain, wordlist_path):
        """Run subdomain enumeration only"""
        print("🚀 Starting Subdomain Discovery...")
        print("─" * 50)
        
        # Use our existing comprehensive enumeration
        results = comprehensive_enumeration(domain, wordlist_path)
        
        for result in results:
            target_info = {
                'subdomain': result['subdomain'],
                'ip_address': result['ip_address'],
                'http_status': result['status_code'],
                'open_ports': [],
                'discovered_content': []
            }
            self.results['targets'].append(target_info)
    
    def _run_port_scan(self, domain):
        """Run port scanning on the main domain"""
        print("🚀 Starting Port Scan...")
        print("─" * 50)
        
        # Resolve domain to IP first
        import socket
        try:
            ip = socket.gethostbyname(domain)
            print(f"📡 Resolved {domain} → {ip}")
            
            # Scan common ports
            open_ports = common_ports_scan(ip, "common")
            
            target_info = {
                'subdomain': domain,
                'ip_address': ip,
                'http_status': None,
                'open_ports': open_ports,
                'discovered_content': []
            }
            self.results['targets'].append(target_info)
            
        except socket.gaierror:
            print(f"❌ Could not resolve {domain}")
    
    def _run_standard_scan(self, domain, wordlist_path):
        """Run standard reconnaissance (subdomains + basic port scanning)"""
        print("🚀 Starting Standard Reconnaissance...")
        print("─" * 50)
        
        # Get subdomains with basic port scanning
        results = enumerate_with_port_scan(domain, wordlist_path)
        
        for result in results:
            target_info = {
                'subdomain': result['subdomain'],
                'ip_address': result['ip_address'],
                'http_status': result['status_code'],
                'open_ports': result.get('open_ports', []),
                'discovered_content': []
            }
            self.results['targets'].append(target_info)
    
    def _run_full_scan(self, domain, wordlist_path):
        """Run full reconnaissance with content discovery"""
        print("🚀 Starting Full Reconnaissance...")
        print("─" * 50)
        
        # This would integrate content discovery - we'll build this next
        print("⚠️ Full scan mode coming in v1.1 - falling back to standard scan")
        self._run_standard_scan(domain, wordlist_path)
    
    def _calculate_score(self, target):
        """Calculate 0-100 score for target importance"""
        score = 0
        
        # HTTP 200 is most valuable
        if target['http_status'] == 200:
            score += 50
        
        # Web ports add significant value
        web_ports = [p for p in target['open_ports'] if p['port'] in [80, 443, 8080, 8443]]
        score += len(web_ports) * 15
        
        # Any open ports add value
        score += len(target['open_ports']) * 5
        
        # Admin-like subdomains get bonus
        admin_keywords = ['admin', 'api', 'dev', 'test', 'staging', 'secure', 'portal']
        if any(keyword in target['subdomain'].lower() for keyword in admin_keywords):
            score += 10
        
        return min(100, score)  # Cap at 100
    
    def _rank_targets(self, targets):
        """Rank targets by importance score"""
        ranked = []
        for target in targets:
            score = self._calculate_score(target)
            ranked.append((score, target))
        
        # Sort by score descending
        ranked.sort(key=lambda x: x[0], reverse=True)
        return [target for score, target in ranked]
    
    def _get_priority_badge(self, score):
        """Get priority badge based on score"""
        if score >= 80:
            return "🟢 HIGH"
        elif score >= 50:
            return "🟡 MEDIUM" 
        else:
            return "⚪ LOW"
    
    def _format_technical_field(self, text):
        """Format technical fields for easy copy-paste"""
        return f"`{text}`"
    
    def _suggest_actions(self, target):
        """Generate specific, actionable commands"""
        actions = []
        web_ports = [p for p in target['open_ports'] if p['port'] in [80, 443, 8080, 8443]]
        
        # Web service actions
        if web_ports and target['http_status'] == 200:
            port_str = ",".join([str(p['port']) for p in web_ports])
            actions.append(f"Run `nmap -sV -p{port_str} {target['ip_address']}`")
            
            # Suggest specific paths based on subdomain name
            subdomain_part = target['subdomain'].split('.')[0]
            if 'admin' in subdomain_part.lower():
                actions.append(f"Check `/{subdomain_part}/`, `/admin/`, `/login/`")
            elif 'api' in subdomain_part.lower():
                actions.append(f"Check `/api/`, `/api/v1/`, `/docs/`, `/swagger/`")
            else:
                actions.append(f"Check `/{subdomain_part}/`, `/admin/`, `/api/`")
        
        # SSH actions
        if any(p['port'] == 22 for p in target['open_ports']):
            actions.append(f"Verify SSH: `nmap -sV -p22 {target['ip_address']}`")
        
        # Database actions
        db_ports = [p for p in target['open_ports'] if p['port'] in [3306, 5432, 27017]]
        if db_ports:
            port_str = ",".join([str(p['port']) for p in db_ports])
            actions.append(f"Check DB exposure: `nmap -sV -p{port_str} {target['ip_address']}`")
        
        # No HTTP but has web ports
        if web_ports and not target['http_status']:
            actions.append(f"Try HTTPS: `curl -k https://{target['subdomain']}`")
            
        return actions
    
    def _generate_output(self, domain, output_format, output_dir, duration):
        """Generate output in the requested format"""
        print()
        print("🎉 SCAN COMPLETE!")
        print("=" * 60)
        
        # Console output (always show)
        self._console_output(domain, duration)
        
        # Additional output formats
        if output_format == "json":
            self._json_output(domain, output_dir)
        elif output_format == "html":
            self._html_output(domain, output_dir)
        
        print(f"💾 Results saved to: {output_dir}/")
    
    def _console_output(self, domain, duration):
        """Professional console output with rankings and actionable insights"""
        live_targets = [t for t in self.results['targets'] if t['http_status'] not in [None, 0]]
        total_ports = sum(len(t['open_ports']) for t in self.results['targets'])
        
        # Clear metadata header
        print("📋 SCAN METADATA")
        print("─" * 50)
        print(f"Target: {domain} | Scan: {self.results['metadata']['scan_type'].upper()} | Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Top-line summary card
        print("📊 QUICK SUMMARY")
        print("─" * 50)
        print(f"🎯 Targets: {len(self.results['targets'])} • 🌐 Live: {len(live_targets)} • 🚀 Ports: {total_ports} • ⏱️ {duration:.2f}s")
        print()
        
        # Rank and show top findings
        ranked_targets = self._rank_targets(self.results['targets'])
        top_findings = ranked_targets[:3]  # Show top 3
        
        if top_findings:
            print("🔍 TOP FINDINGS (RANKED)")
            print("─" * 50)
            
            for i, target in enumerate(top_findings, 1):
                score = self._calculate_score(target)
                priority_badge = self._get_priority_badge(score)
                
                print(f"{i}) {target['subdomain']} — {priority_badge} (score: {score})")
                print(f"   📍 IP: {self._format_technical_field(target['ip_address'])}")
                print(f"   📡 Status: HTTP/{target['http_status']}" if target['http_status'] else "   📡 Status: No HTTP")
                
                # Format ports with monospace
                if target['open_ports']:
                    ports_str = " • ".join([f"{self._format_technical_field(str(p['port']))} ({p['service']})" for p in target['open_ports']])
                    print(f"   🚀 Ports: {ports_str}")
                
                # Show banner snippet if available (truncated)
                banner_shown = False
                for port in target['open_ports']:
                    if port.get('banner') and not banner_shown:
                        banner_preview = port['banner'][:80] + "…" if len(port['banner']) > 80 else port['banner']
                        print(f"   📋 Banner: {banner_preview}")
                        banner_shown = True
                        break
                
                # Suggested actions (specific commands)
                actions = self._suggest_actions(target)
                if actions:
                    print(f"   💡 Suggested:")
                    for action in actions[:2]:  # Show max 2 actions
                        print(f"      • {action}")
                
                print()
        
        # Show all targets in compact form
        if len(ranked_targets) > 3:
            print("📋 ALL DISCOVERED TARGETS")
            print("─" * 50)
            for target in ranked_targets:
                status_emoji = "[+] " if target['http_status'] == 200 else "[*]" if target['http_status'] else "🌑"
                ports_str = ",".join([str(p['port']) for p in target['open_ports']]) if target['open_ports'] else "none"
                print(f"{status_emoji} {target['subdomain']} ({self._format_technical_field(target['ip_address'])}) — {ports_str} — HTTP {target['http_status'] or 'N/A'}")
        
        print()
        print("📖 LEGEND: 🟢 HIGH • 🟡 MEDIUM • ⚪ LOW")
        print("💡 Specific next steps provided for each finding")
        print("🔒 Only scan authorized targets")
        print(f"📝 Use `--output json` for machine-readable format")
    
    def _json_output(self, domain, output_dir):
        """Generate JSON output file"""
        # Add scores to JSON output
        for target in self.results['targets']:
            target['score'] = self._calculate_score(target)
            target['priority'] = self._get_priority_badge(target['score'])
        
        filename = f"{output_dir}/proberaptor_{domain}_{self.scan_id}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"📄 JSON Report: {filename}")
    
    def _html_output(self, domain, output_dir):
        """Generate professional HTML output"""
        filename = f"{output_dir}/proberaptor_{domain}_{self.scan_id}.html"
        
        # Rank targets for HTML display and calculate scores
        ranked_targets = self._rank_targets(self.results['targets'])
        for target in ranked_targets:
            target['score'] = self._calculate_score(target)
            target['priority'] = self._get_priority_badge(target['score'])
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ProbeRaptor Report - {domain}</title>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f8fafc; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background: linear-gradient(135deg, #1E40AF, #3730a3); color: white; padding: 30px; border-radius: 12px; margin-bottom: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .summary {{ background: white; padding: 24px; border-radius: 12px; margin-bottom: 24px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
                .target {{ background: white; padding: 20px; margin: 16px 0; border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: transform 0.2s; }}
                .target:hover {{ transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
                .high {{ border-left: 6px solid #10B981; }}
                .medium {{ border-left: 6px solid #F59E0B; }}
                .low {{ border-left: 6px solid #6B7280; }}
                .ports {{ background: #1E40AF; color: white; padding: 4px 12px; border-radius: 6px; margin: 4px; display: inline-block; font-family: monospace; }}
                .badge {{ padding: 4px 12px; border-radius: 6px; font-size: 12px; font-weight: bold; margin-left: 12px; }}
                .high-badge {{ background: #10B981; color: white; }}
                .medium-badge {{ background: #F59E0B; color: white; }}
                .low-badge {{ background: #6B7280; color: white; }}
                .score {{ font-family: monospace; background: #f1f5f9; padding: 2px 8px; border-radius: 4px; }}
                .tech {{ font-family: monospace; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; }}
                .actions {{ background: #f0fdf4; padding: 12px; border-radius: 8px; margin-top: 12px; }}
                .metadata {{ background: #eff6ff; padding: 16px; border-radius: 8px; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🦅 ProbeRaptor Security Report</h1>
                    <p>Comprehensive reconnaissance findings for {domain}</p>
                </div>
                
                <div class="metadata">
                    <h3>Scan Information</h3>
                    <p><strong>Target:</strong> {domain} | <strong>Scan Type:</strong> {self.results['metadata']['scan_type'].upper()} | <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="summary">
                    <h2>Executive Summary</h2>
                    <p><strong>Targets Found:</strong> {len(self.results['targets'])} | 
                       <strong>Live Services:</strong> {len([t for t in self.results['targets'] if t['http_status'] not in [None, 0]])} | 
                       <strong>Open Ports:</strong> {sum(len(t['open_ports']) for t in self.results['targets'])} |
                       <strong>Duration:</strong> {self.results['metadata']['duration']}</p>
                </div>
                
                <h2>Discovered Targets (Ranked by Priority)</h2>
        """
        
        for i, target in enumerate(ranked_targets, 1):
            priority_class = "high" if target['score'] >= 80 else "medium" if target['score'] >= 50 else "low"
            badge_class = f"{priority_class}-badge"
            
            html_content += f"""
            <div class="target {priority_class}">
                <h3>#{i} {target['subdomain']} <span class="badge {badge_class}">{priority_class.upper()}</span> <span class="score">Score: {target['score']}/100</span></h3>
                <p><strong>IP Address:</strong> <span class="tech">{target['ip_address']}</span> | <strong>HTTP Status:</strong> {target['http_status'] or 'N/A'}</p>
            """
            
            if target['open_ports']:
                html_content += "<p><strong>Open Ports:</strong> "
                for port in target['open_ports']:
                    html_content += f'<span class="ports">{port["port"]} ({port["service"]})</span> '
                html_content += "</p>"
            
            # Add banner if available
            for port in target['open_ports']:
                if port.get('banner'):
                    banner_preview = port['banner'][:100] + "…" if len(port['banner']) > 100 else port['banner']
                    html_content += f'<p><strong>Banner:</strong> <code>{banner_preview}</code></p>'
                    break
            
            # Add suggested actions
            actions = self._suggest_actions(target)
            if actions:
                html_content += '<div class="actions"><strong>Recommended Actions:</strong><ul>'
                for action in actions[:2]:
                    html_content += f'<li><code>{action}</code></li>'
                html_content += '</ul></div>'
            
            html_content += "</div>"
        
        html_content += """
                <div class="target" style="background: #f1f5f9;">
                    <h3>About This Report</h3>
                    <p>This report was generated by <strong>ProbeRaptor v1.0</strong> - A professional bug bounty reconnaissance tool.</p>
                    <p><strong>Legend:</strong> 🟢 HIGH • 🟡 MEDIUM • ⚪ LOW priority targets</p>
                    <p><em>Only scan targets you are authorized to test. Respect rate limits and terms of service.</em></p>
                </div>
            </div>
            </body>
            </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
        print(f"🌐 HTML Report: {filename}")

def main():
    """Main command-line interface"""
    parser = argparse.ArgumentParser(
        description='🦅 ProbeRaptor - Professional Bug Bounty Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Examples:
  python3 proberaptor.py -d example.com
  python3 proberaptor.py -d example.com -s full -o json
  python3 proberaptor.py -d example.com --scan-type subdomains
  python3 proberaptor.py -d example.com --output html
  python3 proberaptor.py -d example.com --wordlists custom_wordlist.txt

Scan Types:
  subdomains - Find subdomains only
  ports      - Port scan main domain only  
  standard   - Subdomains + basic port scanning (default)
  full       - Comprehensive reconnaissance (coming soon)

Output Features:
  • Ranked findings with 0-100 score
  • Specific actionable recommendations
  • Machine-readable JSON format
  • Professional HTML reports
        '''
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-s', '--scan-type', 
                       choices=['subdomains', 'ports', 'standard', 'full'], 
                       default='standard', 
                       help='Type of scan to perform (default: standard)')
    parser.add_argument('-o', '--output', 
                       choices=['console', 'json', 'html'], 
                       default='console', 
                       help='Output format (default: console)')
    parser.add_argument('--output-dir', 
                       default='outputs', 
                       help='Output directory (default: outputs)')
    parser.add_argument('--wordlists', 
                       default='wordlists/common_subdomains.txt',
                       help='Path to wordlist file for subdomain enumeration (default: wordlists/common_subdomains.txt)')
    
    args = parser.parse_args()
    
    # Validate domain
    if not validate_url(args.domain):
        print(f"❌ Invalid domain: {args.domain}")
        sys.exit(1)
    
    # Initialize and run scanner
    raptor = ProbeRaptor()
    raptor.print_banner()
    
    success = raptor.run_scan(
        target_domain=args.domain,
        scan_type=args.scan_type,
        output_format=args.output,
        output_dir=args.output_dir,
        wordlist_path=args.wordlists
    )
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
