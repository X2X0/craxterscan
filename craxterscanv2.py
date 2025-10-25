#!/usr/bin/env python3

import argparse
import json
import socket
import subprocess
import sys
import time
from pythonping import ping
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__ = "X2X0"
__version__ = "1.0.0"

BANNER = f"""
╔═══════════════════════════════════════════════════════════╗
║                    CRAXTERSCAN v{__version__}                    ║
║              Network Reconnaissance & Enumeration          ║
║                      Author: {__author__}                        ║
╚═══════════════════════════════════════════════════════════╝

WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY
Unauthorized access to computer systems is illegal.
"""

DISCLAIMER = """
╔═══════════════════════════════════════════════════════════╗
║                    LEGAL DISCLAIMER                        ║
╠═══════════════════════════════════════════════════════════╣
║ By using this tool, you acknowledge that:                 ║
║                                                            ║
║ 1. You have EXPLICIT WRITTEN AUTHORIZATION to test        ║
║    the target systems                                      ║
║ 2. You understand unauthorized access is ILLEGAL          ║
║ 3. All actions will be LOGGED for audit purposes          ║
║ 4. The author is NOT responsible for misuse               ║
╚═══════════════════════════════════════════════════════════╝
"""

class Logger:
    def __init__(self, log_file):
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log(self, level, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
        print(f"[{level}] {message}")

class HostDiscovery:
    def __init__(self, logger, timeout=1):
        self.logger = logger
        self.timeout = timeout

    def ping_sweep(self, network, rate_limit=0.1):
        self.logger.log("INFO", f"Starting host discovery on {network}")
        active_hosts = []

        base_ip = '.'.join(network.split('.')[:-1])
        start_range = int(network.split('.')[-1].split('-')[0])
        end_range = int(network.split('.')[-1].split('-')[1]) if '-' in network.split('.')[-1] else start_range

        for i in range(start_range, end_range + 1):
            target = f"{base_ip}.{i}"
            try:
                response = subprocess.run(
                    ['ping', '-c', '1', '-W', str(self.timeout), target],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout + 1
                )
                if response.returncode == 0:
                    active_hosts.append(target)
                    self.logger.log("SUCCESS", f"Host {target} is UP")
                time.sleep(rate_limit)
            except Exception as e:
                self.logger.log("ERROR", f"Error pinging {target}: {str(e)}")

        return active_hosts

class PortScanner:
    def __init__(self, logger, stealth=False):
        self.logger = logger
        self.stealth = stealth
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

    def scan_port(self, host, port, timeout=1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    def scan_host(self, host, ports=None, rate_limit=0.05):
        if ports is None:
            ports = self.common_ports if self.stealth else range(1, 1001)

        self.logger.log("INFO", f"Scanning ports on {host}")
        open_ports = []

        timeout = 2 if self.stealth else 1

        with ThreadPoolExecutor(max_workers=10 if self.stealth else 50) as executor:
            future_to_port = {executor.submit(self.scan_port, host, port, timeout): port for port in ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        self.logger.log("SUCCESS", f"Port {port} open on {host}")
                    if self.stealth:
                        time.sleep(rate_limit)
                except Exception as e:
                    self.logger.log("ERROR", f"Error scanning port {port} on {host}: {str(e)}")

        return open_ports

class ServiceEnumerator:
    def __init__(self, logger):
        self.logger = logger

    def grab_banner(self, host, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return None

    def enumerate_service(self, host, port):
        self.logger.log("INFO", f"Enumerating service on {host}:{port}")
        service_info = {
            'port': port,
            'service': self.guess_service(port),
            'banner': None,
            'version': None
        }

        banner = self.grab_banner(host, port)
        if banner:
            service_info['banner'] = banner[:200]
            service_info['version'] = self.extract_version(banner)
            self.logger.log("SUCCESS", f"Banner grabbed from {host}:{port}")

        return service_info

    def guess_service(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')

    def extract_version(self, banner):
        keywords = ['Server:', 'Version:', 'OpenSSH', 'Apache', 'nginx', 'Microsoft', 'IIS']
        for keyword in keywords:
            if keyword in banner:
                start = banner.find(keyword)
                end = banner.find('\n', start)
                if end == -1:
                    end = start + 50
                return banner[start:end].strip()
        return None

class ExploitSearcher:
    def __init__(self, logger):
        self.logger = logger

    def search_exploits(self, service, version):
       
        self.logger.log("INFO", f"Searching exploits for {service} {version}")
        exploits = []

        try:
            query = f"{service} {version}" if version else service
            cmd = f"searchsploit -j {query}"

            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)

                if 'RESULTS_EXPLOIT' in data:
                    for exploit in data['RESULTS_EXPLOIT'][:5]:  # 5
                        exploits.append({
                            'title': exploit.get('Title', 'N/A'),
                            'path': exploit.get('Path', 'N/A'),
                            'platform': exploit.get('Platform', 'N/A'),
                            'type': exploit.get('Type', 'N/A'),
                            'date': exploit.get('Date_Published', 'N/A')
                        })

                    self.logger.log("SUCCESS", f"Found {len(exploits)} exploits for {service}")
                else:
                    self.logger.log("INFO", f"No exploits found for {service} {version}")
            else:
                self.logger.log("WARNING", f"searchsploit returned no results for {service}")

        except subprocess.TimeoutExpired:
            self.logger.log("ERROR", f"searchsploit timeout for {service}")
        except json.JSONDecodeError:
            self.logger.log("ERROR", f"Failed to parse searchsploit output for {service}")
        except FileNotFoundError:
            self.logger.log("WARNING", "searchsploit not found. Install with: sudo apt install exploitdb")
        except Exception as e:
            self.logger.log("ERROR", f"Error searching exploits for {service}: {str(e)}")

        return exploits

class WebTechDetector:
    def __init__(self, logger):
        self.logger = logger

    def detect_technologies(self, host, port=80):
        url = f"http://{host}:{port}" if port != 443 else f"https://{host}"
        self.logger.log("INFO", f"Detecting web technologies on {url}")

        tech_info = {
            'url': url,
            'server': None,
            'technologies': [],
            'cms': None,
            'headers': {}
        }

        try:
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)

            tech_info['server'] = response.headers.get('Server', 'Unknown')
            tech_info['headers'] = dict(response.headers)

            content = response.text.lower()

            if 'wp-content' in content or 'wordpress' in content:
                tech_info['cms'] = 'WordPress'
                tech_info['technologies'].append('WordPress')
            elif 'joomla' in content:
                tech_info['cms'] = 'Joomla'
                tech_info['technologies'].append('Joomla')
            elif 'drupal' in content:
                tech_info['cms'] = 'Drupal'
                tech_info['technologies'].append('Drupal')

            if 'jquery' in content:
                tech_info['technologies'].append('jQuery')
            if 'bootstrap' in content:
                tech_info['technologies'].append('Bootstrap')
            if 'react' in content:
                tech_info['technologies'].append('React')
            if 'angular' in content:
                tech_info['technologies'].append('Angular')
            if 'vue' in content:
                tech_info['technologies'].append('Vue.js')

            if 'x-powered-by' in response.headers:
                tech_info['technologies'].append(response.headers['x-powered-by'])

            self.logger.log("SUCCESS", f"Detected technologies on {url}: {', '.join(tech_info['technologies'])}")

        except Exception as e:
            self.logger.log("ERROR", f"Error detecting technologies on {url}: {str(e)}")

        return tech_info

class ReportGenerator:
    def __init__(self, logger):
        self.logger = logger

    def generate_json(self, scan_results, output_file):
        self.logger.log("INFO", f"Generating JSON report: {output_file}")
        with open(output_file, 'w') as f:
            json.dump(scan_results, f, indent=4)
        self.logger.log("SUCCESS", f"JSON report saved to {output_file}")

    def generate_html(self, scan_results, output_file):
        self.logger.log("INFO", f"Generating HTML report: {output_file}")

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CraxterScan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .host {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .port {{ background: #fff; padding: 10px; margin: 10px 0; border-left: 4px solid #3498db; }}
        .tech {{ background: #e8f5e9; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .metadata {{ color: #7f8c8d; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #3498db; color: white; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.85em; }}
        .badge-success {{ background: #27ae60; color: white; }}
        .badge-info {{ background: #3498db; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>CraxterScan Report</h1>
        <div class="metadata">
            <p><strong>Generated:</strong> {scan_results['metadata']['timestamp']}</p>
            <p><strong>Target:</strong> {scan_results['metadata']['target']}</p>
            <p><strong>Scan Mode:</strong> {scan_results['metadata']['scan_mode']}</p>
            <p><strong>Total Hosts:</strong> {len(scan_results['hosts'])}</p>
        </div>

        <h2>Discovered Hosts</h2>
"""

        for host_ip, host_data in scan_results['hosts'].items():
            html_content += f"""
        <div class="host">
            <h3>Host: {host_ip}</h3>
            <p><strong>Open Ports:</strong> {len(host_data['ports'])}</p>
"""

            if host_data['ports']:
                html_content += "<table><tr><th>Port</th><th>Service</th><th>Version</th></tr>"
                for port_info in host_data['ports']:
                    version = port_info.get('version', 'N/A') or 'N/A'
                    html_content += f"<tr><td>{port_info['port']}</td><td>{port_info['service']}</td><td>{version}</td></tr>"
                html_content += "</table>"

            if host_data.get('web_technologies'):
                for tech in host_data['web_technologies']:
                    html_content += f"""
            <div class="tech">
                <h4>Web Technologies - {tech['url']}</h4>
                <p><strong>Server:</strong> {tech['server']}</p>
                <p><strong>CMS:</strong> {tech.get('cms', 'Not Detected')}</p>
                <p><strong>Technologies:</strong> {', '.join(tech['technologies']) if tech['technologies'] else 'None detected'}</p>
            </div>
"""

            html_content += "</div>"

        html_content += """
    </div>
</body>
</html>
"""

        with open(output_file, 'w') as f:
            f.write(html_content)
        self.logger.log("SUCCESS", f"HTML report saved to {output_file}")

def verify_authorization():
    print(DISCLAIMER)
    response = input("\nDo you have WRITTEN AUTHORIZATION to scan the target? (yes/no): ").strip().lower()
    if response != 'yes':
        print("\n[!] Authorization not confirmed. Exiting.")
        sys.exit(0)

    scope = input("Enter the authorized scope/target: ").strip()
    confirmation = input(f"Confirm you are authorized to scan '{scope}' (yes/no): ").strip().lower()
    if confirmation != 'yes':
        print("\n[!] Scope not confirmed. Exiting.")
        sys.exit(0)

    return scope

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="CraxterScan - Network Reconnaissance Tool")
    parser.add_argument('-t', '--target', required=True, help='Target IP or range (e.g., 192.168.1.1-254)')
    parser.add_argument('-m', '--mode', choices=['stealth', 'aggressive'], default='stealth', help='Scan mode')
    parser.add_argument('-p', '--ports', help='Custom port range (e.g., 1-1000)')
    parser.add_argument('-o', '--output', default='output', help='Output directory')
    parser.add_argument('--skip-auth', action='store_true', help='Skip authorization check (use responsibly)')

    args = parser.parse_args()

    if not args.skip_auth:
        authorized_scope = verify_authorization()
        if args.target not in authorized_scope:
            print(f"\n[!] Target '{args.target}' is not within authorized scope '{authorized_scope}'")
            sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = output_dir / f"craxterscan_{timestamp}.log"
    logger = Logger(log_file)

    logger.log("INFO", f"Starting CraxterScan v{__version__}")
    logger.log("INFO", f"Target: {args.target}")
    logger.log("INFO", f"Mode: {args.mode}")

    scan_results = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'target': args.target,
            'scan_mode': args.mode,
            'tool': f'CraxterScan v{__version__}',
            'author': __author__
        },
        'hosts': {}
    }

    discovery = HostDiscovery(logger)
    rate_limit = 0.2 if args.mode == 'stealth' else 0.05
    active_hosts = discovery.ping_sweep(args.target, rate_limit)

    if not active_hosts:
        logger.log("WARNING", "No active hosts found")
        return

    scanner = PortScanner(logger, stealth=(args.mode == 'stealth'))
    enumerator = ServiceEnumerator(logger)
    web_detector = WebTechDetector(logger)
    exploit_searcher = ExploitSearcher(logger)

    for host in active_hosts:
        logger.log("INFO", f"Processing host: {host}")

        ports = None
        if args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = range(start, end + 1)

        open_ports = scanner.scan_host(host, ports, rate_limit)

        scan_results['hosts'][host] = {
            'ports': [],
            'web_technologies': []
        }

        for port in open_ports:
            service_info = enumerator.enumerate_service(host, port)

            # Search for exploits
            exploits = exploit_searcher.search_exploits(
                service_info['service'],
                service_info.get('version')
            )

            if exploits:
                service_info['exploits'] = exploits

            scan_results['hosts'][host]['ports'].append(service_info)

            if port in [80, 443, 8080, 8443]:
                tech_info = web_detector.detect_technologies(host, port)
                if tech_info.get('technologies'):
                    scan_results['hosts'][host]['web_technologies'].append(tech_info)

    reporter = ReportGenerator(logger)
    json_report = output_dir / f"craxterscan_{timestamp}.json"
    html_report = output_dir / f"craxterscan_{timestamp}.html"

    reporter.generate_json(scan_results, json_report)
    reporter.generate_html(scan_results, html_report)

    logger.log("INFO", "Scan completed successfully")
    print(f"\n[+] Reports generated:")
    print(f"    - JSON: {json_report}")
    print(f"    - HTML: {html_report}")
    print(f"    - Log: {log_file}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
        sys.exit(1)