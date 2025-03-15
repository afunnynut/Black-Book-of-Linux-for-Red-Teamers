# Chapter 1: Network Discovery and Mapping

## Nmap: The Network Mapper

### Introduction to Nmap

Nmap ("Network Mapper") stands as perhaps the most essential tool in any cybersecurity professional's arsenal. Created by Gordon Lyon (Fyodor) in 1997, this open-source utility has evolved from a simple port scanner to a comprehensive network discovery and security auditing platform. For red teamers, Nmap serves as the primary reconnaissance tool that forms the foundation of nearly every successful engagement.

In this section, we'll explore advanced Nmap techniques that go far beyond basic scanning, focusing on methodologies that provide maximum information while maintaining stealth when required. We'll skip the basic installation steps (which differ little from any standard Linux package) and focus directly on operational usage patterns.

![Nmap logo and architecture](./images/nmap_architecture.png)
*Figure 1.1: Nmap's modular architecture enables its extensibility*

### Core Scanning Techniques

#### Port Scanning Strategies

The effectiveness of an Nmap scan depends heavily on selecting the right scanning technique for your specific objective. Each technique offers different benefits regarding speed, stealth, firewall evasion, and accuracy.

**TCP SYN Scan (`-sS`)**

The SYN scan, also known as the "half-open" scan, remains the default and most popular scan type for good reason.

```bash
# Basic SYN scan of common ports
sudo nmap -sS 192.168.1.0/24

# SYN scan with timing template, OS detection, and service version detection
sudo nmap -sS -T4 -A 192.168.1.100
```

**How it works:**

1. Nmap sends a SYN packet to the target port
2. If the port is open: Target responds with SYN/ACK
3. Instead of completing the handshake, Nmap sends RST
4. If the port is closed: Target responds with RST

**Advantages:**
- Doesn't complete the TCP handshake, making it less likely to appear in application logs
- Faster than full connect scans
- Can differentiate between open, closed, and filtered ports

**Disadvantages:**
- Requires raw socket privileges (root/sudo access)
- May be detected by sophisticated IDS/IPS systems

**TCP Connect Scan (`-sT`)**

When you don't have raw socket privileges, the TCP connect scan provides a viable alternative:

```bash
# Connect scan as non-privileged user
nmap -sT 192.168.1.100
```

**How it works:**
1. Uses the standard system connect() call to establish a full TCP connection
2. If connection succeeds, port is open
3. Connection is immediately closed with RST after determination

**Advantages:**
- Can be run without root/sudo privileges
- More accurate in certain environments where packet filtering may affect SYN scans

**Disadvantages:**
- Leaves evidence in target logs
- Slower than SYN scans due to complete handshake
- More easily detected by IDS/IPS

**UDP Scan (`-sU`)**

UDP scanning is frequently overlooked but critical for comprehensive enumeration. Many important services (DNS, SNMP, DHCP) run on UDP.

```bash
# Basic UDP scan of top UDP ports
sudo nmap -sU --top-ports 100 192.168.1.100

# Comprehensive but very slow UDP scan
sudo nmap -sU -p- --min-rate 100 192.168.1.100
```

**How it works:**
1. Nmap sends an empty UDP packet to each target port
2. If port is closed: ICMP "port unreachable" message is returned
3. If no response: Port is considered open|filtered
4. If UDP response: Port is definitively open

**Advantages:**
- Identifies UDP services that may be overlooked in standard TCP scans
- Often reveals less-hardened services

**Disadvantages:**
- Extremely slow due to ICMP rate limiting on many systems
- Less accurate due to packet loss and filtering
- Still requires root/sudo privileges

**FIN, XMAS, and NULL Scans (`-sF`, `-sX`, `-sN`)**

These scan types manipulate TCP flags to evade basic firewall rules and primitive intrusion detection systems.

```bash
# FIN scan
sudo nmap -sF -T2 192.168.1.100

# XMAS scan (sets FIN, PSH and URG flags)
sudo nmap -sX -p 1-1000 192.168.1.100

# NULL scan (no flags set)
sudo nmap -sN 192.168.1.100
```

**How they work:**
- FIN scan: Sends packet with just the FIN flag set
- XMAS scan: Sends packet with FIN, PSH, and URG flags (lit up "like a Christmas tree")
- NULL scan: Sends packet with no flags set

In all cases:
- If port is closed: RST packet is returned (per RFC 793)
- If no response: Port is considered open|filtered
- If RST received: Port is closed

**Advantages:**
- May bypass certain non-stateful firewalls and packet filters
- Often less commonly logged than SYN or Connect scans

**Disadvantages:**
- Cannot distinguish between open and filtered ports
- Not reliable on Windows targets due to TCP/IP implementation differences
- Less accurate overall than SYN scans

> **CASE STUDY: The Equifax Breach**
> 
> In the 2017 Equifax breach affecting 147 million people, attackers used basic Nmap scans to discover an unpatched Apache Struts instance. According to the congressional report, "attackers conducted reconnaissance of Equifax's online dispute portal for 76 days" using tools including Nmap to map the network before exploiting the vulnerability. This case demonstrates how even simple scanning can reveal critical vulnerabilities when proper patch management is lacking.
>
> *Source: U.S. House of Representatives Committee on Oversight and Government Reform Report, 2018*

#### Port Selection Strategies

Proper port selection dramatically affects both scan speed and effectiveness. Nmap offers several approaches:

**Default Port Selection**
By default, Nmap scans the 1,000 most common ports for each protocol specified.

**Targeted Port Ranges (`-p`)**
```bash
# Scan specific ports
nmap -p 22,80,443,8080 192.168.1.100

# Scan port ranges
nmap -p 1-1024 192.168.1.100

# Scan all 65535 ports
nmap -p- 192.168.1.100

# Scan top 100 ports
nmap --top-ports 100 192.168.1.100

# Scan specific UDP ports
sudo nmap -sU -p 53,161,123 192.168.1.100
```

**Port Selection by Service (`-p`)**
```bash
# Scan all ports with "http" in their name
nmap -p http* 192.168.1.100
```

**Fast Port Scan Technique**
```bash
# Quick discovery of open ports, then detailed scan of only those
sudo nmap -p- --min-rate 1000 -T4 192.168.1.100 -oG ports.grep
ports=$(grep -oP '(?<=Ports: )[0-9,]*' ports.grep | tr ',' '\n' | sort -nu | tr '\n' ',')
sudo nmap -p$ports -sCV 192.168.1.100
```

This two-phase approach dramatically speeds up comprehensive scans by first identifying open ports quickly, then performing deeper inspection only on those ports.

#### Timing and Performance

Nmap's timing options balance speed against stealth and accuracy:

**Timing Templates (`-T0` through `-T5`)**
```bash
# Paranoid mode - Incredibly slow, one probe at a time
sudo nmap -T0 192.168.1.100

# Sneaky mode - Slow scan to avoid detection
sudo nmap -T1 192.168.1.100

# Polite mode - Slows down to consume less bandwidth
sudo nmap -T2 192.168.1.100

# Normal mode - Default timing
sudo nmap -T3 192.168.1.100

# Aggressive mode - Assumes a reasonably fast and reliable network
sudo nmap -T4 192.168.1.100

# Insane mode - Very aggressive timing, may miss ports
sudo nmap -T5 192.168.1.100
```

**Custom Timing Controls**
```bash
# Set specific timing parameters
sudo nmap --min-rate 300 --max-retries 2 --host-timeout 30m 192.168.1.100
```

| Timing Parameter | Description | Example |
|------------------|-------------|---------|
| `--min-rate` | Minimum number of packets sent per second | `--min-rate 100` |
| `--max-rate` | Maximum number of packets sent per second | `--max-rate 500` |
| `--host-timeout` | Time before giving up on a host | `--host-timeout 30m` |
| `--max-retries` | Limit retry attempts | `--max-retries 2` |
| `--scan-delay` | Minimum time between probes | `--scan-delay 1s` |

**Red Team Timing Strategy**

For red team operations, consider this progressive approach:

1. Start with the stealthiest scans when time permits:
   ```bash
   sudo nmap -T1 -f -sS -sV --version-intensity 0 -oN initial_stealth.txt 192.168.1.0/24
   ```

2. If no immediate detection, gradually increase intensity:
   ```bash
   sudo nmap -T2 -sS -sV --version-intensity 1 -oN secondary_scan.txt 192.168.1.0/24
   ```

3. Focus detailed scans on high-value targets:
   ```bash
   sudo nmap -T3 -A -p- -oN detailed_target.txt 192.168.1.100
   ```

> **PRACTICAL TIP:**
> 
> Target selection dramatically affects scan duration. When scanning a large network, use a two-phase approach: first identify live hosts, then scan only those hosts in depth:
> 
> ```bash
> # Phase 1: Quick host discovery
> sudo nmap -sn 192.168.1.0/24 -oG live_hosts.grep
> 
> # Phase 2: Extract IPs and perform detailed scan only on live hosts
> cat live_hosts.grep | grep "Up" | cut -d " " -f 2 > live_ips.txt
> sudo nmap -T4 -A -iL live_ips.txt -oN detailed_results.txt
> ```

### Service Enumeration and Version Detection

Simply knowing which ports are open provides limited value. The real intelligence comes from identifying exactly what services are running and which versions are deployed. This is where Nmap's service detection capabilities shine.

#### Service Version Detection (`-sV`)

```bash
# Basic service detection
nmap -sV 192.168.1.100

# Lighter service detection (faster but less accurate)
nmap -sV --version-intensity 0 192.168.1.100

# Aggressive service detection (slower but more accurate)
nmap -sV --version-intensity 9 192.168.1.100

# Targeted service detection with light script scan
nmap -sV -sC -p 80,443,8080 192.168.1.100
```

**Version Intensity Levels**
The `--version-intensity` option controls the aggressiveness of version detection:

| Level | Description |
|-------|-------------|
| 0 | Light probing, minimal detection attempts |
| 1-8 | Increasing levels of probe intensity |
| 9 | Try all available probes |

**Version Detection Logic**
Nmap's service detection works in several stages:

1. Send TCP/UDP packets to the port
2. Examine responses for service banners 
3. If no definitive banner, send protocol-specific probes
4. Compare responses against signature database (`nmap-service-probes`)
5. Report confidence level in version identification

**Example Output Analysis**

```
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
```

This output provides multiple levels of information:
- `22/tcp open` - Port 22 is open using TCP
- `ssh` - The service is identified as SSH
- `OpenSSH 7.9p1` - The specific implementation and version
- `Debian 10+deb10u2` - The OS package and update level
- `(protocol 2.0)` - The protocol version

This level of detail allows targeted exploitation research and vulnerability matching.

#### OS Detection (`-O`)

Operating system detection provides crucial intelligence for targeting exploits and understanding the environment.

```bash
# Basic OS detection
sudo nmap -O 192.168.1.100

# OS detection with increased accuracy
sudo nmap -O --osscan-guess 192.168.1.100

# Combined OS and version detection (common approach)
sudo nmap -sV -O 192.168.1.100
```

**OS Detection Methodology**

Nmap sends a series of TCP/IP probes designed to elicit responses that vary between operating systems. Key techniques include:

1. TCP ISN sampling: Examining Initial Sequence Number patterns
2. IP ID sampling: Analyzing how IP IDs are generated
3. TCP timestamp option analysis
4. Window size and flag handling examination

The responses are compared against a database of OS fingerprints in the `nmap-os-db` file.

**OS Detection Limitations**

OS detection requires:
- At least one open and one closed port for accurate results
- Administrative/root privileges
- Unfiltered paths to the target (firewalls may prevent accurate detection)

**Enhancing OS Detection Accuracy**

```bash
# More aggressive OS detection with service detection
sudo nmap -A --osscan-limit --osscan-guess 192.168.1.100
```

| Option | Purpose |
|--------|---------|
| `--osscan-limit` | Only attempt OS detection when at least one open and one closed TCP port are found |
| `--osscan-guess` | Make a more aggressive guess about the OS |
| `-A` | Enable OS detection, version detection, script scanning, and traceroute |

![Nmap OS detection flowchart](./images/nmap_os_detection.png)
*Figure 1.2: Nmap OS detection process*

### NSE: Nmap Scripting Engine

The Nmap Scripting Engine (NSE) transforms Nmap from a port scanner into a comprehensive security assessment platform. NSE scripts automate a wide range of tasks from detailed service enumeration to vulnerability detection and even basic exploitation.

#### NSE Basics

Scripts are organized into categories for easy reference:

| Category | Purpose | Example Usage |
|----------|---------|--------------|
| `auth` | Authentication related scripts | Detect weak credentials |
| `broadcast` | Network discovery via broadcast | Find hosts not responding to ping |
| `brute` | Brute force authentication attacks | Password guessing |
| `default` | Default scripts run with `-sC` | Safe, common scripts |
| `discovery` | Network/service information gathering | Enumerate DNS, SNMP, directories |
| `dos` | Denial of Service testing | Rarely used in red team (risky) |
| `exploit` | Attempt to exploit vulnerabilities | Often used for proof-of-concept |
| `external` | Scripts that use external resources | May query third-party services |
| `fuzzer` | Send unexpected data to test input handling | Find potential vulnerabilities |
| `intrusive` | Scripts that might trigger IDS/IPS | More aggressive probing |
| `malware` | Check for backdoors/malware presence | Detect compromised systems |
| `safe` | Non-intrusive scripts | Low risk of adverse effects |
| `version` | Enhanced service/version detection | Extends `-sV` functionality |
| `vuln` | Vulnerability detection | Check for known CVEs |

#### Basic NSE Usage

```bash
# Run default script set (equivalent to -sC)
nmap --script=default 192.168.1.100

# Run scripts from a specific category
nmap --script=vuln 192.168.1.100

# Run multiple script categories
nmap --script=default,safe,discovery 192.168.1.100

# Run specific scripts
nmap --script=http-title,http-headers 192.168.1.100

# Run all scripts matching a pattern
nmap --script="http-*" 192.168.1.100

# Run all scripts except those matching a pattern
nmap --script="not intrusive" 192.168.1.100
```

#### Advanced NSE Usage

**Script Arguments**

Many NSE scripts accept arguments to customize their behavior:

```bash
# Brute force SSH with custom username/password lists
nmap --script=ssh-brute --script-args userdb=users.txt,passdb=passwords.txt -p 22 192.168.1.100

# Set HTTP paths to check for vulnerabilities
nmap --script=http-shellshock --script-args uri=/cgi-bin/test.cgi -p 80 192.168.1.100
```

**Script Selection Logic**

Scripts can be selected using boolean expressions:

```bash
# Run scripts that are in both the "default" and "safe" categories
nmap --script "default and safe" 192.168.1.100

# Run all HTTP scripts except those that are intrusive
nmap --script "(http-*) and not intrusive" 192.168.1.100
```

**Custom Script Timing**

```bash
# Control script timeout
nmap --script=http-brute --script-timeout 5m 192.168.1.100
```

#### Key Red Team NSE Scripts

**Network Enumeration Scripts**

```bash
# SMB enumeration - discover Windows shares and users
nmap --script="smb-enum-*" -p 445 192.168.1.100

# DNS enumeration - attempt zone transfers, discover subdomains
nmap --script="dns-*" -p 53 192.168.1.100

# SNMP enumeration - extract information from SNMP services
nmap --script="snmp-*" -p 161 -sU 192.168.1.100
```

**Vulnerability Assessment Scripts**

```bash
# Check for vulnerabilities in web servers
nmap --script=vuln -p 80,443,8080 192.168.1.100

# SSL/TLS vulnerability checks (Heartbleed, POODLE, etc.)
nmap --script=ssl-* -p 443 192.168.1.100

# Check for EternalBlue vulnerability (MS17-010)
nmap --script=smb-vuln-ms17-010 -p 445 192.168.1.100
```

**Authentication Testing Scripts**

```bash
# Test for default credentials across multiple services
nmap --script=auth -p 21,22,23,25,110,143 192.168.1.100

# Brute force specific services
nmap --script=ftp-brute -p 21 192.168.1.100
nmap --script=http-form-brute --script-args http-form-brute.path=/login -p 80 192.168.1.100
```

**Information Leakage Scripts**

```bash
# Extract information from HTTP headers
nmap --script=http-headers,http-generator -p 80,443 192.168.1.100

# Retrieve emails from web pages
nmap --script=http-emails -p 80,443 192.168.1.100
```

> **CASE STUDY: Using NSE in a Red Team Scenario**
> 
> During a red team exercise for a financial institution, initial access was gained through a vulnerability discovered using the `http-vuln-cve2017-8917` NSE script. The team identified a Drupal server running version 8.3.3 vulnerable to CVE-2017-8917. The script not only identified the vulnerability but also provided proof-of-concept exploitation that allowed database credentials to be extracted. These credentials were then used to access internal resources due to password reuse, highlighting the danger of exposed vulnerable web applications.
>
> *Source: Redacted real-world red team engagement report, 2018*

#### Creating Custom NSE Scripts

For specialized assessments, custom NSE scripts provide powerful automation capabilities. Below is a simple example script that checks for a custom vulnerability:

```lua
-- File: http-custom-check.nse
description = [[
Checks for a specific custom vulnerability in web applications.
]]

categories = {"safe", "discovery"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

-- Rule to determine which targets to check
portrule = shortport.port_or_service({80, 443}, {"http", "https"})

-- Main action function
action = function(host, port)
  local path = "/admin/status.php"
  local response = http.get(host, port, path)
  
  if response.status == 200 then
    if string.match(response.body, "version%s*=%s*['\"]1%.2%.3['\"]") then
      return "Host is vulnerable to XYZ vulnerability (running version 1.2.3)"
    end
  end
  
  return "No vulnerability detected"
end
```

Save this script to `/usr/share/nmap/scripts/` and update the script database:

```bash
sudo nmap --script-updatedb
```

Then use your custom script:

```bash
nmap --script=http-custom-check -p 80,443 192.168.1.100
```

### Evasion Techniques

In red team operations, avoiding detection is often as important as gathering information. Nmap offers several techniques to evade intrusion detection systems and firewall alerts.

#### Timing Evasion

The simplest evasion technique is to slow down scans:

```bash
# Very slow scan with randomized timing
sudo nmap -T0 --scan-delay 10s 192.168.1.100
```

#### Fragmentation and MTU Manipulation

Breaking packets into smaller fragments can bypass some packet inspection systems:

```bash
# Fragment packets into 8 bytes or less
sudo nmap -f 192.168.1.100

# Double fragmentation for even smaller fragments
sudo nmap -ff 192.168.1.100

# Specify custom MTU (must be multiple of 8)
sudo nmap --mtu 24 192.168.1.100
```

#### Decoys and Spoofing

Make the scan appear to come from multiple sources:

```bash
# Generate 5 random decoys plus your real IP
sudo nmap -D RND:5 192.168.1.100

# Specify exact decoy IPs (ME indicates your real IP position)
sudo nmap -D 10.0.0.1,10.0.0.2,ME,10.0.0.3 192.168.1.100

# Appear completely spoofed (won't see results)
sudo nmap -S 10.0.0.200 -e eth0 192.168.1.100
```

#### Source Port Manipulation

Many firewalls allow traffic from certain source ports (e.g., DNS, HTTP):

```bash
# Scan from source port 53 (DNS)
sudo nmap --source-port 53 192.168.1.100

# Scan from source port 80 (HTTP)
sudo nmap --source-port 80 192.168.1.100
```

#### Data Payload Manipulation

Add random data to packets to evade signature-based detection:

```bash
# Append random data to packets
sudo nmap --data-length 200 192.168.1.100
```

#### MAC Address Spoofing

When scanning local networks, MAC spoofing can be useful:

```bash
# Spoof MAC address
sudo nmap --spoof-mac 00:11:22:33:44:55 192.168.1.100

# Use random MAC address
sudo nmap --spoof-mac 0 192.168.1.100
```

#### Advanced Obfuscation Technique

For maximum evasion, combine multiple techniques:

```bash
# Comprehensive evasion example
sudo nmap -T1 -f -D RND:10 --data-length 110 --source-port 53 \
     --spoof-mac 0 --randomize-hosts -p 445 -Pn 192.168.1.0/24
```

> **WARNING**
> Advanced evasion techniques that involve packet manipulation may cause network issues or trigger different types of alerts. Always ensure you have proper authorization before employing these techniques.

### Practical Examples

#### Network Topology Mapping

Creating a comprehensive map of a target network involves several steps:

```bash
# 1. Identify live hosts
sudo nmap -sn -PE -PP -PS80,443 -PA3389 -PU40125 -T4 192.168.1.0/24 --open

# 2. Discover host details
sudo nmap -p 21,22,23,25,80,443,445,3389 -sV -O --osscan-guess 192.168.1.0/24 -oX network_scan.xml

# 3. Generate network diagram (requires additional tools)
xsltproc -o network_scan.html /usr/share/nmap/nmap.xsl network_scan.xml
```

You can visualize the results further with tools like Zenmap (Nmap's GUI) or convert the XML to visuals using tools like EyeWitness or Maltego.

#### Identifying Vulnerable Services

```bash
# Comprehensive vulnerability scan
sudo nmap -sS -sV -p- --script vuln 192.168.1.100 -oN vulnerabilities.txt

# Targeted vulnerability scan for web servers
sudo nmap -sV -p 80,443,8080 --script "http-vuln-*" 192.168.1.100
```

#### Internal Network Penetration Testing Workflow

```bash
# 1. Initial host discovery (minimal traffic)
sudo nmap -sn -PS 192.168.1.0/24 -oG hosts_up.grep

# 2. Extract live hosts
cat hosts_up.grep | grep "Up" | cut -d " " -f 2 > live_hosts.txt

# 3. Open port detection (minimal service interaction)
sudo nmap -sS -p 21,22,23,25,53,80,139,443,445,3389,8080 -iL live_hosts.txt -oG open_ports.grep

# 4. Focus on servers with web ports
cat open_ports.grep | grep "80/open" > web_servers.txt

# 5. Detailed analysis of web servers
sudo nmap -sV -p- --script "http-*,ssl-*" -iL web_servers.txt -oN web_detailed.txt
```

#### External Penetration Testing Workflow

```bash
# 1. Footprinting with minimal interaction
sudo nmap -sS -p 80,443,8080 -T2 --open --randomize-hosts example.com -oG external_initial.grep

# 2. Service enumeration on discovered hosts
cat external_initial.grep | grep "open" | cut -d " " -f 2 > external_hosts.txt
sudo nmap -sV -p 80,443,8080 --version-intensity 6 -iL external_hosts.txt -oN external_services.txt

# 3. Vulnerability assessment
sudo nmap --script vuln -p 80,443,8080 -iL external_hosts.txt -oN external_vulnerabilities.txt
```

### Nmap Scripting and Automation

#### Nmap in Bash Scripts

Automating Nmap scans with Bash makes complex workflows repeatable:

```bash
#!/bin/bash
# progressive_scan.sh - Perform increasingly detailed scans

target=$1
output_dir="scan_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p $output_dir

echo "[+] Starting initial host discovery"
nmap -sn $target -oG $output_dir/hosts.grep

echo "[+] Extracting live hosts"
cat $output_dir/hosts.grep | grep "Up" | cut -d " " -f 2 > $output_dir/live_hosts.txt

echo "[+] Performing quick port scan"
nmap -sS --top-ports 100 -iL $output_dir/live_hosts.txt -oG $output_dir/quick_ports.grep

echo "[+] Identifying interesting hosts"
cat $output_dir/quick_ports.grep | grep "open" > $output_dir/interesting_hosts.grep
cat $output_dir/interesting_hosts.grep | cut -d " " -f 2 > $output_dir/interesting_hosts.txt

echo "[+] Performing detailed scan on interesting hosts"
nmap -sS -sV -O -p- -iL $output_dir/interesting_hosts.txt -oN $output_dir/detailed_scan.txt

echo "[+] Running vulnerability scripts on interesting hosts"
nmap --script vuln -iL $output_dir/interesting_hosts.txt -oN $output_dir/vulnerabilities.txt

echo "[+] Scans complete. Results in $output_dir/"
```

Usage:
```bash
./progressive_scan.sh 192.168.1.0/24
```

#### Nmap Output Processing

Nmap produces several output formats that can be processed programmatically:

```bash
# Generate all output formats
sudo nmap 192.168.1.0/24 -oA network_scan

# This creates:
# - network_scan.nmap (human-readable)
# - network_scan.xml (XML format)
# - network_scan.gnmap (grepable format)
```

**Processing XML output with Python:**

```python
#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import sys

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    # Dictionary to store results
    results = {}
    
    # Process each host
    for host in root.findall('./host'):
        # Get IP address
        addr = host.find('./address').get('addr')
        results[addr] = {'ports': []}
        
        # Get hostname if available
        hostname_elem = host.find('./hostnames/hostname')
        if hostname_elem is not None:
            results[addr]['hostname'] = hostname_elem.get('name')
        
        # Get open ports and services
        for port in host.findall('./ports/port'):
            if port.find('./state').get('state') == 'open':
                port_info = {
                    'protocol': port.get('protocol'),
                    'port': port.get('portid')
                }
                
                # Get service info if available
                service = port.find('./service')
                if service is not None:
                    port_info['service'] = service.get('name')
                    if service.get('product'):
                        port_info['product'] = service.get('product')
                    if service.get('version'):
                        port_info['version'] = service.get('version')
                
                results[addr]['ports'].append(port_info)
    
    return results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} <nmap_xml_file>".format(sys.argv[0]))
        sys.exit(1)
    
    results = parse_nmap_xml(sys.argv[1])
    
    # Print results in a simple format
    for ip, host_info in results.items():
        print(f"Host: {ip}")
        if 'hostname' in host_info:
            print(f"Hostname: {host_info['hostname']}")
        
        print("Open Ports:")
        for port in host_info['ports']:
            port_str = f"  {port['port']}/{port['protocol']}"
            if 'service' in port:
                port_str += f" - {port['service']}"
            if 'product' in port:
                port_str += f" ({port['product']}"
                if 'version' in port:
                    port_str += f" {port['version']}"
                port_str += ")"
            print(port_str)
        print()
```

Usage:
```bash
python3 parse_nmap.py network_scan.xml
```

#### Integrating Nmap with Other Tools

**Nmap to Metasploit:**

```bash
# Run Nmap and create output for Metasploit
sudo nmap -sS -sV -O -p- 192.168.1.0/24 -oX network_scan.xml

# In Metasploit:
db_import network_scan.xml
hosts
services
```

**Nmap to EyeWitness:**

```bash
# Generate XML output
sudo nmap -sV -p 80,443,8080,8443 --open 192.168.1.0/24 -oX web_services.xml

# Use EyeWitness to capture screenshots
eyewitness --web -x web_services.xml -d eyewitness_output
```

### Conclusion

Nmap remains the most critical reconnaissance tool in a red teamer's arsenal. Its flexibility, extensibility, and power allow for tailored scanning approaches in virtually any scenario. While we've covered advanced usage patterns here, the tool continues to evolve, and new scripts are added regularly. Regular review of the official documentation and script repository is recommended to stay current with the latest capabilities.

Mastering Nmap's advanced features provides a significant advantage in security assessments, allowing for precise, efficient, and targeted information gathering that forms the foundation of successful red team engagements.

### Additional Resources

- [Official Nmap Documentation](https://nmap.org/docs.html)
- [Nmap Network Scanning](https://nmap.org/book/) by Gordon "Fyodor" Lyon
- [NSE Script Database](https://nmap.org/nsedoc/)
- [Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)
