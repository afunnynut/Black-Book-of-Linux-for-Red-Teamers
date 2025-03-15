# Chapter 6: Network Vulnerability Assessment

Network vulnerability assessment is a critical phase in the red team methodology. It involves identifying and analyzing security weaknesses in network infrastructure, services, and configurations. This chapter explores powerful tools available in Kali Linux and Parrot OS designed specifically for network vulnerability assessment.

## Legion

Legion (formerly SECFORCE's Sparta) is an open-source, semi-automated network penetration testing framework that combines various reconnaissance and vulnerability scanning tools into a streamlined workflow.

### Key Features

- **Integrated toolset**: Combines Nmap, Nikto, Hydra, and various other tools
- **Service enumeration**: Automatically identifies running services
- **Vuln scanning**: Scans detected services for vulnerabilities
- **Brute forcing**: Automated credential attacks
- **Interactive GUI**: Simplifies the assessment process
- **Reporting**: Generates detailed reports of findings

### Service Enumeration and Vulnerability Detection

Legion uses a staged approach to network assessment:

1. **Host discovery**: Identifies live hosts on the network
2. **Port scanning**: Discovers open ports and services
3. **Service fingerprinting**: Determines service versions
4. **Vulnerability scanning**: Tests services for known vulnerabilities
5. **Credential attacks**: Attempts to brute-force service credentials

The tool automatically selects appropriate scanning methods based on discovered services. For example:

- For web servers: Runs Nikto, dirb, wpscan (if WordPress is detected)
- For SMB: Runs enum4linux, nbtscan, samrdump
- For SSH/FTP/SMTP: Attempts credential brute-forcing with Hydra

### Example: Comprehensive Network Assessment

To initiate a comprehensive scan of a target network:

1. Launch Legion from the Applications menu or terminal:
   ```bash
   sudo legion
   ```

2. Enter target IP ranges or hostnames in the "Host(s)" field:
   ```
   192.168.1.0/24
   ```

3. Configure scan options:
   - Select scan type (Quick, Regular, or Comprehensive)
   - Choose specific tools to run
   - Configure threading options

4. Start the scan and monitor progress in the GUI

After the scan completes, Legion displays results in a hierarchical view:
- Hosts → Ports → Services → Vulnerabilities

Sample output for a vulnerable web server:
```
Host: 192.168.1.10
  Port: 80 (http)
    Service: Apache 2.4.29
      Vulnerabilities:
        - CVE-2021-40438: mod_proxy SSRF (Critical)
        - Directory listing enabled (Medium)
      Notes:
        - PHP version 7.2.24 detected (outdated)
        - WordPress 5.2.3 detected
```

### Red Team Workflow with Legion

For effective red team operations, consider this Legion workflow:

1. **Initial reconnaissance**:
   ```bash
   sudo legion -t 192.168.1.0/24 --nmap-options "-sS -T4 -A"
   ```

2. **Focus on critical infrastructure**:
   - Select discovered hosts of interest
   - Right-click and choose "Re-scan host(s)"
   - Select more comprehensive scanning options

3. **Export findings for exploitation**:
   - Right-click on services or vulnerabilities
   - Select "Copy to clipboard" for use with other tools
   - Use "Notes" feature to document potential attack vectors

4. **Generate reports for documentation**:
   - Go to "Tools" → "Generate Report"
   - Select report format (HTML or Text)

## Sparta/SPARTA

While Legion is the successor to Sparta/SPARTA, some red teams still prefer the original tool for its simplicity and reliability. This section covers the original SPARTA's unique features and workflows.

### Key Features

- **Minimalist interface**: Simple, task-oriented design
- **Service-specific automation**: Targeted tools for each service type
- **Custom tool integration**: Easily add your own tools
- **Stage-based workflow**: Logical progression through testing phases

### Workflow Automation

SPARTA excels in automating common penetration testing tasks with its stage-based approach:

1. **Port scanning**: Uses Nmap to identify open ports
2. **Service identification**: Fingerprints services running on open ports
3. **Service enumeration**: Runs appropriate tools based on discovered services

The tool automatically schedules tasks, prioritizing them based on expected run time and importance.

### Example: From Discovery to Exploitation

A typical SPARTA workflow for a network assessment:

```bash
# Start SPARTA
sudo sparta
```

1. Enter target IP or network in the "Target host/range" field:
   ```
   10.10.10.0/24
   ```

2. Click "Add target" and then "Start scan"

3. As services are discovered, SPARTA will schedule specific tools:
   - For HTTP: nikto, whatweb, dirb
   - For MySQL: mysql-default-credentials
   - For SSH: ssh-default-credentials

4. Review results by clicking on a host, then selecting services and tool outputs

Example output from a service scan:
```
[+] Found HTTP service on port 80
[+] nikto results:
    - /admin/ directory discovered
    - Outdated Apache version 2.4.18
    - PHP information disclosure
[+] dirb results:
    - /backup/ directory accessible
    - /config.php~ backup file discovered
```

### Custom Tool Integration

One of SPARTA's strengths is the ability to add custom tools to your workflow:

1. Click on "Settings" → "Configure tool paths"
2. Select "Add new tool"
3. Configure the tool properties:
   - Name: CustomSMBEnum
   - Command: python3 /path/to/custom_smb_enum.py [IP] [PORT]
   - Services: smb
   - Inferences: host.enumerated

This allows red teams to integrate specialized or custom-developed tools into their assessment workflow.

## AutoRecon

AutoRecon is a multi-threaded reconnaissance tool designed to automate the initial enumeration process and save time during CTFs and penetration tests.

### Key Features

- **Multi-threaded design**: Runs multiple tools concurrently
- **Comprehensive scanning**: Automates numerous enumeration tools
- **Targeted scanning**: Service-specific enumeration
- **Organized output**: Well-structured results for easy analysis
- **Low resource usage**: Efficient resource management
- **Customizable**: Configurable tool behavior

### Tool Configuration

AutoRecon uses a plugin-based architecture that allows for flexible configuration of scanning behavior. The default configuration includes:

- **Port scanning**: Initial and full TCP/UDP port scans
- **Service enumeration**: Service-specific enumeration tools
- **Web scanning**: Web content discovery and vulnerability assessment
- **Brute forcing**: Service authentication testing

Custom configuration can be specified using command-line options or configuration files. For example:

```bash
# Use custom configuration file
autorecon target.com --config /path/to/custom-config.toml

# Override specific tool options
autorecon target.com --nmap-append="-T4 --script vulners"
```

### Example: CTF-style Network Enumeration

Here's how to use AutoRecon for efficient enumeration of a target:

```bash
# Basic scan of a single target
autorecon 10.10.10.10

# Scan multiple targets
autorecon 10.10.10.10 target.com 192.168.1.0/24

# Scan with verbose output and custom output directory
autorecon 10.10.10.10 -v -o ~/engagements/target-company
```

After execution, AutoRecon creates a directory structure organized by target, port, and service:

```
output/
└── 10.10.10.10/
    ├── nmap/
    │   ├── _quick_tcp_nmap.txt
    │   ├── _full_tcp_nmap.txt
    │   └── _top_udp_nmap.txt
    ├── scans/
    │   ├── tcp_80_http/
    │   │   ├── dirb.txt
    │   │   ├── nikto.txt
    │   │   └── whatweb.txt
    │   ├── tcp_22_ssh/
    │   │   └── ssh_enum.txt
    │   └── tcp_445_smb/
    │       ├── smbmap.txt
    │       └── enum4linux.txt
    └── report/
        └── notes.txt
```

Sample output from a scan might reveal:

```
[*] Target:   10.10.10.10
[*] Services:
    - TCP/22: OpenSSH 7.6p1 Ubuntu
    - TCP/80: Apache httpd 2.4.29
    - TCP/445: Samba 4.7.6-Ubuntu
[*] Findings:
    - HTTP: WordPress installation at /blog/
    - SMB: Anonymous access enabled
    - SSH: User enumeration possible (CVE-2018-15473)
```

### Red Team Strategies with AutoRecon

For effective use in red team operations:

1. **Initial phase scanning**:
   ```bash
   autorecon --only-scans-dir target-range.txt
   ```

2. **Targeted scanning based on initial findings**:
   ```bash
   autorecon 10.10.10.10 -t ftp,smb,http --heartbeat 60
   ```

3. **Integrate into a broader workflow**:
   ```bash
   # Scan and generate findings summary
   autorecon 10.10.10.10 -o output
   
   # Use findings for targeted exploitation
   grep -r "Found" output/10.10.10.10/
   ```

## Additional Network Vulnerability Assessment Tools

### OpenVAS (GVM)

Greenbone Vulnerability Manager (formerly OpenVAS) is a comprehensive vulnerability scanning framework.

Quick setup and scan:
```bash
# Initialize OpenVAS
gvm-setup

# Start services
gvm-start

# Create a quick task from command line
gvm-cli --gmp-username admin --gmp-password admin socket --xml "<create_task><name>Quick Scan</name><target id='target-uuid'></target><config id='daba56c8-73ec-11df-a475-002264764cea'></config></create_task>"
```

### Nessus Essentials

Nessus Essentials (formerly Nessus Home) provides professional-grade vulnerability scanning for free with limited targets.

Key scanning strategies:
- Basic Network Scan: Identifies common network vulnerabilities
- Web Application Tests: Focuses on web-specific issues
- Credential Patch Audits: Verifies patching status

### Nexpose Community Edition

Rapid7's Nexpose Community Edition provides enterprise-grade vulnerability scanning.

Example console commands:
```bash
# Create a new site
nexpose-cli site create --name "Target Network" --hosts "192.168.1.0/24"

# Run a scan
nexpose-cli scan start --site-id 1
```

### Lynis

Lynis is a security auditing tool for Linux systems.

Example for targeted system assessment:
```bash
lynis audit system --pentest
```

## Comprehensive Network Assessment Methodology

For thorough network vulnerability assessments, red teams should follow a structured methodology:

### 1. Initial Reconnaissance
- Identify network boundaries and accessible hosts
- Map the network topology 
- Identify key infrastructure components

### 2. Service Enumeration and Fingerprinting
- Identify all running services and their versions
- Determine operating systems and configurations
- Document potential entry points

### 3. Vulnerability Identification
- Scan for known vulnerabilities in detected services
- Map findings to exploit databases
- Prioritize vulnerabilities based on exploitability and impact

### 4. Exploitation Verification
- Validate vulnerabilities through controlled exploitation
- Document successful attack paths
- Note potential lateral movement opportunities

### 5. Documentation and Reporting
- Document findings with evidence
- Provide clear, actionable remediation steps
- Include risk assessment and business impact

## Best Practices for Network Vulnerability Assessment

1. **Scope Definition**: Clearly define assessment boundaries and rules of engagement before starting

2. **Staged Approach**: Begin with passive techniques before moving to more active scanning

3. **Resource Limitations**: Be mindful of bandwidth and system resource constraints

4. **Avoid Disruption**: Configure scanners to minimize impact on production services

5. **False Positive Verification**: Manually verify critical findings to eliminate false positives

6. **Documentation**: Maintain detailed logs of all testing activities

7. **Compliance Awareness**: Be aware of regulatory requirements affecting the target environment

## Conclusion

Network vulnerability assessment tools form a critical component of the red team toolkit. Each tool offers different strengths and capabilities:

- Legion/SPARTA provides an integrated GUI-based approach for comprehensive assessment
- AutoRecon excels at efficient, multi-threaded enumeration
- OpenVAS, Nessus, and Nexpose offer enterprise-grade vulnerability detection
- Lynis provides focused Linux system security auditing

By mastering these tools and following structured methodologies, red teams can efficiently discover and document vulnerabilities across complex network environments. Remember that the most effective assessments combine automated scanning with manual verification and creative thinking to identify security weaknesses that automated tools might miss.

The findings from network vulnerability assessments feed directly into exploitation and post-exploitation activities, which we'll explore in subsequent chapters. The vulnerable services, systems, and applications discovered during this phase become the primary targets for the next stages of the red team operation.
