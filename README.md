The Back Book of Linux for CyberSecurity and RedTeamers is a pet project of mine where I am attempting to document common Kali and Parrot OS tools for redteaming, cyber security and bug bounty. The overall structure of the book is as below

# [The Black Book of Linux for CyberSecurity](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/fd0d006508ccb348e29c963604fb7facc924ad61/README.md)

## Book Structure Overview

### [Preface](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/2c7ab9bec46bf29704686a7bdec2393a80f3fc58/preface.md)
- Purpose and scope of this book
- Who this book is for (experienced Linux users focusing on red teaming)
- How to use this book effectively

### [Introduction: The Red Team Arsenal](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/introduction.md)
- The philosophy behind offensive security tools
- Understanding the red team methodology
- How tools map to the MITRE ATT&CK framework
- Setting up a proper lab environment for practicing

## Part I: Reconnaissance and Information Gathering

### [Chapter 1: Network Discovery and Mapping](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-1.md)
- **Nmap** - Advanced usage techniques
  - Port scanning strategies
  - Service enumeration
  - NSE scripting for targeted reconnaissance
  - Timing and evasion techniques
  - Practical examples: Network topology mapping, identifying vulnerable services
- **Masscan** - Rapid port scanning
  - Configuration for speed vs. accuracy
  - Integration with other tools
  - Example: Internet-scale scanning techniques
- **Spiderfoot** - Automated OSINT
  - Module configuration
  - Target profiling
  - Example: Building a complete digital footprint of a target organization
- **Recon-ng** - Modular reconnaissance framework
  - Creating custom workflows
  - Data management and reporting
  - Example: Automating multi-phase reconnaissance

### [Chapter 2: Web Application Reconnaissance](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-2.md)
- **Gobuster/Dirb/Dirbuster** - Directory enumeration
  - Custom wordlists
  - Handling different response codes
  - Example: Discovering hidden administrative interfaces
- **Nikto** - Web server scanning
  - Configuration options
  - False positive reduction
  - Example: Identifying server misconfigurations
- **WhatWeb** - Website fingerprinting
  - Identification techniques
  - Example: Determining technology stacks
- **Wappalyzer** (CLI version) - Technology detection
  - Example: Mapping an application's components
- **Sublist3r/Amass** - Subdomain enumeration
  - Techniques for discovering subdomains
  - Example: Mapping an organization's web presence

### [Chapter 3: Wireless Network Analysis](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-3.md)
- **Aircrack-ng Suite** - Complete toolkit
  - Airmon-ng, Airodump-ng, Aireplay-ng
  - WEP/WPA/WPA2 analysis
  - Example: Setting up rogue access points
- **Kismet** - Wireless network detector
  - Passive monitoring techniques
  - Example: Creating signal maps
- **Wifite** - Automated wireless auditing
  - Configuration for different attack types
  - Example: Rapid assessment of multiple networks
- **Bettercap** - WiFi monitoring and MITM
  - Example: Setting up WiFi jamming and evil twin attacks

## Part II: Vulnerability Assessment

### [Chapter 4: Automated Scanning Tools](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-4.md)
- **OpenVAS** - Vulnerability scanning framework
  - Scan configuration
  - Report interpretation
  - Example: Full vulnerability assessment of a network
- **Nessus Essentials** (formerly Home) - Configuration and usage
  - Effective scanning strategies
  - Example: Targeted vulnerability discovery
- **Nexpose Community Edition** - Enterprise-grade scanning
  - Example: Risk scoring and prioritization
- **Lynis** - Security auditing for Linux systems
  - Example: Hardening assessment of Linux servers

### [Chapter 5: Web Application Vulnerability Scanning](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-5.md)
- **OWASP ZAP** - Web application scanner
  - Active vs. passive scanning
  - Custom scan policies
  - Example: Detecting OWASP Top 10 vulnerabilities
- **Skipfish** - Active web application scanner
  - Configuration for different application types
  - Example: High-speed application mapping
- **Wapiti** - Web vulnerability scanner
  - Module configuration
  - Example: Identifying injection flaws
- **Nuclei** - Template-based vulnerability scanner
  - Creating custom templates
  - Example: Discovering new CVEs with custom templates

### [Chapter 6: Network Vulnerability Assessment](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-6.md)
- **Legion** - Automated network scanner
  - Service enumeration and vulnerability detection
  - Example: Comprehensive network assessment
- **Sparta/SPARTA** - Network infrastructure penetration testing
  - Workflow automation
  - Example: From discovery to exploitation
- **AutoRecon** - Multi-threaded reconnaissance
  - Tool configuration
  - Example: CTF-style network enumeration

## Part III: Exploitation

### [Chapter 7: Metasploit Framework In-Depth](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-7.md)
- **MSFconsole** - Core interface mastery
  - Command structure and workflows
  - Database integration
  - Example: Setting up workspaces for different engagements
- **Payload Generation and Delivery**
  - Msfvenom usage for various scenarios
  - Encoder selection and evasion techniques
  - Example: Creating undetectable payloads
- **Post-Exploitation Modules**
  - Credential harvesting
  - Privilege escalation
  - Persistence mechanisms
  - Example: Complete post-compromise workflow
- **Metasploit Automation**
  - Resource scripts
  - API usage
  - Example: Creating custom automated attack chains

### [Chapter 8: Social Engineering Toolkit](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-8.md)
- **SET Framework** - Comprehensive overview
  - Spear-phishing attacks
  - Website cloning
  - Example: Crafting convincing phishing campaigns
- **BeEF** - Browser Exploitation Framework
  - Hook integration
  - Command modules
  - Example: Client-side attack chaining
- **Gophish** - Phishing campaign management
  - Campaign setup and monitoring
  - Example: Measuring user susceptibility to phishing

### [Chapter 9: Exploitation Frameworks and Tools](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-9.md)
- **Routersploit** - Router exploitation
  - Module usage
  - Example: Compromising common network devices
- **Empire** - Post-exploitation framework
  - Agents and listeners
  - PowerShell without PowerShell
  - Example: Living-off-the-land techniques
- **Koadic** - COM Command & Control
  - JScript RAT usage
  - Example: Establishing stealth persistence
- **Armitage** - Graphical cyber attack management
  - Collaborative penetration testing
  - Example: Team-based exploitation

### [Chapter 10: Web Application Exploitation](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-10.md)
- **SQLmap** - SQL injection mastery
  - Detection techniques
  - Database enumeration and extraction
  - Example: Extracting sensitive data through blind SQLi
- **Commix** - Command injection exploiter
  - Detection and exploitation modes
  - Example: Gaining shell access through injection flaws
- **OWASP Juice Shop** - Practice environment
  - Example: Real-world exploitation techniques
- **XSSer** - Cross-site scripting framework
  - Payload generation
  - Example: Session hijacking via XSS

## Part IV: Post-Exploitation

### [Chapter 11: Privilege Escalation](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-11.md)
- **LinPEAS/WinPEAS** - Privilege escalation scanning
  - Output interpretation
  - Example: Automating privilege escalation discovery
- **Linux Exploit Suggester** - Kernel vulnerability identification
  - Example: Targeting kernel exploits
- **GTFOBins** techniques - Living off the land
  - Example: Escalating privileges with standard binaries
- **PwnKit, DirtyCow, and other specific exploits**
  - Technical details and usage
  - Example: Reliable privilege escalation chains

### [Chapter 12: Maintaining Access](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-12.md)
- **Weevely** - Web shell management
  - Stealth configuration
  - Example: Creating undetectable backdoors
- **Cowrie** - SSH honeypot (for understanding defenses)
  - Example: Setting up monitoring for SSH attacks
- **Veil Framework** - Payload generation
  - AV evasion techniques
  - Example: Creating persistent backdoors
- **TheFatRat** - Backdoor creator
  - Multi-platform payloads
  - Example: Android backdoor deployment

### [Chapter 13: Data Exfiltration and Collection](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-13.md)
- **PacketWhisper** - Steganographic exfiltration
  - Configuration options
  - Example: Bypassing DLP systems
- **DNScat2** - Command and control over DNS
  - Tunneling techniques
  - Example: Bypassing firewall restrictions
- **Mimikatz** (on Linux) - Credential extraction
  - Cross-platform techniques
  - Example: Extracting Windows credentials from Linux
- **LaZagne** - Password recovery
  - Module configuration
  - Example: Comprehensive credential harvesting

## Part V: Network Attacks and Analysis

### [Chapter 14: Man-in-the-Middle Frameworks](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-14.md)
- **Ettercap** - MITM attacks
  - ARP poisoning
  - Custom filters
  - Example: SSL stripping attack
- **Bettercap** - Network attack toolkit
  - Module usage
  - Example: Automated credential harvesting
- **Wireshark/Tshark** - Traffic analysis
  - Capture filters
  - Display filters
  - Example: Extracting credentials from unencrypted protocols
- **Responder** - LLMNR/NBT-NS/MDNS poisoning
  - Configuration options
  - Example: Capturing NTLMv2 hashes

### [Chapter 15: Wireless Attacks](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-15.md)
- **Fluxion** - WPA/WPA2 security auditing
  - Attack methodology
  - Example: Social engineering wireless attacks
- **Airgeddon** - Wireless attack framework
  - Attack modes
  - Example: Complete wireless compromise workflow
- **WiFi-Pumpkin** - Rogue access point framework
  - Module configuration
  - Example: Creating captive portals for credential harvesting
- **Wifiphisher** - Automated phishing attacks
  - Template customization
  - Example: Evil twin attacks

### [Chapter 16: Network Spoofing and Hijacking](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-16.md)
- **Scapy** - Packet manipulation
  - Custom packet creation
  - Example: Advanced network spoofing
- **Yersinia** - Layer 2 attack framework
  - Protocol attacks
  - Example: DHCP starvation and spoofing
- **Macchanger** - MAC address manipulation
  - Example: Evading MAC filtering
- **MITM6** - IPv6 MITM tool
  - Example: DNS takeover via IPv6

## Part VI: Password Attacks

### [Chapter 17: Password Cracking Tools](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-17.md)
- **Hashcat** - GPU-accelerated password cracking
  - Attack modes
  - Rule-based attacks
  - Example: Optimizing for different hash types
- **John the Ripper** - Versatile password cracker
  - Custom rules
  - Example: Cracking complex password patterns
- **Hydra** - Online password attacks
  - Service-specific techniques
  - Example: Rate limiting bypass methods
- **Medusa** - Parallel brute forcing
  - Example: Distributed password attacks
- **Mentalist** - Wordlist generation
  - Profile-based wordlists
  - Example: Creating targeted wordlists

### [Chapter 18: Credential Hunting and Management](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-18.md)
- **CeWL** - Custom wordlist generator
  - Website scraping for organization-specific terms
  - Example: Creating targeted wordlists
- **Crunch** - Wordlist generation
  - Pattern-based generation
  - Example: Exhaustive smaller character sets
- **CredNinja** - Credential validation
  - Mass validation techniques
  - Example: Testing discovered credentials across networks
- **BruteSpray** - Service bruteforcing
  - Example: From Nmap to access

## Part VII: Advanced Topics

### [Chapter 19: Anonymity and Evasion](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-19.md)
- **ProxyChains/Proxychains-ng** - Traffic proxying
  - Configuration for different proxy types
  - Example: Routing tools through TOR
- **Anonsurf** (Parrot OS) - Anonymization
  - Configuration options
  - Example: Setting up fully anonymous testing
- **Tor** - Anonymous networking
  - Example: Setting up hidden services
- **Nipe** - Traffic routing through Tor
  - Example: Transparent tool anonymization

### [Chapter 20: Cryptography and Steganography Tools](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-20.md)
- **OpenSSL** - Cryptographic toolkit
  - Common red team uses
  - Example: Creating malicious certificates
- **Steghide** - Steganography tool
  - Embedding and extracting data
  - Example: Creating covert communication channels
- **Stegosuite** - Advanced steganography
  - Example: Multi-format data hiding
- **CloakifyFactory** - Data exfiltration
  - Example: Evading data loss prevention systems

### [Chapter 21: Forensics Tools for Red Teamers](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-21.md)
- **Foremost/Scalpel** - File carving
  - Understanding how data is recovered
  - Example: Anti-forensics techniques
- **Autopsy/Sleuth Kit** - Digital forensics
  - Understanding investigative techniques
  - Example: Covering tracks effectively
- **Volatility** - Memory forensics
  - Understanding memory artifacts
  - Example: Memory-resident malware techniques
- **Extundelete** - File recovery
  - Example: Secure deletion methods

### [Chapter 22: Reporting and Documentation](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-22.md)
- **Dradis** - Collaboration and reporting
  - Project setup
  - Example: Comprehensive red team documentation
- **Faraday** - Integrated penetration testing environment
  - Workflow management
  - Example: Collaborative penetration testing
- **MagicTree** - Data management
  - Example: Organizing complex test results
- **Pipal** - Password analysis
  - Example: Creating insightful statistics from engagements

## Part VIII: MITRE ATT&CK Integration

### [Chapter 23: Mapping Tools to TTPs](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-23.md)
- Reconnaissance techniques and corresponding tools
- Initial access tools and methods
- Execution frameworks and utilities
- Persistence mechanisms and tools
- Privilege escalation techniques and tools
- Defense evasion tools and techniques
- Credential access specialized tools
- Discovery automation tools
- Lateral movement frameworks
- Collection and exfiltration tools
- Command and control frameworks

### [Chapter 24: Emulating Advanced Threat Actors](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-24.md)
- **Caldera** - Automated adversary emulation
  - Operation configuration
  - Example: Running complete adversary profiles
- **Atomic Red Team** - Test case execution
  - Example: Validating detection capabilities
- **APTSimulator** - Quick APT simulation
  - Example: Generating artifacts of known threat actors
- **Infection Monkey** - Data center security testing
  - Example: Testing zero-trust architectures

## Part IX: Specialized Environments

###[ Chapter 25: Cloud Security Tools](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-25.md)
- **ScoutSuite** - Multi-cloud security auditing
  - Provider-specific modules
  - Example: Assessing AWS security posture
- **Pacu** - AWS exploitation framework
  - Module usage
  - Example: Privilege escalation in AWS
- **CloudSploit** - Cloud security scanning
  - Example: Detecting common cloud misconfigurations
- **S3Scanner** - AWS S3 bucket enumeration
  - Example: Finding exposed data

### [Chapter 26: Container Security](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-26.md)
- **Kube-Hunter** - Kubernetes penetration testing
  - Example: Attacking container orchestration
- **Deepce** - Docker enumeration
  - Example: Container escape techniques
- **Grype** - Container vulnerability scanning
  - Example: Finding exploitable container components
- **Trivy** - Comprehensive vulnerability scanner
  - Example: Detecting vulnerable dependencies

### [Chapter 27: IoT Security Tools](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/chapter-27.md)
- **RFCrack** - RF analysis
  - Example: Testing IoT communications
- **Firmwalker** - Firmware analysis
  - Example: Extracting sensitive information from firmware
- **Expliot** - IoT exploitation framework
  - Example: Attacking IoT protocols
- **IoTSeeker** - IoT device discovery
  - Example: Finding vulnerable devices

## Appendices

### [Appendix A: Comprehensive Tool Reference](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/appendix-a.md)
- Alphabetical listing of all tools
- Quick reference for syntax and common uses
- Alternative tools for specific functions

### [Appendix B: Custom Script Collection](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/web_vuln_scanner.py)
- Time-saving bash scripts
- Integration scripts
- Automation helpers

### [Appendix C: Virtual Lab Setup](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/appendix-c.md)
- Vulnerable machines and networks
- Isolated testing environments
- Cloud-based practice labs

### [Appendix D: Additional Resources](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/Appendix-d.md)
- Recommended reading
- Online communities
- Training resources
- CTF platforms

##[ Index](https://github.com/afunnynut/Black-Book-of-Linux-for-Red-Teamers/blob/f9773104f07fbf2c99ba5a28026c0dc54b55f266/Index.md)
- Detailed tool and technique cross-reference


Please share, contribute and help test the code and tools as newer versions of the tools and OSs get released, so this page is always up-to-date
