# Chapter 19: Anonymity and Evasion

In red team operations, maintaining anonymity and evading detection are critical concerns. This chapter explores specialized tools designed to hide your identity, route traffic through proxies, and prevent attribution of your activities. These capabilities are essential for emulating sophisticated threat actors who prioritize operational security.

## Introduction to Anonymity and Evasion

Operational security (OPSEC) forms the foundation of successful red team engagements. Beyond technical exploitation, maintaining anonymity serves several critical purposes:

- **Attack attribution prevention**: Making it difficult to trace activities back to your true identity or location
- **Target reconnaissance without detection**: Gathering information while minimizing the digital footprint
- **Realistic threat emulation**: Accurately modeling sophisticated adversaries who use anonymity techniques
- **Avoiding defensive measures**: Bypassing network monitoring and traffic analysis
- **Multiple-route access**: Establishing diverse paths to targets to maintain persistence

This chapter covers four powerful tools that enable different aspects of anonymity and evasion, from simple traffic proxying to comprehensive anonymization frameworks.

## ProxyChains/Proxychains-ng: Traffic Proxying

ProxyChains is a tool that forces any TCP connection made by a program to go through proxy servers (SOCKS4, SOCKS5, or HTTP). It allows for chaining multiple proxies together, adding additional layers of anonymity and making traffic analysis more difficult.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install proxychains4

# On Arch-based systems
sudo pacman -S proxychains-ng

# On Fedora
sudo dnf install proxychains-ng

# From source (for the newer ProxyChains-ng)
git clone https://github.com/rofl0r/proxychains-ng.git
cd proxychains-ng
./configure --prefix=/usr --sysconfdir=/etc
make
sudo make install
sudo make install-config
```

### Basic Usage

```bash
# Basic syntax
proxychains4 [options] <command> [arguments]

# Example: Route Nmap through the proxy chain
proxychains4 nmap -sT -p 80,443 example.com

# Example: Route SSH through the proxy chain
proxychains4 ssh user@target.com

# Specify a different configuration file
proxychains4 -f /path/to/config/file.conf <command>

# Enable quiet mode (less output)
proxychains4 -q <command>
```

### Configuration for Different Proxy Types

ProxyChains allows various proxy configurations through its configuration file (typically `/etc/proxychains4.conf` or `~/.proxychains/proxychains.conf`):

#### 1. Basic Configuration Options

```bash
# Edit the configuration file
sudo nano /etc/proxychains4.conf

# Key settings to configure
# - dynamic_chain: Enables dynamic chaining (tries each proxy in order until one works)
# - strict_chain: Requires all proxies in the chain to be available
# - random_chain: Uses random proxies from the list
# - chain_len: Number of random proxies to use with random_chain
# - tcp_read_time_out/tcp_connect_time_out: Connection timeouts
# - proxy_dns: Whether to proxy DNS requests
```

#### 2. Setting Up Proxy Chains

```bash
# Example proxychains.conf for multiple proxy types
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Format: <proxy_type> <ip> <port> [user] [password]
http 192.168.1.1 3128
socks4 192.168.1.2 1080
socks5 192.168.1.3 1080 user password
```

#### 3. Using ProxyChains with Different Tools

```bash
# Web reconnaissance
proxychains4 curl https://target-site.com

# Port scanning (TCP connect scan only)
proxychains4 nmap -sT -Pn target.com

# Web application testing
proxychains4 nikto -h https://target-site.com
```

### Example: Routing Tools through TOR

This example demonstrates how to configure and use ProxyChains to route various tools through the Tor network:

1. **Setup Tor as a SOCKS proxy**:

```bash
# Install Tor
sudo apt update
sudo apt install tor

# Configure Tor to act as a SOCKS proxy
sudo nano /etc/tor/torrc

# Uncomment or add these lines:
# SocksPort 9050
# SocksPolicy accept 127.0.0.1
# Log notice file /var/log/tor/notices.log

# Restart Tor
sudo systemctl restart tor
```

2. **Configure ProxyChains for Tor**:

```bash
# Create a Tor-specific ProxyChains configuration
sudo cp /etc/proxychains4.conf /etc/proxychains4-tor.conf
sudo nano /etc/proxychains4-tor.conf

# Replace the existing [ProxyList] section with:
[ProxyList]
# Tor SOCKS proxy
socks5 127.0.0.1 9050
```

3. **Verify Tor connectivity**:

```bash
# Check if Tor is working correctly
proxychains4 -f /etc/proxychains4-tor.conf curl https://check.torproject.org | grep "Congratulations"
```

4. **Use ProxyChains for reconnaissance**:

```bash
# Conduct OSINT through Tor
proxychains4 -f /etc/proxychains4-tor.conf whois target-domain.com

# GitHub reconnaissance
proxychains4 -f /etc/proxychains4-tor.conf curl -s https://api.github.com/users/target-organization/repos

# Basic service detection
proxychains4 -f /etc/proxychains4-tor.conf nmap -sT -Pn -p 80,443,8080 target.com
```

5. **Create a function for easier usage**:

```bash
# Add to your ~/.bashrc or ~/.zshrc
function torify() {
    proxychains4 -f /etc/proxychains4-tor.conf -q "$@"
}

# Source the file
source ~/.bashrc

# Now you can use the simpler command
torify curl https://target-site.com
```

This approach is effective because:
- It routes all TCP connections through the Tor network, hiding your real IP address
- It provides a simple way to anonymize existing tools without modifying them
- It can be used with a wide range of tools for different phases of an engagement
- It creates a consistent pattern for anonymizing network activity

ProxyChains has some limitations, particularly for tools that use raw sockets or UDP (like certain Nmap scan types). It's important to understand these limitations and verify that your traffic is actually being proxied correctly.

## Anonsurf (Parrot OS): Anonymization

Anonsurf is a comprehensive anonymization tool included with Parrot OS. It routes all internet traffic through the Tor network, ensuring anonymity at the system level rather than just for individual applications.

### Installation

Anonsurf comes pre-installed on Parrot OS. For other Debian-based distributions:

```bash
# Clone the repository
git clone https://github.com/ParrotSec/anonsurf.git
cd anonsurf

# Install dependencies
sudo apt update
sudo apt install tor iptables network-manager

# Install Anonsurf
sudo make install
```

### Basic Usage

```bash
# Start Anonsurf
sudo anonsurf start

# Check status
sudo anonsurf status

# Get a new Tor identity
sudo anonsurf change

# Stop Anonsurf
sudo anonsurf stop

# Show IP address
sudo anonsurf myip
```

### Configuration Options

Anonsurf can be configured through its configuration file:

```bash
# Edit the configuration file
sudo nano /etc/anonsurf/anonsurf.conf

# Key settings to consider:
# - TOR_DNS: Use Tor for DNS resolution
# - CLEARNET_DNS: DNS server to use when Anonsurf is disabled
# - IPV6_SUPPORT: Enable/disable IPv6 (disabling recommended)
```

### Example: Setting up Fully Anonymous Testing

This example demonstrates how to create a comprehensive anonymous testing environment using Anonsurf:

1. **Prepare a secure testing environment**:

```bash
# Verify you're starting clean
sudo anonsurf status

# Check your original IP for comparison
curl ipinfo.io

# Start Anonsurf
sudo anonsurf start

# Verify your IP has changed
sudo anonsurf myip
```

2. **Configure browser for maximum anonymity**:

```bash
# Install and configure Firefox with enhanced privacy
sudo apt install firefox-esr

# Create a fresh Firefox profile
firefox-esr -CreateProfile "anon"

# Set up a script to launch Firefox with the anonymous profile
cat > ~/anon-firefox.sh << 'EOF'
#!/bin/bash
firefox-esr -P "anon" --private-window about:blank
EOF

chmod +x ~/anon-firefox.sh

# Launch Firefox with the anonymous profile
~/anon-firefox.sh
```

3. **Configure browser settings manually**:
   - Go to Firefox preferences
   - Set Enhanced Tracking Protection to Strict
   - Set Firefox to clear history when closed
   - Disable geolocation, camera, microphone, and notifications
   - Install privacy-enhancing extensions (uBlock Origin, HTTPS Everywhere)

4. **Set up an anonymous testing framework**:

```bash
# Create a script to launch tools in anonymous mode
cat > ~/anonymous-testing.sh << 'EOF'
#!/bin/bash

# Check if Anonsurf is running
if ! sudo anonsurf status | grep -q "activated"; then
    echo "[-] Anonsurf is not running. Starting Anonsurf..."
    sudo anonsurf start
    sleep 5
fi

# Verify anonymity
current_ip=$(curl -s ipinfo.io/ip)
echo "[+] Current external IP: $current_ip"

# Create a testing directory
timestamp=$(date +%Y%m%d_%H%M%S)
test_dir="$HOME/anonymous_tests_$timestamp"
mkdir -p "$test_dir"
cd "$test_dir"

echo "[+] Created testing directory: $test_dir"

# Menu for common red team tools
while true; do
    echo "
    Anonymous Testing Framework
    ===========================
    1. Run Nmap scan (TCP Connect)
    2. Run Nikto scan
    3. Run Dirb/Gobuster scan
    4. Run Whois lookup
    5. Run custom command anonymously
    6. Get new Tor identity
    7. Launch anonymous Firefox
    8. Exit
    "
    read -p "Select an option: " option
    
    case $option in
        1)
            read -p "Enter target (IP or domain): " target
            echo "[+] Running Nmap scan against $target"
            nmap -sT -Pn "$target" | tee "nmap_$target.txt"
            ;;
        2)
            read -p "Enter target URL: " target
            echo "[+] Running Nikto scan against $target"
            nikto -h "$target" | tee "nikto_$(echo $target | sed 's/[:\/.]/\_/g').txt"
            ;;
        3)
            read -p "Enter target URL: " target
            echo "[+] Running Gobuster scan against $target"
            gobuster dir -u "$target" -w /usr/share/wordlists/dirb/common.txt | tee "gobuster_$(echo $target | sed 's/[:\/.]/\_/g').txt"
            ;;
        4)
            read -p "Enter domain to lookup: " target
            echo "[+] Running Whois lookup for $target"
            whois "$target" | tee "whois_$target.txt"
            ;;
        5)
            read -p "Enter command to run: " custom_cmd
            echo "[+] Running: $custom_cmd"
            eval "$custom_cmd"
            ;;
        6)
            echo "[+] Getting new Tor identity"
            sudo anonsurf change
            current_ip=$(curl -s ipinfo.io/ip)
            echo "[+] New external IP: $current_ip"
            ;;
        7)
            echo "[+] Launching anonymous Firefox"
            ~/anon-firefox.sh &
            ;;
        8)
            echo "[+] Exiting"
            exit 0
            ;;
        *)
            echo "[-] Invalid option"
            ;;
    esac
    
    read -p "Press Enter to continue..."
done
EOF

chmod +x ~/anonymous-testing.sh
```

5. **Launch the anonymous testing framework**:

```bash
~/anonymous-testing.sh
```

This comprehensive approach is effective because:
- It ensures all traffic is routed through Tor at the system level
- It creates a dedicated testing environment with a clear framework for different tools
- It provides mechanisms to change Tor identity as needed during testing
- It maintains logs of testing activities for future reference

Anonsurf's system-wide approach to anonymization makes it particularly valuable for red team operations where ensuring anonymity for all tools and traffic is essential.

## Tor: Anonymous Networking

The Tor network (The Onion Router) is a distributed network designed to improve privacy and security on the Internet. It enables anonymous communication by routing Internet traffic through a worldwide overlay network of volunteer relays.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install tor

# On Arch-based systems
sudo pacman -S tor

# On Fedora
sudo dnf install tor
```

### Basic Configuration

```bash
# Edit the Tor configuration file
sudo nano /etc/tor/torrc

# Key configuration options:
# - SocksPort 9050: The default port for SOCKS proxy
# - ControlPort 9051: Port for controlling Tor via API
# - HashedControlPassword: Password for ControlPort access
# - ExitNodes, EntryNodes: Control entry/exit countries
# - StrictNodes: Enforce use of specified nodes
```

### Using Tor for Various Operations

#### 1. Basic SOCKS Proxy Usage

```bash
# Configure Tor as a SOCKS proxy
sudo nano /etc/tor/torrc
# Add or uncomment: SocksPort 9050

# Restart Tor
sudo systemctl restart tor

# Use with curl
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

#### 2. Tor Browser for Web Reconnaissance

```bash
# Download and extract Tor Browser
wget https://www.torproject.org/dist/torbrowser/12.0/tor-browser-linux64-12.0_en-US.tar.xz
tar -xf tor-browser-linux64-12.0_en-US.tar.xz

# Launch Tor Browser
cd tor-browser_en-US
./start-tor-browser.desktop
```

#### 3. Torsocks for Command-Line Tools

```bash
# Install Torsocks
sudo apt install torsocks

# Use with command-line tools
torsocks wget https://example.com
torsocks ssh user@server
```

### Example: Setting up Hidden Services

This example demonstrates how to set up a Tor hidden service (onion service) to host tools or receive connections anonymously:

1. **Configure Tor to create a hidden service**:

```bash
# Edit Tor configuration
sudo nano /etc/tor/torrc

# Add these lines to create a hidden service
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:8080
HiddenServicePort 22 127.0.0.1:22

# Restart Tor
sudo systemctl restart tor

# Get your .onion address
sudo cat /var/lib/tor/hidden_service/hostname
```

2. **Set up a web server behind the hidden service**:

```bash
# Install a simple web server
sudo apt install nginx

# Configure the web server
sudo nano /etc/nginx/sites-available/hidden_service

# Add a basic configuration
server {
    listen 127.0.0.1:8080;
    root /var/www/hidden_service;
    index index.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
}

# Create a symbolic link to enable the site
sudo ln -s /etc/nginx/sites-available/hidden_service /etc/nginx/sites-enabled/

# Create a web directory
sudo mkdir -p /var/www/hidden_service

# Create a test page
echo "<html><body><h1>Hidden Service Test</h1></body></html>" | sudo tee /var/www/hidden_service/index.html

# Restart Nginx
sudo systemctl restart nginx
```

3. **Set up SSH access through the hidden service**:

```bash
# Ensure SSH is configured to listen on localhost
sudo nano /etc/ssh/sshd_config

# Make sure these lines are set
ListenAddress 127.0.0.1
Port 22

# Restart SSH
sudo systemctl restart sshd
```

4. **Test accessing your hidden service**:

```bash
# In Tor Browser, navigate to your .onion address
# For example: http://abcdefghijk2l3m.onion

# For SSH access through Tor
torsocks ssh user@abcdefghijk2l3m.onion
```

5. **Create a more advanced hidden service for red team operations**:

```bash
# Create a directory for operational tools
sudo mkdir -p /var/www/hidden_service/tools

# Set up a simple file upload/download capability
cat > /var/www/hidden_service/tools/upload.php << 'EOF'
<?php
$secret_key = "redteamsecretkey";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['key']) && $_POST['key'] === $secret_key) {
        if (isset($_FILES['file'])) {
            $target_dir = "./uploads/";
            if (!file_exists($target_dir)) {
                mkdir($target_dir, 0777, true);
            }
            
            $target_file = $target_dir . basename($_FILES["file"]["name"]);
            
            if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
                echo "File uploaded successfully";
            } else {
                echo "Error uploading file";
            }
        }
    } else {
        echo "Invalid key";
    }
} else {
?>
<!DOCTYPE html>
<html>
<head>
    <title>Secure File Transfer</title>
</head>
<body>
    <h2>Upload File</h2>
    <form method="post" enctype="multipart/form-data">
        <label>Security Key:</label>
        <input type="password" name="key"><br><br>
        <input type="file" name="file"><br><br>
        <input type="submit" value="Upload">
    </form>
    
    <h2>Available Files</h2>
    <ul>
    <?php
    $files = glob("./uploads/*");
    foreach($files as $file) {
        $filename = basename($file);
        echo "<li><a href='uploads/$filename'>$filename</a></li>";
    }
    ?>
    </ul>
</body>
</html>
<?php
}
?>
EOF

# Set appropriate permissions
sudo chown -R www-data:www-data /var/www/hidden_service
sudo chmod -R 755 /var/www/hidden_service
```

This hidden service setup is valuable for red team operations because:
- It provides an anonymous communication channel that's difficult to trace
- It enables receiving data exfiltrated from target environments
- It allows remote access to infrastructure through an anonymous channel
- It helps maintain operational security by separating infrastructure from identifiable IPs

Tor's robust anonymity features make it an essential component of red team operations, particularly for long-term engagements where preventing attribution is critical.

## Nipe: Traffic Routing through Tor

Nipe is a specialized tool that routes all system traffic through the Tor network. Unlike ProxyChains, which works on a per-application basis, Nipe operates at the system level, ensuring comprehensive anonymization.

### Installation

```bash
# Install dependencies on Debian/Ubuntu
sudo apt update
sudo apt install git build-essential libproc-processtable-perl libjson-perl libwww-perl

# Clone the repository
git clone https://github.com/htrgouvea/nipe.git
cd nipe

# Install Perl dependencies
sudo cpan install Switch JSON LWP::UserAgent

# Install Nipe
sudo perl nipe.pl install
```

### Basic Usage

```bash
# Start Nipe
sudo perl nipe.pl start

# Check status
sudo perl nipe.pl status

# Stop Nipe
sudo perl nipe.pl stop

# Restart Nipe
sudo perl nipe.pl restart
```

### Example: Transparent Tool Anonymization

This example demonstrates how to use Nipe to create a fully transparent anonymization environment for red team operations:

1. **Verify initial configuration**:

```bash
# Check current IP address
curl -s ipinfo.io/ip
curl -s ipinfo.io/country

# Start Nipe
cd nipe
sudo perl nipe.pl start

# Verify Tor routing is working
sudo perl nipe.pl status
curl -s ipinfo.io/ip
curl -s ipinfo.io/country
```

2. **Create a script to maintain anonymity**:

```bash
# Create an anonymity check script
cat > ~/check-anon.sh << 'EOF'
#!/bin/bash

echo "[*] Checking anonymization status..."

# Check if nipe is running
cd ~/nipe
status=$(sudo perl nipe.pl status)

if echo "$status" | grep -q "activated"; then
    echo "[+] Nipe is active and routing through Tor"
else
    echo "[-] Nipe is not active. Attempting to start..."
    sudo perl nipe.pl restart
    sleep 5
    
    # Check again
    status=$(sudo perl nipe.pl status)
    if echo "$status" | grep -q "activated"; then
        echo "[+] Nipe successfully started"
    else
        echo "[-] Failed to start Nipe. Exiting for safety."
        exit 1
    fi
fi

# Get current IP information
IP=$(curl -s ipinfo.io/ip)
COUNTRY=$(curl -s ipinfo.io/country)
ORG=$(curl -s ipinfo.io/org)

echo "[+] Current exit node information:"
echo "    IP: $IP"
echo "    Country: $COUNTRY"
echo "    Organization: $ORG"

# Verify DNS is not leaking
echo "[*] Checking for DNS leaks..."
dig +short myip.opendns.com @resolver1.opendns.com

echo "[+] Anonymity check complete"
EOF

chmod +x ~/check-anon.sh
```

3. **Create a secure red team environment**:

```bash
# Create a script to prepare anonymous red team environment
cat > ~/anon-redteam.sh << 'EOF'
#!/bin/bash

# Check anonymity first
if ! ~/check-anon.sh; then
    echo "[-] Anonymity check failed. Please fix before continuing."
    exit 1
fi

echo "[+] Anonymity confirmed. Preparing red team environment..."

# Create a session directory
SESSION_DIR="$HOME/redteam_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SESSION_DIR"
cd "$SESSION_DIR"

# Keep a log of all commands
exec > >(tee -a "$SESSION_DIR/session.log") 2>&1

# Log start time and Tor exit node
echo "=== Red Team Session Started at $(date) ==="
echo "=== Exit Node: $(curl -s ipinfo.io/ip) ($(curl -s ipinfo.io/country)) ==="

# Create helper function for changing identity periodically
change_identity() {
    cd ~/nipe
    echo "[*] Changing Tor identity..."
    sudo perl nipe.pl restart
    sleep 10
    echo "[+] New exit node: $(curl -s ipinfo.io/ip) ($(curl -s ipinfo.io/country))"
}

# Launch a shell in the environment
echo "[+] Launching anonymous shell. Type 'exit' to end session."
echo "[+] Type 'newid' to change Tor identity."

# Export the function for use in the subshell
export -f change_identity

# Launch a new shell with altered prompt to indicate anonymous environment
PS1="\\[\\033[1;31m\\][ANON]\\[\\033[00m\\] \\w \\$ " bash --rcfile <(echo '
alias newid="change_identity"
echo "Anonymous Red Team Environment"
echo "- All traffic is routed through Tor"
echo "- Session is being logged to session.log"
echo "- Type \"newid\" to change your Tor identity"
')

# Log end time
echo "=== Red Team Session Ended at $(date) ==="
EOF

chmod +x ~/anon-redteam.sh
```

4. **Launch the anonymous red team environment**:

```bash
~/anon-redteam.sh
```

5. **Use the environment for anonymous operations**:

```bash
# Inside the anonymous environment
[ANON] ~/redteam_20230521_120000 $ nmap -sT -Pn example.com
[ANON] ~/redteam_20230521_120000 $ newid  # Change Tor identity
[ANON] ~/redteam_20230521_120000 $ wget https://target-site.com/interesting-file.pdf
```

This approach using Nipe is effective because:
- It ensures all system traffic is routed through Tor, not just specific applications
- It creates a structured environment for red team operations with logging
- It provides easy identity switching to avoid correlation of activities
- It maintains a constant reminder of the anonymized status

Nipe's system-wide approach to Tor routing makes it particularly valuable for red team operations where ensuring anonymity for all tools and traffic is essential, and setting up each tool individually with ProxyChains would be cumbersome.

## Advanced Anonymity Techniques

Beyond the core tools, consider these advanced techniques for enhanced anonymity:

### 1. Multiple Layers of Anonymization

```bash
# Set up a multi-layer anonymization chain
# VPN → Tor → Second VPN

# First, connect to primary VPN
sudo openvpn --config /path/to/vpn1.ovpn

# Then start Tor
sudo systemctl start tor

# Configure ProxyChains for Tor
sudo nano /etc/proxychains4.conf
# Ensure the ProxyList contains: socks5 127.0.0.1 9050

# Use ProxyChains to connect to the second VPN through Tor
proxychains4 sudo openvpn --config /path/to/vpn2.ovpn
```

### 2. Virtual Machine Isolation

```bash
# Create a dedicated anonymous VM
# Using VirtualBox or KVM/QEMU

# Install a minimal Linux distribution (Debian/Ubuntu)
# Configure all traffic routing through Tor or VPN+Tor

# Use VM snapshots for clean state between operations
vboxmanage snapshot "Anonymous_VM" take "clean_state"

# Restore to clean state after each operation
vboxmanage snapshot "Anonymous_VM" restore "clean_state"
```

### 3. MAC Address Randomization

```bash
# Install macchanger
sudo apt install macchanger

# Randomize MAC before connecting to networks
sudo ifconfig wlan0 down
sudo macchanger -r wlan0
sudo ifconfig wlan0 up
```

### 4. Time Zone and Locale Modification

```bash
# Change system time zone to match exit node location
sudo timedatectl set-timezone Europe/Amsterdam

# Modify browser locale settings

# Reset when done
sudo timedatectl set-timezone UTC
```

## Anonymity Testing and Verification

Always verify your anonymity setup before conducting operations:

### 1. Network Traffic Verification

```bash
# Create a comprehensive anonymity test script
cat > ~/verify-anonymity.sh << 'EOF'
#!/bin/bash

echo "=== Anonymity Verification Test ==="
echo "=== $(date) ==="

echo -e "\n[*] Basic IP Information:"
curl -s ipinfo.io

echo -e "\n[*] DNS Leak Test:"
dig +short myip.opendns.com @resolver1.opendns.com

echo -e "\n[*] Testing for WebRTC leaks (if relevant):"
echo "Check manually in browser: https://browserleaks.com/webrtc"

echo -e "\n[*] Testing IPv6 leaks:"
curl -s https://ipv6.icanhazip.com || echo "No IPv6 connectivity (good)"

echo -e "\n[*] Testing Tor connectivity:"
curl -s https://check.torproject.org | grep -E "Sorry|Congratulations"

echo -e "\n[*] Testing TCP port 80 connectivity:"
ncat -v check.torproject.org 80 -w 5 < /dev/null

echo -e "\n[*] Browser fingerprinting reminder:"
echo "Run a manual test at: https://panopticlick.eff.org"

echo -e "\n=== Test Completed ==="
EOF

chmod +x ~/verify-anonymity.sh
```

### 2. Browser Fingerprinting Reduction

For web-based operations, configure your browser to minimize fingerprinting:

```bash
# Firefox about:config settings
# privacy.resistFingerprinting = true
# privacy.trackingprotection.enabled = true
# webgl.disabled = true
# media.peerconnection.enabled = false (WebRTC)
```

## Conclusion

Anonymity and evasion tools are essential components of the red team toolkit, enabling operators to emulate sophisticated threat actors who prioritize operational security. The tools covered in this chapter—ProxyChains, Anonsurf, Tor, and Nipe—represent different approaches to anonymization, from application-specific proxying to comprehensive system-level traffic routing.

These tools demonstrate why anonymity is critical for effective red team operations: they allow teams to conduct reconnaissance without alerting defensive measures, prevent attribution of activities to specific operators or organizations, and provide realistic emulation of advanced threat actors.

Remember that as a professional red teamer, your objective is to help organizations identify and address their security weaknesses while maintaining proper operational security. Always operate within the scope of your engagement and with proper authorization.

In the next chapter, we'll explore cryptography and steganography tools that can be used to conceal sensitive data and create covert communication channels.
