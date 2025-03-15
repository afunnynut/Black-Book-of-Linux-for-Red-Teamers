# Chapter 20: Cryptography and Steganography Tools

Cryptography and steganography are essential components of a red team's toolkit. While cryptography secures communications and data through encryption, steganography conceals the very existence of those communications. This chapter explores tools that enable secure data handling, covert communications, and methods to bypass security controls that block traditional communication channels.

## Introduction to Cryptography and Steganography

In red team operations, secure communications and data handling are critical for:

- **Operational security**: Protecting sensitive command and control communications
- **Data exfiltration**: Securely removing discovered information from target environments
- **Bypass detection systems**: Avoiding triggering data loss prevention (DLP) mechanisms
- **Post-exploitation persistence**: Establishing hidden communication channels
- **Client data protection**: Securing sensitive client information and findings

This chapter covers four powerful tools that provide different capabilities for cryptography and steganography, from general-purpose cryptographic operations to specialized data hiding techniques.

## OpenSSL: Cryptographic Toolkit

OpenSSL is a robust, full-featured, and open-source toolkit that implements the Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols, along with a general-purpose cryptography library. It's a Swiss Army knife for cryptographic operations, supporting numerous algorithms and functions.

### Installation

OpenSSL comes pre-installed on most Linux distributions. If needed:

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install openssl

# On Fedora
sudo dnf install openssl

# On Arch Linux
sudo pacman -S openssl
```

### Basic Cryptographic Operations

#### 1. Symmetric Encryption and Decryption

```bash
# Encrypt a file with AES-256-CBC
openssl enc -aes-256-cbc -salt -in sensitive_data.txt -out encrypted_data.enc -k "password"

# Decrypt the file
openssl enc -aes-256-cbc -d -in encrypted_data.enc -out decrypted_data.txt -k "password"

# Use a key file instead of password
openssl rand -base64 32 > key.bin
openssl enc -aes-256-cbc -salt -in sensitive_data.txt -out encrypted_data.enc -kfile key.bin
```

#### 2. Password-Based Key Derivation

```bash
# Encrypt with stronger key derivation (PBKDF2)
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in sensitive_data.txt -out encrypted_data.enc -k "password"

# Decrypt with the same parameters
openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 100000 -in encrypted_data.enc -out decrypted_data.txt -k "password"
```

#### 3. Hashing and Message Digests

```bash
# Generate SHA-256 hash of a file
openssl dgst -sha256 file.txt

# Generate MD5 hash (less secure, but useful for checksums)
openssl dgst -md5 file.txt

# Generate HMAC (Hash-based Message Authentication Code)
openssl dgst -sha256 -hmac "secretkey" file.txt
```

#### 4. Random Data Generation

```bash
# Generate 32 bytes of random data
openssl rand -hex 32

# Generate a random password
openssl rand -base64 12
```

### Common Red Team Uses

OpenSSL offers several capabilities specifically useful for red team operations:

#### 1. Creating Malicious Certificates

In red team operations, custom certificates can be useful for various scenarios, such as man-in-the-middle attacks or setting up malicious web servers that appear legitimate:

```bash
# Create a private key
openssl genrsa -out malicious.key 2048

# Create a self-signed certificate
openssl req -new -x509 -key malicious.key -out malicious.crt -days 365 -subj "/CN=legitimate-looking-site.com"

# Create a certificate signing request (CSR) for more sophisticated operations
openssl req -new -key malicious.key -out malicious.csr -subj "/CN=legitimate-looking-site.com"

# Create a configuration file for Subject Alternative Names (SANs)
cat > san.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = legitimate-looking-site.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = legitimate-looking-site.com
DNS.2 = www.legitimate-looking-site.com
DNS.3 = secure.legitimate-looking-site.com
DNS.4 = mail.legitimate-looking-site.com
EOF

# Create a certificate with Subject Alternative Names
openssl req -new -x509 -key malicious.key -out malicious.crt -days 365 -config san.cnf -extensions v3_req
```

#### 2. Testing SSL/TLS Configurations

```bash
# Check SSL/TLS configuration on a remote server
openssl s_client -connect example.com:443 -tls1_2

# Check for supported ciphers
openssl s_client -connect example.com:443 -cipher 'ECDHE-RSA-AES128-GCM-SHA256'

# Check certificate information
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -text -noout
```

#### 3. Secure Data Transfer

```bash
# Create an encrypted archive of sensitive findings
tar czf - /path/to/findings | openssl enc -aes-256-cbc -salt -pbkdf2 -out findings.tar.gz.enc -k "secure_password"

# Create a self-extracting script for the client
cat > decrypt_findings.sh << 'EOF'
#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <password>"
    exit 1
fi

PASSWORD="$1"

# Decrypt and extract
openssl enc -aes-256-cbc -d -salt -pbkdf2 -in findings.tar.gz.enc -k "$PASSWORD" | tar xzf -

echo "Findings extracted successfully."
EOF

chmod +x decrypt_findings.sh
```

### Example: Creating Malicious Certificates

This example demonstrates a complete workflow for creating certificates that could be used in a red team scenario:

1. **Create a certificate authority (CA) for your operation**:

```bash
# Create a directory for certificate materials
mkdir -p ~/cert-authority/
cd ~/cert-authority/

# Generate a private key for the CA
openssl genrsa -out ca.key 4096

# Create a self-signed CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Enterprise Security Authority/O=Enterprise Corp/C=US"
```

2. **Create a configuration file for server certificates**:

```bash
cat > server.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = secure-portal.target-company.com
O = Target Company
C = US

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = secure-portal.target-company.com
DNS.2 = portal.target-company.com
DNS.3 = login.target-company.com
EOF
```

3. **Generate a server certificate for phishing or MitM operations**:

```bash
# Generate server private key
openssl genrsa -out server.key 2048

# Create a certificate signing request (CSR)
openssl req -new -key server.key -out server.csr -config server.cnf

# Sign the CSR with your CA
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -extensions v3_req -extfile server.cnf
```

4. **Verify the certificate information**:

```bash
# Check the server certificate details
openssl x509 -text -noout -in server.crt
```

5. **Set up for use with a web server (like Nginx)**:

```bash
# Combine the certificate and key into a PEM file
cat server.crt server.key > server.pem

# For Nginx configuration
# ssl_certificate /path/to/server.crt;
# ssl_certificate_key /path/to/server.key;
```

This approach is effective for red team operations because:
- It creates certificates that appear legitimate to users
- It can be used with tools like Evilginx for credential harvesting
- It enables encrypted communications that are difficult to inspect
- The certificates can be used for various services (web, email, VPN)

OpenSSL's flexibility and comprehensive feature set make it an essential tool for red team operations involving cryptography, secure communications, and certificate manipulation.

## Steghide: Steganography Tool

Steghide is a steganography program that allows you to hide data within various file types, including JPEG, BMP, WAV, and AU files. It embeds the secret data in the least significant bits of the cover file, making the changes virtually imperceptible to casual observation.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install steghide

# On Fedora
sudo dnf install steghide

# On Arch Linux (from AUR)
git clone https://aur.archlinux.org/steghide.git
cd steghide
makepkg -si
```

### Basic Usage

```bash
# Basic syntax
steghide [command] [options] [arguments]

# Embed data into a cover file
steghide embed -cf cover.jpg -ef secret.txt -p "password"

# Extract data from a steganographic file
steghide extract -sf cover.jpg -p "password"

# Get information about a file (without extracting)
steghide info cover.jpg
```

### Embedding and Extracting Data

#### 1. Basic Data Embedding

```bash
# Embed a text file into an image
steghide embed -cf innocent_image.jpg -ef secret_data.txt -p "secure_password"

# Embed without a passphrase (not recommended)
steghide embed -cf innocent_image.jpg -ef secret_data.txt -p ""

# Embed with encryption algorithm specification
steghide embed -cf innocent_image.jpg -ef secret_data.txt -p "secure_password" -e rijndael-128
```

#### 2. Data Extraction

```bash
# Extract the hidden data
steghide extract -sf innocent_image.jpg -p "secure_password"

# Specify output file for extraction
steghide extract -sf innocent_image.jpg -p "secure_password" -xf extracted_data.txt
```

#### 3. File Information

```bash
# Check if a file contains hidden data
steghide info innocent_image.jpg

# For detailed information, including compression stats
steghide info innocent_image.jpg -p "secure_password"
```

### Example: Embedding and Extracting Data

This example demonstrates creating covert communication channels using Steghide:

1. **Prepare the secret message and cover media**:

```bash
# Create a secret message
cat > mission_details.txt << 'EOF'
TARGET: Internal network segment 10.45.67.0/24
OBJECTIVE: Locate and exfiltrate customer database
TIMELINE: Operation must be completed between 01:00-03:00
RESTRICTIONS: No destructive actions permitted
CONTACTS: If compromised, email backup-admin@legitimate-domain.com

Network diagram attached in second image.
EOF

# Ensure you have appropriate cover images
# These should be legitimate-looking images that won't raise suspicion
ls -la cover_image1.jpg cover_image2.jpg
```

2. **Encrypt and embed the secret message**:

```bash
# Embed the mission details
steghide embed -cf cover_image1.jpg -ef mission_details.txt -p "operationSECURE2023" -v

# Embed a network diagram image into another cover image
# First compress the diagram to minimize size
gzip -c network_diagram.png > network_diagram.png.gz
steghide embed -cf cover_image2.jpg -ef network_diagram.png.gz -p "operationSECURE2023" -v
```

3. **Create a simple extraction script for the receiver**:

```bash
cat > extract_intel.sh << 'EOF'
#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <stegofile> <password>"
    exit 1
fi

STEGOFILE="$1"
PASSWORD="$2"

# Extract the hidden data
OUTPUT=$(basename "$STEGOFILE" .jpg)_extracted
steghide extract -sf "$STEGOFILE" -p "$PASSWORD" -xf "$OUTPUT"

# Check if extraction was successful
if [ $? -eq 0 ]; then
    echo "Extraction successful. Data saved to $OUTPUT"
    
    # If the extracted file is gzipped, decompress it
    if file "$OUTPUT" | grep -q "gzip compressed data"; then
        mv "$OUTPUT" "$OUTPUT.gz"
        gunzip "$OUTPUT.gz"
        echo "Decompressed gzipped data"
    fi
    
    # If it's text, show a preview
    if file "$OUTPUT" | grep -q "text"; then
        echo "----- Content Preview -----"
        head -n 5 "$OUTPUT"
        echo "--------------------------"
    fi
else
    echo "Extraction failed. Check the password and stegofile."
fi
EOF

chmod +x extract_intel.sh
```

4. **Test the extraction process**:

```bash
# Test extraction of the mission details
./extract_intel.sh cover_image1.jpg "operationSECURE2023"

# Test extraction of the network diagram
./extract_intel.sh cover_image2.jpg "operationSECURE2023"
```

5. **Create a validation script to verify files**:

```bash
cat > verify_stego.sh << 'EOF'
#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

FILE="$1"

# Check if file exists
if [ ! -f "$FILE" ]; then
    echo "Error: File not found."
    exit 1
fi

# Check file type
filetype=$(file -b "$FILE")
echo "File type: $filetype"

# Check if it's a supported file type for steghide
if echo "$filetype" | grep -q -E "JPEG|BMP|WAV|AU"; then
    echo "File format is supported by steghide."
    
    # Check for steganographic content
    steghide info "$FILE" 2>&1 | grep -q "embedded file"
    if [ $? -eq 0 ]; then
        echo "File appears to contain hidden data."
        echo "Use steghide extract to retrieve the data."
    else
        echo "No obvious embedded data detected."
        echo "Note: This does not guarantee absence of hidden data protected by a password."
    fi
else
    echo "Warning: File format is not supported by steghide."
fi
EOF

chmod +x verify_stego.sh
```

This approach to steganography is effective for red team operations because:
- It hides data in files that appear innocuous and can be shared openly
- It provides an additional layer of security through encryption
- It can bypass data loss prevention (DLP) systems that look for suspicious file types
- The carrier files can be transmitted through normal channels like social media or email

Steghide's focus on image and audio files makes it a valuable tool for creating covert communication channels, especially in environments where encrypted communications might be blocked or monitored.

## Stegosuite: Advanced Steganography

Stegosuite is a more advanced steganography application with a graphical user interface, providing a user-friendly way to hide data in image files. It supports JPEG, GIF, BMP, and PNG formats, offering more flexibility than Steghide.

### Installation

```bash
# On Debian/Ubuntu-based systems
sudo apt update
sudo apt install stegosuite

# From source
git clone https://github.com/stegosuite/stegosuite.git
cd stegosuite
# Follow the compilation instructions in the repository
```

### Basic Usage (GUI)

1. Launch Stegosuite:
   ```bash
   stegosuite
   ```

2. For embedding:
   - Select a carrier image
   - Select a file to hide or enter text directly
   - Set a password (optional but recommended)
   - Click "Embed"

3. For extraction:
   - Select a steganographic image
   - Enter the password if one was used
   - Click "Extract"
   - Save the extracted data

### Command-Line Usage

```bash
# Basic syntax (if command-line functionality is supported)
stegosuite [options] [command] [file]

# Embed data (example, check actual syntax for your version)
stegosuite --embed --carrier-file image.png --data-file secret.txt --password "secret" --output stego.png

# Extract data
stegosuite --extract --carrier-file stego.png --password "secret" --output extracted_data
```

### Example: Multi-format Data Hiding

This example demonstrates more advanced steganography techniques using various formats:

1. **Prepare different types of carrier files**:

```bash
# Ensure you have different image formats
ls -la image1.jpg image2.png image3.bmp

# Create a script to automate the process with Stegosuite (if CLI is supported)
# Otherwise, this process would be done through the GUI
cat > multi_stego.sh << 'EOF'
#!/bin/bash

# This script assumes Stegosuite has command-line capabilities
# If not, these operations would need to be performed manually through the GUI

# Split sensitive data into multiple parts
split -b 1k sensitive_document.pdf part_

# Embed each part into a different carrier file
stegosuite --embed --carrier-file image1.jpg --data-file part_aa --password "password1" --output stego1.jpg
stegosuite --embed --carrier-file image2.png --data-file part_ab --password "password2" --output stego2.png
stegosuite --embed --carrier-file image3.bmp --data-file part_ac --password "password3" --output stego3.bmp

echo "Data has been split and hidden across multiple carrier files."
EOF

chmod +x multi_stego.sh
```

2. **Create a reassembly script for extraction**:

```bash
cat > reassemble_data.sh << 'EOF'
#!/bin/bash

# Directory to store extracted parts
mkdir -p extracted_parts
cd extracted_parts

# Extract from each carrier file
# Again, if CLI isn't supported, this would be done through the GUI
stegosuite --extract --carrier-file ../stego1.jpg --password "password1" --output part_aa
stegosuite --extract --carrier-file ../stego2.png --password "password2" --output part_ab
stegosuite --extract --carrier-file ../stego3.bmp --password "password3" --output part_ac

# Combine the parts back into the original file
cat part_* > ../reassembled_document.pdf

echo "Data has been extracted and reassembled as reassembled_document.pdf"
EOF

chmod +x reassemble_data.sh
```

3. **For GUI-only versions, create a guide document**:

```bash
cat > steganography_guide.txt << 'EOF'
Multi-Format Steganography Guide
================================

This document provides instructions for hiding and extracting fragmented data across multiple image files.

Preparation:
1. Split sensitive data into parts of approximately 1KB each using:
   split -b 1k sensitive_document.pdf part_

Embedding Process:
1. Launch Stegosuite: stegosuite
2. For each part:
   a. Select a different carrier image
   b. Select the part file to embed
   c. Set the appropriate password (see password list)
   d. Click "Embed"
   e. Save the resulting steganographic image

Extraction Process:
1. Launch Stegosuite: stegosuite
2. For each steganographic image:
   a. Select the image
   b. Enter the corresponding password
   c. Click "Extract"
   d. Save the extracted part

Reassembling:
1. Once all parts are extracted, combine them:
   cat part_* > reassembled_document.pdf

Password List:
- stego1.jpg: "password1"
- stego2.png: "password2"
- stego3.bmp: "password3"

Security Notes:
- Store this guide separately from the steganographic images
- Transmit the passwords through a different channel
- Delete all original files and parts after embedding
EOF
```

This multi-format approach is effective for red team operations because:
- It distributes sensitive data across multiple files, reducing risk
- It utilizes different image formats, making detection more difficult
- It implements separate passwords for each file, enhancing security
- The approach can bypass size limitations of individual carrier files

Stegosuite's support for multiple image formats provides flexibility in creating steganographic content tailored to specific operational needs.

## CloakifyFactory: Data Exfiltration

CloakifyFactory is an advanced tool designed to help exfiltrate data while evading data loss prevention (DLP) systems. It transforms any file type into a list of strings that can blend in with normal traffic or be hidden in plain sight.

### Installation

```bash
# Clone the repository
git clone https://github.com/TryCatchHCF/Cloakify.git
cd Cloakify
```

### Basic Usage

```bash
# Basic syntax
python3 cloakify.py [file_to_hide] [ciphers/cipher_name] [output_file]
python3 decloakify.py [cloaked_file] [ciphers/cipher_name] [output_file]

# Example: Cloakify a file using Star Trek characters
python3 cloakify.py secret_data.zip ciphers/startrek.txt cloaked_data.txt

# Decloakify the file
python3 decloakify.py cloaked_data.txt ciphers/startrek.txt decloaked_data.zip
```

### Available Ciphers

CloakifyFactory comes with numerous pre-built ciphers for different scenarios:

```bash
# List available ciphers
ls -la ciphers/

# Categories include:
# - Fantasy (e.g., gameofthrones.txt, harry_potter_characters.txt)
# - Technical (e.g., hex.txt, Base64.txt)
# - Lists (e.g., Top100_words.txt, airports.txt)
# - Foreign languages (e.g., french_top1000.txt, spanish_top1000.txt)
```

### Example: Evading Data Loss Prevention Systems

This example demonstrates using CloakifyFactory to bypass data loss prevention systems:

1. **Prepare the sensitive data**:

```bash
# Compress and encrypt the sensitive data first
tar -czf sensitive_data.tar.gz /path/to/sensitive/files/
openssl enc -aes-256-cbc -salt -in sensitive_data.tar.gz -out sensitive_data.enc -k "secretpassword"
```

2. **Analyze your target environment's DLP**:

```bash
# Check for blocked file types or monitored keywords
cat > dlp_analysis.txt << 'EOF'
# DLP Analysis:
# - File transfers monitored
# - Encrypted files blocked
# - Base64 encoding detected
# - Standard data transfer channels monitored
# - No monitoring of emoji usage
# - Twitter access allowed
EOF
```

3. **Select an appropriate cipher and cloakify the data**:

```bash
# For example, using emojis might bypass DLP
cd Cloakify
python3 cloakify.py ../sensitive_data.enc ciphers/emoji.txt ../exfiltration_ready.txt
```

4. **Create a script to automate exfiltration**:

```bash
cat > exfil_chunks.py << 'EOF'
#!/usr/bin/env python3
import sys
import time
import os

def chunk_file(filename, chunk_size=10):
    """Split a file into chunks of specified number of lines."""
    chunks = []
    with open(filename, 'r') as f:
        current_chunk = []
        for line in f:
            current_chunk.append(line.rstrip())
            if len(current_chunk) >= chunk_size:
                chunks.append(current_chunk)
                current_chunk = []
        if current_chunk:  # Don't forget the last chunk if it's smaller
            chunks.append(current_chunk)
    return chunks

def simulate_exfiltration(chunks):
    """Simulates the exfiltration of chunks, printing what would be sent."""
    for i, chunk in enumerate(chunks):
        print(f"Sending chunk {i+1} of {len(chunks)} ({len(chunk)} lines)")
        for line in chunk:
            print(f"  {line}")
        print(f"Waiting for next chunk...")
        time.sleep(1)  # In real exfiltration, this would be much longer

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cloaked_file> [chunk_size]")
        sys.exit(1)
    
    cloaked_file = sys.argv[1]
    chunk_size = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    if not os.path.exists(cloaked_file):
        print(f"File not found: {cloaked_file}")
        sys.exit(1)
    
    chunks = chunk_file(cloaked_file, chunk_size)
    print(f"File split into {len(chunks)} chunks of approximately {chunk_size} lines each")
    
    # Ask before starting simulation
    answer = input("Start exfiltration simulation? [y/N] ")
    if answer.lower() == 'y':
        simulate_exfiltration(chunks)
        print("Exfiltration simulation complete")
    else:
        print("Simulation aborted")

if __name__ == "__main__":
    main()
EOF

chmod +x exfil_chunks.py
```

5. **Test the exfiltration process**:

```bash
./exfil_chunks.py exfiltration_ready.txt 5
```

6. **Create a reassembly script for the receiving end**:

```bash
cat > reassemble.sh << 'EOF'
#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <reassembled_file> <password>"
    exit 1
fi

REASSEMBLED_FILE="$1"
PASSWORD="$2"

# Navigate to Cloakify directory
cd Cloakify

# Decloakify the data
python3 decloakify.py ../reassembled_file.txt ciphers/emoji.txt ../recovered_data.enc

# Decrypt the data
openssl enc -aes-256-cbc -d -salt -in ../recovered_data.enc -out ../recovered_data.tar.gz -k "$PASSWORD"

# Extract the archive
cd ..
mkdir -p recovered_files
tar -xzf recovered_data.tar.gz -C recovered_files

echo "Data has been recovered to the 'recovered_files' directory"
EOF

chmod +x reassemble.sh
```

This approach is effective for evading data loss prevention systems because:
- It transforms binary data into text that appears harmless
- It can use contextually appropriate ciphers (emojis, quotes, etc.)
- It avoids typical DLP detection patterns like Base64 encoding
- The data can be transmitted through channels not monitored for exfiltration
- It can be fragmented and sent over time to avoid volume-based alerts

CloakifyFactory's versatility in transforming data makes it particularly valuable for red team operations in environments with strict data controls.

## Advanced Cryptography and Steganography Techniques

Beyond the core tools, consider these advanced techniques for enhanced data protection and covert communications:

### 1. Layered Encryption and Steganography

```bash
# First encrypt the data
openssl enc -aes-256-cbc -salt -in sensitive_data.txt -out encrypted_data.enc -k "password1"

# Then use steganography to hide it
steghide embed -cf cover_image.jpg -ef encrypted_data.enc -p "password2"

# Finally, transform the image to avoid detection
python3 Cloakify/cloakify.py cover_image.jpg Cloakify/ciphers/hex.txt transportable_data.txt
```

### 2. Polyglot Files

Polyglot files are valid in multiple formats simultaneously, providing unique steganographic opportunities:

```bash
# Example: Creating a JPEG/ZIP polyglot
cat > create_polyglot.sh << 'EOF'
#!/bin/bash

# This creates a file that is both a valid JPEG and a valid ZIP
# Based on the technique described in "The Hitchhiker's Guide to Steganography"

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <jpeg_file> <files_to_hide> <output_file>"
    exit 1
fi

JPEG_FILE="$1"
FILES_TO_HIDE="$2"
OUTPUT_FILE="$3"

# Create a ZIP file with the files to hide
zip hidden.zip "$FILES_TO_HIDE"

# Combine the JPEG and ZIP files
cat "$JPEG_FILE" hidden.zip > "$OUTPUT_FILE"

# The resulting file can be viewed as an image or extracted as a ZIP
echo "Polyglot file created: $OUTPUT_FILE"
echo "You can view it as an image or unzip it to extract the hidden content"

# Clean up
rm hidden.zip
EOF

chmod +x create_polyglot.sh
```

### 3. Network-Based Steganography

```bash
# Example: TCP ISN steganography concept
cat > isn_stego_concept.py << 'EOF'
#!/usr/bin/env python3
"""
Concept demonstration of TCP Initial Sequence Number steganography.
This is a CONCEPT ONLY and would need significant development for real-world use.

The idea is to encode data in the Initial Sequence Numbers of TCP connections.
"""

import random
import string
import sys

def text_to_binary(text):
    """Convert text to binary representation."""
    binary = ''.join(format(ord(char), '08b') for char in text)
    return binary

def binary_to_text(binary):
    """Convert binary representation back to text."""
    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:  # Ensure we have a full byte
            text += chr(int(byte, 2))
    return text

def encode_in_isn(binary_data):
    """Encode binary data into ISN values."""
    isns = []
    
    # Process binary data in 24-bit chunks (preserving 8 bits for randomness)
    for i in range(0, len(binary_data), 24):
        chunk = binary_data[i:i+24].ljust(24, '0')
        # Convert to integer and add random noise in the least significant 8 bits
        # Real implementation would use proper bit manipulation
        isn = int(chunk, 2) << 8 | random.randint(0, 255)
        isns.append(isn)
    
    return isns

def decode_from_isn(isns):
    """Decode binary data from ISN values."""
    binary = ""
    
    for isn in isns:
        # Extract the 24 most significant bits, dropping the noisy 8 LSBs
        # Real implementation would use proper bit manipulation
        binary_chunk = format(isn >> 8, '024b')
        binary += binary_chunk
    
    return binary

def demo():
    """Demonstrate the concept with a simple message."""
    message = "secret"
    print(f"Original message: {message}")
    
    binary = text_to_binary(message)
    print(f"Binary: {binary}")
    
    isns = encode_in_isn(binary)
    print(f"ISNs that would be used in TCP connections:")
    for i, isn in enumerate(isns):
        print(f"  Connection {i+1}: {isn} (0x{isn:08x})")
    
    decoded_binary = decode_from_isn(isns)
    decoded_message = binary_to_text(decoded_binary)
    print(f"Decoded message: {decoded_message}")

if __name__ == "__main__":
    demo()
EOF

chmod +x isn_stego_concept.py
```

### 4. Secure Data Destruction

```bash
# Create a secure data cleanup script
cat > secure_cleanup.sh << 'EOF'
#!/bin/bash

# Securely remove files after exfiltration
secure_delete() {
    file="$1"
    if [ ! -f "$file" ]; then
        echo "File not found: $file"
        return 1
    fi
    
    # Get file size
    size=$(stat -c %s "$file")
    
    # Overwrite with random data
    dd if=/dev/urandom of="$file" bs=1 count=$size conv=notrunc status=none
    
    # Overwrite with zeros
    dd if=/dev/zero of="$file" bs=1 count=$size conv=notrunc status=none
    
    # Overwrite with ones (0xFF)
    tr '\000' '\377' < /dev/zero | dd of="$file" bs=1 count=$size conv=notrunc status=none
    
    # Delete the file
    rm -f "$file"
    
    echo "Securely deleted: $file"
}

# Usage example
if [ $# -eq 0 ]; then
    echo "Usage: $0 <file1> [file2] [file3] ..."
    exit 1
fi

for file in "$@"; do
    secure_delete "$file"
done
EOF

chmod +x secure_cleanup.sh
```

## Conclusion

Cryptography and steganography tools form a critical component of the red team toolkit, enabling secure communications, covert data exfiltration, and bypassing of security controls. The tools covered in this chapter—OpenSSL, Steghide, Stegosuite, and CloakifyFactory—represent different approaches to securing and concealing data.

These tools demonstrate the importance of layered security approaches: using encryption to protect the content and steganography to hide its very existence. By combining these techniques, red teams can establish covert communication channels that are resistant to detection and interception.

Remember that as a professional red teamer, your objective is to help organizations identify and address their security weaknesses. Always operate within the scope of your engagement and with proper authorization.

In the next chapter, we'll explore forensics tools that red teamers can use to understand how their activities might be detected, and how to minimize forensic evidence during operations.
