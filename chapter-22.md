# Chapter 22: Reporting and Documentation

## Introduction to Reporting in Red Team Operations

Effective reporting and documentation transform a technical red team exercise into actionable intelligence for organizational security improvement. While the exploitation techniques and offensive tools discussed throughout this book generate valuable findings, it is the communication of these results that ultimately drives security posture enhancement. 

As a red team operator, your reporting capabilities are as critical as your technical skills. A sophisticated attack that goes undocumented or poorly reported provides limited value to the organization and can diminish the perceived efficacy of the entire red team function. Conversely, clear, comprehensive, and actionable reporting amplifies the impact of your technical findings and helps justify continued investment in security testing.

This chapter examines the specialized reporting and documentation tools available to red team professionals, exploring how to effectively document, manage, and communicate your findings throughout the engagement lifecycle.

![Red team reporting workflow](./images/reporting_workflow.png)
*Figure 22.1: The red team reporting lifecycle from data collection to final deliverables*

## Dradis: Collaborative Reporting Framework

Dradis is an open-source reporting and collaboration framework designed specifically for information security teams. It provides a centralized platform for collecting, organizing, and sharing security findings across team members, making it particularly valuable for complex red team operations involving multiple operators.

### Core Capabilities

Dradis excels in several key areas essential to red team documentation:

1. **Centralized Repository**: Aggregates findings from multiple team members and tools
2. **Cross-Team Collaboration**: Enables real-time information sharing during operations
3. **Standardized Reporting**: Maintains consistent documentation across engagements
4. **Tool Integration**: Directly imports data from various security tools
5. **Report Generation**: Creates customizable reports in multiple formats

### Setting Up Dradis

#### Installation

While Dradis comes pre-installed on many security-focused Linux distributions, you can install it manually if needed:

```bash
# Clone the repository
git clone https://github.com/dradis/dradis-ce.git

# Navigate to the directory
cd dradis-ce

# Install dependencies
bundle install

# Setup the database
bundle exec rake db:setup

# Start the Dradis server
bundle exec rails server
```

Access the web interface at `http://localhost:3000` and create your administrator account during the first login.

#### Project Setup

Creating a well-structured project is the foundation of effective reporting:

1. **Create a New Project**:
   - Navigate to the Dradis dashboard
   - Click "Add Project"
   - Enter a descriptive project name (e.g., "Company X External Assessment Q1 2023")
   - Add project methodology and scope details

2. **Configure Project Structure**:
   - Create logical node structure matching your assessment approach
   - Example structure:
     - External Perimeter
       - Web Applications
       - Infrastructure
     - Internal Network
       - Active Directory
       - Endpoint Security
     - Social Engineering
       - Phishing Campaign
       - Physical Security

![Dradis project structure](./images/dradis_project_structure.png)
*Figure 22.2: Example Dradis project structure for a comprehensive red team assessment*

3. **Define Custom Fields**:
   - Navigate to "Project → Project properties"
   - Add custom fields relevant to your engagement:
     - CVSS Score
     - Business Impact
     - Exploitation Difficulty 
     - Detection Likelihood

### Importing Tool Data

One of Dradis's strengths is its ability to import data from various security tools, streamlining the documentation process:

#### Nmap Import

```bash
# Run Nmap scan with XML output
sudo nmap -sV -A 192.168.1.0/24 -oX nmap_results.xml

# In Dradis: Upload → Nmap → Select nmap_results.xml
```

#### Metasploit Import

```bash
# In Metasploit, run:
db_export -f xml msf_results.xml

# In Dradis: Upload → Metasploit → Select msf_results.xml
```

#### Burp Suite Import

```bash
# In Burp Suite:
# 1. Select findings to export
# 2. Right-click → Report selected issues
# 3. Choose XML format

# In Dradis: Upload → Burp Suite → Select burp_results.xml
```

### Collaborative Workflow

Dradis shines in team environments where multiple red team operators work simultaneously:

1. **Issue Assignment**:
   - Create issues for each vulnerability
   - Assign to team members based on expertise
   - Set status (New, In Progress, Ready for Review, etc.)

2. **Evidence Management**:
   - Upload screenshots, logs, and proof-of-concept files
   - Link evidence to specific issues
   - Add comments explaining significance

3. **Real-time Updates**:
   - Use project notes for live updates during operations
   - Document ongoing activities and findings
   - Share command outputs and techniques

```markdown
# Example Dradis Note Format

## Command Execution Vulnerability

**Description:**
Remote command execution vulnerability discovered in the web application's file upload functionality.

**Technical Details:**
The application fails to validate the file extension properly, allowing for PHP file uploads.

**Evidence:**
- See attached screenshot: command_execution_proof.png
- Payload used: `<?php system($_GET['cmd']); ?>`

**Impact:**
This vulnerability allows attackers to execute arbitrary commands with the privileges of the web server user.

**CVSS Score:** 9.8 (Critical)

**Exploitation Path:**
1. Navigate to file upload form at `/admin/upload.php`
2. Upload malicious PHP file with JPG extension
3. Access uploaded file and execute commands via the `cmd` parameter
```

### Report Generation

Dradis provides flexible reporting capabilities to create deliverables for different audiences:

1. **Executive Summary Reports**:
   - Project → Export → Word Document
   - Choose "Executive Summary" template
   - Customize with company logo and branding

2. **Technical Reports**:
   - Project → Export → Word Document
   - Choose "Technical Report" template
   - Include detailed findings and remediation steps

3. **Custom Report Templates**:
   ```bash
   # Clone the report templates
   git clone https://github.com/dradis/dradis-plugins.git
   
   # Navigate to the templates directory
   cd dradis-plugins/dradis-word_export/templates
   
   # Create custom template based on existing ones
   cp technical_report.template custom_report.template
   ```

#### Report Template Customization

Dradis uses a template language that allows for extensive customization:

```ruby
# Sample template snippet for custom severity formatting
<% issues_by_severity = { 'Critical' => [], 'High' => [], 'Medium' => [], 'Low' => [], 'Info' => [] } %>
<% issues.each do |issue| %>
  <% if issue.fields['Severity'] == 'Critical' %>
    <% issues_by_severity['Critical'] << issue %>
  <% elsif issue.fields['Severity'] == 'High' %>
    <% issues_by_severity['High'] << issue %>
  <% # Continue for other severities %>
  <% end %>
<% end %>

<h1>Critical Findings</h1>
<% issues_by_severity['Critical'].each do |issue| %>
  <h2><%= issue.title %></h2>
  <% # Additional formatting %>
<% end %>
```

> **RED TEAM TIP:**
>
> For more effective reporting, maintain a library of high-quality screenshots, code snippets, and attack narrative templates that can be quickly customized for specific engagements. This approach significantly reduces report preparation time while maintaining quality.

### Comprehensive Red Team Documentation Example

For a complete red team engagement, structure your Dradis documentation to capture the full attack lifecycle:

1. **Reconnaissance Phase**:
   - Document external footprint
   - Note potential entry points
   - Record OSINT findings

2. **Initial Access**:
   - Detail successful entry methods
   - Document failed attempts (also valuable)
   - Include timestamps for attack timeline

3. **Privilege Escalation**:
   - Record step-by-step privilege escalation paths
   - Document system vulnerabilities exploited
   - Note credential capture methods

4. **Lateral Movement**:
   - Map network traversal
   - Document pivot techniques
   - Record access to critical systems

5. **Data Exfiltration Simulation**:
   - Detail what data could be extracted
   - Document exfiltration methods tested
   - Note detection evasion techniques

6. **Persistence Mechanisms**:
   - Document persistence techniques deployed
   - Record cleanup procedures
   - Note potential long-term access methods

Each section should include:
- Technical details
- Business impact
- Detection opportunities
- Remediation recommendations

> **CASE STUDY: Financial Institution Red Team Report**
>
> A red team assessment for a major financial institution used Dradis to document how the team bypassed multifactor authentication using a combination of social engineering and technical exploits. The report included:
>
> - A detailed attack path showing each step from initial email compromise to funds transfer attempt
> - Annotated screenshots demonstrating the exploitation process
> - Timeline correlation with existing security controls to identify detection gaps
> - Clear remediation steps prioritized by implementation difficulty and security impact
>
> The structured reporting approach in Dradis allowed executives to quickly understand critical vulnerabilities while providing technical teams with detailed remediation guidance. This directly led to security improvements that prevented a similar attack vector six months later during an actual attack attempt.

## Faraday: Integrated Penetration Testing Environment

Faraday takes a different approach to security reporting by functioning as an integrated penetration testing IDE (Integrated Development Environment). It combines real-time collaboration, automated tool integration, and comprehensive reporting in a unified workspace.

### Key Features

Faraday offers several advantages for red team operations:

1. **Real-time Collaboration**: Multiple team members can work simultaneously
2. **Automated Tool Integration**: Direct integration with over 70 security tools
3. **Vulnerability Management**: Track vulnerability lifecycle from discovery to resolution
4. **Multiuser Support**: Role-based access control for team members
5. **Web UI**: Access from any location through the web interface

### Installation and Setup

```bash
# Clone the repository
git clone https://github.com/infobyte/faraday.git

# Navigate to the directory
cd faraday

# Install dependencies
pip3 install -r requirements.txt

# Install Faraday
./install.sh

# Start the Faraday server
faraday-server

# Access the web interface at http://localhost:5985
```

### Workspace Management

Faraday organizes penetration testing data into workspaces, which typically correspond to individual engagements:

```bash
# Creating a new workspace via CLI
faraday-client --workspace "CompanyX_External_2023Q1" --create

# Or create through the web interface:
# 1. Click "New Workspace"
# 2. Enter workspace name and description
# 3. Configure workspace settings
```

### Tool Integration

Faraday's plugin architecture automatically processes the output from various security tools:

#### Automated Integration

```bash
# Run a tool through Faraday for automatic processing
faraday-client --workspace "CompanyX_External_2023Q1" --plugin nmap -i office_network_scan.xml

# For multiple tools
faraday-client --workspace "CompanyX_External_2023Q1" --plugin nmap,nikto -i nmap_results.xml,nikto_results.xml
```

#### Supported Tools

Faraday integrates with numerous tools, including:

| Category | Tools |
|----------|-------|
| **Scanners** | Nmap, OpenVAS, Nikto, Acunetix, Burp Suite, ZAP |
| **Exploitation** | Metasploit, sqlmap, w3af, Arachni |
| **Information Gathering** | Shodan, TheHarvester, Recon-ng, Fierce |
| **Password Attacks** | Hydra, John the Ripper, Hashcat |
| **Wireless** | Aircrack-ng, Kismet |

#### Custom Tool Integration

For tools without built-in support, you can create custom plugins:

```python
# simple_plugin.py
from faraday_plugins.plugins.plugin import PluginBase

class SimplePlugin(PluginBase):
    def __init__(self, *args, **kwargs):
        super(SimplePlugin, self).__init__(*args, **kwargs)
        self.id = "custom_tool"
        self.name = "Custom Tool Plugin"

    def parseOutputString(self, output):
        # Parse output and create hosts, services, vulnerabilities
        host_id = self.createAndAddHost("192.168.1.1")
        service_id = self.createAndAddServiceToHost(
            host_id, "tcp", "web", ports=["80"]
        )
        self.createAndAddVulnToService(
            host_id, service_id, "SQL Injection",
            desc="SQL injection in login form",
            severity="high"
        )
```

### Workflow Management

Faraday provides a structured workflow for managing the penetration testing process:

1. **Host Management**:
   - Automatically populated from scan results
   - Manually add hosts when needed
   - Group hosts by network segments

2. **Service Tracking**:
   - Identify open ports and running services
   - Tag critical services for focused testing
   - Document service configurations

3. **Vulnerability Management**:
   - Categorize by severity and type
   - Assign to team members for verification
   - Track status (Open, Confirmed, Closed)

4. **Task Assignment**:
   - Create tasks for team members
   - Set deadlines and priorities
   - Track completion status

![Faraday workflow](./images/faraday_workflow.png)
*Figure 22.3: Faraday's vulnerability management workflow*

### Collaborative Penetration Testing Example

Faraday excels in multi-stage red team operations where different team members focus on specific aspects of the assessment:

#### Phase 1: Reconnaissance and Scanning

```bash
# Team member 1: Network scanning
sudo nmap -sV -A 192.168.1.0/24 -oX network_scan.xml
faraday-client --workspace "RTAssessment" --plugin nmap -i network_scan.xml

# Team member 2: Web application scanning
sudo nikto -h 192.168.1.100 -o nikto_results.xml
faraday-client --workspace "RTAssessment" --plugin nikto -i nikto_results.xml
```

#### Phase 2: Vulnerability Verification

Using the Faraday web interface, team members can:
1. Filter vulnerabilities by host, service, or severity
2. Assign verification tasks to specific team members
3. Update vulnerability status based on manual verification
4. Add notes and evidence for confirmed vulnerabilities

#### Phase 3: Exploitation

As the team exploits identified vulnerabilities, they document the process in Faraday:

```bash
# Document Metasploit exploitation
faraday-client --workspace "RTAssessment" --plugin metasploit -i msf_results.xml

# Add manual exploitation notes through the web interface
# 1. Select the target vulnerability
# 2. Click "Add note"
# 3. Document exploitation steps and results
```

#### Phase 4: Reporting

Faraday offers multiple reporting options:

1. **Executive Report**:
   - Vulnerability summary by severity
   - Statistical analysis of findings
   - Risk assessment

2. **Technical Report**:
   - Detailed vulnerability descriptions
   - Exploitation narratives
   - Remediation recommendations

3. **Custom Reports**:
   - CSV exports for data analysis
   - JSON exports for integration with other tools
   - PDF reports with customized branding

```bash
# Generate executive summary report
faraday-client --workspace "RTAssessment" --report executive --output exec_summary.pdf

# Generate technical report
faraday-client --workspace "RTAssessment" --report technical --output technical_report.pdf
```

### Comparative Analysis: Dradis vs. Faraday

While both tools excel at security reporting, they serve different operational needs:

| Feature | Dradis | Faraday |
|---------|--------|---------|
| **Primary Focus** | Reporting and documentation | Integrated testing environment |
| **Tool Integration** | Upload-based import | Direct integration and automation |
| **Collaboration** | Good for document-focused teams | Better for real-time operation teams |
| **Learning Curve** | Moderate | Steeper due to broader functionality |
| **Customization** | Highly customizable reports | Customizable workspace and plugins |
| **Best Use Case** | Detailed final reporting | Active testing and documentation |

> **RED TEAM TIP:**
> 
> For complex engagements, consider using both tools in tandem: Faraday during active operations for real-time collaboration and findings tracking, and Dradis for final report preparation and client deliverables.

## MagicTree: Hierarchical Data Management

MagicTree provides a structured approach to managing the vast amounts of data generated during security assessments. It organizes information in a tree structure, making it particularly effective for large-scale engagements with complex scopes.

### Key Capabilities

MagicTree focuses on data organization and transformation:

1. **Hierarchical Data Structure**: Organizes data in a logical tree format
2. **Data Transformation**: Processes raw tool output into structured data
3. **Query System**: Filters and searches across all collected data
4. **Report Generation**: Creates customized reports from selected data
5. **Cross-Platform**: Runs on Linux, macOS, and Windows

### Installation

MagicTree is Java-based, making installation straightforward on Linux systems:

```bash
# Download the latest version (check for updates)
wget https://www.gremwell.com/sites/default/files/MagicTree-1.3.jar

# Make executable
chmod +x MagicTree-1.3.jar

# Run MagicTree
java -jar MagicTree-1.3.jar
```

### Data Organization

MagicTree uses a hierarchical tree structure to organize data:

1. **Root Node**: Typically represents the entire assessment
2. **Domain/Network Nodes**: Organizational units (domains, networks)
3. **Host Nodes**: Individual systems
4. **Service Nodes**: Services running on hosts
5. **Finding Nodes**: Vulnerabilities or notable information
6. **Data Nodes**: Raw and processed output from tools

![MagicTree data hierarchy](./images/magictree_hierarchy.png)
*Figure 22.4: MagicTree's hierarchical data organization*

### Importing and Processing Data

MagicTree can import data from various sources:

```bash
# Within MagicTree:
# 1. Right-click on the appropriate node
# 2. Select "Add data from file"
# 3. Choose the file format (Nmap XML, Nessus, etc.)
# 4. Select the file and import
```

The true power of MagicTree comes from its data transformation capabilities:

1. **Parsing Raw Data**:
   - Import tool output (XML, text)
   - Parse into structured format
   - Organize in the tree hierarchy

2. **Data Transformation Rules**:
   - Apply XSLT transformations to XML data
   - Convert between different formats
   - Extract specific information from complex outputs

```xml
<!-- Example XSLT transformation for Nmap data -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <results>
      <xsl:for-each select="//host[status/@state='up']">
        <host>
          <address><xsl:value-of select="address/@addr"/></address>
          <hostname><xsl:value-of select="hostnames/hostname/@name"/></hostname>
          <ports>
            <xsl:for-each select="ports/port[state/@state='open']">
              <port>
                <protocol><xsl:value-of select="@protocol"/></protocol>
                <number><xsl:value-of select="@portid"/></number>
                <service><xsl:value-of select="service/@name"/></service>
                <product><xsl:value-of select="service/@product"/></product>
                <version><xsl:value-of select="service/@version"/></version>
              </port>
            </xsl:for-each>
          </ports>
        </host>
      </xsl:for-each>
    </results>
  </xsl:template>
</xsl:stylesheet>
```

3. **Query System**:
   - Search across all data
   - Filter by attributes (port, service, vulnerability)
   - Create complex queries using XPath

```xpath
# Find all critical SQL injection vulnerabilities
//vulnerability[@severity='Critical' and contains(@name,'SQL injection')]

# Find all Windows hosts with SMB enabled
//host[os/contains(text(),'Windows')]//service[@name='smb' or @name='microsoft-ds']
```

### Organizing Complex Test Results

MagicTree's structure makes it ideal for managing complex security assessments:

#### Example: Enterprise Network Assessment

```
Root: Company X Assessment
├── External Testing
│   ├── DMZ Network (192.168.1.0/24)
│   │   ├── Web Server (192.168.1.10)
│   │   │   ├── HTTP (80)
│   │   │   │   └── Outdated Apache [Critical]
│   │   │   └── HTTPS (443)
│   │   │       └── SSL Certificate Issues [Medium]
│   │   └── Mail Server (192.168.1.20)
│   │       ├── SMTP (25)
│   │       └── IMAP (143)
│   └── Public Website (company.com)
│       ├── SQL Injection in Login [Critical]
│       └── XSS in Search Function [High]
├── Internal Testing
│   ├── User Network (10.1.0.0/24)
│   │   └── [Multiple Hosts]
│   └── Server Network (10.2.0.0/24)
│       ├── File Server (10.2.0.5)
│       └── Database Server (10.2.0.10)
└── Wireless Assessment
    ├── Corporate SSID
    └── Guest SSID
```

This structure allows team members to:
1. Navigate directly to areas of interest
2. Understand the relationship between systems
3. Track findings across network segments
4. Generate focused reports for specific areas

### Report Generation

MagicTree provides flexible reporting capabilities:

1. **Node Selection**:
   - Select specific nodes for inclusion
   - Filter by attributes (severity, status)
   - Include/exclude specific data types

2. **Format Templates**:
   - HTML reports
   - XML exports
   - Text reports
   - Custom formats via XSLT

3. **Report Customization**:
   - Apply corporate branding
   - Customize layout and structure
   - Include specific sections (executive summary, technical details)

```bash
# Within MagicTree:
# 1. Select the nodes to include
# 2. Right-click and select "Report"
# 3. Choose the report template
# 4. Configure options and generate
```

### Example: Advanced Network Topology Mapping

MagicTree excels at visualizing complex network relationships discovered during red team assessments:

1. **Data Collection**:
   - Import Nmap network scans
   - Add traceroute data
   - Include routing information

2. **Relationship Mapping**:
   - Link hosts based on network proximity
   - Identify gateway systems
   - Map trust relationships

3. **Attack Path Visualization**:
   - Document successful compromise paths
   - Highlight critical junction points
   - Identify network segmentation bypasses

This visual representation helps both technical teams understand attack vectors and executives comprehend the impact of security weaknesses.

> **RED TEAM TIP:**
>
> When documenting complex attack chains in MagicTree, create a specialized branch in your tree specifically for attack paths. This allows you to map the sequence of compromises while maintaining the detailed technical information in the main assessment structure.

## Pipal: Password Analysis

While the previous tools focus on general reporting and data management, Pipal addresses a specific but critical aspect of red team operations: password analysis. Understanding password patterns and user behaviors provides valuable insights for both current and future engagements.

### Password Analysis Importance

Password analysis serves multiple purposes in red team operations:

1. **Current Engagement Value**:
   - Identify password patterns for further exploitation
   - Discover password reuse across systems
   - Generate targeted wordlists for additional cracking

2. **Client Security Improvement**:
   - Demonstrate password policy weaknesses
   - Provide concrete examples of password behaviors
   - Support stronger policy recommendations

3. **Future Engagement Intelligence**:
   - Build organization-specific dictionaries
   - Identify common password creation patterns
   - Improve efficiency of future cracking attempts

### Basic Pipal Usage

```bash
# Install Pipal if not available
git clone https://github.com/digininja/pipal.git
cd pipal

# Basic password analysis
ruby pipal.rb passwords.txt

# Analysis with advanced options
ruby pipal.rb --top 20 --output=analysis_report.txt passwords.txt
```

### Password Corpus Preparation

For accurate analysis, prepare your password corpus carefully:

```bash
# Remove duplicates
sort passwords.txt | uniq > unique_passwords.txt

# Split domain and username data (if present)
awk -F: '{print $2}' credentials.txt > passwords_only.txt

# Combine multiple sources
cat domain1_passwords.txt domain2_passwords.txt > all_passwords.txt
sort all_passwords.txt | uniq > unique_all_passwords.txt
```

### Analysis Categories

Pipal provides comprehensive password statistics across multiple categories:

1. **Basic Statistics**:
   - Password length distribution
   - Character type usage
   - Character positions analysis

2. **Pattern Analysis**:
   - Common prefixes and suffixes
   - Character substitution patterns
   - Keyboard pattern detection

3. **Policy Testing**:
   - Compliance with complexity requirements
   - Common policy circumvention techniques
   - Effectiveness of current policies

![Pipal output example](./images/pipal_output.png)
*Figure 22.5: Example Pipal analysis output showing password patterns*

### Advanced Usage

Pipal supports custom analysis through various options:

```bash
# Analyze passwords with usernames for correlation
ruby pipal.rb --username-list usernames.txt passwords.txt

# Use custom pattern matching rules
ruby pipal.rb --pattern-file custom_patterns.txt passwords.txt

# Generate advanced statistics
ruby pipal.rb --statistics all --output=detailed_analysis.txt passwords.txt
```

### Creating Insightful Password Reports

Transform raw Pipal output into actionable security intelligence:

1. **Statistical Summary**:
   - Password length distribution
   - Character complexity analysis
   - Policy compliance rates

2. **Pattern Identification**:
   - Common base words
   - Frequently used numbers/symbols
   - Organizational terminology usage

3. **Security Implications**:
   - Password guessability assessment
   - Resistance to cracking attempts
   - Account compromise risk evaluation

4. **Remediation Recommendations**:
   - Policy improvement suggestions
   - User awareness training focus
   - Technical control enhancements

#### Example: Executive Summary Section

```markdown
## Password Security Assessment Summary

Analysis of 10,473 cracked passwords from the corporate domain revealed significant security concerns:

- **Policy Circumvention**: 83% of passwords technically meet the policy requirements but follow predictable patterns that weaken security
- **Common Patterns**: 62% of passwords follow the pattern "Word+Number+Symbol" (e.g., "Company2023!")
- **Organizational Terms**: 47% of passwords incorporate company name, products, or location
- **Password Reuse**: 38% of users employ the same password pattern across multiple systems

These findings indicate that while current policies are technically enforced, they do not effectively prevent easily guessable passwords. Specific recommendations include:

1. Implementing longer minimum length requirements (14+ characters)
2. Deploying advanced password strength measurement tools
3. Enhancing user education about effective password creation
4. Considering passwordless authentication alternatives where appropriate
```

> **CASE STUDY: Manufacturing Company Password Audit**
>
> During a red team assessment for a manufacturing company, Pipal analysis revealed that 72% of passwords contained either the company name or product names, followed by production years. This pattern was so consistent that the red team created a targeted wordlist that successfully cracked an additional 3,000 accounts beyond the initial compromise.
>
> The report visualized these patterns with heat maps showing character positions and common word usage, convincingly demonstrating to executives why their current password policy was ineffective despite meeting "complexity" requirements.

### Custom Analysis Scripts

For more advanced analysis, combine Pipal with custom scripts:

```python
#!/usr/bin/env python3
# password_analyzer.py
import sys
import re
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter

def load_passwords(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def analyze_structure(passwords):
    structures = []
    
    for password in passwords:
        structure = ""
        for char in password:
            if char.isupper():
                structure += "U"
            elif char.islower():
                structure += "L"
            elif char.isdigit():
                structure += "D"
            else:
                structure += "S"
        structures.append(structure)
    
    return Counter(structures)

def extract_word_components(passwords):
    # Dictionary words of 4+ characters
    word_pattern = re.compile(r'[a-zA-Z]{4,}')
    words = []
    
    for password in passwords:
        matches = word_pattern.findall(password)
        words.extend(matches)
    
    return Counter(words)

def visualize_results(structure_counts, word_counts):
    # Structure visualization
    top_structures = dict(structure_counts.most_common(10))
    
    plt.figure(figsize=(15, 10))
    
    plt.subplot(2, 1, 1)
    plt.bar(top_structures.keys(), top_structures.values())
    plt.title('Top 10 Password Structures')
    plt.xlabel('Structure (U=Uppercase, L=Lowercase, D=Digit, S=Symbol)')
    plt.ylabel('Count')
    
    # Word visualization
    top_words = dict(word_counts.most_common(10))
    
    plt.subplot(2, 1, 2)
    plt.bar(top_words.keys(), top_words.values())
    plt.title('Top 10 Word Components')
    plt.xlabel('Word')
    plt.ylabel('Count')
    
    plt.tight_layout()
    plt.savefig('password_analysis.png')
    print("Analysis visualization saved to password_analysis.png")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python password_analyzer.py passwords.txt")
        sys.exit(1)
        
    passwords = load_passwords(sys.argv[1])
    print(f"Loaded {len(passwords)} passwords for analysis")
    
    structures = analyze_structure(passwords)
    print("\nTop 10 Password Structures:")
    for structure, count in structures.most_common(10):
        print(f"{structure}: {count} ({count/len(passwords)*100:.2f}%)")
    
    words = extract_word_components(passwords)
    print("\nTop 10 Word Components:")
    for word, count in words.most_common(10):
        print(f"{word}: {count} ({count/len(passwords)*100:.2f}%)")
    
    visualize_results(structures, words)
```

This script enhances Pipal's analysis with:
- Password structure visualization
- Word component extraction
- Graphical representation of patterns
- Percentage-based analysis

### Integrating Password Analysis into Reports

Password analysis provides compelling evidence of security weaknesses and should be featured prominently in red team reports:

1. **Visual Representation**:
   - Include pattern distribution graphs
   - Show character position heat maps
   - Visualize word frequency clouds

2. **Real-world Examples**:
   - Include anonymized but real examples
   - Demonstrate pattern consistency
   - Show password families across accounts

3. **Attack Narrative Integration**:
   - Explain how password patterns facilitated access
   - Document password reuse across systems
   - Show privilege escalation via pattern prediction

This integration transforms abstract password policy discussions into concrete security concerns with demonstrated impact.

## Integrated Reporting Workflow

For maximum effectiveness, incorporate multiple tools into a comprehensive reporting workflow:

### Pre-Engagement Setup

1. **Create Project Structure**:
   - Set up Dradis project with appropriate nodes
   - Configure Faraday workspace for team collaboration
   - Establish MagicTree hierarchy for data organization

2. **Define Documentation Standards**:
   - Establish finding template format
   - Define severity classification criteria
   - Create evidence collection guidelines

3. **Prepare Automation**:
   - Configure tool integrations
   - Set up report templates
   - Establish workflow for data sharing between tools

### During Active Testing

1. **Live Documentation**:
   - Document findings in real-time with Faraday
   - Upload evidence and screenshots to Dradis
   - Organize raw data in MagicTree

2. **Team Coordination**:
   - Track testing progress in Faraday
   - Share critical findings via Dradis notes
   - Maintain current attack status documentation

3. **Data Processing**:
   - Transform raw tool output in MagicTree
   - Process password data with Pipal
   - Prepare interim reports for status updates

### Post-Testing Analysis

1. **Finding Verification**:
   - Validate vulnerabilities and remove false positives
   - Ensure consistent severity ratings
   - Cross-reference findings across systems

2. **Impact Assessment**:
   - Document business impact for each finding
   - Map attack chains and exploitation paths
   - Evaluate overall security posture

3. **Recommendation Development**:
   - Create specific, actionable remediation steps
   - Prioritize fixes based on risk and effort
   - Develop strategic security improvement recommendations

### Final Reporting

1. **Report Assembly**:
   - Generate technical reports from Dradis
   - Extract statistical data from Faraday
   - Include specialized analyses (password patterns, attack paths)

2. **Quality Control**:
   - Review for technical accuracy
   - Ensure findings are clearly communicated
   - Validate remediation recommendations

3. **Deliverable Production**:
   - Create tailored reports for different audiences
   - Prepare presentation materials
   - Assemble supporting evidence packages

![Integrated reporting workflow](./images/integrated_reporting.png)
*Figure 22.6: Integrated reporting workflow combining multiple tools*

## Conclusion

Effective reporting transforms technical findings into actionable security intelligence. The tools covered in this chapter—Dradis, Faraday, MagicTree, and Pipal—provide complementary capabilities that support comprehensive documentation throughout the red team operation lifecycle.

The most successful red teams understand that their value lies not just in finding vulnerabilities but in communicating them effectively. By mastering these reporting tools and integrating them into a cohesive workflow, you ensure that your technical expertise translates into measurable security improvements for the organizations you assess.

In the next chapter, we'll explore how to map your tools and techniques to the MITRE ATT&CK framework, providing an additional layer of context that enhances the strategic value of your red team operations.

## Additional Resources

- [Dradis Framework Documentation](https://dradisframework.com/documentation/)
- [Faraday User Manual](https://docs.faradaysec.com/)
- [MagicTree User Guide](https://www.gremwell.com/magictree_user_guide)
- [DigiNinja's Pipal Documentation](https://github.com/digininja/pipal)
- [SANS Writing the Penetration Testing Report](https://www.sans.org/reading-room/whitepapers/testing/writing-penetration-testing-report-33343)
- [Red Team Reporting Guide by SANS](https://www.sans.org/reading-room/whitepapers/testing/red-team-assessment-reporting-guide-35310)
- [The Art of Reporting by Offensive Security](https://www.offensive-security.com/reports/sample-penetration-testing-report.pdf)
