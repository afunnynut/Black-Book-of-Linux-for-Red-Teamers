# Appendix C: Virtual Lab Setup

Setting up a personal virtual lab environment is essential for practicing and refining the security testing techniques covered throughout this book. A properly configured lab allows you to safely experiment with offensive tools and techniques without risk to production systems or legal complications. This appendix provides comprehensive guidance on establishing effective virtual lab environments for cybersecurity testing and research.

## Vulnerable Machines and Networks

Purposely vulnerable systems provide realistic targets to practice exploitation techniques against known vulnerabilities. These systems are designed to contain security flaws that mirror real-world scenarios.

### Essential Vulnerable Virtual Machines

#### Metasploitable Series

Metasploitable is among the most widely used vulnerable VM series for security testing.

**Metasploitable 2**
```bash
# Download and setup
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/
unzip metasploitable-linux-2.0.0.zip
# Import into virtualization platform (VMware/VirtualBox)
# Default credentials: msfadmin/msfadmin
```

Metasploitable 2 includes vulnerable services such as:
- Unpatched vsftpd 2.3.4 (backdoored)
- Vulnerable Samba version (trans2open exploit)
- Multiple vulnerable web applications (DVWA, Mutillidae)
- Unprotected MySQL instance
- Outdated SSH server

**Metasploitable 3**

For a more advanced experience, Metasploitable 3 provides a vulnerable Windows environment:

```bash
# Requirements: Vagrant, VirtualBox/VMware, Packer
git clone https://github.com/rapid7/metasploitable3.git
cd metasploitable3
# For Windows
.\build.ps1
# For Linux/macOS
./build.sh
vagrant up
```

Metasploitable 3 features vulnerabilities like:
- Outdated and misconfigured JBoss and Apache Tomcat
- Vulnerable WordPress and phpMyAdmin installations
- Unpatched SMB services
- Weak credentials throughout the system

#### OWASP Broken Web Applications (BWA)

For web application security testing specifically:

```bash
# Download and import the VM
wget https://sourceforge.net/projects/owaspbwa/files/
# Import OVA file into virtualization platform
# Access web interface at https://VM_IP/
```

OWASP BWA contains numerous vulnerable web applications:
- DVWA (Damn Vulnerable Web Application)
- Mutillidae
- WebGoat
- bWAPP
- Vulnerable WordPress and Joomla installations

#### Vulnerable Active Directory Setup

For practicing Active Directory attacks:

```bash
# Using DetectionLab
git clone https://github.com/clong/DetectionLab.git
cd DetectionLab/Vagrant
vagrant up dc logger wef win10
```

This creates a complete Windows domain environment with:
- Domain Controller with misconfigurations
- Workstations with weak group policies
- Common privilege escalation paths
- Monitoring capabilities for learning

### Creating Custom Vulnerable Networks

Beyond pre-made vulnerable systems, you can create custom networks that reflect real-world scenarios:

```bash
# Example network topology script for VirtualBox
#!/bin/bash
# Create internal network
VBoxManage natnetwork add --netname vulnnet --network "10.10.10.0/24" --enable

# Create vulnerable Ubuntu web server
VBoxManage createvm --name "web-server" --ostype Ubuntu_64 --register
VBoxManage modifyvm "web-server" --memory 2048 --cpus 2
VBoxManage modifyvm "web-server" --nic1 natnetwork --nat-network1 vulnnet
# Additional configuration steps...

# Create vulnerable Windows client
VBoxManage createvm --name "windows-client" --ostype Windows10_64 --register
VBoxManage modifyvm "windows-client" --memory 4096 --cpus 2
VBoxManage modifyvm "windows-client" --nic1 natnetwork --nat-network1 vulnnet
# Additional configuration steps...
```

When creating custom vulnerable networks, consider:

1. **Layer separation** - Create multiple network segments (DMZ, internal, management)
2. **Diverse operating systems** - Mix Windows, Linux, and potentially network devices
3. **Realistic services** - Deploy actual services like web servers, databases, and file shares
4. **Deliberate misconfigurations** - Implement common security mistakes (weak passwords, excessive permissions)
5. **Documentation** - Document all vulnerabilities for learning purposes

### Automating Vulnerable Environment Deployment

For reproducible environments, consider Infrastructure as Code approaches:

```yaml
# Example docker-compose.yml for a vulnerable lab
version: '3'
services:
  vulnerable-webapp:
    image: vulnerables/web-dvwa
    ports:
      - "80:80"
    networks:
      - vulnnet
  
  vulnerable-api:
    image: vulnerables/api-mutillidae
    ports:
      - "8080:80"
    networks:
      - vulnnet
  
  database:
    image: mysql:5.7
    environment:
      MYSQL_ROOT_PASSWORD: password
      MYSQL_DATABASE: vulnerable_db
    networks:
      - vulnnet

networks:
  vulnnet:
    driver: bridge
```

Using automation tools like Ansible for larger deployments:

```yaml
# Example Ansible playbook snippet for deploying vulnerable infrastructure
- name: Deploy Vulnerable Windows Server
  hosts: windows_targets
  tasks:
    - name: Disable Windows Firewall
      win_firewall:
        state: disabled
        profiles:
          - Domain
          - Private
          - Public
    
    - name: Install Vulnerable Services
      win_package:
        path: '{{ item }}'
        state: present
      with_items:
        - 'https://example.com/outdated_software.msi'
        - 'https://example.com/vulnerable_service.msi'
```

## Isolated Testing Environments

Creating proper isolation for your testing environments is crucial to prevent accidental exposure or compromise of other systems.

### Network Isolation Techniques

#### Virtual Network Isolation

Most virtualization platforms provide options for network isolation:

**VirtualBox Host-Only Networks**
```bash
# Create a host-only network
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# Attach VMs to host-only network
VBoxManage modifyvm "vulnerable-vm" --nic1 hostonly --hostonlyadapter1 vboxnet0

# Optionally add NAT interface for internet access
VBoxManage modifyvm "vulnerable-vm" --nic2 nat
```

**VMware Workstation/Fusion**
```bash
# Through GUI: Edit > Virtual Network Editor
# Create custom VMnet for isolation
# Set to Host-only mode without DHCP
```

#### Physical Network Isolation

For more complex labs with physical equipment:

1. **Dedicated network switch** - Use VLAN isolation
   ```bash
   # Example Cisco switch configuration
   switch# configure terminal
   switch(config)# vlan 100
   switch(config-vlan)# name SECURITY_LAB
   switch(config-vlan)# exit
   switch(config)# interface range gigabitethernet 0/1-8
   switch(config-if-range)# switchport mode access
   switch(config-if-range)# switchport access vlan 100
   ```

2. **Air-gapped networks** - Completely disconnected from production/internet
   - Use a dedicated switch/router with no uplink
   - Physically separate hardware
   - Remove wireless capabilities from machines when possible

### Virtualization Security Considerations

When setting up virtualization for security testing:

1. **Hypervisor isolation**
   ```bash
   # For VirtualBox, disable shared folders and clipboard
   VBoxManage modifyvm "vulnerable-vm" --clipboard-mode disabled
   VBoxManage modifyvm "vulnerable-vm" --draganddrop disabled
   
   # For VMware, edit .vmx file to add:
   isolation.tools.copy.disable = "TRUE"
   isolation.tools.paste.disable = "TRUE"
   ```

2. **Snapshot management**
   ```bash
   # Create clean state snapshot
   VBoxManage snapshot "vulnerable-vm" take "clean-state"
   
   # Restore to clean state
   VBoxManage snapshot "vulnerable-vm" restore "clean-state"
   ```

3. **Resource limitations** - Prevent DoS of host system
   ```bash
   # Limit VM resources
   VBoxManage modifyvm "vulnerable-vm" --memory 2048 --cpus 2
   VBoxManage modifyvm "vulnerable-vm" --cpuexecutioncap 50
   ```

### Complete Isolation with Dedicated Hardware

For the most secure isolation, consider dedicated hardware:

1. **Repurposed computers** - Use older hardware exclusively for security testing
   - Install a hypervisor like ESXi or Proxmox
   - Create an isolated virtual network
   - Use separate physical network interfaces for management and lab networks

2. **Mini-PC clusters** - Small form-factor PCs for flexible lab setups
   ```bash
   # Example network configuration on Ubuntu-based mini PC
   sudo ip link add lab0 type bridge
   sudo ip link set lab0 up
   
   # Configure network interfaces
   sudo ip addr add 10.0.0.1/24 dev lab0
   
   # Setup NAT for controlled internet access
   sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
   sudo echo 1 > /proc/sys/net/ipv4/ip_forward
   ```

### Monitoring and Logging for Learning

Implementing monitoring in your lab enhances the learning experience:

1. **Central logging server**
   ```bash
   # Simple ELK stack deployment
   docker run -d --name elasticsearch -p 9200:9200 -p 9300:9300 \
     -e "discovery.type=single-node" elasticsearch:7.12.0
   
   docker run -d --name kibana --link elasticsearch:elasticsearch \
     -p 5601:5601 kibana:7.12.0
   
   docker run -d --name logstash --link elasticsearch:elasticsearch \
     -v "$PWD/logstash.conf:/usr/share/logstash/pipeline/logstash.conf" \
     -p 5044:5044 logstash:7.12.0
   ```

2. **Network traffic capture**
   ```bash
   # Setup continuous packet capture
   sudo tcpdump -i any -s0 -w /var/log/lab/$(date +%Y%m%d-%H%M%S).pcap port not 22
   
   # For web traffic analysis
   sudo tcpdump -i any -s0 -w /var/log/lab/http-$(date +%Y%m%d-%H%M%S).pcap port 80 or port 443
   ```

3. **Security visualization**
   ```bash
   # Simple visualization with ELK
   # Create dashboard in Kibana for:
   # - Attack patterns
   # - Service access
   # - Failed login attempts
   # - Network traffic patterns
   ```

## Cloud-Based Practice Labs

Cloud platforms offer flexibility and scalability for security labs, especially for larger environments or team-based exercises.

### AWS Security Testing Environments

AWS provides powerful capabilities for security lab environments:

```bash
# Example using AWS CLI to deploy a basic lab environment
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=SecurityLab}]'

# Create subnets
aws ec2 create-subnet --vpc-id vpc-XXXXXXXX --cidr-block 10.0.1.0/24 --availability-zone us-east-1a
aws ec2 create-subnet --vpc-id vpc-XXXXXXXX --cidr-block 10.0.2.0/24 --availability-zone us-east-1b

# Create security group allowing internal traffic only
aws ec2 create-security-group --group-name SecurityLabInternal --description "Security Lab Internal Traffic" --vpc-id vpc-XXXXXXXX
aws ec2 authorize-security-group-ingress --group-id sg-XXXXXXXX --protocol all --source-group sg-XXXXXXXX

# Launch vulnerable instances
aws ec2 run-instances --image-id ami-XXXXXXXX --count 1 --instance-type t2.micro --key-name security-lab-key --security-group-ids sg-XXXXXXXX --subnet-id subnet-XXXXXXXX
```

**Using CloudFormation for reproducible labs:**

```yaml
# Example CloudFormation template snippet
Resources:
  VulnerableWebServer:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t2.micro
      SecurityGroupIds:
        - !Ref WebServerSecurityGroup
      SubnetId: !Ref PrivateSubnet
      ImageId: ami-0a1b2c3d4e5f67890  # Vulnerable AMI
      Tags:
        - Key: Name
          Value: Vulnerable-WebServer
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          yum update -y
          yum install -y httpd php mysql php-mysql
          echo "<?php phpinfo(); ?>" > /var/www/html/info.php
          service httpd start
          chkconfig httpd on
```

### Azure Security Labs

Microsoft Azure provides excellent options for Windows-focused security testing:

```bash
# Create a resource group for isolation
az group create --name SecurityLab --location eastus

# Create a virtual network
az network vnet create --resource-group SecurityLab --name LabNetwork --address-prefix 10.0.0.0/16 --subnet-name LabSubnet --subnet-prefix 10.0.0.0/24

# Create NSG with restrictive rules
az network nsg create --resource-group SecurityLab --name LabNSG
az network nsg rule create --resource-group SecurityLab --nsg-name LabNSG --name AllowInternalTraffic --priority 100 --source-address-prefixes 10.0.0.0/16 --destination-address-prefixes 10.0.0.0/16 --access Allow --protocol "*" --direction Inbound

# Deploy a vulnerable Windows server
az vm create --resource-group SecurityLab --name VulnerableServer --image Win2016Datacenter --admin-username azureuser --admin-password "ComplexPassword123!" --nsg LabNSG --subnet LabSubnet --vnet-name LabNetwork
```

For automated deployment of vulnerable Active Directory environments:

```bash
# Clone BadBlood for automated AD vulnerabilities creation
git clone https://github.com/davidprowe/BadBlood.git

# Deploy template AD environment, then run BadBlood inside it
# You'll need to RDP into the domain controller first
.\BadBlood\Invoke-BadBlood.ps1
```

### GCP Security Testing Environments

Google Cloud Platform can also be used for security labs:

```bash
# Create network for isolation
gcloud compute networks create security-lab-network --subnet-mode=custom

# Create subnet
gcloud compute networks subnets create lab-subnet --network=security-lab-network --region=us-central1 --range=10.0.0.0/24

# Create firewall rules for internal traffic only
gcloud compute firewall-rules create allow-internal --network security-lab-network --allow tcp,udp,icmp --source-ranges 10.0.0.0/24

# Deploy vulnerable instance
gcloud compute instances create vulnerable-instance --machine-type=e2-medium --subnet=lab-subnet --image-family=debian-10 --image-project=debian-cloud --metadata=startup-script='#!/bin/bash
apt-get update
apt-get install -y apache2 php
echo "<?php phpinfo(); ?>" > /var/www/html/info.php'
```

### Specialized Cloud-Based Platforms

Several platforms are specifically designed for security training:

#### Hack The Box

[Hack The Box](https://www.hackthebox.com/) provides both free and subscription-based security labs:

- **Starting Point** - For beginners learning the basics
- **Pro Labs** - Enterprise-like environments (Active Directory, entire networks)
- **Battlegrounds** - Red vs. Blue team exercises
- **Dedicated Labs** - Private environments for team training

To connect:

```bash
# Download and connect to HTB VPN
sudo openvpn hackthebox.ovpn

# Verify connection
ping 10.10.10.X # Target IP
```

#### TryHackMe

[TryHackMe](https://tryhackme.com/) offers guided rooms and challenges:

- **Learning Paths** - Structured security learning paths
- **Challenges** - Hands-on rooms with guided or unguided challenges
- **King of the Hill** - Competitive security exercises

Connection:

```bash
# Connect via VPN
sudo openvpn tryhackme.ovpn

# Or use in-browser attack box (subscription feature)
```

#### RangeForce

[RangeForce](https://www.rangeforce.com/) provides enterprise-focused training environments:

- **CyberSkills Platform** - Hands-on cybersecurity training
- **SOC Analyst** - Specific training for security operations
- **DevSecOps** - Security training for developers

### Cost Optimization for Cloud Labs

Cloud environments can become expensive. Here are strategies to manage costs:

1. **Automated shutdown schedules**
   ```bash
   # AWS example - Create Lambda function to stop instances after hours
   aws lambda create-function --function-name StopInstances \
     --runtime python3.8 --handler lambda_function.lambda_handler \
     --role arn:aws:iam::123456789012:role/LambdaExecutionRole \
     --zip-file fileb://stop_instances.zip
   
   # Create CloudWatch rule to trigger Lambda
   aws events put-rule --name StopInstancesRule \
     --schedule-expression "cron(0 18 ? * MON-FRI *)"
   
   aws events put-targets --rule StopInstancesRule \
     --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:123456789012:function:StopInstances"
   ```

2. **Resource limitations**
   ```bash
   # Use smaller instance types
   # AWS example
   aws ec2 run-instances --image-id ami-XXXXXXXX --instance-type t2.micro
   
   # Azure example
   az vm create --resource-group SecurityLab --name VulnerableServer --size Standard_B1s
   ```

3. **Spot instances** (AWS)
   ```bash
   # Use spot instances for non-critical lab components
   aws ec2 request-spot-instances --spot-price "0.03" --instance-count 1 \
     --type "one-time" --launch-specification file://specification.json
   ```

### Building Hybrid Lab Environments

Combining local and cloud resources often provides the best balance:

1. **Local attack machine, cloud targets**
   ```bash
   # Set up VPN connection to cloud environment
   # AWS Site-to-Site VPN example
   aws ec2 create-vpn-gateway --type ipsec.1
   aws ec2 create-customer-gateway --type ipsec.1 --public-ip your.public.ip --bgp-asn 65000
   
   # Configure local VPN endpoint (varies by device)
   ```

2. **Cloud management with local vulnerable targets**
   ```bash
   # Deploy management tools in cloud
   # Example: Deploying Kali in AWS
   aws ec2 run-instances --image-id ami-XXXXXXXXX --instance-type t2.large \
     --key-name kali-key --security-group-ids sg-XXXXXXXX
   
   # Connect from Kali to local lab via VPN or reverse proxy
   ```

## Conclusion

Setting up a proper virtual lab environment is essential for effectively practicing the security techniques covered in this book. Whether you choose local virtualization, cloud-based solutions, or a hybrid approach, the key considerations remain the same:

1. **Isolation** - Ensure testing environments are properly contained
2. **Diversity** - Include various operating systems and network configurations
3. **Realism** - Model environments after real-world scenarios
4. **Documentation** - Maintain detailed records of lab configurations
5. **Safety** - Implement controls to prevent accidental exposure

By following the guidelines in this appendix, you can build sophisticated testing environments that allow for safe, effective practice of advanced security testing techniques. Remember that the quality of your lab environment directly impacts your learning experience and skill development.