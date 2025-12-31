# snort-and-suricata-home-lab

When setting and securing a networking, having the proper measures in force to defend from outside activity or attacks is important to securing it. Usually involves having security features, firewalls, and more in order for everything to be securred.  
With Snort and Suricata implemented into the system on their own respective machines, it helps with getting everything situated and secure and to be able to detect and alert of unusual traffic that might be present.  

For this lab it will require 3 VMs, one attacker, one victim, and one for Suricata and Snort. Also make a couple networks for a management and monitored one and turn promiscious mode off.  
For the Snort and Suricata VMs, first adapter will be intnet_lab, second adapter will be set to host only adapter 
Attacker VM Setup:
Base Memory: 8048 MB  
Processors: 4  
Video Memory: 128
Kali Linux ISO  
Adapter 1: 

IDS/IPS VM:  
Base Memory: 8048 MB  
Processors: 3  
Video Memory: 128 MB  
Ubuntu Server iso
Adapter 1: NAT
Adpater 2: management one
Adapter 3: monitored one with promiscious mode on to all VMs

Victom VM:
Base Memory: 8048 MB  
Processors: 3  
Video Memory: 128 MB  
Ubuntu Server ISO 24.04.02
Adatper 1: intnet_lab, promisicious mode  
Adapter 2: Host only adapter

# Snort installation
Get the IDS/IPS VM set up and going on it. Once set up run the sudo apt install chromium-browser -y command
<img width="1282" height="804" alt="image" src="https://github.com/user-attachments/assets/93551647-6991-41d5-9df9-1066d682697f" />  
Then run the command: sudo nano /etc/netplan/00-installer-config.yaml and add this to the file:  
<img width="808" height="575" alt="image" src="https://github.com/user-attachments/assets/2d1e1222-db37-4bef-88a1-9ae254fc208e" />  
Then save it and run sudo netplan apply.  
Then type sudo ip link set enp0s9 promisc on and ip link show enp0s9.  
Next time to install Snort onto the system. Type the command sudo apt install -y snort and run it to install Snort.  
Then verify it by running sudo snort -V:  
<img width="816" height="576" alt="image" src="https://github.com/user-attachments/assets/8dd47820-78fd-4227-9c45-569f20a95ae0" />  
To do Snort 2.9.7:  
sudo apt install -y build-essential libpcap-dev libpcre3-dev \  
  libdumbnet-dev bison flex zlib1g-dev liblzma-dev \  
  openssl libssl-dev ethtool git  

cd /tmp
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz  
tar -xvzf daq-2.0.7.tar.gz  
cd daq-2.0.7  
./configure  
make
sudo make install

To do Snort 2.9.20:
wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz  
tar -xvzf snort-2.9.20.tar.gz  
cd snort-2.9.20  
./configure --enable-sourcefire  
make  
sudo make install  
Then do snort -V to verify its the right version.  

Then go make these directories for snort:  
sudo mkdir -p /etc/snort/rules  
sudo mkdir -p /etc/snort/rules/iplists  
sudo mkdir -p /etc/snort/preproc_rules  
sudo mkdir -p /var/log/snort  
sudo mkdir -p /var/log/snort/archived_logs  
sudo mkdir -p /usr/local/lib/snort_dynamicrules  
Then create the files needed for snort by typing the commands:  
sudo touch /etc/snort/rules/white_list.rules  
sudo touch /etc/snort/rules/black_list.rules  
sudo touch /etc/snort/rules/local.rules  

Then type cd /tmp/snort-2.9.20/etc/  
sudo cp *.conf* /etc/snort/  
sudo cp *.map /etc/snort/  
sudo cp *.dtd /etc/snort/  

Then set the file permissions  
sudo chmod -R 5775 /etc/snort  
sudo chmod -R 5775 /var/log/snort  
sudo chmod -R 5775 /usr/local/lib/snort_dynamicrules  

Then type sudo nano /etc/snort/snort.conf  
Go to line around 45 and change HOME_NET to 192.168.56.0/24 and ipvar EXTERNAL_NET to !$HOME_NET  
Then go to line 104 and change these:  
var RULE_PATH /etc/snort/rules  
var SO_RULE_PATH /etc/snort/so_rules  
var PREPROC_RULE_PATH /etc/snort/preproc_rules  
To include the snort paths  
At around line 109:  
var WHITE_LIST_PATH /etc/snort/rules  
var BLACK_LIST_PATH /etc/snort/rules  
Then around line 546:  
Uncomment output log_tcpdump: tcpdump.log and add output alert_fast: alert.txt  
and go down to the bottom of the file and type include $RULE_PATH/local.rules  
Then save it and type sudo nano /etc/snort/rules/local.rules  
Enter these in:  
# ICMP Rules  
alert icmp any any -> $HOME_NET any (msg:"SURICATA ICMP Ping Detected"; sid:2000001; rev:1;)  
alert icmp any any -> any any (msg:"SURICATA ICMP Echo Request"; itype:8; sid:2000002; rev:1;)  

# TCP Rules  
alert tcp any any -> $HOME_NET 22 (msg:"SURICATA SSH Connection"; flow:to_server; flags:S; sid:2000003; rev:1;)  
alert tcp any any -> $HOME_NET 80 (msg:"SURICATA HTTP Request"; flow:to_server; sid:2000004; rev:1;)  
alert tcp any any -> $HOME_NET 21 (msg:"SURICATA FTP Connection"; sid:2000005; rev:1;)  
alert tcp any any -> $HOME_NET 23 (msg:"SURICATA TELNET Connection"; sid:2000006; rev:1;)  
alert tcp any any -> $HOME_NET 3306 (msg:"SURICATA MySQL Connection"; sid:2000007; rev:1;)  

# Port Scan Detection  
alert tcp any any -> $HOME_NET any (msg:"SURICATA Possible SYN Scan"; flags:S; threshold:type both, track by_src, count 20, seconds 60; sid:2000008; rev:1;)  

# HTTP Attacks  
alert http any any -> $HOME_NET any (msg:"SURICATA Possible SQL Injection in URI"; flow:established,to_server; content:"union"; nocase; http_uri; content:"select"; nocase; http_uri; sid:2000009; rev:1;)  
alert http any any -> $HOME_NET any (msg:"SURICATA Possible XSS in URI"; flow:established,to_server; content:"<script"; nocase; http_uri; sid:2000010; rev:1;)  
alert http any any -> $HOME_NET any (msg:"SURICATA Directory Traversal Attempt"; flow:established,to_server; content:"../"; http_uri; sid:2000011; rev:1;)  

# Nmap Detection  
alert tcp any any -> $HOME_NET any (msg:"SURICATA NMAP XMAS Scan"; flags:FPU,12; sid:2000012; rev:1;)  
alert tcp any any -> $HOME_NET any (msg:"SURICATA NMAP NULL Scan"; flags:0; sid:2000013; rev:1;)  
alert tcp any any -> $HOME_NET any (msg:"SURICATA NMAP FIN Scan"; flags:F,12; sid:2000014; rev:1;)  

# SSH Brute Force  
alert ssh any any -> $HOME_NET 22 (msg:"SURICATA Possible SSH Brute Force"; flow:to_server; threshold:type both, track by_src, count 5, seconds 60; sid:2000015; rev:1;)  
*Note you might need to comment out different things such as ftp_telnet through gtp. Use the command sudo sed -i 's/preprocesser ftp_telnet/# preprocessor ftp_telnet/g' /etc/snort/snort.conf until you reach gtp*  
*You might also need to replace the entirety of /etc/snort/rules/local.rules with a different ruleset but that can be if needed. Will add the rules as needed.*
Next type sudo nano /etc/systemd/system/snort.service and enter in this information:  
<img width="1132" height="535" alt="image" src="https://github.com/user-attachments/assets/429ffb38-33e8-4e8b-8a3f-96a35e2fde9d" />  
After that run sudo systemctl daemon-reload, them sudo systemctl enable snort, sudo systemctl start snort, then sudo systemctl status snort.  
# Suricata Installation






