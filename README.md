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
Adapter 1: same as IDS/IPS VPN

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
Adatper 1: same as IDS/IPS one

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
To install Suricata first run the command sudo add-apt-repository ppa:oisf:/suricata-stable, then sudo apt update, then sudo apt install -y suricata jq.  
Then to check the version run suricata-update --version.  
Then run sudo suricata-update to add the rules.  
Then to configure Suricata type the command sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup then sudo nano /etc/suricata/suricata.yaml to edit several different sections.  
vars should look like this:  
<img width="669" height="406" alt="image" src="https://github.com/user-attachments/assets/826ff407-d655-4101-995e-e6145edf51da" />
port groups:  
<img width="467" height="303" alt="image" src="https://github.com/user-attachments/assets/1644d6af-6066-4ed1-8469-5c636e8c44b9" />  
default-rule-paths:  
<img width="491" height="134" alt="image" src="https://github.com/user-attachments/assets/ff9a218d-10d7-43ab-9c00-ee7737fde3c7" />  
eve-log:  
<img width="1091" height="476" alt="image" src="https://github.com/user-attachments/assets/8ea0a8f7-677f-4f98-9408-8171b5b2fe9d" />  
dns:  
<img width="381" height="178" alt="image" src="https://github.com/user-attachments/assets/b2224c23-4c9d-42ce-aaf4-5404d7d11587" />  
stats:  
<img width="224" height="84" alt="image" src="https://github.com/user-attachments/assets/fc5ca031-fd7d-456e-b68e-d9972b839783" />  
Then type save and type sudo mkdir -p /etc/suricata.rules and then then type sudo nano /etc/suricata/rules/local.rules  
<img width="1202" height="573" alt="image" src="https://github.com/user-attachments/assets/9d0fd348-95a3-4d0e-8a06-438b4f8b5c8b" />  
or to get it to run differently just change HOME_NET under address groups to the ip address being used, af-packet interface to enp0s9, and add /etc/suricata/rules.local to rule-files and save it.  
Then type sudo suricata -T -c /etc/suricata/suricata.yaml -v to test the configuration.  
Then type sudo systemctl enable suricata, then sudo systemctl start suricata, then sudo systemctl status suricata to enable suricata.  

# Attacker VM
Attacker VM Setup:  
Base Memory: 8048 MB  
Processors: 4  
Video Memory: 128  
Kali Linux ISO   
Adapter 1: same as IDS/IPS VPN  

After setting up the VM, type sudo nano /etc/network/interfaces and change the info in there to this:  
<img width="710" height="296" alt="image" src="https://github.com/user-attachments/assets/227f899b-d7e4-42c3-867d-f211e5bdf9dd" />  
Then type sudo nmtui and will be greeted by a GUI:  
<img width="278" height="293" alt="image" src="https://github.com/user-attachments/assets/eec06919-21f6-4caf-ac12-3d1fb5694aaa" />  
Click on edit connection and change ipv4 configuration to manual and add 192.168.56.10/24, gateway to 192.168.56.1, and dns to 8.8.8.8, then click on ok.  
You will be then taken back to the GUI and click on Activate a connection and then will you see this GUi:  
<img width="437" height="777" alt="image" src="https://github.com/user-attachments/assets/573e7d9a-cdeb-40ae-87e5-42efa8de17c4" />  
Click on deactivate and then activate to turn back on the connection, then scroll down to back and click on quit.  
Then type ip a show eth0 to verify the change.  
Then to verify connectivity, type ping -c 3 192.168.56.5 and get this result:  
<img width="630" height="208" alt="image" src="https://github.com/user-attachments/assets/8042b942-0d55-48b2-aa77-67bf978a1212" />  

# Ubuntu Target VM Setup
Victom VM:
Base Memory: 8048 MB  
Processors: 3  
Video Memory: 128 MB  
Ubuntu Server ISO 24.04.02  
Adatper 1: intnet_lab, promisicious mode  
Adapter 2: Host only adapter  














