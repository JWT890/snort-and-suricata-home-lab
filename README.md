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







