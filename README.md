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
Next time to install Snort onto the system.  


