# snort-and-suricata-home-lab

When setting and securing a networking, having the proper measures in force to defend from outside activity or attacks is important to securing it. Usually involves having security features, firewalls, and more in order for everything to be securred.  
With Snort and Suricata implemented into the system on their own respective machines, it helps with getting everything situated and secure and to be able to detect and alert of unusual traffic that might be present.  

For this lab it will require 4 VMs, one attacker, one victim, one for Suricata, and one for Snort. Also make a internet network named intnet_lab for Attack and Target and turn promiscious mode off.  
For the Snort and Suricata VMs, first adapter will be intnet_lab, second adapter will be set to host only adapter 
Attacker VM Setup:
Base Memory: 8048 MB  
Processors: 4  
Video Memory: 128
Kali Linux ISO  
Adapter 1: intnet_lab  

Victim VM:  
Base Memory: 8048 MB  
Processors: 3  
Video Memory: 128 MB  
Kali Linux ISO  
Adpater 1: intenet_lab  

IDS Snort VM:
Base Memory: 8048 MB  
Processors: 3  
Video Memory: 128 MB  
Ubuntu Server ISO 24.04.02
Adatper 1: intnet_lab, promisicious mode  
Adapter 2: Host only adapter

IDS Suricata VM:
Base Memory: 8048 MB  
Processors: 3  
Video Memory: 128 MB  
Ubntu Server ISO 24.04.2  
Adapter 1: intnet_lab, promisicious mode  
Adapter 2: Host only adapter  
