# Network-Projects
Completed and Ongoing Projects associated with Network Security, Traffic Analysis, and Threat Detection. 
The goal of this repo is to chronicle my ongoing education and success. Only what is measured can be improved.


## Process

I will compile screenshots and explanations of my process for each of these projects. This will show my thoughts and decisions, displaying my process and areas where I can improve.


## Snort Live Attack Project (TryHackMe)
### Premise
In this exercise, it is known that someone is attempting a brute-force attack on the network. The task is to sniff out anamalous activity using Snort, identify the threat, craft a Snort rule, then activate IPS mode on Snort to stop the attack for at least one minute.

*Step One*:
I start out by engage Sniffer mode on Snort on the *eth0* interface. The 

![Step 01](https://github.com/user-attachments/assets/fe34493e-cb1b-4958-aac5-985752000bd4)

*Step Two*:
I receive the results in the console and something catches my eye. I rerun the command, this time adding the flag ```-l .``` to create a log in the directory I am in. I catch an obvious anomaly.

![Step 02 1](https://github.com/user-attachments/assets/fe3ae0cb-3cdd-4c0c-a9a7-16756a28619c)

As seen below, in the payload of one of the packets I see a suspicious port and details that seem to point to a hosts desktop information

![Step 02](https://github.com/user-attachments/assets/b289a9fd-cb6f-4c96-bb78-d21e0ea78ab4)

*Step Three*:
To confirm my findings, I search through the log using the following command: ```sudo snort -r snort.log.* | grep "4444"``` . And I see that this suspicious port can be seen in use throughout the log. Port 4444 is a common listening port for the exploitation tool, Metasploit. It would appear the network has been compromised. 

![Step 03 1](https://github.com/user-attachments/assets/1d76ebba-8e40-4985-b02a-67570789b82d)

*Step Four*:
My next task is to block the connection to the port to defend the network. I begin by writing a custom rule to the ```local.rules``` file in snort using the command ```sudo gedit /etc/snort/rules/local.rules```.

![Step 04](https://github.com/user-attachments/assets/5a48d12a-043b-478c-9f14-6aa0b4cc98a9)

The rule I craft is designed to drop any connection to tcp port 4444 in any direction. While a more fine tuned approach may be advisable, it fit withing the scope of this project.

![Step 05](https://github.com/user-attachments/assets/93c3bedc-0906-4ad6-8550-c4f39f44e021)

*Step Five*:
I turn on Snort's IPS mode (quietly) by running the command ```sudo snort -c /etc/snort/rules/local.rules -q -Q --daq afpacket -i eth0:eth1 -A full```. In about a minute, the success conditions are met and the flag is tripped. The attack has been stopped!


![Step 06](https://github.com/user-attachments/assets/725a490e-fdda-49a7-b1c6-4d5ceed06025)

### Lessons Learned
Understanding the nature and nuance of Snort has helped me see the need to be vigilant at all times to protect CIA. Having a deep understanding of the tools at hand, and deploying in an efficient way is key. I look forward to continuing my development. 
