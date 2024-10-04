# Zeek Exercises (TryHackMe)

## Premise
Investigate a series of traffic data and stop malicious activity under different scenarios. Use Zeek to analyze captured traffic data. 

## Scenario 1: Anomalous DNS
*An alert was triggered: "Anomalous DNS detected." The case was assigned to me and it is up to me to inspect the PCAP and retrieve artifacts to confirm the alert is a true positive.* 

**Step 01:** I begin by running zeek to analyse the ```.pcap``` file given to me. A ```.pcap``` ,which stands for packet capture, is the process of intercepting and recording data packets that make up network traffic. Programs like Zeek, tcpdump, and Wireshark can examine and extract information from them. To examine the ```.pcap``` in Zeek, I enter the following command:

```zeek -Cr dns-tunneling.pcap``` The ```-C``` flag makes Zeek ignore checksums. This is helpful so packets aren't needlessly dropped from the ```.log``` report, which could cause important information to be missed. The ```-r``` flag is instructing Zeek to *read* the indicated file ```dns-tunneling.pcap```.

![Zeek_01](https://github.com/user-attachments/assets/5f3a2263-a876-4842-b761-d9678660ae01)

Here are the logs Zeek created from the check. Given it is a DNS anomaly, we will take a closer look at the ```dns.log```.

![Zeek_02](https://github.com/user-attachments/assets/6dfe3cdb-1f65-4463-b02f-3de734464a0f)

**Step 02:** I am first tasked with discovering how many DNS records are linked to IPv6 addresses. I did some OSINT to see what information in the log could tell me that. I found this webpage that had a simple and brief explanation: 

![image](https://github.com/user-attachments/assets/8136614f-e2e5-4680-a40b-4f47cb275afc)

IPv6 address will have the label "AAAA" in the DNS log. I visited zeek.org to find out which record type in the log could help me filter out that information. It is the ```qtype_name``` record. 

![image](https://github.com/user-attachments/assets/247fc78e-cdda-4770-a1fe-1751ae0c0746)

With this information in tow, I enter the command ```cat dns.log |zeek-cut qtype_name | grep "AAAA" | wc -l``` and receive the answer 320 records. 
```cat dns.log``` reads the file, which is then piped into the ```zeek-cut``` command to filter for ```qtype_name```. That is then piped into the ```grep``` command which is looking for IPv6 connections using the ```AAAA``` designation. These findings are then piped into the ```wc``` command which will output the number of records found and the ```-l``` flag is added so it only focuses on newline findings.

![image](https://github.com/user-attachments/assets/22980ecf-6c65-4f27-805c-c4400a2ea797)

**Step 03:** We are now going to take a closer look at the ```conn.log``` to see what is the longest connection duration.

I use the ```clear``` command to tidy up the screen. Then the ```cat conn.log | head -20``` command to look at the first 20 lines of the conn.log. The ```service duration``` record type can be seen. To find what the longest connection was the command ```cat conn.log | zeek-cut service duration | sort -n```. The ```sort -n``` will order the findings numerically. The findings are below. 

![image](https://github.com/user-attachments/assets/b5f3c677-e03a-40ff-b948-309e7c8418c8)

The longest connection is a http connection that lasted 9.420791 seconds. 

**Step 04:** Our next task is to filter to find out how many unique domain queries there were. We are going back to the ```dns.log``` to find out. 
Initially, the command ```cat dns.log | zeek-cut query | uniq | wc -l``` was entered, but it returned too many results (almost 7000). I took a closer look at the log file by entereing ```cat dns.log | head -20``` to take a peek, and I see something odd:

![image](https://github.com/user-attachments/assets/aaef1e5f-3556-4d70-9919-5c865eaff9ac)

There are many connections to  *.cisco-update.com (suspicious), and each one has a unique subdomain, which is inflating the findings of my search. To work around this, I enter the command ```cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort -u | wc -l```. ```rev``` reverses each query string of the file that is read. This is useful because of the long encryption on the subdomain. the ```cut -d '.' -f 1-2``` splits the reversed string based on the "." delimiter. Then it selects the first two fields after spliting. The second ```rev``` then reverses the output of the ```cut``` back to its original order. ```sort -u``` then sorts it and only keeps the unique entires, discarding repeats, and the ```wc -l``` gives me the numerical amount, which is 6. There are six unique DNS queries in this packet capture.

![image](https://github.com/user-attachments/assets/940e37a6-2688-4bc7-a820-42cbc90f82c8)

**Step 05:** There are a massive amount of queries to the *.cisco-update.com domain. The next task is to find out which host are involved with this activity. We can see that easily with the command ```cat dns.log | zeek-cut id.orig_h query | grep ".cisco-update.com" | column | head -20```. And we see the source IP is 10[.]20[.]57[.]3.

![image](https://github.com/user-attachments/assets/c81cb577-c774-4bc3-b99c-6f95cd19a592)

This concludes the first investigation.

## Scenario 02: Phishing
*An alert was triggered: "Phishing Attempt". The task is to investigate the PCAP and find if the event is a true positive.*

**Step One:** This time I will analyze the pcap with a Zeek script. The script is designed to find and extract any files found within the payload. The command ```zeek -Cr phishing.pcap file-extract-demo.zeek``` is used, and the log files are generated along with the folder ```extract_files```. Possibly malicious files were discovered! 

![image](https://github.com/user-attachments/assets/43c89803-cb69-49ca-bc79-38d485c80b3e)

**Step Two:** We will locate the suspicious source address first. 


