# Analyzing Output from Security Appliance Logs: Analyzing IDS logs on a SIEM
<h3>Objectives</h3>

- Analyzed data as part of security monitoring activities.
- Implemented configuration changes to existing controls to improve security.
- Analyzed potential indicators of compromise.
#
**Setup**

Firstly I'll be setting up the IDS, in this case, I can't set the IDS behind a firewall so instead I'll configure port mirroring so that any frames processed by the router are copied to the sensor's sniffing interface.

![Screenshot 2024-05-25 121413](https://github.com/user-attachments/assets/31f82885-9fbd-4743-97fd-eeaa0f50a0fc)
#
The SIEM Im using is Security Onion, which includes the Snort, Suricata, and Zeek (Bro) network-based IDS packages and software designed to process and analyze the alerts they generate.

![Screenshot 2024-05-25 132725](https://github.com/user-attachments/assets/6f716e15-1fa3-4d71-b431-81e2a46281e7)
We see that under the ST field alerts are color-coded based on priority, and the CNT field shows how many packets match that alert. 
- Also the Event Message field shows us the ruleset that produced that match, in the case of Alert ID 3.19 the ruleset is ET or Emerging Threat is a widely used IDS ruleset, and SCAN, which is the alert type, in this case being a potential outbound SSH scan. 
- This same rule has a match for alerts 3.20 and 3.27
- Also by clicking on an alert, displays the packet data
#
You can see correlated events by right-clicking the corresponding CNT field of an alert. This shows all the individual packets associated with a single event, in this case, Alert 3.27 - 3.30.

![Screenshot 2024-05-25 133551](https://github.com/user-attachments/assets/6f84f9ad-7ed7-4592-8b43-8ac9542230bb)

![Screenshot 2024-05-25 133606](https://github.com/user-attachments/assets/71a62636-0272-4e25-852f-03c94d4167ec)
#
By right-clicking the Alert ID I can view the alert using Wireshark, NetworkMiner, or Bro.

![Screenshot 2024-05-25 134131](https://github.com/user-attachments/assets/8c8669f7-f619-4454-9f44-b0a32663e7e0)
#
Right-clicking the Src IP field I can look up information about this IP address like information already stored about that value elsewhere in the database using the Kibana IP lookup, or via a CTI provider.

![Screenshot 2024-05-25 134230](https://github.com/user-attachments/assets/53353fd9-351e-4136-b47f-6657082fdfba)

By doing the Kibana lookup we see that there is no previous information about that IP address. This is because the lab environment isnt connected to the internet and there is no local reputation database for it to pull information from.
![Screenshot 2024-05-25 134909](https://github.com/user-attachments/assets/0fea4da7-8b63-4d61-a9c6-4ba0b6fa23a2)
#
By right-clicking the ST field, I can update the event status and categorize the event, it also shows that the (F6) key is a shortcut to doing the same for other events.

![Screenshot 2024-05-25 135041](https://github.com/user-attachments/assets/270345bb-e738-461f-b4e0-b3ad91ee9520)
#
Alert ID 3.31 is color-coded red for the highest priority, the rule stated in the event message is ET Trojan. The tibs downloader trojan is connected to a website over port 80 and downloaded a file.
![Screenshot 2024-05-25 140113](https://github.com/user-attachments/assets/45169629-664f-434b-9e7d-07c44f0f8893)
#
Events 3.90 and 3.91 both a CVE ID linked to an attempt to exploit the Shellshock vulnerability to run arbitrary commands through the web server’s shell (CVE-2014-6271).

![Screenshot 2024-05-25 141244](https://github.com/user-attachments/assets/c338cf0f-8f76-4fab-a7b3-edc953820b89)

#
**Creating Custom Rules**

These are 3 custom rules that will now alert when an event matching the rule is detected. But they will not work if I dont update the ruleset, which is done with the command- rule-update

![Screenshot 2024-05-25 142401](https://github.com/user-attachments/assets/a944f98b-b0f9-46f0-a162-4c1ca3171ccc)

![Screenshot 2024-05-25 142833](https://github.com/user-attachments/assets/99aa5bcc-81ab-4479-ab81-b5b68afee94d)

I can see the new ruleset with: tail /etc/nsm/rules/downloaded.rules, all 3 rules were added to the ruleset.

![Screenshot 2024-05-25 143044](https://github.com/user-attachments/assets/a70cda5a-ba4a-410a-b8a1-9a0a65956252)

Each rule has a header plus a body, which is enclosed in brackets. The header includes the action, protocol, source host or network, source port, direction, target host or network, and target port. The body must include at least an identifier (sid:) and a message (msg:). A local rule should have an SID of 1000000 or greater. The parts of the body are delimited by semicolons.
#
**Testing The Custom Rules**

Now I can test the rules by pinging some IPs, and by checking Security Onion.

I'll test the first rule: alert icmp any any -> $HOME_NET any (msg:“ICMP detected”; sid:1000001; rev:1;) 
- It detects ICMP packets sent by any IP, into or within the protected network. 
- I'll use these three pings: ping -c4 10.1.0.1, ping -c4 10.1.0.246, ping -c4 172.16.0.254

![image](https://github.com/user-attachments/assets/6fd39230-797b-4811-8b66-0b6ed120d56f)

The siem alert shows 8 packets triggered this rule, but 12 packets were sent in total so one of those IP addresses that were pinged is not being monitored by the IDS
- Also a built-in rule was triggered aswell

![image](https://github.com/user-attachments/assets/d9ceae5f-df06-4e9f-ac79-4b3670d8cba5)

Viewing the correlated events, both 10.1.0.1 and 10.1.0.246 received the ICMP packets, and they are on the same network so that network is being monitored by the IDS. 172.16.0.254 however is not being monitored by the IDS

![image](https://github.com/user-attachments/assets/86a206b8-ca3e-4cb4-a4a5-b6c56588ffc3)
#
Now I'll test the second rule: alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:“External ICMP probe detected”; sid:1000002; rev:2;)
- It detects ICMP pings from an external network into the protected network
- I only used one ping this time: ping -c4 10.1.0.1

![image](https://github.com/user-attachments/assets/b66b124c-81fe-489f-b43f-b9c93acd2de2)

The siem alert shows the rule did pick up the 4 ICMP packets, and we see that the other rules were also triggered which makes sense as I left them on, and they too alert on ICMP packets.

![image](https://github.com/user-attachments/assets/c84c2693-7cac-43a8-bda4-51c05c4f45c2)

Now I'll log onto 10.1.0.1 and ping the other two IPs: ping 10.1.0.246, and ping 12.16.0.254

![image](https://github.com/user-attachments/assets/01aa7b2f-af8a-41c8-b801-7dffcc1285e3)

The siem alerts show that the second rule was not triggered but the first rule was. This makes sense since the first rule will detect any ICMP packets sent by any IP, into or within the protected network. 

![image](https://github.com/user-attachments/assets/03e509d3-cee7-4e00-8ec4-d6934eb6401a)

- These two pings were sent from 10.1.0.1 which is within the protected network, however, the ping made to 127.16.0.254 was not detected because it was an outbound ping, and both rules are set to alert for inbound pings.
- That's also the reason we dont see the replies trigger the alert when testing rule 1 since I pinged from 192.168.1.1 which is an external IP and outbound ICMP packets won't trigger the alert.

#

Now I'll test the third rule: alert icmp $EXTERNAL_NET any -> $HOME_NET any (itype:8; msg:“External ICMP probe detected”; detection_filter:track by_src,count 20,seconds 30; priority:4; classtype:icmp-event; sid:1000003; rev:3;)

This rule is similar to the second rule except for these parameters: 
- itype:8 This parameter only matches ICMP echo requests, as opposed to the last two rules which would detect any kind of ICMP packets.
- detection_filter:track by_src,count 20,seconds 30 This detection filter will only trigger alerts if the pings last longer than 30 seconds and more than 20 packets
- priority:4 This changes the priority level from the higher default number that the other rules had.
- So only external pings that are 20 packets or more, over a 30 seconds period will trigger this alert

First I'll ping 10.1.0.254 and 172.16.0.254
- We know pinging 172.16.0.254 won't generate an alert and that pinging 10.1.0.254 triggers the 1st alert since 10.1.0.1 is on the same network

![image](https://github.com/user-attachments/assets/7b454c50-2b1e-4aa2-93d5-2087f3f2b675)

As predicted no alerts mention 172.16.0.254, and pinging 10.1.0.254 alerted of the 4 packets sent from 10.1.0.1 and the 4 reply packets sent to 10.1.0.1 from 10.1.0.254
![image](https://github.com/user-attachments/assets/eeacdfe5-4623-48ee-a0ff-51dab5bdae19)


This time I will ping 10.1.0.1 from 192.168.1.1 and I have disabled the 1st rule to reduce the amount of alerts, and disabled the 2nd rule since it has a higher priority by default, so it will trigger instead of the 3rd rule.

![image](https://github.com/user-attachments/assets/81d1290c-0801-4f1c-8d46-dfed20f7bc4f)

I'll do ping -c40 10.1.0.1 to ensure all the detection parameters are met

![image](https://github.com/user-attachments/assets/584717d6-0acc-41c1-94ad-f2055b5b48ec)

The siem shows only 20 packets were detected, because of the detection parameters. 
- The reason it only picked up 20 packets is that it only alerted after the first 20, so starting with the 21st packet
![image](https://github.com/user-attachments/assets/02af81e4-0fe1-4f2f-9313-c2ac4160759f)

#

**Summary: A Security Information and Event Management system or SIEM is a centralized log repository, with the ability to correlate logs to allow for faster detection, analysis, and response to security events and potential threats. It collects logs from various devices and security monitoring tools such as an Intrusion Detection System(IDS), or a firewall, and can recognize logs created by a single security event. These logs are then used to identify, examine, and resolve issues quickly.**
