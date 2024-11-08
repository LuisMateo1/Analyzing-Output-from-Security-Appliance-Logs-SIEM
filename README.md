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
- Also the Event Message field shows us the ruleset that produced that match, in the case of Alert ID 3.19 the ruleset is ET(Emerging Threat) SCAN(SCAN is the alert type)
- This same rule has a match for alerts 3.20 and 3.27
- Also by clicking on an alert, we can see packet data
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

By doing the Kibana lookup we see that there is no previous information about that IP address
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
**Custom Rules**
These are 3 custom rules that will now alert when an even matching it happens. But they will not work if I dont update the ruleset.

![Screenshot 2024-05-25 142401](https://github.com/user-attachments/assets/a944f98b-b0f9-46f0-a162-4c1ca3171ccc)

![Screenshot 2024-05-25 142833](https://github.com/user-attachments/assets/99aa5bcc-81ab-4479-ab81-b5b68afee94d)

I can see the new ruleset with: tail /etc/nsm/rules/downloaded.rules, all 3 rules were added to the rule set. And the ruleset will update with the command: rule-update 

![Screenshot 2024-05-25 143044](https://github.com/user-attachments/assets/a70cda5a-ba4a-410a-b8a1-9a0a65956252)

Each rule has a header plus a body, which is enclosed in brackets. The header includes the action, protocol, source host or network, source port, direction, target host or network, and target port. The body must include at least an identifier (sid:) and a message (msg:). A local rule should have an SID of 1000000 or greater. The parts of the body are delimited by semicolons.
#
**Testing The New Rules**

Now I can test the rules by pinging some IPs, and by checking Security Onion.

![Screenshot 2024-05-25 143409](https://github.com/user-attachments/assets/a84aac19-7654-41e8-8b56-3260e5617692)

![Screenshot 2024-05-25 144054](https://github.com/user-attachments/assets/3f86af83-e4f4-4ba8-acff-4c99d58861c2)

![Screenshot 2024-05-25 144124](https://github.com/user-attachments/assets/954456b2-0068-44a9-8170-5f02c9f4f71b)

This shows that rules are working as intended since new alerts have been created based on these new rules.
#

**Summary: A Security Information and Event Management system or SIEM is a centralized log repository, with the ability to correlate logs to allow for faster detection, analysis, and response to security events and potential threats. It collects logs from various devices and security monitoring tools such as an Intrusion Detection System(IDS), or a firewall, and can recognize logs created by a single security event. These logs are then used to identify, examine, and resolve issues quickly.**
