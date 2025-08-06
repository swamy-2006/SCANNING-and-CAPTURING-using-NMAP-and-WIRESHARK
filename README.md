## SCANNING-and-CAPTURING-using-NMAP-and-WIRESHARK
Scanning and Capturing using Nmap and Wireshark This repository demonstrates basic network reconnaissance using Nmap and Wireshark. The main goal is to understand how to scan a local network for active hosts, identify open ports, and analyze network traffic for security insights.


DOWNLOAD NMAP FROM HERE: [NMAP](https://nmap.org/download.html#windows)

DOWNLOAD WIRESHARK FROM HERE: [WIRESHARK](https://www.wireshark.org/#download)

{NOTE: These links are from the orignal websites)

![img alt](https://github.com/swamy-2006/SCANNING-and-CAPTURING-using-NMAP-and-WIRESHARK/blob/76ea751f7e8a7cce52a0b1aad657ecc30202f854/Screenshot%202025-08-04%20211806.png)
 
🧠 Scan Summary
Target: 10.140.63.210

Scan Type: nmap -T4 -A -v 10.140.63.210
This means:
-T4: Aggressive timing template for faster scanning
-A: Enable OS detection, version detection, script scanning, and traceroute
-v: Verbose output

📄 Key Findings
✅ Open Ports
Port	State	Service	Version
*135	open	msrpc	Microsoft Windows RPC
*139	open	netbios-ssn	Microsoft Windows netbios-ssn
*445	open	microsoft-ds	Microsoft Windows SMB


This tells us:

*The target is likely a Windows machine.
*The ports open are related to Windows file and printer sharing:
*135: MS RPC – used by services like DCOM
*139: NetBIOS session service
*445: SMB (Server Message Block)



Open ports can expose a system to various security risks if the services running on them are misconfigured, outdated, or vulnerable. For example:


*Port 135 (MS RPC) 

*Used for Windows Remote Procedure Call. 

*Vulnerable to DCOM and MSBlaster exploits. 

*Attackers can use it to enumerate services or launch remote code execution 

*Port 139 (NetBIOS Session Service) 

*Used for file and printer sharing. 

*Can be exploited for SMB relay attacks or to gather sensitive system information. 

*Port 445 (Microsoft-DS / SMB)  

*High-risk port due to past exploits like EternalBlue (used in WannaCry ransomware). 

*Allows attackers to spread malware or access shared resources if SMB is unprotected. 



General Risks of Open Ports

*Unauthorized Access: Attackers may connect to open services and try default or weak credentials.

*Information Leakage: Open services can reveal OS details, usernames, or configuration data.

*Vulnerability Exposure: Outdated services might have known exploits available publicly.

*Lateral Movement: Attackers can use open ports to move through the network after gaining access.

___________________________________________________________________________________________________________________________________________________________________________________________________________

![img alt](https://github.com/swamy-2006/SCANNING-and-CAPTURING-using-NMAP-and-WIRESHARK/blob/489cbbf218469e70ad655e397597ea803cd15a7d/Screenshot%202025-08-04%20211854.png)


Second Scan (nmap -sS -p 22,80,443 10.140.63.210)
This was a quick SYN scan on ports 22, 80, and 443.
The target is up.

All three ports are closed:
22 (SSH)

80 (HTTP)

443 (HTTPS)

This means no web or SSH services are running on the system.
___________________________________________________________________________________________________________________________________________________________________________________________________________

__________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________

# WIRESHARK(http analysis)


![img alt](https://github.com/swamy-2006/SCANNING-and-CAPTURING-using-NMAP-and-WIRESHARK/blob/f20b9064f2ee4a7e213c7c575336d6c51281f4fd/Screenshot%202025-08-06%20171349.png)
Insecure HTTP Login Page
This screenshot shows a web browser viewing a login page served over an unencrypted HTTP connection. It represents the user's perspective when interacting with an insecure web application.

Key Features:
"Not Secure" Warning: The browser's address bar prominently displays a "Not secure" warning.  This is a standard security feature in modern browsers to alert users when a page requesting sensitive information (like a password) is not using an encrypted connection.

Login Form: The page presents a standard form asking for a username and password.

[testphp.vulnhub.com](http://test.vulweb.com)      IP:44.228.249.3

Vulnerable by Design: This specific website (testphp.vulnweb.com) is a well-known, intentionally vulnerable application created for security professionals to practice testing and hacking skills.



Context and Significance

This image shows the cause of the security risk illustrated in the corresponding Wireshark capture. When a user fills out this form and clicks "login," their credentials are sent across the network in plain text. This allows an attacker to easily intercept and read the sensitive data. It's the "open door" that makes a credential sniffing attack possible.
___________________________________________________________________________________________________________________________________________________________________________________________________________
![img alt](https://github.com/swamy-2006/SCANNING-and-CAPTURING-using-NMAP-and-WIRESHARK/blob/main/Screenshot%202025-08-06%20171638.png)
Wireshark Capture: Unencrypted HTTP Login
This image is a screenshot from Wireshark, a network protocol analyzer. It demonstrates a significant security vulnerability: the transmission of login credentials in plain text over an unencrypted HTTP connection.

Key Observations from the Capture:
Packet Analysis: The highlighted packet (No. 2177) is an HTTP POST request, which is the method used to send form data from a browser to a web server.

Target: The request is sent to /wp-login.php, the standard login page for a WordPress website.

Unencrypted Data: The connection uses the HTTP protocol. Because it is not encrypted with HTTPS, all data within the packet is visible to anyone monitoring the network.

Exposed Credentials: The "HTML Form URL Encoded" section in the packet details pane clearly displays the captured credentials:

Username (log): admin

Password (pwd): admin


http is  unsecure
__

___________________________________________________________________________________________________________________________________________________________________________________________________________
_____________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________
# Nmap Scan Explanation

Nmap is a network scanning tool used to discover hosts and services on a network.

The command nmap -T4 -A -v 10.140.63.210 performs an aggressive scan with OS detection, version detection, script scanning, and traceroute.

It detected that ports 135, 139, and 445 were open, indicating the system is running Windows services like RPC and SMB.

Another scan with nmap -sS -p 22,80,443 10.140.63.210 showed that these specific ports were closed.

SYN scans (-sS) send only SYN packets and wait for responses (RST or SYN-ACK) without completing the TCP handshake.





___________________________________________________________________________________________________________________________________________________________________________________________________________

# Wireshark Packet Capture Explanation

Wireshark is a packet analyzer used to capture and analyze network traffic in real-time.

The capture shows TCP SYN packets sent to port 135, and TCP RST packets received in response, meaning the port is closed.

ICMP "Destination unreachable" packets suggest that some ports or protocols on the system are blocked or not responding.

This confirms the results from Nmap and provides low-level packet details for verification.



❖ Well-Known Ports (0–1023):

➢ Used for standard services.

➢ Examples:

■ HTTP: Port 80

■ HTTPS: Port 443

■ FTP: Ports 20 and 21

■ SSH: Port 22

■ SMTP: Port 25

■ DNS: Port 53


___________________________________________________________________________________________________________________________________________________________________________________________________________
# Network Reconnaissance & Scanning

Network reconnaissance is the process of gathering information about systems and services in a network before performing security analysis. It helps identify active hosts, open ports, and running services to assess network security.


# Port Scanning

Port scanning is a technique used to find which ports on a system are open and listening for connections. Each port corresponds to a specific service (e.g., port 80 for HTTP, port 443 for HTTPS). Open ports can be entry points for attackers, so scanning helps in vulnerability assessment.


# TCP SYN Scan

A TCP SYN scan is one of the most common and stealthy scanning techniques. It works by sending a SYN packet (used to start a TCP connection) to the target port:
If the port is open, the target replies with a SYN-ACK packet.
If the port is closed, the target sends an RST (reset) packet.
This method is fast and doesn’t complete the full TCP handshake, making it less likely to be logged by the target system.


# IP Ranges

Instead of scanning one IP at a time, you can scan an entire IP range (e.g., 192.168.0.1–192.168.0.255) to find multiple active devices on the same network. This is useful for discovering hosts in a local or enterprise network.


# Open Ports

Open ports indicate that a service is running on that port and is accepting connections. Examples:

Port 22 – SSH (Remote Login)

Port 80 – HTTP (Web)

Port 443 – HTTPS (Secure Web)

Attackers target open ports, so administrators must monitor and secure them.


# Network Security Basics


Use Firewalls: Block unnecessary ports and restrict access.

Update Systems: Patch vulnerabilities in services.

Monitor Traffic: Detect unusual activities.

Disable Unused Services: Reduce attack surface.

ANSWERS TO SOME QUESTIONS about the PORTS and TCP


# 1. What is an open port?
An open port is a network port on a computer that is configured to accept incoming data packets. Think of it like an open door on a building. Each door is numbered (the port number) and leads to a specific service or application running inside (like a mailroom or a front desk). For example, port 80 is the standard "door" for web traffic (HTTP). An open port means a service is actively listening for and ready to communicate with other devices.


# 2. How does Nmap perform a TCP SYN scan?
A TCP SYN scan, often called a "half-open" scan, is a popular and stealthy way to check for open ports. It works by manipulating the standard three-way handshake used to establish a TCP connection (SYN -> SYN/ACK -> ACK).

Here’s the process:

Probe: Nmap sends a TCP packet with the SYN (synchronize) flag set to a target port.

Analyze Response:

If the port is open, the target system responds with a packet that has both the SYN and ACK (acknowledge) flags set.

If the port is closed, the target responds with a packet that has the RST (reset) flag set.

If there is no response, the port is likely filtered by a firewall.

Reset: As soon as Nmap receives the SYN/ACK from an open port, it sends an RST packet to tear down the connection. By never completing the handshake, the scan is less likely to be logged by the target application, making it stealthy.

# 3. What risks are associated with open ports?
The main risk of an open port is that it provides a potential attack vector. An open port signifies a running service, and if that service has a vulnerability, an attacker can exploit it to compromise the system.

Key risks include:

Exploitation: Attackers can use known vulnerabilities in the service (e.g., an outdated web server on port 80) to execute malicious code.

Unauthorized Access: Weakly configured services, like a database with a default password on port 3306, can allow attackers to gain access.

Information Leakage: Some services can be tricked into revealing sensitive information about the system, its configuration, or its users.

Denial-of-Service (DoS) Attacks: Open ports can be flooded with traffic, overwhelming the service and making it unavailable to legitimate users.

# 4. Explain the difference between TCP and UDP scanning.
The difference lies in how the two protocols work.

TCP Scanning: TCP is a connection-oriented protocol. It uses a handshake to establish a reliable connection. This makes TCP scanning very accurate. When a scanner probes a TCP port, it gets a definitive response: a SYN/ACK for an open port or an RST for a closed one.

UDP Scanning: UDP is a connectionless protocol. It just sends packets without any guarantee of delivery or a formal connection. This makes scanning much harder.

When a UDP packet is sent to a closed port, the system usually replies with an "ICMP Port Unreachable" message.

When a UDP packet is sent to an open port, there is typically no response. The scanner has to wait for a timeout and assume the port is open, which is slow and less reliable.

In short, TCP scanning is fast and reliable; UDP scanning is slow and depends on inference.

# 5. How can open ports be secured?
Securing open ports is about managing and minimizing the attack surface. The best practices follow the principle of least privilege.

Close Unnecessary Ports: The most effective method. If a service isn't needed, shut it down so the corresponding port is no longer open.

Use a Firewall: Implement a firewall to create strict rules about who can connect to the open ports. For example, allow access to a database port only from the application server's IP address.

Keep Software Updated: Regularly patch and update the services running on open ports to fix known vulnerabilities.

Strong Configuration: Harden the configuration of services by changing default passwords, disabling unused features, and enforcing strong authentication.

Monitor Traffic: Use an Intrusion Detection System (IDS) or Intrusion Prevention System (IPS) to monitor traffic for suspicious activity targeting open ports.

# 6. What is a firewall's role regarding ports?
A firewall acts as a gatekeeper for network traffic flowing in and out of a device or network. 🛡️ Its primary role regarding ports is to enforce access control rules.

Specifically, a firewall can:

Allow Traffic: Permit traffic to a specific port (e.g., allow everyone to connect to port 443 for HTTPS).

Block Traffic: Deny all traffic to a specific port, effectively making it inaccessible from the outside, even if the service is running.

Filter Traffic: Allow traffic to a port based on specific conditions, such as the source IP address. This is crucial for restricting access to sensitive services like remote desktop (RDP) or SSH.

By filtering traffic, a firewall drastically reduces the exposure of open ports to potential attackers on the internet.

# 7. What is a port scan and why do attackers perform it?
A port scan is a technique used to probe a server or host for open ports. The scan involves sending a series of messages to different ports to elicit responses and identify which services are available.

Attackers perform port scans during the reconnaissance phase of an attack. It's like a burglar casing a neighborhood to find houses with unlocked doors or open windows. The goal is to gather critical intelligence, including:

Which hosts are live on a network.

Which ports are open and what services are running on them (e.g., web server, mail server, database).

The versions of the services and the operating system, which helps identify potential vulnerabilities.

This information allows an attacker to create a map of the target and choose the most promising vector for an attack.

# 8. How does Wireshark complement port scanning?
If a port scanner like Nmap tells you what is happening (e.g., "port 22 is open"), a packet analyzer like Wireshark tells you how and shows you the raw conversation. They are powerful tools that complement each other.

Verification and Learning: You can run Wireshark while performing a port scan to see the exact packets being exchanged. This helps you understand precisely how different scan types work (e.g., you can visually confirm the SYN, SYN/ACK, and RST packets of a SYN scan).

Deep-Dive Analysis: After Nmap finds an open port, you can use Wireshark to capture and analyze the traffic going to that service. This is useful for debugging application issues or for security analysts looking for malicious payloads in the data stream.

Scan Detection: From a defender's viewpoint, Wireshark is excellent for detecting when you are being port-scanned. You can easily spot a single IP address sending probes to many different ports on your machine in rapid succession.
