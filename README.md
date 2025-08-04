# SCANNING-and-CAPTURING-using-NMAP-and-WIRESHARK
Scanning and Capturing using Nmap and Wireshark This repository demonstrates basic network reconnaissance using Nmap and Wireshark. The main goal is to understand how to scan a local network for active hosts, identify open ports, and analyze network traffic for security insights.

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
135	open	msrpc	Microsoft Windows RPC
139	open	netbios-ssn	Microsoft Windows netbios-ssn
445	open	microsoft-ds	Microsoft Windows SMB

This tells us:
The target is likely a Windows machine.
The ports open are related to Windows file and printer sharing:
135: MS RPC – used by services like DCOM
139: NetBIOS session service
445: SMB (Server Message Block)

Open ports can expose a system to various security risks if the services running on them are misconfigured, outdated, or vulnerable. For example:
Port 135 (MS RPC)
Used for Windows Remote Procedure Call.
Vulnerable to DCOM and MSBlaster exploits.
Attackers can use it to enumerate services or launch remote code execution.
Port 139 (NetBIOS Session Service)
Used for file and printer sharing.
Can be exploited for SMB relay attacks or to gather sensitive system information.
Port 445 (Microsoft-DS / SMB)
High-risk port due to past exploits like EternalBlue (used in WannaCry ransomware).
Allows attackers to spread malware or access shared resources if SMB is unprotected.

General Risks of Open Ports
Unauthorized Access: Attackers may connect to open services and try default or weak credentials.
Information Leakage: Open services can reveal OS details, usernames, or configuration data.
Vulnerability Exposure: Outdated services might have known exploits available publicly.
Lateral Movement: Attackers can use open ports to move through the network after gaining access.


![img alt](https://github.com/swamy-2006/SCANNING-and-CAPTURING-using-NMAP-and-WIRESHARK/blob/489cbbf218469e70ad655e397597ea803cd15a7d/Screenshot%202025-08-04%20211854.png)
Second Scan (nmap -sS -p 22,80,443 10.140.63.210)
This was a quick SYN scan on ports 22, 80, and 443.
The target is up.
All three ports are closed:
22 (SSH
80 (HTTP)
443 (HTTPS)
This means no web or SSH services are running on the system.

#Nmap Scan Explanation
Nmap is a network scanning tool used to discover hosts and services on a network.
The command nmap -T4 -A -v 10.140.63.210 performs an aggressive scan with OS detection, version detection, script scanning, and traceroute.
It detected that ports 135, 139, and 445 were open, indicating the system is running Windows services like RPC and SMB.
Another scan with nmap -sS -p 22,80,443 10.140.63.210 showed that these specific ports were closed.
SYN scans (-sS) send only SYN packets and wait for responses (RST or SYN-ACK) without completing the TCP handshake.

#Wireshark Packet Capture Explanation
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

#Network Reconnaissance & Scanning
Network reconnaissance is the process of gathering information about systems and services in a network before performing security analysis. It helps identify active hosts, open ports, and running services to assess network security.

#Port Scanning
Port scanning is a technique used to find which ports on a system are open and listening for connections. Each port corresponds to a specific service (e.g., port 80 for HTTP, port 443 for HTTPS). Open ports can be entry points for attackers, so scanning helps in vulnerability assessment.

#TCP SYN Scan
A TCP SYN scan is one of the most common and stealthy scanning techniques. It works by sending a SYN packet (used to start a TCP connection) to the target port:
If the port is open, the target replies with a SYN-ACK packet.
If the port is closed, the target sends an RST (reset) packet.
This method is fast and doesn’t complete the full TCP handshake, making it less likely to be logged by the target system.

#IP Ranges
Instead of scanning one IP at a time, you can scan an entire IP range (e.g., 192.168.0.1–192.168.0.255) to find multiple active devices on the same network. This is useful for discovering hosts in a local or enterprise network.

#Open Ports
Open ports indicate that a service is running on that port and is accepting connections. Examples:
Port 22 – SSH (Remote Login)
Port 80 – HTTP (Web)
Port 443 – HTTPS (Secure Web)
Attackers target open ports, so administrators must monitor and secure them.

#Network Security Basics
Use Firewalls: Block unnecessary ports and restrict access.
Update Systems: Patch vulnerabilities in services.
Monitor Traffic: Detect unusual activities.
Disable Unused Services: Reduce attack surface.
