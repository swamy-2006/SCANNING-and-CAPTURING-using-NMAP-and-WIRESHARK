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

❖ Well-Known Ports (0–1023):
➢ Used for standard services.
➢ Examples:
■ HTTP: Port 80
■ HTTPS: Port 443
■ FTP: Ports 20 and 21
■ SSH: Port 22
■ SMTP: Port 25
■ DNS: Port 53











Network Reconnaissance & Scanning
Network reconnaissance is the process of gathering information about systems and services in a network before performing security analysis. It helps identify active hosts, open ports, and running services to assess network security.

Port Scanning
Port scanning is a technique used to find which ports on a system are open and listening for connections. Each port corresponds to a specific service (e.g., port 80 for HTTP, port 443 for HTTPS). Open ports can be entry points for attackers, so scanning helps in vulnerability assessment.

TCP SYN Scan
A TCP SYN scan is one of the most common and stealthy scanning techniques. It works by sending a SYN packet (used to start a TCP connection) to the target port:

If the port is open, the target replies with a SYN-ACK packet.

If the port is closed, the target sends an RST (reset) packet.
This method is fast and doesn’t complete the full TCP handshake, making it less likely to be logged by the target system.

IP Ranges
Instead of scanning one IP at a time, you can scan an entire IP range (e.g., 192.168.0.1–192.168.0.255) to find multiple active devices on the same network. This is useful for discovering hosts in a local or enterprise network.

Open Ports
Open ports indicate that a service is running on that port and is accepting connections. Examples:

Port 22 – SSH (Remote Login)

Port 80 – HTTP (Web)

Port 443 – HTTPS (Secure Web)

Attackers target open ports, so administrators must monitor and secure them.

Network Security Basics
Use Firewalls: Block unnecessary ports and restrict access.

Update Systems: Patch vulnerabilities in services.

Monitor Traffic: Detect unusual activities.

Disable Unused Services: Reduce attack surface.
