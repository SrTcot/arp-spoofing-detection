# 🔐 ARP Spoofing Detection Tool – Python

This repository contains a lightweight, engineer-oriented Python tool for detecting **ARP Spoofing** (ARP Poisoning) attacks in real time.  
The program listens to ARP traffic using **Scapy** and alerts whenever an IP address suddenly changes its associated MAC address — a common indicator of **Man-in-the-Middle (MITM)** activity.

This tool is intended for cybersecurity analysts, blue teams, network engineers, and security researchers performing continuous network monitoring.



## 📌 Features

- Real-time ARP traffic monitoring  
- Detection of IP–MAC inconsistencies  
- Clear alerts when ARP spoofing is suspected  
- Efficient, lightweight, and easy to deploy  
- Suitable for SOC environments, labs, and defensive monitoring setups  



## 🛡️ What Is ARP Spoofing?

**ARP Spoofing** is a Layer-2 attack where an attacker sends forged ARP replies to associate their MAC address with the IP address of a legitimate device (gateway, server, workstation).  
This enables:

- MITM interception  
- Packet redirection or manipulation  
- Credential/session theft  
- Network disruption  
- Traffic hijacking  

This tool detects those changes early to reduce the risk of compromise.


## 🚀 Installation

### 1. Clone the repository
bash
git clone https://github.com/SrTcot/arp-spoofing-detection.git
cd arp-spoof-detector

2. Install required dependencies

pip install scapy




▶️ Usage

Run the tool with administrator/root permissions:

sudo python3 arp_detector.py

Expected output when the network is clean:

=== ARP Spoofing Detector ===
Listening for suspicious ARP traffic...

Alert example when spoofing is detected:

[!!] ARP SPOOFING DETECTED
[!] IP: 192.168.1.1
[!] Old MAC: 00:11:22:33:44:55
[!] New MAC: aa:bb:cc:dd:ee:ff
[!] Possible MITM attack.




🧠 How It Works

1. Listens for ARP replies (op=2)


2. Maps each IP address to its known MAC address


3. If the mapping changes → suspicious event detected


4. Prints an alert for potential spoofing/MITM attempts




🧬 Project Structure

/
├── arp_detector.py
└── README.md



🛡️ Hardening Recommendations

To complement this ARP spoofing detector:

Enable Dynamic ARP Inspection (DAI) on switches

Use static ARP entries on critical servers

Implement Port Security (MAC binding)

Network segmentation and Zero Trust principles

Continuous monitoring via SOC, SIEM, or EDR tools



🤝 Contributing

Contributions are welcome.
Please ensure that your submissions follow:

Clean Python code practices

Proper documentation

Security-oriented engineering principles

Functional testing




📄 License

Released under the MIT License.



👨‍💻 Author
SrTCOT
Developed from an engineering and cybersecurity perspective to support early detection of local network compromis.
