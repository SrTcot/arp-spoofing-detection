#!/usr/bin/env python3
from scapy.all import ARP, sniff
from collections import defaultdict
import logging
import time
import os

class ARPSpoofDetector:
    def __init__(self):
        self.ip_mac_map = defaultdict(str)
        self.last_alert_time = 0
        self.alert_cooldown = 5  # seconds

        # Configure logging
        logging.basicConfig(
            filename="arp_alerts.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )

    def get_mac_vendor(self, mac):
        """Attempts to identify vendor via OUI lookup."""
        oui = mac.upper().replace(":", "")[:6]

        # Simple built-in list (extendable)
        known_vendors = {
            "00163E": "Cisco Systems",
            "F4F5E8": "Apple",
            "BC92B8": "Samsung",
            "FCF5C4": "Intel Corporate",
            "D850E6": "Huawei Technologies",
        }

        return known_vendors.get(oui, "Unknown Vendor")

    def alert(self, src_ip, old_mac, new_mac):
        current_time = time.time()

        # Rate limit alerts
        if current_time - self.last_alert_time < self.alert_cooldown:
            return

        self.last_alert_time = current_time

        print("\n[!!] SECURITY ALERT: ARP SPOOFING DETECTED")
        print(f"[>] Target IP: {src_ip}")
        print(f"[>] Old MAC: {old_mac} ({self.get_mac_vendor(old_mac)})")
        print(f"[>] New MAC: {new_mac} ({self.get_mac_vendor(new_mac)})")
        print(f"[>] Potential MITM attack.\n")

        logging.warning(
            f"ARP Spoofing Detected | IP: {src_ip} | Old MAC: {old_mac} | "
            f"New MAC: {new_mac}"
        )

    def analyze_packet(self, pkt):
        """Handles each incoming ARP packet."""
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:  # ARP Reply
            return

        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        # If IP not seen before, register MAC
        if self.ip_mac_map[src_ip] == "":
            self.ip_mac_map[src_ip] = src_mac
            return

        # If MAC changed → Spoofing detected
        if self.ip_mac_map[src_ip] != src_mac:
            self.alert(src_ip, self.ip_mac_map[src_ip], src_mac)
            self.ip_mac_map[src_ip] = src_mac  # Update tracking to avoid spam

    def run(self):
        print("=== Advanced ARP Spoofing Detector ===")
        print("Monitoring network for malicious ARP activity...\n")

        logging.info("ARP Spoofing Detector Started")

        try:
            sniff(
                filter="arp",
                store=False,
                prn=self.analyze_packet,
            )
        except PermissionError:
            print("[ERROR] Run this program with sudo or administrator privileges.")
        except KeyboardInterrupt:
            print("\nStopping ARP detector...")
            logging.info("ARP Spoofing Detector Stopped")


if __name__ == "__main__":
    detector = ARPSpoofDetector()
    detector.run()
