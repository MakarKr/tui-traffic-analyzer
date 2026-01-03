#!/usr/bin/env python3

from scapy.all import ARP, Ether, srp, conf
import threading
from utils import get_interface_info

class NetworkScanner:
    def __init__(self):
        self.hosts = []
        self.scanning = False
        self.thread = None

    def scan(self, network, intf=None, timeout=2):
        """Scan network for hosts"""
        try:
            arp = ARP(pdst=network)
            eth = Ether(dst="ff:ff:ff:ff:ff:ff")
            pkt = eth/arp

            ans = srp(pkt, timeout=timeout, verbose=False, iface=intf)[0]

            hosts = []
            for sent, recv in ans:
                hosts.append({
                    "ip": recv.psrc,
                    "mac": recv.hwsrc,
                    "vendor": self._get_vendor(recv.hwsrc),
                    "interface": intf
                })

            return hosts
        except Exception as e:
            print(f"Scan error: {e}")
            return []

    def scan_async(self, network, intf, callback):
        """Scan in background"""
        self.scanning = True

        def task():
            try:
                results = self.scan(network, intf)
                callback(results)
            finally:
                self.scanning = False

        self.thread = threading.Thread(target=task, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop scanning"""
        self.scanning = False
        if self.thread:
            self.thread.join(timeout=1)

    def _get_vendor(self, mac):
        """Get vendor from MAC"""
        mac = mac.upper().replace(':', '').replace('-', '')
        prefix = mac[:6]

        vendors = {
            "000C29": "VMware",
            "080027": "VirtualBox",
            "525400": "QEMU",
            "001B21": "HP",
            "001E0B": "HP",
            "001D4F": "Apple",
            "001F5B": "Apple",
            "002241": "Apple",
            "002636": "Apple",
            "0050F2": "Microsoft",
            "000569": "Dell",
            "001C42": "Dell",
            "001A4B": "ASRock",
            "001A6B": "ASUS",
            "001D60": "ASUS",
            "00E018": "TP-Link",
            "001E8C": "TP-Link",
            "000B6A": "Intel",
            "0016EA": "Intel",
            "001B21": "Intel"
        }

        for vprefix, vendor in vendors.items():
            if prefix.startswith(vprefix):
                return vendor

        return "Unknown"

    def get_local_network_range(self, intf):
        """Get network range for interface"""
        info = get_interface_info(intf)
        if info["ip"] and info["netmask"]:
            import ipaddress
            net = ipaddress.IPv4Network(f"{info['ip']}/{info['netmask']}", strict=False)
            return str(net)
        return None
