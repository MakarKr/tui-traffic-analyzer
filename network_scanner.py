#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import ARP, Ether, srp, conf
import threading
import time
from typing import List, Dict, Optional
from utils import get_interface_info


class NetworkScanner:
    def __init__(self):
        self.hosts = []
        self.scanning = False
        self.scan_thread = None

    def scan_network(self, network_range: str, interface: str = None, timeout: int = 2) -> List[Dict]:
        """Сканировать сеть на наличие активных хостов"""
        try:
            # Создаем ARP запрос
            arp_request = ARP(pdst=network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            # Отправляем пакеты
            answered_list = srp(
                arp_request_broadcast,
                timeout=timeout,
                verbose=False,
                iface=interface
            )[0]

            # Обрабатываем ответы
            hosts = []
            for sent, received in answered_list:
                hosts.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "vendor": self.get_vendor_by_mac(received.hwsrc),
                    "interface": interface
                })

            return hosts

        except Exception as e:
            print(f"[!] Ошибка сканирования: {e}")
            return []

    def scan_async(self, network_range: str, interface: str, callback):
        """Асинхронное сканирование сети"""
        self.scanning = True

        def scan_task():
            try:
                results = self.scan_network(network_range, interface)
                callback(results)
            finally:
                self.scanning = False

        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        """Остановить сканирование"""
        self.scanning = False
        if self.scan_thread:
            self.scan_thread.join(timeout=1)

    def get_vendor_by_mac(self, mac: str) -> str:
        """Определить производителя по MAC адресу"""
        # Сокращенная база OUI (в реальном проекте нужно использовать полную базу)
        oui_db = {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:1C:42": "Parallels",
            "00:16:3E": "Xen",
            "00:1A:4B": "ASRock",
            "00:1D:0F": "ASUS",
            "00:21:5A": "Dell",
            "00:24:8C": "Dell",
            "00:25:64": "Dell",
            "00:26:B9": "Dell",
            "00:50:8B": "Dell",
            "00:1F:29": "Dell",
            "00:1E:4F": "Lenovo",
            "00:25:11": "Lenovo",
            "00:26:18": "Lenovo",
            "00:15:5D": "Microsoft Hyper-V",
            "08:00:27": "VirtualBox",
            "0A:00:27": "VirtualBox",
            "52:54:00": "QEMU/KVM",
            "00:1B:21": "HP",
            "00:1E:0B": "HP",
            "00:22:64": "HP",
            "00:23:7D": "HP",
            "00:25:B3": "HP",
            "00:18:FE": "Apple",
            "00:1B:63": "Apple",
            "00:1D:4F": "Apple",
            "00:1E:52": "Apple",
            "00:1F:5B": "Apple",
            "00:1F:F3": "Apple",
            "00:21:E9": "Apple",
            "00:22:41": "Apple",
            "00:23:32": "Apple",
            "00:23:6C": "Apple",
            "00:23:DF": "Apple",
            "00:24:36": "Apple",
            "00:26:08": "Apple",
            "00:26:4A": "Apple",
            "00:26:B0": "Apple",
            "00:30:65": "Apple",
            "00:50:E4": "Apple",
            "00:56:CD": "Apple",
            "00:61:71": "Apple",
            "00:88:65": "Apple",
            "00:A0:40": "Apple",
            "00:C0:8C": "Apple",
            "00:C6:10": "Apple",
            "08:00:07": "Apple",
            "08:66:98": "Apple",
            "0C:15:39": "Apple",
            "0C:30:21": "Apple",
            "0C:4D:E9": "Apple",
            "0C:74:C2": "Apple",
            "10:1C:0C": "Apple",
            "10:40:F3": "Apple",
            "10:93:E9": "Apple",
            "10:DD:B1": "Apple",
            "14:10:9F": "Apple",
            "18:20:32": "Apple",
            "18:34:51": "Apple",
            "18:9E:FC": "Apple",
            "1C:1A:C0": "Apple",
            "1C:5A:3E": "Apple",
            "20:3D:66": "Apple",
            "20:A2:E4": "Apple",
            "24:A2:E1": "Apple",
            "28:0B:5C": "Apple",
            "28:37:37": "Apple",
            "28:6A:B8": "Apple",
            "28:6A:BA": "Apple",
            "28:CF:DA": "Apple",
            "28:CF:E9": "Apple",
            "2C:B4:3A": "Apple",
            "30:10:E4": "Apple",
            "34:12:98": "Apple",
            "3C:15:C2": "Apple",
            "3C:AB:8E": "Apple",
            "40:30:04": "Apple",
            "44:FB:42": "Apple",
            "4C:8D:79": "Apple",
            "54:26:96": "Apple",
            "54:72:4F": "Apple",
            "54:E4:3A": "Apple",
            "60:33:4B": "Apple",
            "64:E6:82": "Apple",
            "68:09:27": "Apple",
            "68:5B:35": "Apple",
            "68:96:7B": "Apple",
            "68:9C:70": "Apple",
            "6C:70:9F": "Apple",
            "70:56:81": "Apple",
            "78:31:C1": "Apple",
            "78:7B:8A": "Apple",
            "78:9F:70": "Apple",
            "78:CA:39": "Apple",
            "7C:6D:62": "Apple",
            "7C:C5:37": "Apple",
            "80:00:6E": "Apple",
            "84:38:35": "Apple",
            "84:85:06": "Apple",
            "84:B1:53": "Apple",
            "84:FC:FE": "Apple",
            "88:53:95": "Apple",
            "8C:7B:9D": "Apple",
            "90:84:0D": "Apple",
            "98:01:A7": "Apple",
            "9C:04:EB": "Apple",
            "A4:67:06": "Apple",
            "AC:87:A3": "Apple",
            "B8:8D:12": "Apple",
            "BC:3B:AF": "Apple",
            "BC:52:B7": "Apple",
            "BC:67:78": "Apple",
            "C0:CC:F8": "Apple",
            "C8:2A:14": "Apple",
            "C8:6F:1D": "Apple",
            "CC:08:E0": "Apple",
            "D0:23:DB": "Apple",
            "D8:30:62": "Apple",
            "F0:18:98": "Apple",
            "F0:24:75": "Apple",
            "F0:B4:79": "Apple",
            "F0:CB:A1": "Apple",
            "F4:F1:5A": "Apple",
            "FC:25:3F": "Apple"
        }

        mac_prefix = mac.upper().replace(':', '').replace('-', '')[:6]
        for oui, vendor in oui_db.items():
            if mac_prefix.startswith(oui.replace(':', '')):
                return vendor

        return "Неизвестно"

    def get_local_network_range(self, interface: str) -> Optional[str]:
        """Получить диапазон локальной сети"""
        info = get_interface_info(interface)
        if info["ip"] and info["netmask"]:
            import ipaddress
            network = ipaddress.IPv4Network(f"{info['ip']}/{info['netmask']}", strict=False)
            return str(network)
        return None