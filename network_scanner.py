#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import ARP, Ether, srp, conf
import threading
import time
import json
import os
from typing import List, Dict, Optional
from utils import get_interface_info


class NetworkScanner:
    def __init__(self):
        self.hosts = []
        self.scanning = False
        self.scan_thread = None
        self.mac_vendors_db = self._load_mac_vendors_db()

        # ВСТРОЕННАЯ РЕЗЕРВНАЯ БАЗА ДАННЫХ ПРЯМО В КОДЕ
        self.builtin_mac_db = {
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
            "FC:25:3F": "Apple",
            "00:03:93": "Apple",
            "00:05:02": "Apple",
            "00:0A:27": "Apple",
            "00:0A:95": "Apple",
            "00:0D:93": "Apple",
            "00:11:24": "Cisco",
            "00:12:00": "Cisco",
            "00:12:7F": "Cisco",
            "00:13:19": "Cisco",
            "00:13:5F": "Cisco",
            "00:14:69": "Cisco",
            "00:15:62": "Cisco",
            "00:16:46": "Cisco",
            "00:17:94": "Cisco",
            "00:18:B9": "Cisco",
            "00:19:06": "Cisco",
            "00:1B:0D": "Cisco",
            "00:1C:0E": "Cisco",
            "00:1D:45": "Cisco",
            "00:1E:13": "Cisco",
            "00:1E:7D": "Cisco",
            "00:1F:6C": "Cisco",
            "00:21:55": "Cisco",
            "00:22:55": "Cisco",
            "00:23:04": "Cisco",
            "00:23:EB": "Cisco",
            "00:24:14": "Cisco",
            "00:25:84": "Cisco",
            "00:26:0B": "Cisco",
            "00:26:98": "Cisco",
            "00:50:00": "D-Link",
            "00:50:BA": "D-Link",
            "00:80:C8": "D-Link",
            "00:1C:F0": "TP-Link",
            "00:23:CD": "TP-Link",
            "00:26:5A": "TP-Link",
            "00:27:19": "TP-Link",
            "1C:AF:F7": "TP-Link",
            "50:BD:5F": "TP-Link",
            "B0:95:8E": "TP-Link",
            "F4:EC:38": "TP-Link",
            "00:1A:2B": "Samsung",
            "00:12:47": "Samsung",
            "00:13:77": "Samsung",
            "00:15:99": "Samsung",
            "00:16:32": "Samsung",
            "00:16:6B": "Samsung",
            "00:16:6C": "Samsung",
            "00:17:62": "Samsung",
            "00:17:C9": "Samsung",
            "00:1A:8A": "Samsung",
            "00:1B:98": "Samsung",
            "00:1C:43": "Samsung",
            "00:1D:25": "Samsung",
            "00:1D:F6": "Samsung",
            "00:1E:7D": "Samsung",
            "00:21:4C": "Samsung",
            "00:22:47": "Samsung",
            "00:23:39": "Samsung",
            "00:23:99": "Samsung",
            "00:24:54": "Samsung",
            "00:25:38": "Samsung",
            "00:26:5D": "Samsung",
            "00:26:E8": "Samsung",
            "00:50:F1": "Samsung",
            "00:E0:64": "Samsung",
            "04:18:0F": "Samsung",
            "08:08:C2": "Samsung",
            "0C:14:20": "Samsung",
            "10:1D:C0": "Samsung",
            "10:30:47": "Samsung",
            "10:77:B1": "Samsung",
            "10:9A:DD": "Samsung",
            "14:10:9F": "Samsung",
            "14:1F:78": "Samsung",
            "18:16:C9": "Samsung",
            "18:26:66": "Samsung",
            "1C:66:AA": "Samsung",
            "20:2B:C1": "Samsung",
            "20:64:32": "Samsung",
            "24:4B:81": "Samsung",
            "24:92:0E": "Samsung",
            "24:DB:AC": "Samsung",
            "28:BA:B5": "Samsung",
            "2C:44:01": "Samsung",
            "2C:54:CF": "Samsung",
            "30:19:66": "Samsung",
            "34:23:BA": "Samsung",
            "34:BE:00": "Samsung",
            "38:01:95": "Samsung",
            "38:2C:4A": "Samsung",
            "3C:8B:FE": "Samsung",
            "3C:BD:D8": "Samsung",
            "40:D3:2D": "Samsung",
            "44:F4:59": "Samsung",
            "48:13:7E": "Samsung",
            "48:44:F7": "Samsung",
            "4C:66:41": "Samsung",
            "4C:BC:A5": "Samsung",
            "50:01:BB": "Samsung",
            "50:2E:5C": "Samsung",
            "54:88:0E": "Samsung",
            "5C:0A:5B": "Samsung",
            "5C:51:88": "Samsung",
            "60:6B:FF": "Samsung",
            "60:92:17": "Samsung",
            "64:77:91": "Samsung",
            "68:27:37": "Samsung",
            "6C:2E:85": "Samsung",
            "70:72:3C": "Samsung",
            "74:51:BA": "Samsung",
            "78:4B:87": "Samsung",
            "7C:11:CB": "Samsung",
            "80:18:A7": "Samsung",
            "84:25:DB": "Samsung",
            "84:38:38": "Samsung",
            "88:83:22": "Samsung",
            "8C:71:F8": "Samsung",
            "90:48:9A": "Samsung",
            "94:76:B7": "Samsung",
            "98:0C:82": "Samsung",
            "9C:65:B0": "Samsung",
            "A0:0B:BA": "Samsung",
            "A4:92:CB": "Samsung",
            "A8:06:00": "Samsung",
            "AC:36:13": "Samsung",
            "B0:DF:3A": "Samsung",
            "B4:79:A7": "Samsung",
            "B8:57:D8": "Samsung",
            "BC:14:85": "Samsung",
            "BC:72:B1": "Samsung",
            "C0:BD:D1": "Samsung",
            "C4:50:06": "Samsung",
            "C8:14:79": "Samsung",
            "CC:3A:61": "Samsung",
            "D0:22:BE": "Samsung",
            "D0:59:E4": "Samsung",
            "D4:9C:28": "Samsung",
            "D8:31:CF": "Samsung",
            "DC:68:EB": "Samsung",
            "E0:99:71": "Samsung",
            "E4:58:B8": "Samsung",
            "E4:92:FB": "Samsung",
            "E8:11:32": "Samsung",
            "EC:1F:72": "Samsung",
            "F0:25:B7": "Samsung",
            "F4:09:D8": "Samsung",
            "F8:04:2E": "Samsung",
            "FC:64:3A": "Samsung",
            "00:04:4F": "NVIDIA",
            "00:0C:6E": "Dell",
            "00:0E:35": "Dell",
            "00:11:11": "Dell",
            "00:12:3F": "Dell",
            "00:14:22": "Dell",
            "00:15:C5": "Dell",
            "00:18:8B": "Dell",
            "00:1A:A0": "Dell",
            "00:1D:09": "Dell",
            "00:21:70": "Dell",
            "00:22:19": "Dell",
            "00:24:E8": "Dell",
            "00:26:B9": "Dell",
            "00:50:56": "VMware (Dell)",
            "00:06:5B": "Dell",
            "00:08:74": "Dell",
            "00:0B:DB": "Dell",
            "00:0C:29": "VMware (Dell)",
            "00:0F:1F": "Dell",
            "00:10:F4": "Dell",
            "00:11:43": "Dell",
            "00:12:3F": "Dell",
            "00:13:72": "Dell",
            "00:14:22": "Dell",
            "00:15:C5": "Dell",
            "00:16:41": "Dell",
            "00:18:8B": "Dell",
            "00:1A:A0": "Dell",
            "00:1B:24": "Dell",
            "00:1C:23": "Dell",
            "00:1D:09": "Dell",
            "00:1E:4F": "Dell",
            "00:1F:29": "Dell",
            "00:21:70": "Dell",
            "00:22:19": "Dell",
            "00:23:AE": "Dell",
            "00:24:E8": "Dell",
            "00:26:B9": "Dell",
            "00:50:8B": "Dell",
            "00:06:7C": "Cisco",
            "00:0C:85": "Microsoft",
            "00:0D:3A": "Microsoft",
            "00:12:5A": "Microsoft",
            "00:15:5D": "Microsoft",
            "00:17:FA": "Microsoft",
            "00:1D:D8": "Microsoft",
            "00:22:48": "Microsoft",
            "00:25:AE": "Microsoft",
            "00:50:F2": "Microsoft",
            "00:03:FF": "Microsoft",
            "00:0F:FE": "Microsoft",
            "00:1F:29": "Microsoft",
            "00:50:56": "VMware (Microsoft)",
            "00:0C:29": "VMware (Microsoft)",
            "00:1C:42": "Microsoft (Parallels)",
            "00:16:3E": "Microsoft (Xen)",
        }

    def _load_mac_vendors_db(self) -> Dict:
        """Загрузить базу данных производителей MAC-адресов из JSON файла"""
        vendors_db = {}
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(script_dir, "mac-vendors-export.json")

        try:
            if os.path.exists(db_path):
                with open(db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for entry in data:
                        # Нормализуем MAC префикс для поиска
                        mac_prefix = entry['macPrefix'].upper().replace(':', '').replace('-', '')
                        vendors_db[mac_prefix] = entry['vendorName']
                print(f"[*] Loaded {len(vendors_db)} MAC vendors from database")
            else:
                print(f"[!] MAC vendors database not found at {db_path}")
                print(f"[*] Using built-in database with {len(self.builtin_mac_db)} vendors")
        except Exception as e:
            print(f"[!] Error loading MAC vendors database: {e}")
            print(f"[*] Using built-in database with {len(self.builtin_mac_db)} vendors")

        return vendors_db

    def scan_network(self, network_range: str, interface: str = None, timeout: int = 2) -> List[Dict]:
        """Сканировать сеть на наличие активных хостов"""
        try:
            print(f"[*] Scanning network: {network_range} on interface: {interface}")

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

            print(f"[*] Found {len(answered_list)} active hosts")

            # Обрабатываем ответы
            hosts = []
            for sent, received in answered_list:
                mac = received.hwsrc.upper()
                vendor = self.get_vendor_by_mac(mac)

                hosts.append({
                    "ip": received.psrc,
                    "mac": mac,
                    "vendor": vendor,
                    "interface": interface
                })

            return hosts

        except Exception as e:
            print(f"[!] Ошибка сканирования: {e}")
            import traceback
            traceback.print_exc()
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
        if not mac:
            return "Неизвестно"

        # Нормализуем MAC адрес
        mac_clean = mac.upper().replace(':', '').replace('-', '')

        # Проверяем первые 6 символов (OUI)
        if len(mac_clean) >= 6:
            oui_prefix = mac_clean[:6]

            # Ищем в JSON базе данных
            if self.mac_vendors_db and oui_prefix in self.mac_vendors_db:
                return self.mac_vendors_db[oui_prefix]

            # Создаем форматированный префикс для поиска в built-in базе
            formatted_oui = f"{mac_clean[0:2]}:{mac_clean[2:4]}:{mac_clean[4:6]}"

            # Ищем в built-in базе
            if formatted_oui in self.builtin_mac_db:
                return self.builtin_mac_db[formatted_oui]

        return "Неизвестно"

    def get_local_network_range(self, interface: str) -> Optional[str]:
        """Получить диапазон локальной сети"""
        info = get_interface_info(interface)
        if info["ip"] and info["netmask"]:
            import ipaddress
            try:
                network = ipaddress.IPv4Network(f"{info['ip']}/{info['netmask']}", strict=False)
                return str(network)
            except Exception as e:
                print(f"[!] Error calculating network range: {e}")
                # Попробуем альтернативный метод
                try:
                    ip_parts = info['ip'].split('.')
                    netmask_parts = info['netmask'].split('.')

                    # Вычисляем сетевой адрес
                    network_parts = []
                    for i in range(4):
                        network_parts.append(str(int(ip_parts[i]) & int(netmask_parts[i])))

                    # Вычисляем префикс сети
                    prefix = sum(bin(int(x)).count('1') for x in netmask_parts)

                    network_range = f"{'.'.join(network_parts)}/{prefix}"
                    print(f"[*] Calculated network range: {network_range}")
                    return network_range
                except Exception as e2:
                    print(f"[!] Alternative calculation also failed: {e2}")
                    return None
        else:
            print(f"[!] No IP or netmask for interface {interface}")
            print(f"[*] Interface info: {info}")
            return None
