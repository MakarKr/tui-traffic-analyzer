#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import platform
import socket
import psutil
import ipaddress
import re
from typing import Optional, List, Tuple, Dict
from colorama import Fore, Style, init

init(autoreset=True)


def get_network_interfaces() -> List[str]:
    """Получить список сетевых интерфейсов с улучшенным детектированием"""
    interfaces = []

    try:
        if platform.system() == "Windows":
            # Используем psutil для Windows
            for interface, addrs in psutil.net_if_addrs().items():
                # Пропускаем loopback и виртуальные интерфейсы
                if any(keyword in interface.lower() for keyword in
                       ['loopback', 'lo', 'isatap', 'teredo', 'bluetooth', 'virtual', 'vmware', 'vbox']):
                    continue

                # Проверяем, есть ли IPv4 адрес
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address != '127.0.0.1' and addr.address != '0.0.0.0':
                        interfaces.append(interface)
                        break

            # Если psutil не нашел интерфейсы, пробуем через ipconfig
            if not interfaces:
                try:
                    output = subprocess.check_output(
                        "ipconfig",
                        shell=True,
                        text=True,
                        stderr=subprocess.DEVNULL,
                        timeout=5
                    )

                    current_interface = ""
                    for line in output.split('\n'):
                        line = line.strip()
                        if 'adapter' in line.lower() and ':' in line:
                            current_interface = line.split(':')[0].strip()
                            # Пропускаем нежелательные интерфейсы
                            if current_interface and not any(
                                keyword in current_interface.lower()
                                for keyword in ['loopback', 'bluetooth', 'virtual', 'wan miniport']
                            ):
                                interfaces.append(current_interface)
                except:
                    pass

        else:
            # Linux/Mac - используем psutil или netifaces
            try:
                for interface, addrs in psutil.net_if_addrs().items():
                    # Пропускаем loopback интерфейсы
                    if interface == 'lo' or interface.startswith('lo:'):
                        continue

                    # Проверяем, есть ли IPv4 адрес
                    for addr in addrs:
                        if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                            interfaces.append(interface)
                            break
            except:
                # Fallback на простой метод
                import netifaces
                all_interfaces = netifaces.interfaces()
                for iface in all_interfaces:
                    if iface != 'lo' and not iface.startswith('lo:'):
                        interfaces.append(iface)

    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error getting network interfaces: {e}")

    # Убираем дубликаты
    interfaces = list(dict.fromkeys(interfaces))

    print(f"[*] Found {len(interfaces)} network interfaces")
    return interfaces


def get_interface_info(interface: str) -> Dict:
    """Получить информацию об интерфейсе с улучшенной надежностью"""
    info = {
        "name": interface,
        "ip": "",
        "mac": "",
        "netmask": "",
        "gateway": "",
        "description": interface,
        "status": "unknown"
    }

    if not interface:
        return info

    try:
        if platform.system() == "Windows":
            # Используем psutil для Windows
            addrs = psutil.net_if_addrs().get(interface, [])
            stats = psutil.net_if_stats().get(interface)

            if stats:
                info["status"] = "up" if stats.isup else "down"
                info["speed"] = stats.speed

            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    info["ip"] = addr.address
                    info["netmask"] = addr.netmask
                elif addr.family == psutil.AF_LINK:  # MAC
                    info["mac"] = addr.address.replace('-', ':').upper()

            # Получаем шлюз по умолчанию
            try:
                import ctypes
                from ctypes import wintypes

                # Используем GetAdaptersInfo для получения шлюза
                # Это более надежно на Windows
                result = subprocess.check_output(
                    f"route print 0.0.0.0",
                    shell=True,
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )

                lines = result.split('\n')
                for i, line in enumerate(lines):
                    if '0.0.0.0' in line and '0.0.0.0' in line:
                        # Следующая строка должна содержать шлюз
                        if i + 1 < len(lines):
                            next_line = lines[i + 1]
                            parts = next_line.split()
                            if len(parts) >= 3:
                                info["gateway"] = parts[2]
                                break
            except:
                pass

        else:
            # Linux/Mac
            try:
                import netifaces
                addrs = netifaces.ifaddresses(interface)

                # MAC адрес
                if netifaces.AF_LINK in addrs:
                    info["mac"] = addrs[netifaces.AF_LINK][0].get('addr', '').upper()

                # IP адрес и маска
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    info["ip"] = ip_info.get('addr', '')
                    info["netmask"] = ip_info.get('netmask', '')
                    info["broadcast"] = ip_info.get('broadcast', '')

                # Шлюз по умолчанию
                gateways = netifaces.gateways()
                if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                    gateway_info = gateways['default'][netifaces.AF_INET]
                    if gateway_info[1] == interface:
                        info["gateway"] = gateway_info[0]

                # Статус интерфейса
                try:
                    with open(f"/sys/class/net/{interface}/operstate", 'r') as f:
                        info["status"] = f.read().strip()
                except:
                    pass

            except ImportError:
                # Fallback без netifaces
                pass

    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error getting info for interface {interface}: {e}")

    return info


def enable_ip_forwarding() -> bool:
    """Включить IP forwarding для MITM с улучшенной обработкой"""
    try:
        if platform.system() == "Linux":
            # Проверяем текущее значение
            result = subprocess.run(
                ["sysctl", "-n", "net.ipv4.ip_forward"],
                capture_output=True,
                text=True,
                timeout=5
            )

            current_value = result.stdout.strip()
            print(f"[*] Current IP forwarding value: {current_value}")

            # Включаем
            subprocess.run(
                ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
                check=True,
                timeout=10
            )

            # Проверяем что включилось
            result = subprocess.run(
                ["sysctl", "-n", "net.ipv4.ip_forward"],
                capture_output=True,
                text=True,
                timeout=5
            )

            new_value = result.stdout.strip()
            if new_value == "1":
                print("[*] IP forwarding enabled successfully")
                return True
            else:
                print(f"[!] Failed to enable IP forwarding (value: {new_value})")
                return False

        elif platform.system() == "Darwin":  # macOS
            subprocess.run(
                ["sudo", "sysctl", "-w", "net.inet.ip.forwarding=1"],
                check=True,
                timeout=10
            )
            print("[*] IP forwarding enabled on macOS")
            return True

        else:
            print(f"{Fore.YELLOW}[!] Automatic IP forwarding not supported for {platform.system()}")
            return False

    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}[!] Timeout enabling IP forwarding")
        return False
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] Error enabling IP forwarding: {e}")
        return False
    except Exception as e:
        print(f"{Fore.RED}[!] Exception enabling IP forwarding: {e}")
        return False


def disable_ip_forwarding() -> bool:
    """Выключить IP forwarding"""
    try:
        if platform.system() == "Linux":
            subprocess.run(
                ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"],
                check=True,
                timeout=10
            )

            # Очищаем iptables
            subprocess.run(["sudo", "iptables", "--flush"], timeout=5)
            subprocess.run(["sudo", "iptables", "-t", "nat", "--flush"], timeout=5)

            return True
        elif platform.system() == "Darwin":
            subprocess.run(
                ["sudo", "sysctl", "-w", "net.inet.ip.forwarding=0"],
                check=True,
                timeout=10
            )
            return True
        else:
            return False
    except:
        return False


def calculate_network_range(ip: str, netmask: str) -> List[str]:
    """Рассчитать диапазон сети с улучшенной обработкой"""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        # Ограничиваем количество хостов для больших сетей
        hosts = list(network.hosts())
        if len(hosts) > 1000:
            print(f"[*] Large network detected ({len(hosts)} hosts), limiting scan range")
            hosts = hosts[:1000]
        return [str(ip) for ip in hosts]
    except:
        return []


def is_valid_ip(ip: str) -> bool:
    """Проверить валидность IP адреса"""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False


def is_valid_mac(mac: str) -> bool:
    """Проверить валидность MAC адреса"""
    if not mac:
        return False

    # Проверяем несколько форматов
    mac_patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
        r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$',  # Cisco format
        r'^([0-9A-Fa-f]{12})$'  # Без разделителей
    ]

    for pattern in mac_patterns:
        if re.match(pattern, mac):
            return True

    return False


def format_bytes(size: int) -> str:
    """Форматировать размер в байтах"""
    if size < 0:
        return "0 B"

    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def format_time_delta(seconds: float) -> str:
    """Форматировать разницу во времени"""
    if seconds < 0:
        return "0ms"

    if seconds < 0.001:
        return "<1ms"
    elif seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def clear_screen():
    """Очистить экран терминала"""
    os.system('cls' if os.name == 'nt' else 'clear')


def check_root() -> bool:
    """Проверить наличие root-прав с улучшенной проверкой"""
    if os.name == 'nt':
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        try:
            # Проверяем через id команду
            result = subprocess.run(
                ["id", "-u"],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                return result.stdout.strip() == "0"
        except:
            pass

        # Fallback на проверку EUID
        return os.geteuid() == 0


def get_system_info() -> Dict:
    """Получить информацию о системе"""
    info = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "is_root": check_root()
    }

    # Дополнительная информация
    if platform.system() == "Windows":
        info["windows_version"] = platform.win32_ver()
    elif platform.system() == "Linux":
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        info["distribution"] = line.split('=', 1)[1].strip().strip('"')
                        break
        except:
            pass

    return info
