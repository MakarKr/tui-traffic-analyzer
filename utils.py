#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import platform
import netifaces
import ipaddress
from typing import Optional, List, Tuple, Dict
from colorama import Fore, Style, init

init(autoreset=True)


def get_network_interfaces() -> List[str]:
    """Получить список сетевых интерфейсов"""
    interfaces = []
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("netsh interface show interface", shell=True, text=True)
            lines = output.split('\n')
            for line in lines:
                if "Connected" in line or "Disconnected" in line:
                    parts = line.split()
                    if len(parts) > 3:
                        interfaces.append(parts[-1])
        else:
            # Linux/Mac
            interfaces = netifaces.interfaces()
    except:
        # Fallback для Linux
        interfaces = os.listdir('/sys/class/net/')

    # Убираем loopback интерфейсы
    interfaces = [iface for iface in interfaces if iface != 'lo' and not iface.startswith('lo:')]
    return interfaces


def get_interface_info(interface: str) -> Dict:
    """Получить информацию об интерфейсе"""
    info = {
        "name": interface,
        "ip": "",
        "mac": "",
        "netmask": "",
        "gateway": ""
    }

    try:
        # MAC адрес
        if platform.system() == "Windows":
            output = subprocess.check_output(f"getmac /fo csv /v", shell=True, text=True)
            for line in output.split('\n'):
                if interface in line:
                    parts = line.split(',')
                    if len(parts) > 2:
                        info["mac"] = parts[2].strip().replace('"', '')
        else:
            mac_path = f"/sys/class/net/{interface}/address"
            if os.path.exists(mac_path):
                with open(mac_path, 'r') as f:
                    info["mac"] = f.read().strip()

        # IP адрес и маска
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            info["ip"] = ip_info.get('addr', '')
            info["netmask"] = ip_info.get('netmask', '')

        # Шлюз по умолчанию
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            gateway_info = gateways['default'][netifaces.AF_INET]
            if gateway_info[1] == interface:
                info["gateway"] = gateway_info[0]

    except Exception as e:
        print(f"{Fore.YELLOW}[!] Ошибка получения информации об интерфейсе: {e}")

    return info


def enable_ip_forwarding() -> bool:
    """Включить IP forwarding для MITM"""
    try:
        if platform.system() == "Linux":
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
            subprocess.run(["sudo", "iptables", "--flush"], check=True)
            subprocess.run(
                ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j",
                 "REDIRECT", "--to-port", "8080"], check=True)
            subprocess.run(
                ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "443", "-j",
                 "REDIRECT", "--to-port", "8080"], check=True)
            return True
        elif platform.system() == "Darwin":  # macOS
            subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=1"], check=True)
            return True
        else:
            print(f"{Fore.YELLOW}[!] Автоматическое включение IP forwarding не поддерживается для {platform.system()}")
            return False
    except Exception as e:
        print(f"{Fore.RED}[!] Ошибка включения IP forwarding: {e}")
        return False


def disable_ip_forwarding() -> bool:
    """Выключить IP forwarding"""
    try:
        if platform.system() == "Linux":
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], check=True)
            subprocess.run(["sudo", "iptables", "--flush"], check=True)
            subprocess.run(["sudo", "iptables", "-t", "nat", "--flush"], check=True)
            return True
        elif platform.system() == "Darwin":
            subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=0"], check=True)
            return True
        else:
            return False
    except:
        return False


def calculate_network_range(ip: str, netmask: str) -> List[str]:
    """Рассчитать диапазон сети"""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return [str(ip) for ip in network.hosts()]
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
    import re
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(mac_pattern.match(mac))


def format_bytes(size: int) -> str:
    """Форматировать размер в байтах"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def format_time_delta(seconds: float) -> str:
    """Форматировать разницу во времени"""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"


def clear_screen():
    """Очистить экран терминала"""
    os.system('cls' if os.name == 'nt' else 'clear')


def check_root() -> bool:
    """Проверить наличие root-прав"""
    if os.name == 'nt':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    else:
        return os.geteuid() == 0