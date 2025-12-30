#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import platform
import netifaces
import ipaddress
import socket
import psutil
from typing import Optional, List, Tuple, Dict
from colorama import Fore, Style, init

init(autoreset=True)


def get_network_interfaces() -> List[str]:
    """Получить список сетевых интерфейсов"""
    interfaces = []
    try:
        if platform.system() == "Windows":
            # Используем psutil для Windows
            for interface, addrs in psutil.net_if_addrs().items():
                # Пропускаем loopback и виртуальные интерфейсы
                if interface.startswith('Loopback') or interface.startswith('lo') or interface.startswith('isatap'):
                    continue
                # Проверяем, есть ли IPv4 адрес
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                        interfaces.append(interface)
                        break
        else:
            # Linux/Mac - используем netifaces
            interfaces = netifaces.interfaces()

            # Убираем loopback интерфейсы
            interfaces = [iface for iface in interfaces if iface != 'lo' and not iface.startswith('lo:')]
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Ошибка получения интерфейсов: {e}")
        # Fallback
        if platform.system() == "Windows":
            try:
                # Пробуем получить через ipconfig
                output = subprocess.check_output("ipconfig", shell=True, text=True, stderr=subprocess.DEVNULL)
                lines = output.split('\n')
                current_interface = ""
                for line in lines:
                    if 'adapter' in line.lower() and ':' in line:
                        current_interface = line.split(':')[0].strip()
                        if current_interface and current_interface not in interfaces:
                            interfaces.append(current_interface)
            except:
                pass

    return interfaces


def get_interface_info(interface: str) -> Dict:
    """Получить информацию об интерфейсе"""
    info = {
        "name": interface,
        "ip": "",
        "mac": "",
        "netmask": "",
        "gateway": "",
        "description": interface
    }

    try:
        if platform.system() == "Windows":
            # Используем psutil для Windows
            addrs = psutil.net_if_addrs().get(interface, [])
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    info["ip"] = addr.address
                    info["netmask"] = addr.netmask
                elif addr.family == psutil.AF_LINK:  # MAC
                    info["mac"] = addr.address

            # Получаем шлюз по умолчанию
            try:
                gateways = psutil.net_if_stats().get(interface)
                if gateways:
                    # Пытаемся получить шлюз из таблицы маршрутизации
                    import ctypes
                    from ctypes import wintypes

                    # Windows API для получения таблицы маршрутизации
                    GetIpForwardTable = ctypes.windll.iphlpapi.GetIpForwardTable
                    GetIpForwardTable.argtypes = [
                        ctypes.POINTER(ctypes.c_ubyte),
                        wintypes.PULONG,
                        wintypes.BOOL
                    ]

                    size = wintypes.ULONG(0)
                    GetIpForwardTable(None, ctypes.byref(size), False)

                    if size.value > 0:
                        buffer = (ctypes.c_ubyte * size.value)()
                        GetIpForwardTable(buffer, ctypes.byref(size), False)

                        # Парсим таблицу маршрутизации
                        # Это упрощенный пример - в реальности нужно парсить структуру MIB_IPFORWARDROW

                        # Вместо сложного парсинга, используем простой способ
                        try:
                            # Пробуем получить шлюз через tracert к 8.8.8.8
                            result = subprocess.check_output(
                                f"route print 0.0.0.0",
                                shell=True,
                                text=True,
                                stderr=subprocess.DEVNULL
                            )
                            lines = result.split('\n')
                            for line in lines:
                                if '0.0.0.0' in line and interface[:15] in line:
                                    parts = line.split()
                                    for i, part in enumerate(parts):
                                        if part == '0.0.0.0' and i + 1 < len(parts):
                                            info["gateway"] = parts[i + 1]
                                            break
                        except:
                            pass
            except:
                pass

        else:
            # Linux/Mac
            addrs = netifaces.ifaddresses(interface)

            # MAC адрес
            if netifaces.AF_LINK in addrs:
                info["mac"] = addrs[netifaces.AF_LINK][0].get('addr', '')

            # IP адрес и маска
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
        print(f"{Fore.YELLOW}[!] Ошибка получения информации об интерфейсе {interface}: {e}")

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
