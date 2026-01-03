#!/usr/bin/env python3

import os
import socket
import psutil
import platform
import ipaddress
import sys
import subprocess
from rich.console import Console
from rich.table import Table

console = Console()


def clear_screen():
    """Очистить экран терминала"""
    os.system('cls' if os.name == 'nt' else 'clear')


def check_root():
    """Проверить права root/administrator"""
    if os.name == 'nt':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0


def wait_for_key():
    """Ожидать нажатия любой клавиши"""
    if os.name == 'nt':
        import msvcrt
        return msvcrt.getch()
    else:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            tty.setraw(fd)
            return sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def get_interfaces():
    """Получить список сетевых интерфейсов"""
    if platform.system() == "Windows":
        intfs = []
        for intf, addrs in psutil.net_if_addrs().items():
            if 'Loopback' in intf or intf.startswith('lo'):
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    intfs.append(intf)
                    break
        return intfs
    else:
        try:
            import netifaces
            intfs = [i for i in netifaces.interfaces() if i != 'lo']
            return intfs
        except:
            return []


def get_interface_info(interface):
    """Получить информацию об интерфейсе"""
    info = {
        "ip": None,
        "netmask": None,
        "mac": None,
        "gateway": None,
        "up": False
    }

    try:
        # Получить MAC адрес
        if platform.system() == "Windows":
            addrs = psutil.net_if_addrs().get(interface, [])
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    info["mac"] = addr.address
                elif addr.family == socket.AF_INET:
                    info["ip"] = addr.address
                    info["netmask"] = addr.netmask
        else:
            # Linux/MacOS
            with open(f"/sys/class/net/{interface}/operstate") as f:
                info["up"] = f.read().strip() == "up"

            try:
                import netifaces
                if interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)

                    # MAC
                    if netifaces.AF_LINK in addrs:
                        info["mac"] = addrs[netifaces.AF_LINK][0]['addr']

                    # IPv4
                    if netifaces.AF_INET in addrs:
                        info["ip"] = addrs[netifaces.AF_INET][0]['addr']
                        info["netmask"] = addrs[netifaces.AF_INET][0]['netmask']

                    # Gateway
                    gws = netifaces.gateways()
                    if 'default' in gws and netifaces.AF_INET in gws['default']:
                        info["gateway"] = gws['default'][netifaces.AF_INET][0]
            except:
                pass
    except Exception as e:
        console.print(f"[red]Error getting interface info: {e}[/red]")

    return info


def enable_ip_forward():
    """Включить IP форвардинг (для MITM)"""
    if platform.system() == "Linux":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            console.print("[green]IP forwarding enabled[/green]")
            return True
        except:
            console.print("[red]Failed to enable IP forwarding[/red]")
            return False
    elif platform.system() == "Darwin":  # macOS
        try:
            subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=1"],
                         check=True, capture_output=True)
            return True
        except:
            return False
    return True  # Windows handles this differently


def disable_ip_forward():
    """Выключить IP форвардинг"""
    if platform.system() == "Linux":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            console.print("[green]IP forwarding disabled[/green]")
            return True
        except:
            console.print("[red]Failed to disable IP forwarding[/red]")
            return False
    elif platform.system() == "Darwin":
        try:
            subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=0"],
                         check=True, capture_output=True)
            return True
        except:
            return False
    return True


def format_bytes(size):
    """Форматировать размер в байтах в читаемый вид"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def format_time(seconds):
    """Форматировать время в читаемый вид"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds // 60
        seconds %= 60
        return f"{minutes:.0f}m {seconds:.0f}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours:.0f}h {minutes:.0f}m"


def calculate_network_range(ip, netmask):
    """Вычислить диапазон сети"""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except:
        return None


def is_valid_ip(ip):
    """Проверить валидность IP адреса"""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False


def is_valid_mac(mac):
    """Проверить валидность MAC адреса"""
    import re
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return re.match(pattern, mac) is not None


def show_interfaces_table():
    """Показать таблицу интерфейсов через rich"""
    intfs = get_interfaces()

    if not intfs:
        console.print("[yellow]No network interfaces found[/yellow]")
        return

    table = Table(title="Network Interfaces", show_header=True)
    table.add_column("Interface", style="cyan")
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address", style="yellow")
    table.add_column("Status", style="magenta")

    for intf in intfs[:10]:  # Показать первые 10 интерфейсов
        info = get_interface_info(intf)
        ip = info.get("ip", "No IP")
        mac = info.get("mac", "No MAC") or "No MAC"
        status = "UP" if info.get("up") or info.get("ip") else "DOWN"

        table.add_row(intf, ip, mac, status)

    console.print(table)


if __name__ == "__main__":
    clear_screen()
    console.print("[bold cyan]Network Interface Information[/bold cyan]")
    console.print("-" * 50)
    show_interfaces_table()

    if check_root():
        console.print("[green]✓ Running with administrator privileges[/green]")
    else:
        console.print("[yellow]⚠ Running without administrator privileges[/yellow]")
        console.print("[yellow]Some features may not work properly[/yellow]")
