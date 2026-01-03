#!/usr/bin/env python3

import os
import socket
import psutil
import platform
import ipaddress
from rich.console import Console
from rich.table import Table

console = Console()

def get_interfaces():
    """Get network interfaces with rich display"""
    if platform.system() == "Windows":
        intfs = []
        for intf, addrs in psutil.net_if_addrs().items():
            if 'Loopback' in intf or intf.startswith('lo'):
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    intfs.append(intf)
                    break

        # Display with rich table
        table = Table(title="Network Interfaces", show_header=True)
        table.add_column("Interface", style="cyan")
        table.add_column("IP Address", style="green")

        for intf in intfs[:5]:  # Show first 5
            info = get_interface_info(intf)
            table.add_row(intf, info.get("ip", "No IP"))

        if intfs:
            console.print(table)

        return intfs
    else:
        try:
            import netifaces
            intfs = [i for i in netifaces.interfaces() if i != 'lo']

            table = Table(title="Network Interfaces", show_header=True)
            table.add_column("Interface", style="cyan")
            table.add_column("IP Address", style="green")

            for intf in intfs[:5]:
                info = get_interface_info(intf)
                table.add_row(intf, info.get("ip", "No IP"))

            if intfs:
                console.print(table)

            return intfs
        except:
            return []
