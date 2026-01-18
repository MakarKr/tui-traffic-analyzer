#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import curses
import sys
import os
import time
import platform
from tui import TUI
from utils import check_root, clear_screen
from colorama import init, Fore, Style

# Добавляем путь к директории скрипта для корректной работы PyInstaller
if getattr(sys, 'frozen', False):
    # Если запущено как исполняемый файл
    application_path = os.path.dirname(sys.executable)
else:
    # Если запущено как скрипт
    application_path = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, application_path)

init(autoreset=True)


def get_keypress():
    # Получить нажатие любой клавиши без Enter (кроссплатформенный)
    try:
        # Для Windows
        if platform.system() == "Windows":
            import msvcrt
            return msvcrt.getch().decode('utf-8', errors='ignore').lower()
        # Для Linux/Mac
        else:
            import termios
            import tty
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                ch = sys.stdin.read(1).lower()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ch
    except Exception as e:
        # Fallback на input()
        print(f"\n{Fore.YELLOW}[!] Using fallback input method")
        return input("Press any key (Q to quit): ").strip().lower()


def show_startup_info():
    """Показать всю информацию при запуске и ждать нажатия клавиши"""
    print(f"{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN} TUI Traffic Analyzer")
    print(f"{Fore.CYAN} Developer: Makar Krapivin")
    print(f"{Fore.CYAN} License: GNU GPLv3")
    print(f"{Fore.CYAN}{'=' * 70}")
    print()

    # Проверка прав root/admin
    if not check_root():
        print(f"{Fore.YELLOW}[!] WARNING: Administrator/root privileges required for full functionality!")
        print(f"{Fore.YELLOW}[!] Run with sudo/administrator for packet sniffing and MITM attacks.")
        print()

    # Информация о HTTPS
    print(f"{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}HTTPS Traffic Analysis Limitations:")
    print(f"{Fore.CYAN}{'=' * 70}")
    print("1. FULL decryption of HTTPS/TLS is NOT POSSIBLE without:")
    print("   - Server's private key")
    print("   - Client's browser configuration")
    print("   - Pre-shared keys")
    print()
    print("2. What CAN be analyzed:")
    print("   - Server names (SNI)")
    print("   - Certificate information")
    print("   - Connection metadata")
    print("   - Data volumes and timing")
    print()
    print("3. For educational purposes only!")
    print(f"{Fore.CYAN}{'=' * 70}")

    # Информация о совместимости с Windows
    if platform.system() == "Windows":
        print()
        print(f"{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}WINDOWS COMPATIBILITY INFORMATION:")
        print(f"{Fore.CYAN}{'=' * 70}")
        print("Packet capture on Windows:")
        print()
        print("WITH Npcap/WinPcap (recommended):")
        print("   - Full packet capture functionality")
        print("   - Install from: https://nmap.org/npcap/")
        print("   - Select 'WinPcap API-compatible mode' during installation")
        print("   - Restart computer after installation")
        print()
        print("WITHOUT Npcap (limited functionality):")
        print("   - Only local traffic analysis")
        print("   - Basic HTTP/HTTPS/DNS detection")
        print("   - Demo mode available")
        print()
        print("MITM attacks on Windows:")
        print("   - Require Npcap for ARP spoofing")
        print("   - Limited without additional drivers")
        print(f"{Fore.CYAN}{'=' * 70}")

    # Предупреждение о лицензии
    print(f"\n{Fore.RED}[!] WARNING: Unauthorized use is prohibited!")
    print(f"{Fore.GREEN}[i] This tool is for educational purposes only!")
    print(f"{Fore.CYAN}[i] See DISCLAIMER.md for details")
    print()

    # Ожидание нажатия клавиши
    print(f"{Fore.YELLOW}{'=' * 70}")
    print(f"{Fore.YELLOW}Press ANY KEY to continue or 'Q' to quit...")
    print(f"{Fore.YELLOW}{'=' * 70}")

    key = get_keypress()
    if key == 'q':
        print(f"\n{Fore.BLUE}[*] Exiting...")
        sys.exit(0)


def main():
    """Главная функция приложения"""
    # Очищаем экран
    clear_screen()

    # Показываем информацию при запуске
    show_startup_info()

    try:
        # Запускаем TUI
        curses.wrapper(lambda stdscr: TUI(stdscr).run())

    except KeyboardInterrupt:
        print(f"\n{Fore.BLUE}[*] Program stopped by user")
    except Exception as e:
        print(f"{Fore.RED}[!] Critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Program finished")


if __name__ == "__main__":
    main()
