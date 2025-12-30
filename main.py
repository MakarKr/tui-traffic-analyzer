#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import curses
import sys
import os
import time
from tui import TUI
from utils import check_root, clear_screen
from colorama import init, Fore
import platform

# Добавляем путь к директории скрипта для корректной работы PyInstaller
if getattr(sys, 'frozen', False):
    # Если запущено как исполняемый файл
    application_path = os.path.dirname(sys.executable)
else:
    # Если запущено как скрипт
    application_path = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, application_path)

init(autoreset=True)


def enable_https_decryption():
    """Предупреждение о невозможности полной расшифровки HTTPS"""
    print("\n" + "=" * 60)
    print("HTTPS Traffic Analysis Limitations:")
    print("=" * 60)
    print("1. FULL decryption of HTTPS/TLS is NOT POSSIBLE without:")
    print("   - Server's private key")
    print("   - Client's browser configuration")
    print("   - Pre-shared keys")
    print("\n2. What CAN be analyzed:")
    print("   - Server names (SNI)")
    print("   - Certificate information")
    print("   - Connection metadata")
    print("   - Data volumes and timing")
    print("\n3. For educational purposes only!")
    print("=" * 60)


def windows_compatibility_info():
    """Информация о совместимости с Windows"""
    if platform.system() == "Windows":
        print("\n" + "=" * 60)
        print("WINDOWS COMPATIBILITY INFORMATION:")
        print("=" * 60)
        print("Packet capture on Windows:")
        print("\n1. WITH Npcap/WinPcap (recommended):")
        print("   - Full packet capture functionality")
        print("   - Install from: https://nmap.org/npcap/")
        print("   - Select 'WinPcap API-compatible mode' during installation")
        print("   - Restart computer after installation")

        print("\n2. WITHOUT Npcap (limited functionality):")
        print("   - Only local traffic analysis")
        print("   - Basic HTTP/HTTPS/DNS detection")
        print("   - Demo mode available")

        print("\n3. MITM attacks on Windows:")
        print("   - Require Npcap for ARP spoofing")
        print("   - Limited without additional drivers")

        print("\nThe program will automatically detect Npcap.")
        print("=" * 60)


def license_warning():
    print(f"{Fore.CYAN}License: GNU GPLv3 (see LICENSE file)")
    print(f"{Fore.YELLOW}WARNING: Unauthorized use is prohibited!")


def main():
    """Главная функция приложения"""

    # Проверяем наличие root-прав
    if not check_root():
        print(f"{Fore.YELLOW}[!] Внимание: для полного функционала требуются права администратора!")
        print(f"{Fore.YELLOW}[!] Запустите с sudo/администратором для сниффинга трафика и MITM атак.")
        print(f"{Fore.CYAN}[i] Нажмите Enter для продолжения или Ctrl+C для выхода...")
        input()

    # Показываем предупреждение о HTTPS
    enable_https_decryption()

    # Показываем информацию о совместимости с Windows
    windows_compatibility_info()

    # Показываем предупреждение о лицензии
    license_warning()

    # Ожидаем...
    time.sleep(3)

    try:
        # Запускаем TUI
        curses.wrapper(lambda stdscr: TUI(stdscr).run())

    except KeyboardInterrupt:
        print(f"\n{Fore.BLUE}[!] Программа остановлена пользователем")
    except Exception as e:
        print(f"{Fore.RED}[!] Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Программа завершена")


if __name__ == "__main__":
    # Очищаем экран
    clear_screen()

    # Выводим информацию о программе
    print(f"{Fore.CYAN}{'=' * 60}")
    print(f"{Fore.CYAN} TUI Traffic Analyzer v1.0.0")
    print(f"{Fore.CYAN} Разработчик: Makar Krapivin")
    print(f"{Fore.CYAN} Лицензия: GNU GPLv3")
    print(f"{Fore.CYAN}{'=' * 60}")
    print()

    # Запускаем приложение
    main()
