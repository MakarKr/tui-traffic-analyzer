#!/usr/bin/env python3

import sys
import os
import time
import curses
from tui import TUI
from utils import clear_screen, check_root, wait_for_key
from colorama import init, Fore
from prompt_toolkit import prompt
from prompt_toolkit.key_binding import KeyBindings
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

init()
console = Console()


def get_user_input():
    """Получить ввод от пользователя с возможностью выхода"""

    kb = KeyBindings()

    @kb.add('q')
    @kb.add('Q')
    def _(event):
        event.app.exit(result='q')

    try:
        # Попробовать использовать prompt_toolkit для улучшенного ввода
        result = prompt('', key_bindings=kb)
        return result
    except:
        # Fallback на стандартный ввод
        print(f"\n{Fore.YELLOW}Press any key to start (Q to quit)")

        if os.name == 'nt':
            import msvcrt
            key = msvcrt.getch().decode('ascii', 'ignore').lower()
        else:
            import termios
            import tty

            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)

            try:
                tty.setraw(fd)
                key = sys.stdin.read(1).lower()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        return key


def show_welcome_message():
    """Показать приветственное сообщение при запуске"""

    clear_screen()

    # Использовать уже созданный объект console
    console.print(Panel.fit(
        Text("TUI Traffic Analyzer", style="bold cyan"),
        border_style="cyan"
    ))

    # Проверка прав
    if not check_root():
        console.print("[yellow][!] Administrator/root privileges required for full functionality[/yellow]")
        console.print("[yellow][!] Run with sudo/administrator for packet capture and MITM attacks[/yellow]")

    # Информация о программе
    console.print("\n[white]Features:")
    console.print("  • Real-time packet capture (HTTP/HTTPS/DNS)")
    console.print("  • Network scanning and device discovery")
    console.print("  • MITM attacks (ARP spoofing)")
    console.print("  • Session analysis and traffic visualization")

    # Важные предупреждения
    console.print("\n[red][!] IMPORTANT SECURITY NOTICE:[/red]")
    console.print("[red]  • This tool is for educational purposes only[/red]")
    console.print("[red]  • Use only on networks you own or have permission to test[/red]")
    console.print("[red]  • Unauthorized access to computer networks is illegal[/red]")

    # Информация о HTTPS
    console.print("\n[white]HTTPS Analysis Limitations:")
    console.print("  • Full HTTPS decryption is NOT possible without private keys")
    console.print("  • Only metadata analysis (SNI, certificates, timing)")

    # Информация для Windows
    if os.name == 'nt':
        console.print("\n[white]Windows Compatibility:")
        console.print("  • Full functionality requires Npcap/WinPcap")
        console.print("  • Download from: https://nmap.org/npcap/")
        console.print("  • Limited mode available without drivers")


def main():
    """Главная функция приложения"""

    show_welcome_message()

    # Ожидание подтверждения пользователя
    console.print("\n[yellow]Press any key to continue (Q to quit)...[/yellow]")

    key = get_user_input()

    if key == 'q':
        console.print("[blue]Exiting...[/blue]")
        sys.exit(0)

    # Запуск основного интерфейса
    try:
        curses.wrapper(lambda stdscr: TUI(stdscr).run())
    except KeyboardInterrupt:
        console.print("\n[blue]Program stopped by user[/blue]")
    except Exception as e:
        console.print(f"[red]Critical error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    console.print("[green]Program finished successfully[/green]")


if __name__ == "__main__":
    main()
