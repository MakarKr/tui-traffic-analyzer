#!/usr/bin/env python3

import curses
import time
import threading
from datetime import datetime
from rich.console import Console
from rich.text import Text
from utils import get_interfaces, get_interface_info, format_bytes, format_time
from session_manager import SessionManager, PacketType
from packet_analyzer import PacketAnalyzer
from mitm_attacker import MITMAttacker
from network_scanner import NetworkScanner
from config import config

console = Console()


class TUI:
    """Основной класс текстового интерфейса"""

    def __init__(self, stdscr):
        self.stdscr = stdscr

        # Инициализация менеджеров
        self.sm = SessionManager()              # Менеджер сессий
        self.pa = PacketAnalyzer(self.sm)       # Анализатор пакетов
        self.ns = NetworkScanner()              # Сканер сети
        self.ma = None                          # MITM атакер (инициализируется позже)

        # Состояние интерфейса
        self.tab = "dashboard"                  # Текущая вкладка
        self.row = 0                           # Выбранная строка
        self.scroll = 0                        # Смещение прокрутки
        self.running = True                    # Флаг работы программы

        # Данные интерфейса
        self.intfs = []                        # Список сетевых интерфейсов
        self.intf = None                       # Выбранный интерфейс
        self.scan_results = []                 # Результаты сканирования

        # Настройки MITM
        self.target_ip = ""                    # Целевой IP для MITM
        self.gateway_ip = ""                   # IP шлюза
        self.msg = ""                          # Сообщение статуса
        self.msg_time = 0                      # Время сообщения
        self.input_mode = None                 # Режим ввода (target/gateway)
        self.input_buf = ""                    # Буфер ввода

        # Инициализация
        self._init_curses()
        self._update_interfaces()

    def _init_curses(self):
        """Инициализировать библиотеку curses"""

        curses.curs_set(0)          # Скрыть курсор
        self.stdscr.nodelay(1)      # Неблокирующий ввод
        self.stdscr.timeout(100)    # Таймаут для getch (мс)

        # Инициализация цветов
        curses.start_color()
        curses.use_default_colors()

        # Определение цветовых пар
        curses.init_pair(1, curses.COLOR_GREEN, -1)      # Успех
        curses.init_pair(2, curses.COLOR_RED, -1)        # Ошибка
        curses.init_pair(3, curses.COLOR_YELLOW, -1)     # Предупреждение
        curses.init_pair(4, curses.COLOR_CYAN, -1)       # Информация
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)    # Заголовок
        curses.init_pair(6, curses.COLOR_BLUE, -1)       # Выделение
        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Выбранный элемент
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_CYAN)  # Статус бар

    def _update_interfaces(self):
        """Обновить список доступных сетевых интерфейсов"""

        self.intfs = get_interfaces()

        if self.intfs:
            # Выбрать первый интерфейс по умолчанию
            self.intf = self.intfs[0]
            self.pa.intf = self.intf

            # Получить информацию о шлюзе
            info = get_interface_info(self.intf)
            self.gateway_ip = info.get("gateway", "192.168.1.1")

            console.print(f"[green]Selected interface: {self.intf}[/green]")
        else:
            # Нет доступных интерфейсов
            self.intfs = ["No network interfaces found"]
            self.intf = None
            console.print("[red]No network interfaces available[/red]")

    def run(self):
        """Главный цикл интерфейса"""

        while self.running:
            self._handle_input()
            self._draw_interface()
            time.sleep(0.1)  # Частота обновления

    def _handle_input(self):
        """Обработать ввод пользователя"""

        try:
            key = self.stdscr.getch()

            # Режим ввода MITM
            if self.input_mode:
                self._handle_mitm_input(key)
                return

            # Общие клавиши выхода
            if key == ord('q') or key == 27:  # 'q' или ESC
                self.running = False
                return

            # Переключение вкладок (1-6)
            if ord('1') <= key <= ord('6'):
                tabs = ["dashboard", "packets", "sessions", "mitm", "scanner", "settings"]
                self.tab = tabs[key - ord('1')]
                self.row = 0
                self.scroll = 0
                self.input_mode = None

            # Навигация
            elif key == curses.KEY_UP:
                self._move_up()
            elif key == curses.KEY_DOWN:
                self._move_down()
            elif key == curses.KEY_LEFT:
                self.scroll = max(0, self.scroll - 10)
            elif key == curses.KEY_RIGHT:
                self.scroll += 10

            # Действия
            elif key == ord('\n') or key == ord('\r'):  # Enter
                self._handle_enter()
            elif key == ord('s'):  # Start/stop sniffing
                self._toggle_sniffing()
            elif key == ord('r'):  # Refresh interfaces
                self._update_interfaces()
            elif key == ord('c'):  # Clear data
                self.sm.clear_all()
            elif key == ord('d'):  # Show details
                self._show_details()
            elif key == ord('t'):  # Set MITM target
                if self.tab == "mitm":
                    self.input_mode = 'target'
                    self.input_buf = self.target_ip
            elif key == ord('g'):  # Set MITM gateway
                if self.tab == "mitm":
                    self.input_mode = 'gateway'
                    self.input_buf = self.gateway_ip
            elif key == ord('m'):  # Set target from scanner
                if self.tab == "scanner" and self.row > 0:
                    idx = self.row - 1
                    if 0 <= idx < len(self.scan_results):
                        self.target_ip = self.scan_results[idx]['ip']
                        self.msg = f"Target set: {self.target_ip}"
                        self.msg_time = time.time()

        except Exception as e:
            # Игнорировать ошибки ввода
            pass

    def _handle_mitm_input(self, key):
        """Обработать ввод в режиме MITM"""

        if key == 27:  # ESC - отмена
            self.input_mode = None
            self.input_buf = ""

        elif key == ord('\n') or key == ord('\r'):  # Enter - подтверждение
            if self.input_mode == 'target':
                self.target_ip = self.input_buf
                self.msg = f"Target set: {self.target_ip}"
            elif self.input_mode == 'gateway':
                self.gateway_ip = self.input_buf
                self.msg = f"Gateway set: {self.gateway_ip}"

            self.msg_time = time.time()
            self.input_mode = None
            self.input_buf = ""

        elif key == curses.KEY_BACKSPACE or key == 127:  # Backspace
            if self.input_buf:
                self.input_buf = self.input_buf[:-1]

        elif 32 <= key <= 126:  # Печатаемые символы
            self.input_buf += chr(key)

    def _move_up(self):
        """Переместить выделение вверх"""

        if self.tab == "packets":
            packets = self.sm.get_packets()
            if packets:
                self.row = max(0, self.row - 1)
                if self.row < self.scroll:
                    self.scroll = max(0, self.row)

        elif self.tab == "sessions":
            sessions = self.sm.get_sessions()
            if sessions:
                self.row = max(0, self.row - 1)
                if self.row < self.scroll:
                    self.scroll = max(0, self.row)

        elif self.tab == "scanner":
            max_rows = len(self.scan_results)
            self.row = max(0, self.row - 1)

        elif self.tab == "settings":
            if self.intfs:
                self.row = max(0, self.row - 1)

        elif self.tab == "mitm":
            self.row = 0
        elif self.tab == "dashboard":
            self.row = 0

    def _move_down(self):
        """Переместить выделение вниз"""

        if self.tab == "packets":
            packets = self.sm.get_packets()
            if packets:
                max_rows = len(packets) - 1
                if self.row < max_rows:
                    self.row += 1
                    if self.row >= self.scroll + 15:
                        self.scroll = min(max_rows - 14, self.row - 14)

        elif self.tab == "sessions":
            sessions = self.sm.get_sessions()
            if sessions:
                max_rows = len(sessions) - 1
                if self.row < max_rows:
                    self.row += 1
                    if self.row >= self.scroll + 15:
                        self.scroll = min(max_rows - 14, self.row - 14)

        elif self.tab == "scanner":
            max_rows = len(self.scan_results)
            if self.row < max_rows:
                self.row += 1

        elif self.tab == "settings":
            if self.intfs:
                max_rows = len(self.intfs) - 1
                if self.row < max_rows:
                    self.row += 1

        elif self.tab == "mitm":
            self.row = 0
        elif self.tab == "dashboard":
            self.row = 0

    def _handle_enter(self):
        """Обработать нажатие Enter"""

        if self.tab == "mitm":
            self._toggle_mitm()

        elif self.tab == "scanner":
            if self.row == 0:
                self._start_scan()
            elif self.row > 0:
                idx = self.row - 1
                if 0 <= idx < len(self.scan_results):
                    self.target_ip = self.scan_results[idx]['ip']
                    self.msg = f"Target set: {self.target_ip}"
                    self.msg_time = time.time()

        elif self.tab == "settings":
            if 0 <= self.row < len(self.intfs):
                self.intf = self.intfs[self.row]
                self.pa.intf = self.intf

                info = get_interface_info(self.intf)
                self.gateway_ip = info.get("gateway", "192.168.1.1")

                # Перезапустить сниффинг если он активен
                if self.pa.sniffing:
                    self.pa.stop()
                    time.sleep(0.5)
                    self.pa.start(self.intf)

        elif self.tab == "packets":
            self._show_packet_details()

        elif self.tab == "sessions":
            self._show_session_details()

    def _toggle_sniffing(self):
        """Включить/выключить захват пакетов"""

        if self.pa.sniffing:
            self.pa.stop()
        else:
            if self.intf:
                self.pa.start(self.intf)

    def _toggle_mitm(self):
        """Включить/выключить MITM атаку"""

        if self.ma and self.ma.running:
            self.ma.stop_attack()
            self.ma = None
            self.msg = "MITM attack stopped"
            self.msg_time = time.time()

        else:
            if not self.intf:
                self.msg = "Error: No interface selected"
                self.msg_time = time.time()
                return

            if not self.target_ip:
                self.msg = "Error: Target IP not set"
                self.msg_time = time.time()
                return

            if not self.gateway_ip:
                self.msg = "Error: Gateway IP not set"
                self.msg_time = time.time()
                return

            # Создать и запустить MITM атаку
            self.ma = MITMAttacker(self.target_ip, self.gateway_ip, self.intf)

            attack_thread = threading.Thread(target=self.ma.start_attack, daemon=True)
            attack_thread.start()

            self.msg = f"MITM attack started: {self.target_ip} -> {self.gateway_ip}"
            self.msg_time = time.time()

    def _start_scan(self):
        """Начать сканирование сети"""

        if self.intf:
            network_range = self.ns.get_local_network_range(self.intf)
            if network_range:
                self.ns.scan_async(network_range, self.intf, self._scan_complete)

    def _scan_complete(self, results):
        """Обработчик завершения сканирования"""

        self.scan_results = results
        if results:
            self.msg = f"Scan complete: found {len(results)} hosts"
            self.msg_time = time.time()

    def _show_details(self):
        """Показать детали выбранного элемента"""

        if self.tab == "packets":
            self._show_packet_details()
        elif self.tab == "sessions":
            self._show_session_details()

    def _show_packet_details(self):
        """Показать детали выбранного пакета"""

        packets = self.sm.get_packets()
        if 0 <= self.row < len(packets):
            self._draw_packet_detail(packets[self.row])

    def _show_session_details(self):
        """Показать детали выбранной сессии"""

        sessions = self.sm.get_sessions()
        if 0 <= self.row < len(sessions):
            self._draw_session_detail(sessions[self.row])

    def _draw_interface(self):
        """Нарисовать весь интерфейс"""

        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()

        # Заголовок
        self._draw_header(width)

        # Вкладки
        self._draw_tabs(width)

        # Содержимое текущей вкладки
        content_height = height - 6
        if content_height > 0:
            if self.tab == "dashboard":
                self._draw_dashboard(3, 0, width, content_height)
            elif self.tab == "packets":
                self._draw_packets(3, 0, width, content_height)
            elif self.tab == "sessions":
                self._draw_sessions(3, 0, width, content_height)
            elif self.tab == "mitm":
                self._draw_mitm(3, 0, width, content_height)
            elif self.tab == "scanner":
                self._draw_scanner(3, 0, width, content_height)
            elif self.tab == "settings":
                self._draw_settings(3, 0, width, content_height)

        # Статусная строка
        self._draw_status_bar(height - 2, width)

        self.stdscr.refresh()

    def _draw_header(self, width):
        """Нарисовать заголовок программы"""

        title = " TUI Traffic Analyzer v1.0 "
        x = max(0, (width - len(title)) // 2)

        self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
        self.stdscr.addstr(0, x, title)
        self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)

    def _draw_tabs(self, width):
        """Нарисовать панель вкладок"""

        tabs = ["1.Dashboard", "2.Packets", "3.Sessions", "4.MITM", "5.Scanner", "6.Settings"]
        x = 2

        for i, tab in enumerate(tabs):
            if self.tab == ["dashboard", "packets", "sessions", "mitm", "scanner", "settings"][i]:
                self.stdscr.attron(curses.color_pair(7))
                self.stdscr.addstr(2, x, f" {tab} ")
                self.stdscr.attroff(curses.color_pair(7))
            else:
                self.stdscr.attron(curses.color_pair(6))
                self.stdscr.addstr(2, x, f" {tab} ")
                self.stdscr.attroff(curses.color_pair(6))

            x += len(tab) + 2

    def _draw_dashboard(self, y, x, width, height):
        """Нарисовать вкладку Dashboard"""

        stats = self.pa.get_stats()
        cnt = self.sm.get_statistics()

        lines = [
            f"Status: {'SNIFFING' if stats['sniffing'] else 'IDLE'}",
            f"Interface: {stats['interface'] or 'None'}",
            f"Packets captured: {cnt['total_packets']}",
            f"Bytes captured: {format_bytes(cnt['total_bytes'])}",
            f"Sessions: {cnt['total_sessions']}",
            f"HTTP Requests: {cnt['http_requests']}",
            f"HTTP Responses: {cnt['http_responses']}",
            f"HTTPS Sessions: {cnt['https_sessions']}",
            "",
            "Controls:",
            "  [S] Start/stop sniffing",
            "  [R] Refresh interfaces",
            "  [C] Clear data",
            "  [D] Show details",
            "  [Q] Quit"
        ]

        for i, line in enumerate(lines):
            if y + i < y + height:
                self.stdscr.addstr(y + i, x, line[:width])

    def _draw_packets(self, y, x, width, height):
        """Нарисовать вкладку Packets"""

        packets = self.sm.get_packets()

        if not packets:
            self.stdscr.addstr(y, x, "No packets captured - press S to start")
            return

        # Заголовок таблицы
        header = f"{'Time':10} {'Source':20} {'Dest':20} {'Proto':8} {'Size':8}"
        self.stdscr.attron(curses.A_BOLD)
        self.stdscr.addstr(y, x, header[:width])
        self.stdscr.attroff(curses.A_BOLD)

        # Определить диапазон отображаемых пакетов
        start = self.scroll
        end = min(start + height - 1, len(packets))

        for i in range(start, end):
            line_y = y + 1 + i - start
            pkt = packets[i]

            # Форматировать данные пакета
            timestamp = datetime.fromtimestamp(pkt.timestamp).strftime('%H:%M:%S')
            src = f"{pkt.src_ip}:{pkt.src_port}"[:20]
            dst = f"{pkt.dst_ip}:{pkt.dst_port}"[:20]
            line = f"{timestamp:10} {src:20} {dst:20} {pkt.protocol:8} {format_bytes(pkt.size):8}"[:width]

            # Выделить выбранную строку
            if i == self.row:
                self.stdscr.attron(curses.color_pair(7))
                self.stdscr.addstr(line_y, x, line)
                self.stdscr.attroff(curses.color_pair(7))
            else:
                self.stdscr.addstr(line_y, x, line)

    def _draw_sessions(self, y, x, width, height):
        """Нарисовать вкладку Sessions"""

        sessions = self.sm.get_sessions()

        if not sessions:
            self.stdscr.addstr(y, x, "No sessions available")
            return

        # Заголовок таблицы
        header = f"{'ID':12} {'Client':20} {'Server':20} {'Pkts':6} {'Bytes':10}"
        self.stdscr.attron(curses.A_BOLD)
        self.stdscr.addstr(y, x, header[:width])
        self.stdscr.attroff(curses.A_BOLD)

        # Определить диапазон отображаемых сессий
        start = self.scroll
        end = min(start + height - 1, len(sessions))

        for i in range(start, end):
            line_y = y + 1 + i - start
            sess = sessions[i]

            # Форматировать данные сессии
            sid = sess.session_id[:12]
            client = f"{sess.client_ip}:{sess.client_port}"[:20]
            server = f"{sess.server_ip}:{sess.server_port}"[:20]
            line = f"{sid:12} {client:20} {server:20} {len(sess.packets):6} {format_bytes(sess.total_bytes):10}"[:width]

            # Выделить выбранную строку
            if i == self.row:
                self.stdscr.attron(curses.color_pair(7))
                self.stdscr.addstr(line_y, x, line)
                self.stdscr.attroff(curses.color_pair(7))
            else:
                self.stdscr.addstr(line_y, x, line)

    def _draw_mitm(self, y, x, width, height):
        """Нарисовать вкладку MITM"""

        lines = []

        # Режим ввода
        if self.input_mode:
            prompt = "Enter target IP: " if self.input_mode == 'target' else "Enter gateway IP: "
            lines.append(prompt + self.input_buf + "_")
            lines.append("")
            lines.append("[Enter] Confirm  [ESC] Cancel")

        else:
            lines.append("MITM Attack (ARP Spoofing)")
            lines.append("=" * 40)
            lines.append("")

            # Статус атаки
            if self.ma and self.ma.running:
                lines.append("Status: RUNNING")
                lines.append(f"Target: {self.target_ip}")
                lines.append(f"Gateway: {self.gateway_ip}")
                lines.append(f"Interface: {self.intf}")
                lines.append("")
                lines.append("[Enter] Stop attack")
            else:
                lines.append("Status: STOPPED")

            lines.append("")
            lines.append("Configuration:")
            lines.append(f"  Interface: {self.intf or 'Not selected'}")
            lines.append(f"  Target IP: {self.target_ip or 'Not set'}")
            lines.append(f"  Gateway IP: {self.gateway_ip or 'Not set'}")
            lines.append("")
            lines.append("Controls:")
            lines.append("  [T] Set target IP")
            lines.append("  [G] Set gateway IP")
            lines.append("  [Enter] Start/stop attack")
            lines.append("  [M] in Scanner - Set target from scan")

        # Показать статусное сообщение если есть
        if self.msg and time.time() - self.msg_time < 5:
            lines.append("")
            lines.append(f"Status: {self.msg}")

        # Вывести все строки
        for i, line in enumerate(lines):
            if y + i < y + height:
                self.stdscr.addstr(y + i, x, line[:width])

    def _draw_scanner(self, y, x, width, height):
        """Нарисовать вкладку Scanner"""

        lines = [
            "Network Scanner",
            "=" * 40,
            ""
        ]

        # Статус сканирования
        if self.ns.scanning:
            lines.append("Status: SCANNING...")
        else:
            lines.append("Status: IDLE")
            lines.append(f"Interface: {self.intf}")

        lines.append("")
        lines.append("[Enter] Start scanning")
        lines.append("[M] Set as MITM target")
        lines.append("")
        lines.append("Scan Results:")
        lines.append("-" * 40)

        # Результаты сканирования
        if self.scan_results:
            max_show = min(10, len(self.scan_results))
            for i in range(max_show):
                host = self.scan_results[i]
                marker = " <--" if host['ip'] == self.target_ip else ""
                line = f"{host['ip']:15} {host['mac']:17} {host['vendor'][:15]}{marker}"

                # Выделить выбранную строку
                if i == self.row - 1:
                    lines.append(f"> {line}")
                else:
                    lines.append(f"  {line}")
        else:
            lines.append("No scan results")

        # Управление
        lines.append("")
        lines.append("Controls:")
        lines.append("  [Enter] on host - Set as MITM target")
        lines.append("  [M] - Set selected host as MITM target")
        lines.append("  [↑↓] - Navigate hosts")

        # Вывести все строки
        for i, line in enumerate(lines):
            if y + i < y + height:
                self.stdscr.addstr(y + i, x, line[:width])

    def _draw_settings(self, y, x, width, height):
        """Нарисовать вкладку Settings"""

        lines = [
            "Settings",
            "=" * 40,
            "",
            "Network Interfaces:"
        ]

        # Список интерфейсов
        for i, intf in enumerate(self.intfs):
            if i == self.row:
                lines.append(f"> {intf}")
            else:
                lines.append(f"  {intf}")

        # Настройки MITM
        lines.append("")
        lines.append("MITM Configuration:")
        lines.append(f"  Target IP: {self.target_ip or 'Not set'}")
        lines.append(f"  Gateway IP: {self.gateway_ip or 'Not set'}")

        # Управление
        lines.append("")
        lines.append("Controls:")
        lines.append("  [R] Refresh interfaces")
        lines.append("  [↑↓] Select interface")
        lines.append("  [Enter] Apply selection")

        # Вывести все строки
        for i, line in enumerate(lines):
            if y + i < y + height:
                self.stdscr.addstr(y + i, x, line[:width])

    def _draw_packet_detail(self, pkt):
        """Нарисовать детальную информацию о пакете"""

        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()

        lines = [
            "Packet Details",
            "=" * min(width, 60),
            "",
            f"Time: {datetime.fromtimestamp(pkt.timestamp).strftime('%H:%M:%S')}",
            f"Source: {pkt.src_ip}:{pkt.src_port}",
            f"Destination: {pkt.dst_ip}:{pkt.dst_port}",
            f"Protocol: {pkt.protocol}",
            f"Type: {pkt.packet_type.value}",
            f"Size: {format_bytes(pkt.size)}",
            f"Session ID: {pkt.session_id or 'N/A'}",
            "",
            "Packet Data:",
            "-" * min(width, 40)
        ]

        # Добавить данные пакета
        if pkt.data:
            for key, value in pkt.data.items():
                if value:
                    lines.append(f"{key}: {value}")

        lines.append("")
        lines.append("[Enter/ESC] Back to list")

        # Вывести все строки
        for i, line in enumerate(lines):
            if i < height:
                self.stdscr.addstr(i, 0, line[:width])

        self.stdscr.refresh()

        # Ожидать нажатия клавиши
        while True:
            key = self.stdscr.getch()
            if key in [ord('\n'), ord('\r'), ord(' '), 27]:
                break

    def _draw_session_detail(self, sess):
        """Нарисовать детальную информацию о сессии"""

        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()

        lines = [
            "Session Details",
            "=" * min(width, 60),
            "",
            f"Session ID: {sess.session_id}",
            f"Protocol: {sess.protocol}",
            f"Start Time: {datetime.fromtimestamp(sess.start_time).strftime('%H:%M:%S')}",
            f"Client: {sess.client_ip}:{sess.client_port}",
            f"Server: {sess.server_ip}:{sess.server_port}",
            f"Duration: {format_time(sess.get_duration())}",
            f"Total Packets: {len(sess.packets)}",
            f"Total Bytes: {format_bytes(sess.total_bytes)}",
            "",
            "Recent Packets:",
            "-" * min(width, 40)
        ]

        # Добавить информацию о пакетах
        for i, pkt in enumerate(sess.packets[:5]):
            timestamp = datetime.fromtimestamp(pkt.timestamp).strftime('%H:%M:%S')
            lines.append(f"{i+1}. {timestamp} {pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}")

        if len(sess.packets) > 5:
            lines.append(f"... and {len(sess.packets) - 5} more packets")

        lines.append("")
        lines.append("[Enter/ESC] Back to sessions")

        # Вывести все строки
        for i, line in enumerate(lines):
            if i < height:
                self.stdscr.addstr(i, 0, line[:width])

        self.stdscr.refresh()

        # Ожидать нажатия клавиши
        while True:
            key = self.stdscr.getch()
            if key in [ord('\n'), ord('\r'), ord(' '), 27]:
                break

    def _draw_status_bar(self, y, width):
        """Нарисовать строку статуса"""

        # Собрать информацию о статусе
        status_parts = []
        status_parts.append(f"Tab: {self.tab}")

        if self.pa.sniffing:
            status_parts.append("SNIFFING")

        if self.ma and self.ma.running:
            status_parts.append("MITM: ACTIVE")

        # Позиция в списке
        if self.tab == "packets":
            packets = self.sm.get_packets()
            if packets:
                status_parts.append(f"Packet {self.row+1}/{len(packets)}")
        elif self.tab == "sessions":
            sessions = self.sm.get_sessions()
            if sessions:
                status_parts.append(f"Session {self.row+1}/{len(sessions)}")

        # Объединить статус
        status = " | ".join(status_parts)

        # Добавить управление
        controls = "[Q]uit [1-6]Tabs [S]niff [R]efresh [↑↓]Nav [Enter]Select"
        full_status = f" {status} | {controls} "

        # Обрезать если слишком длинный
        if len(full_status) > width:
            full_status = full_status[:width-3] + "..."

        # Нарисовать строку статуса
        self.stdscr.attron(curses.color_pair(8) | curses.A_BOLD)
        self.stdscr.addstr(y, 0, full_status.ljust(width))
        self.stdscr.attroff(curses.color_pair(8) | curses.A_BOLD)
