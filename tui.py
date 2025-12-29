#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import curses
import time
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
from utils import get_network_interfaces, get_interface_info, clear_screen, format_bytes, format_time_delta
from session_manager import SessionManager, PacketType
from packet_analyzer import PacketAnalyzer
from mitm_attacker import MITMAttacker
from network_scanner import NetworkScanner
from config import config


class TUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.session_manager = SessionManager()
        self.packet_analyzer = PacketAnalyzer(self.session_manager)
        self.mitm_attacker: Optional[MITMAttacker] = None
        self.network_scanner = NetworkScanner()

        # Состояние UI
        self.current_tab = "dashboard"  # dashboard, packets, sessions, mitm, scanner, settings
        self.selected_row = 0
        self.scroll_offset = 0
        self.running = True
        self.last_update = 0
        self.update_interval = 0.1

        # Данные для отображения
        self.interfaces = []
        self.selected_interface = None
        self.scan_results = []

        # Инициализация curses
        self.init_curses()

    def init_curses(self):
        """Инициализировать curses"""
        curses.curs_set(0)  # Скрыть курсор
        self.stdscr.nodelay(1)  # Неблокирующий ввод
        self.stdscr.timeout(100)  # Таймаут для getch в мс

        # Инициализировать цвета
        curses.start_color()
        curses.use_default_colors()

        # Определить цветовые пары
        curses.init_pair(1, curses.COLOR_GREEN, -1)  # Успех
        curses.init_pair(2, curses.COLOR_RED, -1)  # Ошибка
        curses.init_pair(3, curses.COLOR_YELLOW, -1)  # Предупреждение
        curses.init_pair(4, curses.COLOR_CYAN, -1)  # Информация
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)  # Заголовок
        curses.init_pair(6, curses.COLOR_BLUE, -1)  # Выделение
        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Выбранный элемент
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_CYAN)  # Статус бар

    def sanitize_string(self, text):
        """Очистить строку от нулевых и непечатаемых символов"""
        if text is None:
            return ""

        # Преобразуем в строку, если это не строка
        if not isinstance(text, str):
            try:
                text = str(text)
            except:
                return "[Binary Data]"

        # Удаляем нулевые символы и другие проблемные символы
        text = text.replace('\x00', '')  # Удаляем нулевые символы
        text = text.replace('\r', '')  # Удаляем возврат каретки
        text = text.replace('\n', ' ')  # Заменяем переносы строк пробелами
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\t')

        return text

    def safe_addstr(self, y, x, text, attr=0):
        """Безопасный вывод строки в curses"""
        try:
            if text is None:
                text = ""

            # Очищаем строку
            text = self.sanitize_string(text)

            # Получаем максимальную ширину экрана
            height, width = self.stdscr.getmaxyx()
            max_width = width - x

            # Обрезаем строку, если она слишком длинная
            if len(text) > max_width:
                text = text[:max_width - 3] + "..."

            # Проверяем, что координаты в пределах экрана
            if y >= height or x >= width:
                return False

            self.stdscr.attron(attr)
            self.stdscr.addstr(y, x, text)
            self.stdscr.attroff(attr)
            return True

        except Exception as e:
            # В случае ошибки, ничего не делаем
            return False

    def run(self):
        """Запустить главный цикл TUI"""
        # Получить список интерфейсов
        self.interfaces = get_network_interfaces()
        if self.interfaces:
            self.selected_interface = self.interfaces[0]

        # Главный цикл
        while self.running:
            self.handle_input()
            self.draw()
            time.sleep(self.update_interval)

    def handle_input(self):
        """Обработать ввод пользователя"""
        try:
            key = self.stdscr.getch()

            if key == ord('q'):
                self.running = False
                return

            # Навигация по табам
            elif key == ord('1'):
                self.current_tab = "dashboard"
                self.selected_row = 0
                self.scroll_offset = 0
            elif key == ord('2'):
                self.current_tab = "packets"
                self.selected_row = 0
                self.scroll_offset = 0
            elif key == ord('3'):
                self.current_tab = "sessions"
                self.selected_row = 0
                self.scroll_offset = 0
            elif key == ord('4'):
                self.current_tab = "mitm"
                self.selected_row = 0
                self.scroll_offset = 0
            elif key == ord('5'):
                self.current_tab = "scanner"
                self.selected_row = 0
                self.scroll_offset = 0
            elif key == ord('6'):
                self.current_tab = "settings"
                self.selected_row = 0
                self.scroll_offset = 0

            # Навигация в текущем табе (работает везде)
            elif key == curses.KEY_UP:
                self.handle_up()
            elif key == curses.KEY_DOWN:
                self.handle_down()
            elif key == curses.KEY_LEFT:
                self.handle_left()
            elif key == curses.KEY_RIGHT:
                self.handle_right()

            # Действия в зависимости от таба
            elif key == ord('\n') or key == ord(' ') or key == ord('\r'):
                self.handle_enter()

            # Старт/стоп сниффинга
            elif key == ord('s'):
                self.toggle_sniffing()

            # Очистка данных
            elif key == ord('c'):
                self.session_manager.clear_all()

            # Экспорт данных
            elif key == ord('e'):
                filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                self.session_manager.export_to_json(filename)

        except Exception as e:
            pass

    def handle_up(self):
        """Обработка клавиши Вверх"""
        if self.current_tab == "packets":
            packets = self.session_manager.get_packets(limit=1000)
            if packets:
                self.selected_row = max(0, self.selected_row - 1)

        elif self.current_tab == "sessions":
            sessions = self.session_manager.get_sessions(limit=1000)
            if sessions:
                self.selected_row = max(0, self.selected_row - 1)

        elif self.current_tab == "scanner":
            # В сканере есть выбор хоста
            max_rows = len(self.scan_results) + 2  # Результаты + 2 строки управления
            self.selected_row = max(0, self.selected_row - 1)

        elif self.current_tab == "settings":
            # В настройках выбираем интерфейс
            if self.interfaces:
                self.selected_row = max(0, self.selected_row - 1)

        elif self.current_tab == "mitm":
            # Вкладка MITM имеет только одну строку для выбора
            self.selected_row = 0
        elif self.current_tab == "dashboard":
            # В дашборде нет списка для выбора
            self.selected_row = 0

    def handle_down(self):
        """Обработка клавиши Вниз"""
        if self.current_tab == "packets":
            packets = self.session_manager.get_packets(limit=1000)
            if packets:
                max_rows = len(packets) - 1
                if self.selected_row < max_rows:
                    self.selected_row += 1

        elif self.current_tab == "sessions":
            sessions = self.session_manager.get_sessions(limit=1000)
            if sessions:
                max_rows = len(sessions) - 1
                if self.selected_row < max_rows:
                    self.selected_row += 1

        elif self.current_tab == "scanner":
            # В сканере: 0=Start scan, 1=Stop scan, далее результаты
            max_rows = len(self.scan_results) + 1  # Результаты + 1 строка управления
            if self.selected_row < max_rows:
                self.selected_row += 1

        elif self.current_tab == "settings":
            # В настройках выбираем интерфейс
            if self.interfaces:
                max_rows = len(self.interfaces) - 1
                if self.selected_row < max_rows:
                    self.selected_row += 1

        elif self.current_tab == "mitm":
            # Вкладка MITM имеет только одну строку для выбора
            self.selected_row = 0
        elif self.current_tab == "dashboard":
            # В дашборде нет списка для выбора
            self.selected_row = 0

    def handle_left(self):
        """Обработка клавиши Влево"""
        if self.current_tab == "packets":
            self.scroll_offset = max(0, self.scroll_offset - 10)
        elif self.current_tab == "sessions":
            self.scroll_offset = max(0, self.scroll_offset - 10)

    def handle_right(self):
        """Обработка клавиши Вправо"""
        if self.current_tab == "packets":
            self.scroll_offset += 10
        elif self.current_tab == "sessions":
            self.scroll_offset += 10

    def handle_enter(self):
        """Обработать нажатие Enter"""
        if self.current_tab == "mitm":
            if self.selected_row == 0:
                self.toggle_mitm()

        elif self.current_tab == "scanner":
            if self.selected_row == 0:
                self.start_scan()
            elif self.selected_row == 1:
                self.stop_scan()
            elif self.selected_row >= 2:
                # Выбор хоста из результатов сканирования
                host_index = self.selected_row - 2
                if 0 <= host_index < len(self.scan_results):
                    selected_host = self.scan_results[host_index]
                    print(f"Selected host: {selected_host['ip']} ({selected_host['mac']})")
                    # Здесь можно добавить логику для использования выбранного хоста

        elif self.current_tab == "settings":
            # Выбор интерфейса
            if 0 <= self.selected_row < len(self.interfaces):
                self.selected_interface = self.interfaces[self.selected_row]
                print(f"Selected interface: {self.selected_interface}")
                # Перезапускаем сниффинг если он активен
                if self.packet_analyzer.sniffing:
                    self.packet_analyzer.stop_sniffing()
                    time.sleep(0.5)
                    self.packet_analyzer.start_sniffing(self.selected_interface)

    def toggle_sniffing(self):
        """Включить/выключить сниффинг"""
        if self.packet_analyzer.sniffing:
            self.packet_analyzer.stop_sniffing()
        else:
            if self.selected_interface:
                self.packet_analyzer.start_sniffing(self.selected_interface)

    def toggle_mitm(self):
        """Включить/выключить MITM атаку"""
        if self.mitm_attacker and self.mitm_attacker.running:
            self.mitm_attacker.stop_attack()
            self.mitm_attacker = None
        else:
            # TODO: Запросить target_ip и gateway_ip у пользователя
            # Временные значения для демонстрации
            if self.selected_interface:
                info = get_interface_info(self.selected_interface)
                target_ip = info.get("gateway", "192.168.1.1")
                gateway_ip = info.get("gateway", "192.168.1.254")
                self.mitm_attacker = MITMAttacker(target_ip, gateway_ip, self.selected_interface)
                attack_thread = threading.Thread(target=self.mitm_attacker.start_attack, daemon=True)
                attack_thread.start()

    def start_scan(self):
        """Начать сканирование сети"""
        if self.selected_interface:
            network_range = self.network_scanner.get_local_network_range(self.selected_interface)
            if network_range:
                self.network_scanner.scan_async(network_range, self.selected_interface, self.on_scan_complete)

    def stop_scan(self):
        """Остановить сканирование"""
        self.network_scanner.stop_scan()

    def on_scan_complete(self, results):
        """Обработчик завершения сканирования"""
        self.scan_results = results

    def draw(self):
        """Нарисовать интерфейс"""
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()

        # Рисуем заголовок
        self.draw_header(width)

        # Рисуем табы
        self.draw_tabs(width)

        # Рисуем содержимое текущего таба
        content_height = height - 6
        if content_height > 0:
            if self.current_tab == "dashboard":
                self.draw_dashboard(3, 0, width, content_height)
            elif self.current_tab == "packets":
                self.draw_packets(3, 0, width, content_height)
            elif self.current_tab == "sessions":
                self.draw_sessions(3, 0, width, content_height)
            elif self.current_tab == "mitm":
                self.draw_mitm(3, 0, width, content_height)
            elif self.current_tab == "scanner":
                self.draw_scanner(3, 0, width, content_height)
            elif self.current_tab == "settings":
                self.draw_settings(3, 0, width, content_height)

        # Рисуем статусную строку
        self.draw_status_bar(height - 2, width)

        self.stdscr.refresh()

    def draw_header(self, width):
        """Нарисовать заголовок"""
        title = "TUI Traffic Analyzer"
        version = "v1.0.0"
        header = f" {title} - {version} "

        # Центрируем заголовок
        x = max(0, (width - len(header)) // 2)

        self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
        self.safe_addstr(0, x, header)
        self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)

        # Рисуем разделитель
        self.safe_addstr(1, 0, "=" * min(width, 100))

    def draw_tabs(self, width):
        """Нарисовать табы"""
        tabs = [
            ("1. Dashboard", "dashboard"),
            ("2. Packets", "packets"),
            ("3. Sessions", "sessions"),
            ("4. MITM", "mitm"),
            ("5. Scanner", "scanner"),
            ("6. Settings", "settings")
        ]

        x = 2
        for tab_text, tab_id in tabs:
            if self.current_tab == tab_id:
                self.stdscr.attron(curses.color_pair(7))
                self.safe_addstr(2, x, f" {tab_text} ")
                self.stdscr.attroff(curses.color_pair(7))
            else:
                self.stdscr.attron(curses.color_pair(6))
                self.safe_addstr(2, x, f" {tab_text} ")
                self.stdscr.attroff(curses.color_pair(6))

            x += len(tab_text) + 3

        # Рисуем разделитель под табами
        self.safe_addstr(3, 0, "-" * min(width, 100))

    def draw_dashboard(self, y, x, width, height):
        """Нарисовать дашборд"""
        stats = self.session_manager.get_statistics()
        analyzer_stats = self.packet_analyzer.get_statistics()

        # Общая информация
        info_lines = [
            f"Status: {'SNIFFING' if analyzer_stats['sniffing'] else 'IDLE'}",
            f"Interface: {analyzer_stats['interface'] or 'None'}",
            f"Packets captured: {stats['total_packets']}",
            f"Bytes captured: {format_bytes(stats['total_bytes'])}",
            f"Sessions: {stats['total_sessions']}",
            f"HTTP Requests: {stats['http_requests']}",
            f"HTTP Responses: {stats['http_responses']}",
            f"HTTPS Sessions: {stats['https_sessions']}",
            "",
            "Protocol Distribution:"
        ]

        # Добавляем распределение по протоколам
        for protocol, count in stats.get('protocols', {}).items():
            info_lines.append(f"  {self.sanitize_string(protocol)}: {count}")

        # Отображаем информацию
        for i, line in enumerate(info_lines):
            if y + i < height + 3:
                self.safe_addstr(y + i, x, line)

        # Клавиши управления
        controls_y = y + len(info_lines) + 2
        controls = [
            "[S] Start/Stop sniffing",
            "[C] Clear data",
            "[E] Export to JSON",
            "[Q] Quit"
        ]

        for i, control in enumerate(controls):
            if controls_y + i < height + 3:
                self.stdscr.attron(curses.color_pair(4))
                self.safe_addstr(controls_y + i, x, control)
                self.stdscr.attroff(curses.color_pair(4))

    def draw_packets(self, y, x, width, height):
        """Нарисовать список пакетов"""
        packets = self.session_manager.get_packets(limit=height)

        if not packets:
            self.safe_addstr(y, x, "No packets captured yet")
            return

        # Заголовок таблицы
        header = f"{'Time':<12} {'Source':<20} {'Destination':<20} {'Protocol':<10} {'Size':<8} {'Info':<30}"
        self.stdscr.attron(curses.A_BOLD)
        self.safe_addstr(y, x, header[:width])
        self.stdscr.attroff(curses.A_BOLD)

        # Пакеты
        for i, packet in enumerate(packets):
            line_y = y + 1 + i

            if line_y >= height + 3:
                break

            # Форматируем время
            timestamp = datetime.fromtimestamp(packet.timestamp).strftime('%H:%M:%S')

            # Форматируем информацию в зависимости от типа пакета
            info = ""
            if packet.packet_type == PacketType.HTTP_REQUEST:
                method = self.sanitize_string(packet.data.get('method', ''))
                host = self.sanitize_string(packet.data.get('host', ''))
                info = f"HTTP {method} {host}"
            elif packet.packet_type == PacketType.HTTP_RESPONSE:
                status = self.sanitize_string(packet.data.get('status_code', ''))
                info = f"HTTP {status}"
            elif packet.packet_type == PacketType.HTTPS_SESSION:
                sni = self.sanitize_string(packet.data.get('sni', 'TLS'))
                info = f"HTTPS {sni}"
            elif packet.packet_type == PacketType.DNS_QUERY:
                queries = packet.data.get('queries', [])
                if queries:
                    qname = self.sanitize_string(queries[0].get('qname', ''))
                    info = f"DNS Query: {qname}"
            elif packet.packet_type == PacketType.DNS_RESPONSE:
                answers = packet.data.get('answers', [])
                if answers:
                    rdata = self.sanitize_string(answers[0].get('rdata', ''))
                    info = f"DNS Answer: {rdata}"

            # Очищаем все строковые поля
            src_ip = self.sanitize_string(packet.src_ip)
            dst_ip = self.sanitize_string(packet.dst_ip)
            protocol = self.sanitize_string(packet.protocol)

            # Создаем строку с очищенными данными
            line = f"{timestamp:<12} {src_ip}:{packet.src_port:<20} {dst_ip}:{packet.dst_port:<20} {protocol:<10} {packet.size:<8} {info:<30}"

            # Дополнительная очистка всей строки
            line = self.sanitize_string(line)

            # Обрезаем строку до максимальной ширины
            if len(line) > width:
                line = line[:width - 3] + "..."

            # Выбираем цвет в зависимости от типа пакета
            color = curses.color_pair(0)
            if packet.packet_type == PacketType.HTTP_REQUEST:
                color = curses.color_pair(1)  # Зеленый
            elif packet.packet_type == PacketType.HTTP_RESPONSE:
                color = curses.color_pair(4)  # Голубой
            elif packet.packet_type == PacketType.HTTPS_SESSION:
                color = curses.color_pair(5)  # Пурпурный
            elif packet.packet_type in [PacketType.DNS_QUERY, PacketType.DNS_RESPONSE]:
                color = curses.color_pair(6)  # Синий

            # Выделяем выбранную строку
            if i == self.selected_row and self.current_tab == "packets":
                self.stdscr.attron(curses.color_pair(7) | curses.A_BOLD)

            try:
                self.stdscr.attron(color)
                self.safe_addstr(line_y, x, line)
                self.stdscr.attroff(color)
            except Exception as e:
                # В случае ошибки вывода, показываем сообщение об ошибке
                error_msg = f"Error displaying packet {i}"
                if len(error_msg) > width:
                    error_msg = error_msg[:width]
                self.safe_addstr(line_y, x, error_msg)

            if i == self.selected_row and self.current_tab == "packets":
                self.stdscr.attroff(curses.color_pair(7) | curses.A_BOLD)

    def draw_sessions(self, y, x, width, height):
        """Нарисовать список сессий"""
        sessions = self.session_manager.get_sessions(limit=height)

        if not sessions:
            self.safe_addstr(y, x, "No sessions yet")
            return

        # Заголовок таблицы
        header = f"{'ID':<30} {'Client':<20} {'Server':<20} {'Duration':<10} {'Packets':<8} {'Bytes':<10}"
        self.stdscr.attron(curses.A_BOLD)
        self.safe_addstr(y, x, header[:width])
        self.stdscr.attroff(curses.A_BOLD)

        # Сессии
        for i, session in enumerate(sessions):
            line_y = y + 1 + i

            if line_y >= height + 3:
                break

            # Укорачиваем ID
            session_id_short = session.session_id[:28] + "..." if len(session.session_id) > 30 else session.session_id

            # Форматируем данные
            duration = format_time_delta(session.get_duration())
            packets = len(session.packets)
            bytes_formatted = format_bytes(session.total_bytes)

            # Очищаем строковые поля
            session_id_display = self.sanitize_string(session_id_short)
            client_ip = self.sanitize_string(session.client_ip)
            server_ip = self.sanitize_string(session.server_ip)

            line = f"{session_id_display:<30} {client_ip}:{session.client_port:<20} {server_ip}:{session.server_port:<20} {duration:<10} {packets:<8} {bytes_formatted:<10}"

            # Очистка строки
            line = self.sanitize_string(line)

            # Обрезаем до ширины
            if len(line) > width:
                line = line[:width - 3] + "..."

            # Выделяем выбранную строку
            if i == self.selected_row and self.current_tab == "sessions":
                self.stdscr.attron(curses.color_pair(7))

            self.safe_addstr(line_y, x, line)

            if i == self.selected_row and self.current_tab == "sessions":
                self.stdscr.attroff(curses.color_pair(7))

    def draw_mitm(self, y, x, width, height):
        """Нарисовать MITM панель"""
        lines = []

        lines.append("MITM Attack (ARP Spoofing)")
        lines.append("=" * 40)
        lines.append("")

        if self.mitm_attacker and self.mitm_attacker.running:
            lines.append("Status: RUNNING")
            lines.append(f"Target: {self.mitm_attacker.target_ip}")
            lines.append(f"Gateway: {self.mitm_attacker.gateway_ip}")
            lines.append(f"Interface: {self.mitm_attacker.interface}")
            lines.append("")
            lines.append("[Enter] Stop MITM attack")
        else:
            lines.append("Status: STOPPED")
            lines.append("")
            lines.append("To start MITM attack:")
            lines.append("1. Select target IP address")
            lines.append("2. Select gateway IP address")
            lines.append("3. Press Enter to start")
            lines.append("")
            lines.append("[Enter] Start MITM attack")

        lines.append("")
        lines.append("Note: Requires root privileges")
        lines.append("      Enable IP forwarding first")

        # Отображаем строки
        for i, line in enumerate(lines):
            if y + i < height + 3:
                self.safe_addstr(y + i, x, line)

    def draw_scanner(self, y, x, width, height):
        """Нарисовать сканер сети"""
        lines = []

        lines.append("Network Scanner")
        lines.append("=" * 40)
        lines.append("")

        if self.network_scanner.scanning:
            lines.append("Status: SCANNING...")
            lines.append("")
            lines.append("[Enter] Stop scanning")
        else:
            lines.append("Status: IDLE")
            lines.append(f"Interface: {self.selected_interface}")
            lines.append("")
            lines.append("[Enter] Start scanning")
            lines.append("[↓] Select host for MITM")

        lines.append("")
        lines.append("Scan Results:")
        lines.append("-" * 40)

        if self.scan_results:
            for i, host in enumerate(self.scan_results[:height - 10]):
                ip = self.sanitize_string(host['ip'])
                mac = self.sanitize_string(host['mac'])
                vendor = self.sanitize_string(host['vendor'])
                lines.append(f"{ip:15} {mac:17} {vendor}")
        else:
            lines.append("No scan results yet")

        # Отображаем строки
        for i, line in enumerate(lines):
            line_y = y + i
            if line_y >= height + 3:
                break

            # Выделяем выбранную строку (учитываем смещение для заголовков)
            if self.current_tab == "scanner":
                # Заголовок и строка состояния - 0 и 1
                # Кнопки Start/Stop - 4 и 5 (после пустой строки)
                # Результаты сканирования начинаются с 8 строки

                if i == 4 and self.selected_row == 0:  # Start scanning
                    self.stdscr.attron(curses.color_pair(7))
                elif i == 5 and self.selected_row == 1:  # Stop scanning
                    self.stdscr.attron(curses.color_pair(7))
                elif i >= 8:  # Результаты сканирования
                    result_index = i - 8
                    if result_index >= 0 and result_index < len(self.scan_results):
                        if self.selected_row == result_index + 2:  # +2 потому что первые 2 - кнопки
                            self.stdscr.attron(curses.color_pair(7))

            self.safe_addstr(line_y, x, line)

            if self.current_tab == "scanner":
                self.stdscr.attroff(curses.color_pair(7))

    def draw_settings(self, y, x, width, height):
        """Нарисовать настройки"""
        lines = []

        lines.append("Settings")
        lines.append("=" * 40)
        lines.append("")

        lines.append("Network Interfaces:")
        for i, iface in enumerate(self.interfaces):
            prefix = ">" if iface == self.selected_interface else " "
            if i == self.selected_row and self.current_tab == "settings":
                lines.append(f"{prefix}▶ {iface}")
            else:
                lines.append(f"{prefix}  {iface}")

        lines.append("")
        lines.append("Configuration:")
        lines.append(f"  Sniff Filter: {config.SNIFF_FILTER}")
        lines.append(f"  Max Packets: {config.MAX_PACKETS_DISPLAY}")
        lines.append(f"  Refresh Rate: {config.REFRESH_RATE}s")

        lines.append("")
        lines.append("[↑↓] Select interface")
        lines.append("[Enter] Apply selection")
        lines.append("[Space] Apply selection")

        # Отображаем строки
        for i, line in enumerate(lines):
            line_y = y + i
            if line_y >= height + 3:
                break

            # Выделяем выбранную строку интерфейса
            if self.current_tab == "settings":
                # Интерфейсы начинаются с 4 строки (после заголовков)
                if i >= 4 and i < 4 + len(self.interfaces):
                    interface_index = i - 4
                    if interface_index == self.selected_row:
                        self.stdscr.attron(curses.color_pair(7))

            self.safe_addstr(line_y, x, line)

            if self.current_tab == "settings":
                self.stdscr.attroff(curses.color_pair(7))

    def draw_status_bar(self, y, width):
        """Нарисовать статусную строку"""
        # Статус выбранного интерфейса
        interface_status = f"Interface: {self.selected_interface}" if self.selected_interface else "No interface selected"

        # Статус сниффинга
        sniff_status = "SNIFFING" if self.packet_analyzer.sniffing else "IDLE"

        # Текущая позиция
        position_info = ""
        if self.current_tab == "packets":
            packets = self.session_manager.get_packets(limit=1000)
            if packets:
                position_info = f"Packet {self.selected_row + 1}/{len(packets)}"
        elif self.current_tab == "sessions":
            sessions = self.session_manager.get_sessions(limit=1000)
            if sessions:
                position_info = f"Session {self.selected_row + 1}/{len(sessions)}"
        elif self.current_tab == "settings":
            if self.interfaces:
                position_info = f"Interface {self.selected_row + 1}/{len(self.interfaces)}"

        # Собираем статусную строку
        status_parts = []
        status_parts.append(f"Tab: {self.current_tab}")
        status_parts.append(f"Status: {sniff_status}")

        if position_info:
            status_parts.append(position_info)

        status = " | ".join(status_parts)

        # Добавляем клавиши управления
        controls = "[Q]uit [1-6]Tabs [S]niff [↑↓]Nav [Enter]Select"

        # Формируем полную строку
        full_status = f" {status} | {controls} "

        # Обрезаем строку, если она слишком длинная
        if len(full_status) > width:
            # Сначала пытаемся обрезать controls
            available_width = width - len(status) - 5  # 5 для разделителей и пробелов
            if available_width > 20:  # Минимальная длина для controls
                controls = controls[:available_width - 3] + "..."
                full_status = f" {status} | {controls} "
            else:
                # Если совсем мало места, показываем только статус
                full_status = status[:width - 3] + "..."

        # Рисуем статусную строку
        self.stdscr.attron(curses.color_pair(8) | curses.A_BOLD)
        self.stdscr.addstr(y, 0, full_status.ljust(width))
        self.stdscr.attroff(curses.color_pair(8) | curses.A_BOLD)
