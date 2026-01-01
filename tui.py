#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import curses
import time
import threading
import json
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

        # MITM атака - цели
        self.mitm_target_ip = ""
        self.mitm_gateway_ip = ""
        self.mitm_status_message = ""
        self.mitm_status_time = 0
        self.mitm_input_mode = None  # 'target' или 'gateway'
        self.mitm_input_buffer = ""

        # Флаги состояния
        self.exporting = False
        self.export_status = ""
        self.export_filename = ""
        self.export_progress = 0
        self.export_total = 0

        # Детальная информация о пакете
        self.selected_packet_detail = None
        self.show_packet_detail = False

        # Инициализация curses
        self.init_curses()

        # Получить список интерфейсов
        self.update_interfaces()

    def update_interfaces(self):
        """Обновить список интерфейсов"""
        self.interfaces = get_network_interfaces()
        if self.interfaces:
            self.selected_interface = self.interfaces[0]
            # Обновляем текущий интерфейс в анализаторе
            self.packet_analyzer.current_interface = self.selected_interface
            # Получаем шлюз по умолчанию для интерфейса
            info = get_interface_info(self.selected_interface)
            self.mitm_gateway_ip = info.get("gateway", "192.168.1.1")
        else:
            # Если интерфейсы не найдены, показываем сообщение
            self.interfaces = ["No interfaces found - check permissions"]
            self.selected_interface = None

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
        curses.init_pair(9, curses.COLOR_BLACK, curses.COLOR_GREEN)  # Экспорт успех
        curses.init_pair(10, curses.COLOR_BLACK, curses.COLOR_RED)  # Экспорт ошибка
        curses.init_pair(11, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Ввод режим

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

    def calculate_column_widths(self, total_width: int, columns_config: Dict) -> Dict[str, int]:
        """Рассчитать ширины столбцов на основе доступной ширины"""
        # Определяем минимальные и желаемые ширины столбцов
        columns = columns_config

        # Вычисляем общую желаемую ширину
        total_desired = sum(col['desired'] for col in columns.values())

        # Если помещается полностью, используем желаемые ширины
        if total_desired <= total_width:
            return {key: columns[key]['desired'] for key in columns}

        # Вычисляем недостающую ширину
        deficit = total_desired - total_width

        # Сортируем столбцы по приоритету (чем выше priority, тем позже урезаем)
        sorted_cols = sorted(columns.items(), key=lambda x: x[1]['priority'])

        # Сначала устанавливаем все ширины на желаемые
        result = {key: columns[key]['desired'] for key in columns}

        # Урезаем столбцы, начиная с наименьшего приоритета
        for col_name, col_info in reversed(sorted_cols):
            if deficit <= 0:
                break

            current_width = result[col_name]
            min_width = col_info['min']

            # Сколько можно урезать
            available_cut = current_width - min_width

            if available_cut > 0:
                # Урезаем этот столбец
                cut_amount = min(deficit, available_cut)
                result[col_name] -= cut_amount
                deficit -= cut_amount

        # Если всё ещё не хватает, урезаем минимальные ширины пропорционально
        if deficit > 0:
            # Распределяем дефицит пропорционально среди всех столбцов
            for col_name in result:
                result[col_name] = max(col_info['min'], result[col_name] - deficit // len(result))

        return result

    def format_column_text(self, text: str, width: int, align: str = 'left') -> str:
        """Форматировать текст столбца с заданной шириной и выравниванием"""
        text = self.sanitize_string(text)

        # Если текст уже подходит, возвращаем его
        if len(text) <= width:
            if align == 'left':
                return text.ljust(width)
            elif align == 'right':
                return text.rjust(width)
            else:  # center
                return text.center(width)

        # Если текст слишком длинный, обрезаем и добавляем "..."
        if width <= 3:
            return '.' * width  # Минимальный индикатор

        truncated = text[:width - 3] + "..."
        if align == 'left':
            return truncated.ljust(width)
        elif align == 'right':
            return truncated.rjust(width)
        else:  # center
            return truncated.center(width)

    def run(self):
        """Запустить главный цикл TUI"""
        # Главный цикл
        while self.running:
            self.handle_input()
            self.draw()
            time.sleep(self.update_interval)

    def handle_input(self):
        """Обработать ввод пользователя"""
        try:
            key = self.stdscr.getch()

            # Если в режиме ввода MITM, обрабатываем специально
            if self.mitm_input_mode:
                self.handle_mitm_input(key)
                return

            # Общие клавиши выхода
            if key == ord('q') or key == 27:  # 'q' или ESC
                self.running = False
                return

            # Если показываем детали пакета, обрабатываем только ESC и Enter
            if self.show_packet_detail and self.selected_packet_detail:
                if key == ord('\n') or key == ord('\r') or key == ord(' ') or key == 27:
                    self.show_packet_detail = False
                    self.selected_packet_detail = None
                return

            # Навигация по табам (всегда доступна, даже во время экспорта)
            if key == ord('1'):
                self.current_tab = "dashboard"
                self.selected_row = 0
                self.scroll_offset = 0
                self.show_packet_detail = False
                self.selected_packet_detail = None
                self.mitm_input_mode = None
            elif key == ord('2'):
                self.current_tab = "packets"
                self.selected_row = 0
                self.scroll_offset = 0
                self.show_packet_detail = False
                self.selected_packet_detail = None
                self.mitm_input_mode = None
            elif key == ord('3'):
                self.current_tab = "sessions"
                self.selected_row = 0
                self.scroll_offset = 0
                self.show_packet_detail = False
                self.selected_packet_detail = None
                self.mitm_input_mode = None
            elif key == ord('4'):
                self.current_tab = "mitm"
                self.selected_row = 0
                self.scroll_offset = 0
                self.show_packet_detail = False
                self.selected_packet_detail = None
                self.mitm_input_mode = None
            elif key == ord('5'):
                self.current_tab = "scanner"
                self.selected_row = 0
                self.scroll_offset = 0
                self.show_packet_detail = False
                self.selected_packet_detail = None
                self.mitm_input_mode = None
            elif key == ord('6'):
                self.current_tab = "settings"
                self.selected_row = 0
                self.scroll_offset = 0
                self.show_packet_detail = False
                self.selected_packet_detail = None
                self.mitm_input_mode = None

            # Навигация в текущем табе (работает везде, кроме экспорта)
            elif key == curses.KEY_UP:
                self.handle_up()
            elif key == curses.KEY_DOWN:
                self.handle_down()
            elif key == curses.KEY_LEFT:
                self.handle_left()
            elif key == curses.KEY_RIGHT:
                self.handle_right()

            # Действия в зависимости от таба
            elif key == ord('\n') or key == ord('\r') or key == ord(' '):
                self.handle_enter()

            # Старт/стоп сниффинга
            elif key == ord('s'):
                self.toggle_sniffing()

            # Обновить интерфейсы
            elif key == ord('r'):
                self.update_interfaces()

            # Очистка данных
            elif key == ord('c'):
                self.session_manager.clear_all()

            # Экспорт данных (работает даже во время экспорта для отмены)
            elif key == ord('e'):
                if self.exporting:
                    # Если экспорт уже идет, показываем статус
                    self.export_status = "Export already in progress..."
                else:
                    self.start_export()

            # Показать детали выбранного пакета
            elif key == ord('d'):
                self.show_packet_details()

            # MITM: Установить цель
            elif key == ord('t'):
                if self.current_tab == "mitm":
                    self.mitm_input_mode = 'target'
                    self.mitm_input_buffer = self.mitm_target_ip

            # MITM: Установить шлюз
            elif key == ord('g'):
                if self.current_tab == "mitm":
                    self.mitm_input_mode = 'gateway'
                    self.mitm_input_buffer = self.mitm_gateway_ip

            # Scanner: Установить выбранный хост как цель MITM
            elif key == ord('m') or key == ord('M'):
                if self.current_tab == "scanner" and self.selected_row >= 2:
                    host_index = self.selected_row - 2
                    if 0 <= host_index < len(self.scan_results):
                        self.mitm_target_ip = self.scan_results[host_index]['ip']
                        self.mitm_status_message = f"Target set to: {self.mitm_target_ip}"
                        self.mitm_status_time = time.time()

        except Exception as e:
            pass

    def handle_mitm_input(self, key):
        """Обработать ввод для MITM"""
        if key == 27:  # ESC - отмена
            self.mitm_input_mode = None
            self.mitm_input_buffer = ""
        elif key == ord('\n') or key == ord('\r'):  # Enter - подтверждение
            if self.mitm_input_mode == 'target':
                self.mitm_target_ip = self.mitm_input_buffer
                self.mitm_status_message = f"Target set to: {self.mitm_target_ip}"
            elif self.mitm_input_mode == 'gateway':
                self.mitm_gateway_ip = self.mitm_input_buffer
                self.mitm_status_message = f"Gateway set to: {self.mitm_gateway_ip}"

            self.mitm_status_time = time.time()
            self.mitm_input_mode = None
            self.mitm_input_buffer = ""
        elif key == curses.KEY_BACKSPACE or key == 127:  # Backspace
            if self.mitm_input_buffer:
                self.mitm_input_buffer = self.mitm_input_buffer[:-1]
        elif 32 <= key <= 126:  # Печатаемые символы
            self.mitm_input_buffer += chr(key)

    def handle_up(self):
        """Обработка клавиши Вверх"""
        if self.current_tab == "packets":
            packets = self.session_manager.get_packets(limit=1000)
            if packets:
                self.selected_row = max(0, self.selected_row - 1)
                # Автопрокрутка для видимости выбранной строки
                if self.selected_row < self.scroll_offset:
                    self.scroll_offset = max(0, self.selected_row)

        elif self.current_tab == "sessions":
            sessions = self.session_manager.get_sessions(limit=1000)
            if sessions:
                self.selected_row = max(0, self.selected_row - 1)
                if self.selected_row < self.scroll_offset:
                    self.scroll_offset = max(0, self.selected_row)

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
                    # Автопрокрутка для видимости выбранной строки
                    # Предполагаем, что высота видимой области около 20 строк
                    if self.selected_row >= self.scroll_offset + 15:
                        self.scroll_offset = min(max_rows - 14, self.selected_row - 14)

        elif self.current_tab == "sessions":
            sessions = self.session_manager.get_sessions(limit=1000)
            if sessions:
                max_rows = len(sessions) - 1
                if self.selected_row < max_rows:
                    self.selected_row += 1
                    if self.selected_row >= self.scroll_offset + 15:
                        self.scroll_offset = min(max_rows - 14, self.selected_row - 14)

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
                    # Автоматически устанавливаем как цель MITM
                    self.mitm_target_ip = selected_host['ip']
                    self.mitm_status_message = f"Target set to: {self.mitm_target_ip}"
                    self.mitm_status_time = time.time()

        elif self.current_tab == "settings":
            # Выбор интерфейса
            if 0 <= self.selected_row < len(self.interfaces):
                self.selected_interface = self.interfaces[self.selected_row]
                # Обновляем текущий интерфейс в анализаторе
                self.packet_analyzer.current_interface = self.selected_interface
                # Получаем шлюз по умолчанию
                info = get_interface_info(self.selected_interface)
                self.mitm_gateway_ip = info.get("gateway", "192.168.1.1")
                # Перезапускаем сниффинг если он активен
                if self.packet_analyzer.sniffing:
                    self.packet_analyzer.stop_sniffing()
                    time.sleep(0.5)
                    self.packet_analyzer.start_sniffing(self.selected_interface)

        elif self.current_tab == "packets":
            # Показать детали выбранного пакета
            self.show_packet_details()

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
            self.mitm_status_message = "MITM attack stopped"
            self.mitm_status_time = time.time()
        else:
            if not self.selected_interface:
                self.mitm_status_message = "Error: No interface selected"
                self.mitm_status_time = time.time()
                return

            if not self.mitm_target_ip:
                self.mitm_status_message = "Error: Target IP not set"
                self.mitm_status_time = time.time()
                return

            if not self.mitm_gateway_ip:
                self.mitm_status_message = "Error: Gateway IP not set"
                self.mitm_status_time = time.time()
                return

            # Запускаем MITM атаку
            self.mitm_attacker = MITMAttacker(
                target_ip=self.mitm_target_ip,
                gateway_ip=self.mitm_gateway_ip,
                interface=self.selected_interface
            )

            attack_thread = threading.Thread(target=self.mitm_attacker.start_attack, daemon=True)
            attack_thread.start()

            self.mitm_status_message = f"MITM attack started: {self.mitm_target_ip} -> {self.mitm_gateway_ip}"
            self.mitm_status_time = time.time()

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
        if results:
            self.mitm_status_message = f"Scan complete: found {len(results)} hosts"
            self.mitm_status_time = time.time()

    def start_export(self):
        """Начать экспорт данных в отдельном потоке"""
        if self.exporting:
            return

        self.exporting = True
        self.export_status = "Starting export..."
        self.export_filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # Запускаем экспорт в отдельном потоке
        export_thread = threading.Thread(target=self.export_data, daemon=True)
        export_thread.start()

    def export_data(self):
        """Экспорт данных в фоновом режиме"""
        try:
            # Получаем статистику для оценки прогресса
            stats = self.session_manager.get_statistics()
            total_packets = stats.get("total_packets", 0)

            if total_packets == 0:
                self.export_status = "No data to export"
                time.sleep(2)
                self.exporting = False
                return

            self.export_status = f"Exporting {total_packets} packets..."

            # Экспортируем данные
            self.session_manager.export_to_json(self.export_filename)

            # Успешный экспорт
            self.export_status = f"Exported to {self.export_filename}"

            # Через 3 секунды очищаем статус
            time.sleep(3)
            self.export_status = ""

        except Exception as e:
            self.export_status = f"Export failed: {str(e)[:50]}"
            time.sleep(3)
            self.export_status = ""
        finally:
            self.exporting = False

    def show_packet_details(self):
        """Показать детали выбранного пакета"""
        if self.current_tab == "packets":
            packets = self.session_manager.get_packets(limit=1000)
            if 0 <= self.selected_row < len(packets):
                self.selected_packet_detail = packets[self.selected_row]
                self.show_packet_detail = True

    def draw(self):
        """Нарисовать интерфейс"""
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()

        # Если показываем детали пакета, рисуем их
        if self.show_packet_detail and self.selected_packet_detail:
            self.draw_packet_detail(0, 0, width, height)
            return

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

        # Определяем интерфейс для отображения
        interface_display = self.selected_interface or "None"
        if analyzer_stats.get('interface'):
            interface_display = analyzer_stats['interface']

        # Общая информация
        info_lines = [
            f"Status: {'SNIFFING' if analyzer_stats['sniffing'] else 'IDLE'}",
            f"Interface: {interface_display}",
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
            "[R] Refresh interfaces",
            "[C] Clear data",
            "[E] Export to JSON",
            "[D] Show packet details",
            "[Q] Quit"
        ]

        for i, control in enumerate(controls):
            if controls_y + i < height + 3:
                self.stdscr.attron(curses.color_pair(4))
                self.safe_addstr(controls_y + i, x, control)
                self.stdscr.attroff(curses.color_pair(4))

    def draw_packets(self, y, x, width, height):
        """Нарисовать список пакетов"""
        packets = self.session_manager.get_packets(limit=height * 2)  # Берем больше для прокрутки

        if not packets:
            self.safe_addstr(y, x, "No packets captured yet")
            self.safe_addstr(y + 1, x, "Press 'S' to start sniffing")
            return

        # Конфигурация столбцов для пакетов
        columns_config = {
            'time': {'min': 8, 'desired': 10, 'priority': 1},    # Время
            'src': {'min': 15, 'desired': 20, 'priority': 3},    # Источник
            'dst': {'min': 15, 'desired': 20, 'priority': 4},    # Назначение
            'proto': {'min': 6, 'desired': 8, 'priority': 2},    # Протокол
            'size': {'min': 6, 'desired': 8, 'priority': 2},     # Размер
            'info': {'min': 15, 'desired': 25, 'priority': 5},   # Информация
        }

        # Рассчитываем ширины столбцов с учётом доступной ширины
        # Учитываем пробелы между столбцами: 1 пробел между 6 столбцами = 5 пробелов
        available_width = width - 5
        col_widths = self.calculate_column_widths(available_width, columns_config)

        # Проверяем, что суммарная ширина не превышает доступную
        total_col_width = sum(col_widths.values())
        if total_col_width > available_width:
            # Корректируем ширину последнего столбца
            diff = total_col_width - available_width
            col_widths['info'] = max(columns_config['info']['min'], col_widths['info'] - diff)

        # Создаём строку формата для выравнивания
        fmt = (
            f"{{:<{col_widths['time']}}} "
            f"{{:<{col_widths['src']}}} "
            f"{{:<{col_widths['dst']}}} "
            f"{{:<{col_widths['proto']}}} "
            f"{{:>{col_widths['size']}}} "  # Размер выравниваем по правому краю
            f"{{:<{col_widths['info']}}}"
        )

        # Заголовок таблицы
        header = fmt.format(
            self.format_column_text("Time", col_widths['time']),
            self.format_column_text("Source", col_widths['src']),
            self.format_column_text("Dest", col_widths['dst']),
            self.format_column_text("Proto", col_widths['proto']),
            self.format_column_text("Size", col_widths['size'], 'right'),
            self.format_column_text("Info", col_widths['info'])
        )

        self.stdscr.attron(curses.A_BOLD)
        self.safe_addstr(y, x, header[:width])
        self.stdscr.attroff(curses.A_BOLD)

        # Ограничиваем отображаемые пакеты с учётом прокрутки
        start_idx = self.scroll_offset
        end_idx = min(start_idx + height - 1, len(packets))

        # Пакеты
        for display_idx, packet_idx in enumerate(range(start_idx, end_idx)):
            line_y = y + 1 + display_idx

            if line_y >= height + 3:
                break

            packet = packets[packet_idx]

            # Форматируем время
            timestamp = datetime.fromtimestamp(packet.timestamp).strftime('%H:%M:%S')

            # Форматируем источник и назначение
            src = f"{packet.src_ip}:{packet.src_port}"
            dst = f"{packet.dst_ip}:{packet.dst_port}"

            # Форматируем информацию в зависимости от типа пакета
            info = ""
            if packet.packet_type == PacketType.HTTP_REQUEST:
                method = packet.data.get('method', '')
                host = packet.data.get('host', '')
                if method and host:
                    info = f"{method} {host[:15]}" if len(host) > 15 else f"{method} {host}"
                else:
                    info = "HTTP Request"
            elif packet.packet_type == PacketType.HTTP_RESPONSE:
                status = packet.data.get('status_code', '')
                info = f"HTTP {status}" if status else "HTTP Response"
            elif packet.packet_type == PacketType.HTTPS_SESSION:
                sni = packet.data.get('sni', '')
                if sni:
                    info = f"TLS {sni[:15]}" if len(sni) > 15 else f"TLS {sni}"
                else:
                    info = "HTTPS"
            elif packet.packet_type == PacketType.DNS_QUERY:
                queries = packet.data.get('queries', [])
                if queries and len(queries) > 0:
                    qname = queries[0].get('qname', '')
                    if qname:
                        info = f"DNS {qname[:15]}" if len(qname) > 15 else f"DNS {qname}"
                if not info:
                    info = "DNS Query"
            elif packet.packet_type == PacketType.DNS_RESPONSE:
                answers = packet.data.get('answers', [])
                if answers and len(answers) > 0:
                    rdata = answers[0].get('rdata', '')
                    if rdata:
                        info = f"DNS→ {rdata[:15]}" if len(rdata) > 15 else f"DNS→ {rdata}"
                if not info:
                    info = "DNS Response"
            elif packet.packet_type == PacketType.TCP_CONNECTION:
                info = "TCP"
            elif packet.packet_type == PacketType.UDP_SESSION:
                info = "UDP"

            # Форматируем размер
            size_str = format_bytes(packet.size)

            # Форматируем строку с выравниванием
            try:
                line = fmt.format(
                    self.format_column_text(timestamp, col_widths['time']),
                    self.format_column_text(src, col_widths['src']),
                    self.format_column_text(dst, col_widths['dst']),
                    self.format_column_text(packet.protocol, col_widths['proto']),
                    self.format_column_text(size_str, col_widths['size'], 'right'),
                    self.format_column_text(info, col_widths['info'])
                )

                # Убедимся, что строка не превышает доступную ширину
                if len(line) > width:
                    line = line[:width]

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
                if packet_idx == self.selected_row and self.current_tab == "packets":
                    self.stdscr.attron(curses.color_pair(7) | curses.A_BOLD)

                self.stdscr.attron(color)
                self.safe_addstr(line_y, x, line)
                self.stdscr.attroff(color)

                if packet_idx == self.selected_row and self.current_tab == "packets":
                    self.stdscr.attroff(curses.color_pair(7) | curses.A_BOLD)

            except Exception as e:
                # В случае ошибки показываем упрощённую строку
                error_line = f"Packet {packet_idx+1}"
                if len(error_line) > width:
                    error_line = error_line[:width]
                self.safe_addstr(line_y, x, error_line)

    def draw_sessions(self, y, x, width, height):
        """Нарисовать список сессий"""
        sessions = self.session_manager.get_sessions(limit=height * 2)

        if not sessions:
            self.safe_addstr(y, x, "No sessions yet")
            return

        # Конфигурация столбцов для сессий
        columns_config = {
            'id': {'min': 12, 'desired': 20, 'priority': 1},
            'client': {'min': 15, 'desired': 20, 'priority': 3},
            'server': {'min': 15, 'desired': 20, 'priority': 4},
            'duration': {'min': 6, 'desired': 10, 'priority': 2},
            'packets': {'min': 6, 'desired': 8, 'priority': 2},
            'bytes': {'min': 8, 'desired': 12, 'priority': 2},
        }

        # Рассчитываем ширины столбцов с учётом доступной ширины
        # 5 пробелов между 6 столбцами
        available_width = width - 5
        col_widths = self.calculate_column_widths(available_width, columns_config)

        # Проверяем, что суммарная ширина не превышает доступную
        total_col_width = sum(col_widths.values())
        if total_col_width > available_width:
            # Корректируем ширину последнего столбца
            diff = total_col_width - available_width
            col_widths['id'] = max(columns_config['id']['min'], col_widths['id'] - diff)

        # Создаём строку формата
        fmt = (
            f"{{:<{col_widths['id']}}} "
            f"{{:<{col_widths['client']}}} "
            f"{{:<{col_widths['server']}}} "
            f"{{:<{col_widths['duration']}}} "
            f"{{:>{col_widths['packets']}}} "
            f"{{:>{col_widths['bytes']}}}"
        )

        # Заголовок таблица
        header = fmt.format(
            self.format_column_text("ID", col_widths['id']),
            self.format_column_text("Client", col_widths['client']),
            self.format_column_text("Server", col_widths['server']),
            self.format_column_text("Duration", col_widths['duration']),
            self.format_column_text("Pkts", col_widths['packets'], 'right'),
            self.format_column_text("Bytes", col_widths['bytes'], 'right')
        )

        self.stdscr.attron(curses.A_BOLD)
        self.safe_addstr(y, x, header[:width])
        self.stdscr.attroff(curses.A_BOLD)

        # Ограничиваем отображаемые сессии с учётом прокрутки
        start_idx = self.scroll_offset
        end_idx = min(start_idx + height - 1, len(sessions))

        # Сессии
        for display_idx, session_idx in enumerate(range(start_idx, end_idx)):
            line_y = y + 1 + display_idx

            if line_y >= height + 3:
                break

            session = sessions[session_idx]

            # Укорачиваем ID
            session_id = session.session_id
            if len(session_id) > col_widths['id']:
                session_id = session_id[:col_widths['id'] - 3] + "..."

            # Форматируем данные
            client = f"{session.client_ip}:{session.client_port}"
            server = f"{session.server_ip}:{session.server_port}"
            duration = format_time_delta(session.get_duration())
            packets = len(session.packets)
            bytes_fmt = format_bytes(session.total_bytes)

            try:
                line = fmt.format(
                    self.format_column_text(session_id, col_widths['id']),
                    self.format_column_text(client, col_widths['client']),
                    self.format_column_text(server, col_widths['server']),
                    self.format_column_text(duration, col_widths['duration']),
                    self.format_column_text(str(packets), col_widths['packets'], 'right'),
                    self.format_column_text(bytes_fmt, col_widths['bytes'], 'right')
                )

                if len(line) > width:
                    line = line[:width]

                # Выделяем выбранную строку
                if session_idx == self.selected_row and self.current_tab == "sessions":
                    self.stdscr.attron(curses.color_pair(7))

                self.safe_addstr(line_y, x, line)

                if session_idx == self.selected_row and self.current_tab == "sessions":
                    self.stdscr.attroff(curses.color_pair(7))

            except Exception as e:
                error_line = f"Session {session_idx+1}"
                if len(error_line) > width:
                    error_line = error_line[:width]
                self.safe_addstr(line_y, x, error_line)

    def draw_mitm(self, y, x, width, height):
        """Нарисовать MITM панель"""
        lines = []

        lines.append("MITM Attack (ARP Spoofing)")
        lines.append("=" * 40)
        lines.append("")

        # Если в режиме ввода
        if self.mitm_input_mode:
            prompt = ""
            if self.mitm_input_mode == 'target':
                prompt = f"Enter Target IP [{self.mitm_target_ip}]: "
            elif self.mitm_input_mode == 'gateway':
                prompt = f"Enter Gateway IP [{self.mitm_gateway_ip}]: "

            lines.append(prompt + self.mitm_input_buffer + "_")
            lines.append("")
            lines.append("[Enter] Confirm  [ESC] Cancel  [Backspace] Delete")
            lines.append("")

            # Отображаем строки
            for i, line in enumerate(lines):
                if y + i < height + 3:
                    if i == 0:  # Первая строка - промпт
                        self.stdscr.attron(curses.color_pair(11))
                        self.safe_addstr(y + i, x, line)
                        self.stdscr.attroff(curses.color_pair(11))
                    else:
                        self.safe_addstr(y + i, x, line)
            return

        # Статус атаки
        if self.mitm_attacker and self.mitm_attacker.running:
            lines.append("Status: RUNNING")
            attacker_status = self.mitm_attacker.get_status()
            lines.append(f"Target: {attacker_status['target_ip']}")
            lines.append(f"Gateway: {attacker_status['gateway_ip']}")
            lines.append(f"Interface: {attacker_status['interface']}")
            lines.append(f"Packets sent: {attacker_status['spoof_packets_sent']}")
            lines.append(f"Duration: {attacker_status['duration']:.1f}s")
            lines.append("")
            lines.append("[Enter] Stop MITM attack")
        else:
            lines.append("Status: STOPPED")

        lines.append("")

        # Текущие настройки
        lines.append("Current Settings:")
        lines.append(f"  Interface: {self.selected_interface or 'Not selected'}")
        lines.append(f"  Target IP: {self.mitm_target_ip or 'Not set'}")
        lines.append(f"  Gateway IP: {self.mitm_gateway_ip or 'Not set'}")
        lines.append("")

        # Инструкция по настройке
        lines.append("How to configure:")
        lines.append("  1. Select interface in Settings tab")
        lines.append("  2. Set target IP (T) or use Scanner (M)")
        lines.append("  3. Set gateway IP (G) or use default")
        lines.append("  4. Press Enter to start/stop attack")
        lines.append("")

        # Управление
        lines.append("Controls:")
        lines.append("  [T] - Set target IP")
        lines.append("  [G] - Set gateway IP")
        lines.append("  [Enter] - Start/Stop attack")
        lines.append("  [M] in Scanner - Set target from scan")
        lines.append("")

        # Статусное сообщение (если есть)
        if self.mitm_status_message and time.time() - self.mitm_status_time < 5:
            lines.append(f"Status: {self.mitm_status_message}")
            lines.append("")

        # Требования
        lines.append("Requirements:")
        lines.append("  - Root/Administrator privileges")
        lines.append("  - IP forwarding enabled automatically")
        lines.append("  - Npcap/WinPcap for Windows (for full functionality)")

        # Отображаем строки
        for i, line in enumerate(lines):
            if y + i < height + 3:
                # Выделяем важные строки
                if "Status: RUNNING" in line:
                    self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
                    self.safe_addstr(y + i, x, line)
                    self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
                elif "Status: STOPPED" in line:
                    self.stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
                    self.safe_addstr(y + i, x, line)
                    self.stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
                elif line.startswith("  [T]") or line.startswith("  [G]"):
                    self.stdscr.attron(curses.color_pair(4))
                    self.safe_addstr(y + i, x, line)
                    self.stdscr.attroff(curses.color_pair(4))
                else:
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
            lines.append("[M] Set selected host as MITM target")

        lines.append("")
        lines.append("Scan Results:")
        lines.append("-" * 40)

        if self.scan_results:
            for i, host in enumerate(self.scan_results[:height - 10]):
                ip = self.sanitize_string(host['ip'])
                mac = self.sanitize_string(host['mac'])
                vendor = self.sanitize_string(host['vendor'])

                # Показываем, если этот хост выбран как цель MITM
                mitm_marker = " ← MITM Target" if ip == self.mitm_target_ip else ""
                lines.append(f"{ip:15} {mac:17} {vendor}{mitm_marker}")
        else:
            lines.append("No scan results yet")

        lines.append("")
        lines.append("Controls:")
        lines.append("  [Enter] on host - Set as MITM target")
        lines.append("  [M] - Set selected host as MITM target")
        lines.append("  [↑↓] - Navigate hosts")

        # Отображаем строки
        for i, line in enumerate(lines):
            line_y = y + i
            if line_y >= height + 3:
                break

            # Выделяем выбранную строку
            if self.current_tab == "scanner":
                # Заголовок и строка состояния - 0 и 1
                # Кнопки Start/Stop - 5 и 6 (после пустой строки)
                # Результаты сканирования начинаются с 9 строки

                if i == 5 and self.selected_row == 0:  # Start scanning
                    self.stdscr.attron(curses.color_pair(7))
                elif i == 6 and self.selected_row == 1:  # Stop scanning
                    self.stdscr.attron(curses.color_pair(7))
                elif i >= 9 and i < 9 + len(self.scan_results):  # Результаты сканирования
                    result_index = i - 9
                    if result_index >= 0 and result_index < len(self.scan_results):
                        if self.selected_row == result_index + 2:  # +2 потому что первые 2 - кнопки
                            self.stdscr.attron(curses.color_pair(7))
                        # Если это цель MITM, выделяем цветом
                        elif self.scan_results[result_index]['ip'] == self.mitm_target_ip:
                            self.stdscr.attron(curses.color_pair(1))

            self.safe_addstr(line_y, x, line)

            if self.current_tab == "scanner":
                self.stdscr.attroff(curses.color_pair(7) | curses.color_pair(1))

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
        lines.append("MITM Settings:")
        lines.append(f"  Target IP: {self.mitm_target_ip or 'Not set'}")
        lines.append(f"  Gateway IP: {self.mitm_gateway_ip or 'Not set'}")

        lines.append("")
        lines.append("[R] Refresh interfaces list")
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

    def draw_packet_detail(self, y, x, width, height):
        """Нарисовать детали пакета"""
        if not self.selected_packet_detail:
            return

        packet = self.selected_packet_detail

        lines = []
        lines.append("Packet Details")
        lines.append("=" * min(width, 60))
        lines.append("")

        # Основная информация
        lines.append(f"Time: {datetime.fromtimestamp(packet.timestamp).strftime('%H:%M:%S.%f')[:-3]}")
        lines.append(f"Source: {packet.src_ip}:{packet.src_port}")
        lines.append(f"Destination: {packet.dst_ip}:{packet.dst_port}")
        lines.append(f"Protocol: {packet.protocol}")
        lines.append(f"Type: {packet.packet_type.value}")
        lines.append(f"Size: {format_bytes(packet.size)}")
        lines.append(f"Session ID: {packet.session_id or 'N/A'}")
        lines.append("")

        # Данные пакета
        lines.append("Packet Data:")
        lines.append("-" * min(width, 40))

        # Отображаем данные в зависимости от типа пакета
        if packet.data:
            try:
                # Для HTTP запросов
                if packet.packet_type == PacketType.HTTP_REQUEST:
                    lines.append(f"Method: {packet.data.get('method', 'N/A')}")
                    lines.append(f"URL: {packet.data.get('url', 'N/A')}")
                    lines.append(f"Host: {packet.data.get('host', 'N/A')}")
                    lines.append(f"Path: {packet.data.get('path', 'N/A')}")

                    if 'headers' in packet.data and packet.data['headers']:
                        lines.append("Headers:")
                        for key, value in packet.data['headers'].items():
                            if key and value:
                                lines.append(f"  {key}: {value}")

                    if 'post_data' in packet.data and packet.data['post_data']:
                        lines.append(f"POST Data: {packet.data['post_data'][:100]}...")

                # Для HTTP ответов
                elif packet.packet_type == PacketType.HTTP_RESPONSE:
                    lines.append(f"Status: {packet.data.get('status_code', 'N/A')}")
                    lines.append(f"Reason: {packet.data.get('reason_phrase', 'N/A')}")

                    if 'headers' in packet.data and packet.data['headers']:
                        lines.append("Headers:")
                        for key, value in packet.data['headers'].items():
                            if key and value:
                                lines.append(f"  {key}: {value}")

                    if 'body_preview' in packet.data and packet.data['body_preview']:
                        lines.append(f"Body Preview: {packet.data['body_preview'][:200]}...")

                # Для HTTPS
                elif packet.packet_type == PacketType.HTTPS_SESSION:
                    lines.append(f"Direction: {packet.data.get('direction', 'N/A')}")
                    lines.append(f"Client: {packet.data.get('client_ip', 'N/A')}")
                    lines.append(f"Server: {packet.data.get('server_ip', 'N/A')}")
                    lines.append(f"TLS Type: {packet.data.get('tls_type', 'N/A')}")

                    if 'sni' in packet.data and packet.data['sni']:
                        lines.append(f"SNI: {packet.data['sni']}")

                    if 'vulnerabilities' in packet.data and packet.data['vulnerabilities']:
                        lines.append("Vulnerabilities:")
                        for vuln in packet.data['vulnerabilities']:
                            lines.append(f"  • {vuln}")

                # Для DNS
                elif packet.packet_type in [PacketType.DNS_QUERY, PacketType.DNS_RESPONSE]:
                    if 'queries' in packet.data and packet.data['queries']:
                        lines.append("Queries:")
                        for query in packet.data['queries']:
                            lines.append(f"  • {query.get('qname', 'N/A')} ({query.get('qtype', 'N/A')})")

                    if 'answers' in packet.data and packet.data['answers']:
                        lines.append("Answers:")
                        for answer in packet.data['answers']:
                            lines.append(f"  • {answer.get('rrname', 'N/A')} -> {answer.get('rdata', 'N/A')}")

                # Для других типов
                else:
                    # Показываем все данные пакета
                    for key, value in packet.data.items():
                        if value:
                            lines.append(f"{key}: {value}")
            except Exception as e:
                lines.append(f"Error displaying data: {str(e)}")

        lines.append("")
        lines.append("[Enter/ESC] Back to packets list")

        # Отображаем строки
        for i, line in enumerate(lines):
            line_y = y + i
            if line_y >= height - 1:
                break

            # Центрируем заголовок
            if i == 0:
                self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
                centered_x = max(0, (width - len(line)) // 2)
                self.safe_addstr(line_y, centered_x, line)
                self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
            else:
                self.safe_addstr(line_y, x, line)

    def draw_status_bar(self, y, width):
        """Нарисовать статусную строку"""
        # Статус выбранного интерфейса
        interface_display = self.selected_interface or "None"

        # Статус сниффинга
        analyzer_stats = self.packet_analyzer.get_statistics()
        sniff_status = "SNIFFING" if analyzer_stats['sniffing'] else "IDLE"

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

        # Статус MITM
        mitm_info = ""
        if self.mitm_attacker and self.mitm_attacker.running:
            mitm_info = " | MITM: RUNNING"
        elif self.mitm_target_ip:
            mitm_info = f" | Target: {self.mitm_target_ip}"

        # Статус экспорта
        export_info = ""
        if self.exporting:
            export_info = f" | Export: {self.export_status}"
        elif self.export_status:
            export_info = f" | {self.export_status}"

        # Собираем статусную строку
        status_parts = []
        status_parts.append(f"Tab: {self.current_tab}")
        status_parts.append(f"Status: {sniff_status}")

        if position_info:
            status_parts.append(position_info)

        status = " | ".join(status_parts) + mitm_info + export_info

        # Добавляем клавиши управления
        if self.show_packet_detail:
            controls = "[Enter/ESC] Back"
        elif self.mitm_input_mode:
            controls = "[Enter] Confirm  [ESC] Cancel"
        else:
            controls = "[Q]uit [1-6]Tabs [S]niff [R]efresh [↑↓]Nav [Enter]Select"

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

        # Выбираем цвет для статусной строки
        if self.exporting:
            color_pair = 10  # Красный для экспорта
        elif self.export_status and "failed" in self.export_status.lower():
            color_pair = 10  # Красный для ошибки
        elif self.export_status and "exported" in self.export_status.lower():
            color_pair = 9   # Зеленый для успеха
        elif self.mitm_attacker and self.mitm_attacker.running:
            color_pair = 2   # Красный для активной MITM атаки
        else:
            color_pair = 8   # Стандартный цвет

        # Рисуем статусную строку
        self.stdscr.attron(curses.color_pair(color_pair) | curses.A_BOLD)
        self.stdscr.addstr(y, 0, full_status.ljust(width))
        self.stdscr.attroff(curses.color_pair(color_pair) | curses.A_BOLD)
