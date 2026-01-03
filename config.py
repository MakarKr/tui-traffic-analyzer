#!/usr/bin/env python3

import json
import os
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


class Colors:
    """Класс для цветовых схем интерфейса"""

    def __init__(self):
        # Цвета для различных типов трафика
        self.HTTP_REQUEST = "#00ff00"      # Зеленый
        self.HTTP_RESPONSE = "#0088ff"     # Синий
        self.HTTPS_SESSION = "#ff00ff"     # Пурпурный
        self.ERROR = "#ff0000"             # Красный
        self.WARNING = "#ffff00"           # Желтый
        self.INFO = "#00ffff"              # Голубой
        self.SUCCESS = "#00ff00"           # Зеленый
        self.DEFAULT = "#ffffff"           # Белый

    def show(self):
        """Отобразить текущие цвета в консоли"""
        text = Text("Color Configuration\n", style="bold")
        for attr in dir(self):
            if not attr.startswith('_') and attr.isupper():
                color = getattr(self, attr)
                text.append(f"{attr}: {color}\n", style=color)

        console.print(Panel(text, title="Colors", border_style="cyan"))


class Config:
    """Основной класс конфигурации приложения"""

    def __init__(self):
        # Настройки сниффинга
        self.SNIFF_TIMEOUT = 0
        self.SNIFF_PROMISC = True  # Режим promiscuous
        self.SNIFF_FILTER = "tcp port 80 or tcp port 443 or tcp port 53"

        # Настройки отображения
        self.MAX_PACKETS_DISPLAY = 1000
        self.MAX_PAYLOAD_DISPLAY = 500
        self.REFRESH_RATE = 0.1  # Секунды

        # Настройки MITM
        self.ARP_SPOOF_INTERVAL = 2  # Интервал отправки ARP пакетов

        # Цветовая схема
        self.colors = Colors()

        # Настройки логирования
        self.LOG_FILE = "traffic_analyzer.log"
        self.LOG_LEVEL = "INFO"

    def load_from_file(self, fname="config.json"):
        """Загрузить конфигурацию из JSON файла"""
        if not os.path.exists(fname):
            console.print(f"[yellow]Config file {fname} not found, using defaults[/yellow]")
            return self

        with open(fname, 'r') as f:
            data = json.load(f)

        # Извлечь данные цветов
        colors_data = data.pop('colors', {})

        # Установить основные параметры
        for k, v in data.items():
            if hasattr(self, k):
                setattr(self, k, v)

        # Установить цвета
        for k, v in colors_data.items():
            if hasattr(self.colors, k):
                setattr(self.colors, k, v)

        console.print(f"[green]Loaded config from {fname}[/green]")
        return self

    def save_to_file(self, fname="config.json"):
        """Сохранить конфигурацию в JSON файл"""
        data = {}

        # Собрать все параметры кроме colors
        for k in dir(self):
            if not k.startswith('_') and k != 'colors' and k.isupper():
                data[k] = getattr(self, k)

        # Сохранить цвета
        data['colors'] = {}
        for k in dir(self.colors):
            if not k.startswith('_'):
                data['colors'][k] = getattr(self.colors, k)

        # Записать в файл
        with open(fname, 'w') as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]Saved config to {fname}[/green]")

    def show(self):
        """Отобразить текущую конфигурацию в консоли"""
        text = Text("Configuration\n", style="bold")
        for k in dir(self):
            if not k.startswith('_') and k != 'colors' and k.isupper():
                v = getattr(self, k)
                text.append(f"{k}: {v}\n")

        console.print(Panel(text, title="Config", border_style="blue"))
        self.colors.show()


# Глобальный экземпляр конфигурации
config = Config()
