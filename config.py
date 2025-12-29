#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from dataclasses import dataclass, field
from typing import Dict, List, Any
import json


@dataclass
class Colors:
    """Цветовые схемы для TUI"""
    HTTP_REQUEST: str = "#00ff00"
    HTTP_RESPONSE: str = "#0088ff"
    HTTPS_SESSION: str = "#ff00ff"
    ERROR: str = "#ff0000"
    WARNING: str = "#ffff00"
    INFO: str = "#00ffff"
    SUCCESS: str = "#00ff00"
    DEFAULT: str = "#ffffff"


@dataclass
class Config:
    """Конфигурация приложения"""
    # Настройки сниффинга
    SNIFF_TIMEOUT: int = 0
    SNIFF_PROMISC: bool = True
    SNIFF_FILTER: str = "tcp port 80 or tcp port 443 or tcp port 53"

    # Настройки отображения
    MAX_PACKETS_DISPLAY: int = 1000
    MAX_PAYLOAD_DISPLAY: int = 500
    REFRESH_RATE: float = 0.1  # секунды

    # Настройки MITM
    ARP_SPOOF_INTERVAL: int = 2  # секунды

    # Цвета - используем field с default_factory для экземпляра класса
    colors: Colors = field(default_factory=Colors)

    # Настройки логирования
    LOG_FILE: str = "traffic_analyzer.log"
    LOG_LEVEL: str = "INFO"

    @classmethod
    def load_from_file(cls, filename: str = "config.json") -> "Config":
        """Загрузить конфигурацию из файла"""
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                data = json.load(f)

                # Обрабатываем цвета отдельно
                colors_data = data.pop('colors', {}) if 'colors' in data else {}
                config = cls(**data)

                # Устанавливаем цвета
                if colors_data:
                    for key, value in colors_data.items():
                        if hasattr(config.colors, key):
                            setattr(config.colors, key, value)

                return config
        return cls()

    def save_to_file(self, filename: str = "config.json"):
        """Сохранить конфигурацию в файл"""
        data = {
            key: value for key, value in self.__dict__.items()
            if not key.startswith('_') and key != 'colors'
        }

        # Добавляем цвета
        data['colors'] = self.colors.__dict__

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)


# Глобальная конфигурация
config = Config()