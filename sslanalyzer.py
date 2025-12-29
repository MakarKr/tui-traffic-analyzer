#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import hashlib
from typing import Dict, List, Any


class SSLAnalyzer:
    def __init__(self):
        self.ssl_sessions = {}
        self.vulnerabilities_db = {
            'weak_ciphers': ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'ANON', 'ADH'],
            'deprecated_protocols': ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'],
            'vulnerable_extensions': ['heartbeat', 'renegotiation']
        }

    def analyze_ssl_handshake(self, packet_data: Dict) -> Dict[str, Any]:
        """Анализ SSL/TLS рукопожатия"""
        analysis = {
            'risk_level': 'LOW',
            'vulnerabilities': [],
            'recommendations': [],
            'encryption_grade': 'A+'
        }

        # Анализ версии протокола
        version = packet_data.get('version', '').upper()
        if any(deprecated in version for deprecated in self.vulnerabilities_db['deprecated_protocols']):
            analysis['vulnerabilities'].append(f'Устаревший протокол: {version}')
            analysis['risk_level'] = 'HIGH'
            analysis['encryption_grade'] = 'F'
            analysis['recommendations'].append('Обновите протокол до TLSv1.2 или TLSv1.3')

        # Анализ шифров
        ciphers = packet_data.get('ciphers', [])
        weak_ciphers_found = []
        for cipher in ciphers:
            cipher_str = str(cipher).upper()
            for weak in self.vulnerabilities_db['weak_ciphers']:
                if weak.upper() in cipher_str:
                    weak_ciphers_found.append(cipher_str)

        if weak_ciphers_found:
            analysis['vulnerabilities'].append(f'Слабые шифры: {", ".join(weak_ciphers_found[:3])}')
            analysis['risk_level'] = 'MEDIUM' if analysis['risk_level'] != 'HIGH' else 'HIGH'
            analysis['encryption_grade'] = 'C' if analysis['encryption_grade'] != 'F' else 'F'
            analysis['recommendations'].append('Используйте современные шифры: AES-GCM, ChaCha20-Poly1305')

        # Анализ сертификата
        cert_info = packet_data.get('certificate', {})
        if cert_info:
            issuer = cert_info.get('issuer', '')
            subject = cert_info.get('subject', '')

            # Проверка самоподписанного сертификата
            if issuer == subject:
                analysis['vulnerabilities'].append('Самоподписанный сертификат')
                analysis['risk_level'] = 'MEDIUM' if analysis['risk_level'] != 'HIGH' else 'HIGH'
                analysis['encryption_grade'] = 'B' if analysis['encryption_grade'] not in ['C', 'F'] else analysis[
                    'encryption_grade']
                analysis['recommendations'].append('Используйте сертификаты от доверенных центров сертификации')

        # Анализ SNI
        sni = packet_data.get('sni', '')
        if not sni:
            analysis['vulnerabilities'].append('Отсутствует SNI (Server Name Indication)')
            analysis['risk_level'] = 'LOW' if analysis['risk_level'] == 'LOW' else analysis['risk_level']

        # Определение уровня риска
        if analysis['risk_level'] == 'LOW' and not analysis['vulnerabilities']:
            analysis['encryption_grade'] = 'A+'
        elif analysis['risk_level'] == 'LOW' and analysis['vulnerabilities']:
            analysis['encryption_grade'] = 'A'
        elif analysis['risk_level'] == 'MEDIUM':
            analysis['encryption_grade'] = 'B' if analysis['encryption_grade'] not in ['C', 'F'] else analysis[
                'encryption_grade']

        return analysis

    def detect_middlebox(self, packet_data: Dict) -> bool:
        """Обнаружение промежуточных устройств (Middlebox)"""
        # Признаки наличия middlebox:
        # 1. Необычные расширения TLS
        # 2. Измененные cipher suites
        # 3. Наличие определенных отпечатков

        tls_type = packet_data.get('tls_type', '')
        if 'Alert' in tls_type:
            # Некоторые middlebox отправляют alert при инспекции
            return True

        return False

    def generate_fingerprint(self, packet_data: Dict) -> str:
        """Генерация отпечатка TLS соединения"""
        fingerprint_data = []

        # Версия протокола
        version = packet_data.get('version', 'Unknown')
        fingerprint_data.append(f"Version:{version}")

        # Шифры (первые 5)
        ciphers = packet_data.get('ciphers', [])
        cipher_str = ','.join([str(c) for c in ciphers[:5]])
        fingerprint_data.append(f"Ciphers:{cipher_str}")

        # SNI
        sni = packet_data.get('sni', '')
        if sni:
            fingerprint_data.append(f"SNI:{sni}")

        # Создаем хэш отпечатка
        fingerprint_str = '|'.join(fingerprint_data)
        fingerprint_hash = hashlib.md5(fingerprint_str.encode()).hexdigest()[:8]

        return fingerprint_hash

    def get_security_report(self, packet_data: Dict) -> str:
        """Полный отчет о безопасности TLS соединения"""
        analysis = self.analyze_ssl_handshake(packet_data)
        fingerprint = self.generate_fingerprint(packet_data)

        report_lines = [
            "=" * 60,
            "TLS/SSL Security Analysis Report",
            "=" * 60,
            f"Target: {packet_data.get('sni', 'Unknown')}",
            f"Protocol: {packet_data.get('version', 'Unknown')}",
            f"Fingerprint: {fingerprint}",
            f"Risk Level: {analysis['risk_level']}",
            f"Encryption Grade: {analysis['encryption_grade']}",
            "-" * 60,
            "Vulnerabilities Found:"
        ]

        if analysis['vulnerabilities']:
            for vuln in analysis['vulnerabilities']:
                report_lines.append(f"  • {vuln}")
        else:
            report_lines.append("  • No critical vulnerabilities found")

        report_lines.extend([
            "-" * 60,
            "Recommendations:"
        ])

        if analysis['recommendations']:
            for rec in analysis['recommendations']:
                report_lines.append(f"  • {rec}")
        else:
            report_lines.append("  • Configuration appears secure")

        report_lines.append("=" * 60)

        return "\n".join(report_lines)