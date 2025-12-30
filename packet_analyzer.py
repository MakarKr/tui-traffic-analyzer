#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
import threading
import time
from typing import Optional, Dict, Any
from session_manager import Packet, PacketType, SessionManager
from utils import format_bytes
import re
import platform
import subprocess


class PacketAnalyzer:
    def __init__(self, session_manager: SessionManager):
        self.session_manager = session_manager
        self.sniffing = False
        self.sniff_thread = None
        self.current_interface = None
        self.packet_count = 0
        self.byte_count = 0

    def start_sniffing(self, interface: str, filter_str: str = "tcp port 80 or tcp port 443 or udp port 53"):
        """Начать захват пакетов"""
        if self.sniffing:
            self.stop_sniffing()

        self.sniffing = True
        self.current_interface = interface
        self.packet_count = 0
        self.byte_count = 0

        def sniff_task():
            try:
                print(f"[*] Starting sniffing on interface: {interface}")
                print(f"[*] Filter: {filter_str}")

                # Проверяем платформу
                if platform.system() == "Windows":
                    print("[*] Windows detected, adjusting sniffing parameters...")

                    # Для Windows используем Npcap
                    # Проверяем, установлен ли Npcap
                    try:
                        # Пробуем получить список интерфейсов через WinPcap/Npcap
                        from scapy.arch.windows import get_windows_if_list
                        ifaces = get_windows_if_list()
                        print(f"[*] Available WinPcap/Npcap interfaces: {len(ifaces)}")
                        for iface in ifaces:
                            print(f"    - {iface['name']} ({iface['description']})")
                    except Exception as e:
                        print(f"[!] Cannot get WinPcap interfaces: {e}")
                        print("[!] Make sure Npcap is installed: https://nmap.org/npcap/")

                    # Для Ethernet на Windows может потребоваться специальный синтаксис
                    # Преобразуем имя интерфейса в формат, понятный WinPcap
                    if "Ethernet" in interface or "eth" in interface.lower():
                        print(f"[*] Ethernet interface detected: {interface}")
                        # Пробуем разные варианты
                        interface_variants = [
                            interface,  # Оригинальное имя
                            f"\\Device\\NPF_{interface}",  # WinPcap формат
                            interface.replace(" ", "_"),  # Без пробелов
                            "Ethernet",  # Просто Ethernet
                        ]

                        for iface_var in interface_variants:
                            try:
                                print(f"[*] Trying interface: {iface_var}")
                                sniff_kwargs = {
                                    'iface': iface_var,
                                    'filter': filter_str,
                                    'prn': self.process_packet,
                                    'store': 0,
                                    'stop_filter': lambda x: not self.sniffing,
                                    'timeout': 5
                                }
                                print(f"[*] Starting sniff with kwargs: {sniff_kwargs}")
                                sniff(**sniff_kwargs)
                                print(f"[*] Successfully started on {iface_var}")
                                return
                            except Exception as e:
                                print(f"[!] Failed with {iface_var}: {e}")
                                continue

                        # Если все варианты не сработали, пробуем без указания интерфейса
                        print("[*] Trying to sniff on all interfaces...")
                        sniff_kwargs = {
                            'filter': filter_str,
                            'prn': self.process_packet,
                            'store': 0,
                            'stop_filter': lambda x: not self.sniffing,
                            'timeout': 5
                        }
                        sniff(**sniff_kwargs)

                    else:
                        # Для других интерфейсов на Windows
                        sniff_kwargs = {
                            'iface': interface,
                            'filter': filter_str,
                            'prn': self.process_packet,
                            'store': 0,
                            'stop_filter': lambda x: not self.sniffing,
                            'timeout': 5
                        }
                        print(f"[*] Starting sniff with kwargs: {sniff_kwargs}")
                        sniff(**sniff_kwargs)

                else:
                    # Для Linux/Unix
                    sniff_kwargs = {
                        'iface': interface,
                        'filter': filter_str,
                        'prn': self.process_packet,
                        'store': False,
                        'stop_filter': lambda x: not self.sniffing
                    }
                    print(f"[*] Starting sniff with kwargs: {sniff_kwargs}")
                    sniff(**sniff_kwargs)

                print("[*] Sniffing started successfully!")

            except Exception as e:
                print(f"[!] Error in sniffing: {e}")
                print(f"[!] Error type: {type(e).__name__}")
                import traceback
                traceback.print_exc()

                # Проверяем, установлен ли Npcap на Windows
                if platform.system() == "Windows":
                    print("\n[*] Troubleshooting steps for Windows:")
                    print("    1. Install Npcap from https://nmap.org/npcap/")
                    print("    2. During installation, check 'Install Npcap in WinPcap API-compatible Mode'")
                    print("    3. Restart your computer after installation")
                    print("    4. Run the program as Administrator")

                self.sniffing = False

        self.sniff_thread = threading.Thread(target=sniff_task, daemon=True)
        self.sniff_thread.start()

        # Даем время на запуск
        time.sleep(1)
        return True

    def stop_sniffing(self):
        """Остановить захват пакетов"""
        print("[*] Stopping sniffing...")
        self.sniffing = False

        # Даем время на остановку
        if self.sniff_thread:
            self.sniff_thread.join(timeout=3)
            print("[*] Sniffing stopped")
        return True

    def process_packet(self, packet):
        """Обработать захваченный пакет"""
        if not self.sniffing or not packet.haslayer(IP):
            return

        try:
            self.packet_count += 1
            self.byte_count += len(packet)

            # Периодически выводим статистику
            if self.packet_count % 50 == 0:
                print(f"[*] Packets captured: {self.packet_count}, Bytes: {format_bytes(self.byte_count)}")

            # Обработка HTTP
            if packet.haslayer(HTTPRequest):
                self._process_http_request(packet)
            elif packet.haslayer(HTTPResponse):
                self._process_http_response(packet)

            # Обработка HTTPS (только метаданные)
            elif packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                self._process_https_metadata(packet)

            # Обработка DNS
            elif packet.haslayer(DNS):
                self._process_dns(packet)

            # Обработка других TCP соединений
            elif packet.haslayer(TCP):
                self._process_tcp_connection(packet)

            # Обработка UDP
            elif packet.haslayer(UDP):
                self._process_udp_session(packet)

        except Exception as e:
            # Игнорируем ошибки обработки пакетов
            if self.packet_count % 100 == 0:  # Логируем только каждую 100-ю ошибку
                print(f"[!] Error processing packet {self.packet_count}: {e}")

    def extract_tls_info(self, packet):
        """Извлечение информации из TLS пакетов"""
        tls_info = {}

        try:
            # Проверяем наличие TLS слоев
            if packet.haslayer('TLS'):
                # Извлечение SNI (Server Name Indication)
                if packet.haslayer('TLSClientHello'):
                    sni = packet['TLSClientHello'].get_field_val('servername')
                    if sni:
                        tls_info['sni'] = sni.decode('utf-8', errors='ignore')

                # Извлечение информации о сертификате
                if packet.haslayer('TLSCertificate'):
                    cert = packet['TLSCertificate']
                    tls_info['certificate'] = {
                        'issuer': str(cert.get_field_val('issuer', 'Unknown')),
                        'validity': cert.get_field_val('validity', 'Unknown'),
                        'subject': str(cert.get_field_val('subject', 'Unknown'))
                    }

                # Версия TLS
                if packet.haslayer('TLSVersion'):
                    tls_info['version'] = str(packet['TLSVersion'])

                # Шифры
                if packet.haslayer('TLSCipherSuites'):
                    ciphers = packet['TLSCipherSuites'].get_field_val('ciphers', [])
                    if ciphers:
                        tls_info['ciphers'] = [str(c) for c in ciphers[:5]]  # Только первые 5

            # Альтернативный метод для извлечения SNI из сырых данных
            elif packet.haslayer(Raw):
                raw_data = packet[Raw].load

                # Поиск SNI в Client Hello
                if b'\x00\x00' in raw_data and b'\x00\x16' in raw_data:
                    try:
                        # Простая эвристика для поиска SNI
                        sni_start = raw_data.find(b'\x00\x00')
                        if sni_start != -1 and sni_start + 5 < len(raw_data):
                            sni_len = int.from_bytes(raw_data[sni_start + 3:sni_start + 5], 'big')
                            if sni_start + 5 + sni_len <= len(raw_data):
                                sni = raw_data[sni_start + 5:sni_start + 5 + sni_len].decode('utf-8', errors='ignore')
                                tls_info['sni'] = sni
                    except:
                        pass

                # Поиск информации о сертификате
                cert_markers = [b'-----BEGIN CERTIFICATE-----', b'Certificate:', b'Issuer:', b'Subject:']
                for marker in cert_markers:
                    if marker in raw_data:
                        tls_info['has_certificate'] = True
                        break

        except Exception as e:
            # В случае ошибки просто возвращаем пустой словарь
            pass

        return tls_info

    def detect_ssl_vulnerabilities(self, tls_info):
        """Обнаружение уязвимостей SSL/TLS"""
        vulnerabilities = []

        try:
            # Проверка устаревших протоколов
            version = tls_info.get('version', '').upper()
            deprecated_versions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
            if any(deprecated in version for deprecated in deprecated_versions):
                vulnerabilities.append(f'Deprecated protocol: {version}')

            # Проверка слабых шифров
            weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'ANON', 'ADH']
            ciphers = tls_info.get('ciphers', [])
            for cipher in ciphers:
                cipher_str = str(cipher).upper()
                if any(weak in cipher_str for weak in weak_ciphers):
                    vulnerabilities.append(f'Weak cipher: {cipher}')

            # Проверка сертификата
            cert_info = tls_info.get('certificate', {})
            if cert_info:
                # Проверка срока действия (простая проверка)
                validity = cert_info.get('validity', '')
                if 'expired' in str(validity).lower():
                    vulnerabilities.append('Expired certificate')

            # Проверка SNI
            if not tls_info.get('sni'):
                vulnerabilities.append('No SNI (Server Name Indication)')

        except Exception as e:
            pass

        return vulnerabilities

    def _process_http_request(self, packet):
        """Обработать HTTP запрос"""
        http = packet[HTTPRequest]
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        host = http.Host.decode() if http.Host else "Unknown"
        path = http.Path.decode() if http.Path else "/"
        method = http.Method.decode() if http.Method else "UNKNOWN"

        # Извлекаем заголовки
        headers = {}
        if hasattr(http, 'fields'):
            for field, value in http.fields.items():
                if value:
                    headers[field] = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)

        # Извлекаем POST данные
        post_data = None
        if method == "POST" and packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                post_data = raw_data.decode('utf-8', errors='ignore')
                if len(post_data) > 1000:
                    post_data = post_data[:1000] + "..."
            except:
                post_data = raw_data.hex()[:200] + "..." if len(raw_data) > 100 else raw_data.hex()

        # Создаем пакет
        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=tcp_layer.sport,
            dst_port=tcp_layer.dport,
            protocol="HTTP",
            packet_type=PacketType.HTTP_REQUEST,
            size=len(packet),
            data={
                "method": method,
                "url": f"http://{host}{path}",
                "host": host,
                "path": path,
                "headers": headers,
                "post_data": post_data,
                "version": "HTTP/1.1" if hasattr(http, 'Http_Version') else "Unknown"
            },
            session_id=f"http-{ip_layer.src}:{tcp_layer.sport}-{ip_layer.dst}:{tcp_layer.dport}"
        )

        self.session_manager.add_packet(packet_obj)

    def _process_http_response(self, packet):
        """Обработать HTTP ответ"""
        http = packet[HTTPResponse]
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # Извлекаем статус и заголовки
        status_code = None
        reason_phrase = None
        headers = {}

        if hasattr(http, 'Status_Code'):
            status_code = http.Status_Code.decode('utf-8', errors='ignore') if isinstance(http.Status_Code,
                                                                                          bytes) else str(
                http.Status_Code)

        if hasattr(http, 'Reason_Phrase'):
            reason_phrase = http.Reason_Phrase.decode('utf-8', errors='ignore') if isinstance(http.Reason_Phrase,
                                                                                              bytes) else str(
                http.Reason_Phrase)

        if hasattr(http, 'fields'):
            for field, value in http.fields.items():
                if value:
                    headers[field] = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)

        # Извлекаем тело ответа
        response_body = None
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                response_body = raw_data.decode('utf-8', errors='ignore')
                if len(response_body) > 1000:
                    response_body = response_body[:1000] + "..."

                # Пытаемся определить Content-Type
                content_type = headers.get('Content-Type', '')
                if 'html' in content_type.lower():
                    # Извлекаем title страницы
                    title_match = re.search(r'<title>(.*?)</title>', response_body, re.IGNORECASE)
                    if title_match:
                        headers['_page_title'] = title_match.group(1)

            except:
                response_body = raw_data.hex()[:200] + "..." if len(raw_data) > 100 else raw_data.hex()

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=tcp_layer.sport,
            dst_port=tcp_layer.dport,
            protocol="HTTP",
            packet_type=PacketType.HTTP_RESPONSE,
            size=len(packet),
            data={
                "status_code": status_code,
                "reason_phrase": reason_phrase,
                "headers": headers,
                "body_preview": response_body,
                "content_length": headers.get('Content-Length', 'Unknown')
            },
            session_id=f"http-{ip_layer.dst}:{tcp_layer.dport}-{ip_layer.src}:{tcp_layer.sport}"
        )

        self.session_manager.add_packet(packet_obj)

    def _process_https_metadata(self, packet):
        """Обработать метаданные HTTPS"""
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # Определяем направление
        if tcp_layer.dport == 443:  # Клиент -> Сервер
            direction = "client->server"
            client_ip = ip_layer.src
            server_ip = ip_layer.dst
            client_port = tcp_layer.sport
            server_port = tcp_layer.dport
        else:  # Сервер -> Клиент
            direction = "server->client"
            client_ip = ip_layer.dst
            server_ip = ip_layer.src
            client_port = tcp_layer.dport
            server_port = tcp_layer.sport

        # Извлекаем TLS информацию
        tls_info = self.extract_tls_info(packet)
        vulnerabilities = self.detect_ssl_vulnerabilities(tls_info)

        # Определяем тип TLS пакета
        tls_type = "Unknown"
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            if len(raw_data) > 0:
                # Первый байт указывает тип TLS записи
                first_byte = raw_data[0]
                if first_byte == 22:  # Handshake
                    if len(raw_data) > 5:
                        handshake_type = raw_data[5]
                        if handshake_type == 1:
                            tls_type = "Client Hello"
                        elif handshake_type == 2:
                            tls_type = "Server Hello"
                        elif handshake_type == 11:
                            tls_type = "Certificate"
                        elif handshake_type == 16:
                            tls_type = "Client Key Exchange"
                        elif handshake_type == 20:
                            tls_type = "Finished"
                elif first_byte == 23:
                    tls_type = "Application Data"
                elif first_byte == 21:
                    tls_type = "Alert"

        # Добавляем TLS информацию в данные пакета
        data = {
            "direction": direction,
            "client_ip": client_ip,
            "server_ip": server_ip,
            "tls_type": tls_type,
            "tcp_flags": str(tcp_layer.flags),
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack
        }

        # Добавляем TLS информацию, если есть
        if tls_info:
            data.update(tls_info)

        # Добавляем информацию об уязвимостях
        if vulnerabilities:
            data['vulnerabilities'] = vulnerabilities

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=tcp_layer.sport,
            dst_port=tcp_layer.dport,
            protocol="HTTPS",
            packet_type=PacketType.HTTPS_SESSION,
            size=len(packet),
            data=data,
            session_id=f"https-{client_ip}:{client_port}-{server_ip}:{server_port}"
        )

        self.session_manager.add_packet(packet_obj)

    def _process_dns(self, packet):
        """Обработать DNS пакет"""
        dns = packet[DNS]
        ip_layer = packet[IP]

        if dns.qr == 0:  # DNS запрос
            packet_type = PacketType.DNS_QUERY
            data = {"queries": []}
            if dns.haslayer(DNSQR):
                for query in dns[DNSQR]:
                    data["queries"].append({
                        "qname": query.qname.decode('utf-8', errors='ignore') if hasattr(query.qname,
                                                                                         'decode') else str(
                            query.qname),
                        "qtype": query.qtype
                    })
        else:  # DNS ответ
            packet_type = PacketType.DNS_RESPONSE
            data = {"answers": []}
            if dns.haslayer(DNSRR):
                for answer in dns[DNSRR]:
                    data["answers"].append({
                        "rrname": answer.rrname.decode('utf-8', errors='ignore') if hasattr(answer.rrname,
                                                                                            'decode') else str(
                            answer.rrname),
                        "type": answer.type,
                        "rdata": answer.rdata.decode('utf-8', errors='ignore') if hasattr(answer.rdata,
                                                                                          'decode') else str(
                            answer.rdata)
                    })

        # Определяем транспортный протокол
        if packet.haslayer(UDP):
            transport = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            transport = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol="DNS",
            packet_type=packet_type,
            size=len(packet),
            data=data
        )

        self.session_manager.add_packet(packet_obj)

    def _process_tcp_connection(self, packet):
        """Обработать TCP соединение"""
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # Пропускаем HTTP/HTTPS/DNS, т.к. они обрабатываются отдельно
        if tcp_layer.dport in [80, 443, 53] or tcp_layer.sport in [80, 443, 53]:
            return

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=tcp_layer.sport,
            dst_port=tcp_layer.dport,
            protocol="TCP",
            packet_type=PacketType.TCP_CONNECTION,
            size=len(packet),
            data={
                "flags": str(tcp_layer.flags),
                "seq": tcp_layer.seq,
                "ack": tcp_layer.ack,
                "window": tcp_layer.window,
                "payload_size": len(tcp_layer.payload) if hasattr(tcp_layer, 'payload') else 0
            },
            session_id=f"tcp-{ip_layer.src}:{tcp_layer.sport}-{ip_layer.dst}:{tcp_layer.dport}"
        )

        self.session_manager.add_packet(packet_obj)

    def _process_udp_session(self, packet):
        """Обработать UDP сессию"""
        ip_layer = packet[IP]
        udp_layer = packet[UDP]

        # Пропускаем DNS
        if udp_layer.dport == 53 or udp_layer.sport == 53:
            return

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=udp_layer.sport,
            dst_port=udp_layer.dport,
            protocol="UDP",
            packet_type=PacketType.UDP_SESSION,
            size=len(packet),
            data={
                "payload_size": len(udp_layer.payload) if hasattr(udp_layer, 'payload') else 0
            },
            session_id=f"udp-{ip_layer.src}:{udp_layer.sport}-{ip_layer.dst}:{udp_layer.dport}"
        )

        self.session_manager.add_packet(packet_obj)

    def get_statistics(self) -> Dict[str, Any]:
        """Получить статистику анализатора"""
        return {
            "sniffing": self.sniffing,
            "interface": self.current_interface,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "formatted_bytes": format_bytes(self.byte_count)
        }
