#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
import threading
import time
import socket
import struct
import platform
import subprocess
import os
from typing import Optional, Dict, Any
from session_manager import Packet, PacketType, SessionManager
from utils import format_bytes, get_interface_info
import re


class PacketAnalyzer:
    def __init__(self, session_manager: SessionManager):
        self.session_manager = session_manager
        self.sniffing = False
        self.sniff_thread = None
        self.current_interface = None
        self.packet_count = 0
        self.byte_count = 0
        self.socket_obj = None
        self.npcap_available = self._check_npcap()

    def _check_npcap(self) -> bool:
        """Проверить наличие Npcap/WinPcap"""
        if platform.system() != "Windows":
            return True  # На Linux/Mac всегда доступно

        try:
            # Проверяем наличие Npcap через scapy
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            if interfaces:
                print("[*] Npcap/WinPcap detected")
                return True
        except:
            pass

        # Проверяем наличие npcap в системных файлах
        npcap_paths = [
            r"C:\Windows\System32\Npcap",
            r"C:\Program Files\Npcap",
            r"C:\Program Files (x86)\Npcap",
            r"C:\Windows\System32\wpcap.dll",
            r"C:\Windows\System32\Packet.dll"
        ]

        for path in npcap_paths:
            if os.path.exists(path) or os.path.exists(path + ".dll"):
                print(f"[*] Npcap found at: {path}")
                return True

        print("[*] Npcap not found, using limited functionality")
        return False

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

                if platform.system() == "Windows":
                    # Проверяем наличие Npcap
                    if self.npcap_available:
                        print("[*] Using Npcap/WinPcap for packet capture")
                        try:
                            sniff_kwargs = {
                                'iface': interface,
                                'filter': filter_str,
                                'prn': self.process_packet,
                                'store': False,
                                'stop_filter': lambda x: not self.sniffing
                            }
                            sniff(**sniff_kwargs)
                        except Exception as e:
                            print(f"[!] Npcap sniffing failed: {e}")
                            print("[*] Trying alternative method...")
                            self._windows_alternative_sniff()
                    else:
                        print("[*] Using alternative method (no Npcap)")
                        self._windows_alternative_sniff()
                else:
                    # На Linux/Mac используем стандартный сниффинг
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
                self.sniffing = False

        self.sniff_thread = threading.Thread(target=sniff_task, daemon=True)
        self.sniff_thread.start()

        time.sleep(0.5)
        return True

    def _windows_alternative_sniff(self):
        """Альтернативный метод сниффинга для Windows без Npcap"""
        print("[*] Using alternative Windows sniffing method")
        print("[*] This method uses system tools and has limited functionality")

        try:
            # Пробуем использовать PowerShell для мониторинга сети
            print("[*] Using PowerShell for network monitoring")

            # Получаем информацию об интерфейсе
            iface_info = get_interface_info(self.current_interface)
            if not iface_info.get("ip"):
                print(f"[!] Interface {self.current_interface} has no IP address")
                print("[!] Cannot start network monitoring")
                return

            ip = iface_info["ip"]
            print(f"[*] Monitoring traffic for IP: {ip}")

            # Создаем простой UDP-сокет для анализа локального трафика
            # Этот метод имеет очень ограниченные возможности
            try:
                # Создаем сокет для захвата локального трафика
                self.socket_obj = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.socket_obj.bind((ip, 0))

                # Включаем promiscuous mode (если поддерживается)
                try:
                    self.socket_obj.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                except:
                    print("[*] Promiscuous mode not available, using normal mode")

                self.socket_obj.settimeout(1)

                while self.sniffing:
                    try:
                        packet_data, addr = self.socket_obj.recvfrom(65565)
                        self._process_raw_packet(packet_data, ip)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.packet_count % 100 == 0:
                            print(f"[!] Error receiving packet: {e}")
                        continue

            except Exception as e:
                print(f"[!] Socket creation failed: {e}")
                print("[*] Using simulated traffic analysis")

                # Если даже сокет не работает, симулируем анализ трафика
                # Это только для демонстрации интерфейса
                while self.sniffing:
                    time.sleep(2)
                    self._simulate_traffic(ip)

        except Exception as e:
            print(f"[!] Alternative sniffing failed: {e}")
            print("[*] Running in demo mode (no actual packet capture)")

    def _process_raw_packet(self, packet_data: bytes, local_ip: str):
        """Обработать сырой пакет"""
        try:
            if len(packet_data) < 20:
                return

            # Парсим IP заголовок
            ip_header = packet_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            # Фильтруем только трафик с участием локального IP
            if src_ip != local_ip and dst_ip != local_ip:
                return

            self.packet_count += 1
            self.byte_count += len(packet_data)

            # Обрабатываем TCP
            if protocol == 6 and len(packet_data) >= iph_length + 20:
                tcp_header = packet_data[iph_length:iph_length + 20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)

                src_port = tcph[0]
                dst_port = tcph[1]

                # Обрабатываем HTTP/HTTPS
                if dst_port == 80 or src_port == 80:
                    self._create_http_packet(src_ip, dst_ip, src_port, dst_port, packet_data, local_ip)
                elif dst_port == 443 or src_port == 443:
                    self._create_https_packet(src_ip, dst_ip, src_port, dst_port, packet_data, local_ip)
                else:
                    self._create_tcp_packet(src_ip, dst_ip, src_port, dst_port, packet_data, local_ip)

            # Обрабатываем UDP
            elif protocol == 17 and len(packet_data) >= iph_length + 8:
                udp_header = packet_data[iph_length:iph_length + 8]
                udph = struct.unpack('!HHHH', udp_header)

                src_port = udph[0]
                dst_port = udph[1]

                # Обрабатываем DNS
                if dst_port == 53 or src_port == 53:
                    self._create_dns_packet(src_ip, dst_ip, src_port, dst_port, packet_data, local_ip)
                else:
                    self._create_udp_packet(src_ip, dst_ip, src_port, dst_port, packet_data, local_ip)

        except Exception as e:
            if self.packet_count % 100 == 0:
                print(f"[!] Error processing raw packet: {e}")

    def _simulate_traffic(self, local_ip: str):
        """Симулировать трафик для демонстрации"""
        import random

        # Создаем демонстрационные пакеты
        demo_hosts = ["google.com", "youtube.com", "github.com", "stackoverflow.com"]
        demo_ips = ["142.250.185.78", "172.217.22.174", "140.82.121.3", "151.101.129.69"]

        for i in range(random.randint(1, 3)):
            host_idx = random.randint(0, len(demo_hosts)-1)
            host = demo_hosts[host_idx]
            server_ip = demo_ips[host_idx]

            # Случайный порт
            src_port = random.randint(49152, 65535)

            # Случайный тип трафика
            traffic_type = random.choice(["HTTP", "HTTPS", "DNS"])

            if traffic_type == "HTTP":
                self._create_http_packet(local_ip, server_ip, src_port, 80, b"", local_ip, host)
            elif traffic_type == "HTTPS":
                self._create_https_packet(local_ip, server_ip, src_port, 443, b"", local_ip, host)
            elif traffic_type == "DNS":
                self._create_dns_packet(local_ip, "8.8.8.8", src_port, 53, b"", local_ip, host)

            time.sleep(0.1)

    def _create_http_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                           packet_data: bytes, local_ip: str, host: str = None):
        """Создать HTTP пакет"""
        if not host:
            host = dst_ip if dst_port == 80 else src_ip

        method = "GET" if src_ip == local_ip else "RESPONSE"

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="HTTP",
            packet_type=PacketType.HTTP_REQUEST if src_ip == local_ip else PacketType.HTTP_RESPONSE,
            size=len(packet_data) if packet_data else 150,
            data={
                "method": method,
                "url": f"http://{host}/",
                "host": host,
                "path": "/",
                "headers": {},
                "version": "HTTP/1.1"
            },
            session_id=f"http-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        )
        self.session_manager.add_packet(packet_obj)

    def _create_https_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                            packet_data: bytes, local_ip: str, host: str = None):
        """Создать HTTPS пакет"""
        if not host:
            host = dst_ip if dst_port == 443 else src_ip

        direction = "client->server" if src_ip == local_ip else "server->client"

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="HTTPS",
            packet_type=PacketType.HTTPS_SESSION,
            size=len(packet_data) if packet_data else 200,
            data={
                "direction": direction,
                "client_ip": local_ip if direction == "client->server" else dst_ip,
                "server_ip": dst_ip if direction == "client->server" else src_ip,
                "tls_type": "Encrypted",
                "sni": host
            },
            session_id=f"https-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        )
        self.session_manager.add_packet(packet_obj)

    def _create_dns_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                          packet_data: bytes, local_ip: str, host: str = None):
        """Создать DNS пакет"""
        if not host:
            host = f"host-{random.randint(1, 100)}.com"

        is_query = src_ip == local_ip

        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="DNS",
            packet_type=PacketType.DNS_QUERY if is_query else PacketType.DNS_RESPONSE,
            size=len(packet_data) if packet_data else 100,
            data={
                "queries": [{"qname": host, "qtype": "A"}] if is_query else [],
                "answers": [{"rrname": host, "type": "A", "rdata": dst_ip}] if not is_query else []
            }
        )
        self.session_manager.add_packet(packet_obj)

    def _create_tcp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                          packet_data: bytes, local_ip: str):
        """Создать TCP пакет"""
        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="TCP",
            packet_type=PacketType.TCP_CONNECTION,
            size=len(packet_data) if packet_data else 100,
            data={
                "flags": "",
                "seq": 0,
                "ack": 0
            },
            session_id=f"tcp-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        )
        self.session_manager.add_packet(packet_obj)

    def _create_udp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                          packet_data: bytes, local_ip: str):
        """Создать UDP пакет"""
        packet_obj = Packet(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="UDP",
            packet_type=PacketType.UDP_SESSION,
            size=len(packet_data) if packet_data else 100,
            data={
                "payload_size": len(packet_data) if packet_data else 0
            },
            session_id=f"udp-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        )
        self.session_manager.add_packet(packet_obj)

    def stop_sniffing(self):
        """Остановить захват пакетов"""
        print("[*] Stopping sniffing...")
        self.sniffing = False

        if platform.system() == "Windows" and self.socket_obj:
            try:
                # Выключаем promiscuous mode
                try:
                    self.socket_obj.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except:
                    pass
                self.socket_obj.close()
            except:
                pass

        if self.sniff_thread:
            self.sniff_thread.join(timeout=2)
            print("[*] Sniffing stopped")
        return True

    # Остальные методы остаются без изменений...
    def process_packet(self, packet):
        """Обработать захваченный пакет (оригинальный метод для Linux/Windows с Npcap)"""
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
            if self.packet_count % 100 == 0:
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
                        tls_info['ciphers'] = [str(c) for c in ciphers[:5]]

            # Альтернативный метод для извлечения SNI из сырых данных
            elif packet.haslayer(Raw):
                raw_data = packet[Raw].load

                # Поиск SNI в Client Hello
                if b'\x00\x00' in raw_data and b'\x00\x16' in raw_data:
                    try:
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

        headers = {}
        if hasattr(http, 'fields'):
            for field, value in http.fields.items():
                if value:
                    headers[field] = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)

        post_data = None
        if method == "POST" and packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                post_data = raw_data.decode('utf-8', errors='ignore')
                if len(post_data) > 1000:
                    post_data = post_data[:1000] + "..."
            except:
                post_data = raw_data.hex()[:200] + "..." if len(raw_data) > 100 else raw_data.hex()

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

        response_body = None
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                response_body = raw_data.decode('utf-8', errors='ignore')
                if len(response_body) > 1000:
                    response_body = response_body[:1000] + "..."

                content_type = headers.get('Content-Type', '')
                if 'html' in content_type.lower():
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

        if tcp_layer.dport == 443:
            direction = "client->server"
            client_ip = ip_layer.src
            server_ip = ip_layer.dst
            client_port = tcp_layer.sport
            server_port = tcp_layer.dport
        else:
            direction = "server->client"
            client_ip = ip_layer.dst
            server_ip = ip_layer.src
            client_port = tcp_layer.dport
            server_port = tcp_layer.sport

        tls_info = self.extract_tls_info(packet)
        vulnerabilities = self.detect_ssl_vulnerabilities(tls_info)

        tls_type = "Unknown"
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            if len(raw_data) > 0:
                first_byte = raw_data[0]
                if first_byte == 22:
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

        data = {
            "direction": direction,
            "client_ip": client_ip,
            "server_ip": server_ip,
            "tls_type": tls_type,
            "tcp_flags": str(tcp_layer.flags),
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack
        }

        if tls_info:
            data.update(tls_info)

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

        if dns.qr == 0:
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
        else:
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
            "formatted_bytes": format_bytes(self.byte_count),
            "npcap_available": self.npcap_available
        }
