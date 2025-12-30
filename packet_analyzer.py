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
from typing import Optional, Dict, Any
from session_manager import Packet, PacketType, SessionManager
from utils import format_bytes
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
                    # На Windows без Npcap используем сырые сокеты для анализа
                    self._windows_raw_socket_sniff()
                else:
                    # На Linux используем стандартный сниффинг
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

    def _windows_raw_socket_sniff(self):
        """Альтернативный метод сниффинга для Windows без Npcap"""
        print("[*] Using raw socket method for Windows (limited functionality)")
        print("[*] Note: This method can only analyze local traffic")

        try:
            # Создаем сырой сокет для перехвата TCP/UDP пакетов
            self.socket_obj = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

            # Биндим на все интерфейсы
            self.socket_obj.bind(('0.0.0.0', 0))

            # Включаем promiscuous mode
            self.socket_obj.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            while self.sniffing:
                try:
                    # Читаем пакет
                    packet_data = self.socket_obj.recvfrom(65565)[0]

                    # Парсим IP заголовок
                    ip_header = packet_data[0:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

                    version_ihl = iph[0]
                    ihl = version_ihl & 0xF
                    iph_length = ihl * 4

                    protocol = iph[6]
                    src_ip = socket.inet_ntoa(iph[8])
                    dst_ip = socket.inet_ntoa(iph[9])

                    # Обрабатываем TCP
                    if protocol == 6:
                        tcp_header = packet_data[iph_length:iph_length + 20]
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

                        src_port = tcph[0]
                        dst_port = tcph[1]
                        data_offset = (tcph[4] >> 4) * 4

                        # Извлекаем данные
                        h_size = iph_length + data_offset
                        data = packet_data[h_size:]

                        # Создаем минимальный объект пакета для обработки
                        class SimplePacket:
                            def __init__(self):
                                self.layers = []

                            def haslayer(self, layer):
                                return layer in self.layers

                            def __len__(self):
                                return len(packet_data)

                        packet = SimplePacket()
                        packet.layers = ['IP', 'TCP']
                        packet[IP] = type('IP', (), {'src': src_ip, 'dst': dst_ip})()
                        packet[TCP] = type('TCP', (), {
                            'sport': src_port,
                            'dport': dst_port,
                            'flags': '',
                            'seq': 0,
                            'ack': 0
                        })()

                        # Добавляем Raw слой если есть данные
                        if data:
                            packet[Raw] = type('Raw', (), {'load': data})()
                            packet.layers.append('Raw')

                        # Обрабатываем HTTP/HTTPS
                        if dst_port == 80 or src_port == 80:
                            packet.layers.append('HTTP')
                            self._process_simple_http(packet, src_ip, dst_ip, src_port, dst_port, data)
                        elif dst_port == 443 or src_port == 443:
                            packet.layers.append('TLS')
                            self._process_simple_https(packet, src_ip, dst_ip, src_port, dst_port)
                        else:
                            self._process_simple_tcp(packet, src_ip, dst_ip, src_port, dst_port)

                        self.packet_count += 1
                        self.byte_count += len(packet_data)

                    # Обрабатываем UDP
                    elif protocol == 17:
                        udp_header = packet_data[iph_length:iph_length + 8]
                        udph = struct.unpack('!HHHH', udp_header)

                        src_port = udph[0]
                        dst_port = udph[1]
                        udp_length = udph[2]

                        data = packet_data[iph_length + 8:iph_length + udp_length]

                        packet = SimplePacket()
                        packet.layers = ['IP', 'UDP']
                        packet[IP] = type('IP', (), {'src': src_ip, 'dst': dst_ip})()
                        packet[UDP] = type('UDP', (), {
                            'sport': src_port,
                            'dport': dst_port
                        })()

                        if data:
                            packet[Raw] = type('Raw', (), {'load': data})()
                            packet.layers.append('Raw')

                        # Обрабатываем DNS
                        if dst_port == 53 or src_port == 53:
                            packet.layers.append('DNS')
                            self._process_simple_dns(packet, src_ip, dst_ip, src_port, dst_port, data)
                        else:
                            self._process_simple_udp(packet, src_ip, dst_ip, src_port, dst_port)

                        self.packet_count += 1
                        self.byte_count += len(packet_data)

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.packet_count % 100 == 0:
                        print(f"[!] Error processing raw packet: {e}")
                    continue

        except Exception as e:
            print(f"[!] Raw socket error: {e}")
            self.sniffing = False
        finally:
            if self.socket_obj:
                try:
                    self.socket_obj.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    self.socket_obj.close()
                except:
                    pass

    def _process_simple_http(self, packet, src_ip, dst_ip, src_port, dst_port, data):
        """Обработать простой HTTP пакет"""
        try:
            if data:
                data_str = data.decode('utf-8', errors='ignore').lower()

                # Определяем тип HTTP пакета
                if data_str.startswith(('get ', 'post ', 'put ', 'delete ', 'head ', 'options ')):
                    # HTTP запрос
                    lines = data_str.split('\r\n')
                    if lines:
                        method_line = lines[0].split()
                        if len(method_line) >= 2:
                            method = method_line[0].upper()
                            path = method_line[1]

                            # Извлекаем хост
                            host = "Unknown"
                            for line in lines[1:]:
                                if line.startswith('host:'):
                                    host = line.split(':', 1)[1].strip()
                                    break

                            packet_obj = Packet(
                                timestamp=time.time(),
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                src_port=src_port,
                                dst_port=dst_port,
                                protocol="HTTP",
                                packet_type=PacketType.HTTP_REQUEST,
                                size=len(data),
                                data={
                                    "method": method,
                                    "url": f"http://{host}{path}",
                                    "host": host,
                                    "path": path,
                                    "headers": {},
                                    "version": "HTTP/1.1"
                                },
                                session_id=f"http-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                            )
                            self.session_manager.add_packet(packet_obj)

                elif data_str.startswith('http/'):
                    # HTTP ответ
                    lines = data_str.split('\r\n')
                    if lines:
                        status_line = lines[0].split()
                        if len(status_line) >= 2:
                            status_code = status_line[1]

                            packet_obj = Packet(
                                timestamp=time.time(),
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                src_port=src_port,
                                dst_port=dst_port,
                                protocol="HTTP",
                                packet_type=PacketType.HTTP_RESPONSE,
                                size=len(data),
                                data={
                                    "status_code": status_code,
                                    "reason_phrase": " ".join(status_line[2:]),
                                    "headers": {},
                                    "content_length": "Unknown"
                                },
                                session_id=f"http-{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                            )
                            self.session_manager.add_packet(packet_obj)

        except Exception as e:
            pass

    def _process_simple_https(self, packet, src_ip, dst_ip, src_port, dst_port):
        """Обработать простой HTTPS пакет"""
        try:
            # Определяем направление
            if dst_port == 443:  # Клиент -> Сервер
                direction = "client->server"
                client_ip = src_ip
                server_ip = dst_ip
                client_port = src_port
                server_port = dst_port
            else:  # Сервер -> Клиент
                direction = "server->client"
                client_ip = dst_ip
                server_ip = src_ip
                client_port = dst_port
                server_port = src_port

            packet_obj = Packet(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol="HTTPS",
                packet_type=PacketType.HTTPS_SESSION,
                size=1500,  # Примерный размер
                data={
                    "direction": direction,
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "tls_type": "Encrypted",
                    "tcp_flags": "",
                    "seq": 0,
                    "ack": 0
                },
                session_id=f"https-{client_ip}:{client_port}-{server_ip}:{server_port}"
            )
            self.session_manager.add_packet(packet_obj)

        except Exception as e:
            pass

    def _process_simple_dns(self, packet, src_ip, dst_ip, src_port, dst_port, data):
        """Обработать простой DNS пакет"""
        try:
            if data and len(data) > 12:
                # Парсим DNS заголовок
                transaction_id = data[0:2]
                flags = data[2:4]
                qr = (flags[0] >> 7) & 0x1

                if qr == 0:  # DNS запрос
                    packet_type = PacketType.DNS_QUERY
                    # Извлекаем доменное имя (упрощенно)
                    domain_parts = []
                    pos = 12
                    while pos < len(data) and data[pos] != 0:
                        length = data[pos]
                        pos += 1
                        if pos + length <= len(data):
                            domain_parts.append(data[pos:pos+length].decode('utf-8', errors='ignore'))
                            pos += length

                    domain = '.'.join(domain_parts)

                    data_dict = {"queries": [{"qname": domain, "qtype": "A"}]}
                else:  # DNS ответ
                    packet_type = PacketType.DNS_RESPONSE
                    data_dict = {"answers": [{"rrname": "unknown", "type": "A", "rdata": "unknown"}]}

                packet_obj = Packet(
                    timestamp=time.time(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="DNS",
                    packet_type=packet_type,
                    size=len(data),
                    data=data_dict
                )
                self.session_manager.add_packet(packet_obj)

        except Exception as e:
            pass

    def _process_simple_tcp(self, packet, src_ip, dst_ip, src_port, dst_port):
        """Обработать простой TCP пакет"""
        try:
            packet_obj = Packet(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol="TCP",
                packet_type=PacketType.TCP_CONNECTION,
                size=1500,
                data={
                    "flags": "",
                    "seq": 0,
                    "ack": 0,
                    "window": 0,
                    "payload_size": 0
                },
                session_id=f"tcp-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            )
            self.session_manager.add_packet(packet_obj)
        except Exception as e:
            pass

    def _process_simple_udp(self, packet, src_ip, dst_ip, src_port, dst_port):
        """Обработать простой UDP пакет"""
        try:
            packet_obj = Packet(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol="UDP",
                packet_type=PacketType.UDP_SESSION,
                size=1500,
                data={
                    "payload_size": 0
                },
                session_id=f"udp-{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            )
            self.session_manager.add_packet(packet_obj)
        except Exception as e:
            pass

    def stop_sniffing(self):
        """Остановить захват пакетов"""
        print("[*] Stopping sniffing...")
        self.sniffing = False

        if platform.system() == "Windows" and self.socket_obj:
            try:
                self.socket_obj.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.socket_obj.close()
            except:
                pass

        if self.sniff_thread:
            self.sniff_thread.join(timeout=2)
            print("[*] Sniffing stopped")
        return True

    def process_packet(self, packet):
        """Обработать захваченный пакет (оригинальный метод для Linux)"""
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

    # Остальные методы остаются без изменений (extract_tls_info, detect_ssl_vulnerabilities,
    # _process_http_request, _process_http_response, _process_https_metadata,
    # _process_dns, _process_tcp_connection, _process_udp_session)

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
            "formatted_bytes": format_bytes(self.byte_count)
        }
