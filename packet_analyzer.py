#!/usr/bin/env python3

import threading
import time
import platform
import os
from scapy.all import *
from session_manager import Packet, PacketType, SessionManager
from utils import format_bytes

class PacketAnalyzer:
    def __init__(self, session_manager):
        self.sm = session_manager
        self.sniffing = False
        self.thread = None
        self.intf = None
        self.count = 0
        self.bytes = 0
        self.npcap = self._check_npcap()

    def _check_npcap(self):
        if platform.system() != "Windows":
            return True

        paths = [
            r"C:\Windows\System32\Npcap",
            r"C:\Program Files\Npcap",
            r"C:\Windows\System32\wpcap.dll"
        ]
        return any(os.path.exists(p) for p in paths)

    def start(self, intf, filt="tcp port 80 or tcp port 443 or udp port 53"):
        if self.sniffing:
            self.stop()

        self.sniffing = True
        self.intf = intf
        self.count = 0
        self.bytes = 0

        def task():
            try:
                if platform.system() == "Windows" and not self.npcap:
                    self._win_sniff()
                else:
                    sniff(iface=intf, filter=filt, prn=self._process,
                          store=False, stop_filter=lambda x: not self.sniffing)
            except Exception as e:
                print(f"Sniff error: {e}")
                self.sniffing = False

        self.thread = threading.Thread(target=task, daemon=True)
        self.thread.start()
        time.sleep(0.5)
        return True

    def _win_sniff(self):
        """Windows fallback"""
        print("Windows limited mode - simulating traffic")
        import random
        hosts = ["google.com", "youtube.com", "github.com"]

        while self.sniffing:
            time.sleep(2)
            h = random.choice(hosts)
            p = Packet(
                timestamp=time.time(),
                src_ip="192.168.1.100",
                dst_ip="142.250.185.78",
                src_port=random.randint(49152, 65535),
                dst_port=443,
                protocol="HTTPS",
                packet_type=PacketType.HTTPS_SESSION,
                size=200,
                data={"sni": h, "direction": "client->server"},
                session_id=f"https-192.168.1.100-142.250.185.78"
            )
            self.sm.add_packet(p)

    def _process(self, pkt):
        if not self.sniffing or not pkt.haslayer(IP):
            return

        self.count += 1
        self.bytes += len(pkt)

        if self.count % 50 == 0:
            print(f"Packets: {self.count}, Bytes: {format_bytes(self.bytes)}")

        # HTTP
        if pkt.haslayer(HTTPRequest):
            self._http_req(pkt)
        elif pkt.haslayer(HTTPResponse):
            self._http_resp(pkt)
        # HTTPS
        elif pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
            self._https(pkt)
        # DNS
        elif pkt.haslayer(DNS):
            self._dns(pkt)
        # TCP
        elif pkt.haslayer(TCP):
            self._tcp(pkt)
        # UDP
        elif pkt.haslayer(UDP):
            self._udp(pkt)

    def _http_req(self, pkt):
        http = pkt[HTTPRequest]
        p = Packet(
            timestamp=time.time(),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            src_port=pkt[TCP].sport,
            dst_port=pkt[TCP].dport,
            protocol="HTTP",
            packet_type=PacketType.HTTP_REQUEST,
            size=len(pkt),
            data={
                "method": http.Method.decode() if http.Method else "GET",
                "host": http.Host.decode() if http.Host else pkt[IP].dst,
                "path": http.Path.decode() if http.Path else "/"
            },
            session_id=f"http-{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
        )
        self.sm.add_packet(p)

    def _http_resp(self, pkt):
        http = pkt[HTTPResponse]
        p = Packet(
            timestamp=time.time(),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            src_port=pkt[TCP].sport,
            dst_port=pkt[TCP].dport,
            protocol="HTTP",
            packet_type=PacketType.HTTP_RESPONSE,
            size=len(pkt),
            data={
                "status": http.Status_Code if hasattr(http, 'Status_Code') else 200,
                "reason": http.Reason_Phrase if hasattr(http, 'Reason_Phrase') else "OK"
            }
        )
        self.sm.add_packet(p)

    def _https(self, pkt):
        data = {
            "direction": "client->server" if pkt[TCP].dport == 443 else "server->client",
            "client_ip": pkt[IP].src if pkt[TCP].dport == 443 else pkt[IP].dst,
            "server_ip": pkt[IP].dst if pkt[TCP].dport == 443 else pkt[IP].src
        }

        # Try to get SNI
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            if b'\x00\x00' in raw:
                try:
                    start = raw.find(b'\x00\x00')
                    if start != -1 and start + 5 < len(raw):
                        length = int.from_bytes(raw[start+3:start+5], 'big')
                        if start + 5 + length <= len(raw):
                            sni = raw[start+5:start+5+length].decode('utf-8', 'ignore')
                            data['sni'] = sni
                except:
                    pass

        p = Packet(
            timestamp=time.time(),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            src_port=pkt[TCP].sport,
            dst_port=pkt[TCP].dport,
            protocol="HTTPS",
            packet_type=PacketType.HTTPS_SESSION,
            size=len(pkt),
            data=data,
            session_id=f"https-{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
        )
        self.sm.add_packet(p)

    def _dns(self, pkt):
        dns = pkt[DNS]
        if dns.qr == 0:
            ptype = PacketType.DNS_QUERY
            data = {"queries": [{"qname": q.qname.decode() if hasattr(q.qname, 'decode') else str(q.qname)}
                               for q in dns[DNSQR]]}
        else:
            ptype = PacketType.DNS_RESPONSE
            data = {"answers": [{"rrname": a.rrname.decode() if hasattr(a.rrname, 'decode') else str(a.rrname),
                                "rdata": a.rdata.decode() if hasattr(a.rdata, 'decode') else str(a.rdata)}
                               for a in dns[DNSRR]]}

        p = Packet(
            timestamp=time.time(),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            src_port=pkt[UDP].sport if pkt.haslayer(UDP) else pkt[TCP].sport,
            dst_port=pkt[UDP].dport if pkt.haslayer(UDP) else pkt[TCP].dport,
            protocol="DNS",
            packet_type=ptype,
            size=len(pkt),
            data=data
        )
        self.sm.add_packet(p)

    def _tcp(self, pkt):
        p = Packet(
            timestamp=time.time(),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            src_port=pkt[TCP].sport,
            dst_port=pkt[TCP].dport,
            protocol="TCP",
            packet_type=PacketType.TCP_CONNECTION,
            size=len(pkt),
            data={"flags": str(pkt[TCP].flags)},
            session_id=f"tcp-{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
        )
        self.sm.add_packet(p)

    def _udp(self, pkt):
        p = Packet(
            timestamp=time.time(),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            src_port=pkt[UDP].sport,
            dst_port=pkt[UDP].dport,
            protocol="UDP",
            packet_type=PacketType.UDP_SESSION,
            size=len(pkt),
            data={},
            session_id=f"udp-{pkt[IP].src}:{pkt[UDP].sport}-{pkt[IP].dst}:{pkt[UDP].dport}"
        )
        self.sm.add_packet(p)

    def stop(self):
        self.sniffing = False
        if self.thread:
            self.thread.join(timeout=2)
        return True

    def get_stats(self):
        return {
            "sniffing": self.sniffing,
            "interface": self.intf,
            "packets": self.count,
            "bytes": self.bytes,
            "bytes_fmt": format_bytes(self.bytes),
            "npcap": self.npcap
        }
