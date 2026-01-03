#!/usr/bin/env python3

import hashlib

class SSLAnalyzer:
    def __init__(self):
        self.weak = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT']
        self.bad_proto = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']

    def analyze(self, pkt_data):
        result = {
            'risk': 'LOW',
            'issues': [],
            'grade': 'A+'
        }

        # Protocol
        ver = pkt_data.get('version', '').upper()
        for p in self.bad_proto:
            if p in ver:
                result['issues'].append(f"Bad protocol: {ver}")
                result['risk'] = 'HIGH'
                result['grade'] = 'F'

        # Ciphers
        ciphers = pkt_data.get('ciphers', [])
        weak = []
        for c in ciphers:
            cstr = str(c).upper()
            for w in self.weak:
                if w in cstr:
                    weak.append(cstr)

        if weak:
            result['issues'].append(f"Weak ciphers: {', '.join(weak[:3])}")
            if result['risk'] != 'HIGH':
                result['risk'] = 'MEDIUM'
                result['grade'] = 'C'

        # Certificate
        cert = pkt_data.get('certificate', {})
        if cert.get('issuer') == cert.get('subject'):
            result['issues'].append("Self-signed certificate")
            if result['risk'] != 'HIGH':
                result['risk'] = 'MEDIUM'
                result['grade'] = 'B'

        # SNI
        if not pkt_data.get('sni'):
            result['issues'].append("No SNI")

        return result

    def fingerprint(self, pkt_data):
        data = []
        data.append(f"ver:{pkt_data.get('version', '')}")
        data.append(f"ciphers:{','.join(str(c) for c in pkt_data.get('ciphers', [])[:3])}")
        data.append(f"sni:{pkt_data.get('sni', '')}")

        s = '|'.join(data)
        return hashlib.md5(s.encode()).hexdigest()[:8]
