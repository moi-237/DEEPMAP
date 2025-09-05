# Writing DEEPMAP.py to /mnt/data and displaying its content for the user.
# The script performs an authorized LAN scan and generates a PDF report.
# It uses standard libs plus `nmap` (external binary) and `reportlab` Python package.
# If those are not installed, the script shows clear instructions.
script = r'''#!/usr/bin/env python3
\"\"\"DEEPMAP.py

Network scanner and PDF report generator for authorized use only.
Scans a network (e.g. 192.168.1.0/24), detects live hosts, scans specified ports
using the nmap binary, and generates a PDF report with the results.

Requirements (install before running):
 - nmap (system package): sudo apt install nmap
 - reportlab (python package): pip install reportlab

Usage examples:
  python DEEPMAP.py --network 192.168.1.0/24 --ports 22,80,443 --output reports/deepmap_report.pdf
  python DEEPMAP.py --network 192.168.253.0/24 --top-ports --output reports/report.pdf

Author: TAKENGNY TESSOH Wilson
License: MIT
\"\"\"

import argparse
import ipaddress
import shutil
import subprocess
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from xml.etree import ElementTree as ET

# Try import reportlab; if missing, we will show instruction at runtime
try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
except Exception:
    reportlab = None
else:
    reportlab = True

# --------------------------- Utility functions ---------------------------

def is_nmap_installed():
    return shutil.which('nmap') is not None

def generate_ip_list(network_cidr):
    net = ipaddress.ip_network(network_cidr, strict=False)
    # skip network and broadcast for IPv4 if applicable
    return [str(ip) for ip in net.hosts()]

def ping_host(ip):
    \"\"\"Return True if host replies to a single ping. Works on Linux/Mac (uses -c), may be slower.\"\"\"
    try:
        # -c 1 send one packet, -W 1 timeout 1 second (Linux)
        cp = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return cp.returncode == 0
    except Exception:
        return False

def scan_host_nmap_xml(ip, ports=None, top_ports=False):
    \"\"\"Run nmap and return parsed dict with open ports info.
    If top_ports True, uses --top-ports 100 instead of -p list.
    Returns: {'ip': ip, 'open_ports': [{'port':port, 'proto':proto, 'service':serv}], 'raw_xml': xmlstring}
    \"\"\"
    if not is_nmap_installed():
        raise RuntimeError('nmap binary not found. Please install nmap (e.g. sudo apt install nmap)')

    args = ['nmap', '-sS', '-Pn', '-T4', '-oX', '-', ip]  # -oX - => XML to stdout
    if top_ports:
        args.insert(1, '--top-ports')
        args.insert(2, '100')
    elif ports:
        args.insert(1, '-p')
        args.insert(2, ports)

    # run nmap
    cp = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if cp.returncode != 0 and not cp.stdout:
        raise RuntimeError(f'nmap scan failed for {ip}: {cp.stderr.strip()}')

    xml = cp.stdout
    result = {'ip': ip, 'open_ports': [], 'raw_xml': xml}

    try:
        root = ET.fromstring(xml)
        for host in root.findall('host'):
            addr = host.find('address')
            # find ports
            ports_elem = host.find('ports')
            if ports_elem is None:
                continue
            for p in ports_elem.findall('port'):
                state = p.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                portid = p.get('portid')
                proto = p.get('protocol')
                service = p.find('service')
                servname = service.get('name') if service is not None and 'name' in service.attrib else ''
                version = service.get('version') if service is not None and 'version' in service.attrib else ''
                product = service.get('product') if service is not None and 'product' in service.attrib else ''
                result['open_ports'].append({
                    'port': int(portid),
                    'proto': proto,
                    'service': servname,
                    'product': product,
                    'version': version
                })
    except ET.ParseError:
        # can't parse xml, but we return raw output in case user wants to inspect
        pass

    return result

# --------------------------- Report generation ---------------------------

def generate_pdf_report(results, network, output_path, scanned_by='DEEPMAP'):
    if not reportlab:
        raise RuntimeError('reportlab not installed. Install with: pip install reportlab')

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=landscape(A4), rightMargin=20, leftMargin=20, topMargin=20, bottomMargin=20)
    styles = getSampleStyleSheet()
    styleN = styles['Normal']
    styleH = styles['Heading1']

    elements = []
    title = Paragraph(f'DEEPMAP - Network scan report', styleH)
    elements.append(title)
    elements.append(Spacer(1, 6))
    meta = Paragraph(f'Network: <b>{network}</b> &nbsp;&nbsp; Generated: {datetime.now().isoformat()} &nbsp;&nbsp; Scanned by: {scanned_by}', styleN)
    elements.append(meta)
    elements.append(Spacer(1, 12))

    # Summary
    total_hosts = len(results)
    alive_hosts = sum(1 for r in results if r.get('alive', False))
    total_open_ports = sum(len(r.get('open_ports', [])) for r in results)
    summary = Paragraph(f'<b>Summary</b><br/>Hosts scanned: {total_hosts} &nbsp;&nbsp; Live hosts: {alive_hosts} &nbsp;&nbsp; Total open ports found: {total_open_ports}', styleN)
    elements.append(summary)
    elements.append(Spacer(1, 12))

    # Table header for each host
    for r in results:
        ip = r['ip']
        alive = r.get('alive', False)
        p = Paragraph(f'<b>Host:</b> {ip} &nbsp;&nbsp; <b>Alive:</b> {alive}', styleN)
        elements.append(p)
        elements.append(Spacer(1, 6))

        open_ports = r.get('open_ports', [])
        if not open_ports:
            elements.append(Paragraph('No open ports detected (or nmap parsing failed).', styleN))
            elements.append(Spacer(1, 6))
        else:
            table_data = [['Port', 'Proto', 'Service', 'Product', 'Version']]
            for op in open_ports:
                table_data.append([str(op.get('port')), op.get('proto', ''), op.get('service', ''), op.get('product', ''), op.get('version', '')])
            t = Table(table_data, hAlign='LEFT')
            t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#222222')),
                                   ('TEXTCOLOR',(0,0),(-1,0),colors.white),
                                   ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
                                   ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold')]))
            elements.append(t)
            elements.append(Spacer(1, 12))

        # page break every few hosts to keep layout neat
        if results.index(r) % 6 == 5:
            elements.append(PageBreak())

    # Build PDF
    doc.build(elements)

# --------------------------- Main CLI flow ---------------------------

def parse_args():
    p = argparse.ArgumentParser(description='DEEPMAP - Network scanner and PDF report generator (authorized use only)')
    p.add_argument('--network', required=True, help='Network CIDR to scan (e.g. 192.168.1.0/24)')
    p.add_argument('--ports', default=None, help='Comma-separated ports to scan (eg 22,80,443) or range (1-1024)')
    p.add_argument('--top-ports', action='store_true', help='Scan top 100 ports (nmap --top-ports 100)')
    p.add_argument('--output', default='deepmap_report.pdf', help='Output PDF path (default: deepmap_report.pdf)')
    p.add_argument('--workers', type=int, default=50, help='Number of threads for ping/scan (default: 50)')
    p.add_argument('--fast', action='store_true', help='Fast mode: ping sweep only (no port scan)')
    return p.parse_args()

def main():
    args = parse_args()

    # safety notice
    print('DEEPMAP - network scanner (authorized use only). Make sure you have permission to scan this network.')
    network = args.network

    # basic checks
    if not is_nmap_installed() and not args.fast:
        print('Warning: nmap is not installed. Port scanning will not work. Install nmap (sudo apt install nmap) or run with --fast to only do ping sweep.')
    if reportlab is None:
        print('Warning: reportlab Python package not installed. Install with: pip install reportlab to enable PDF generation.')

    # generate IP list
    ip_list = generate_ip_list(network)
    print(f'[*] IPs to check: {len(ip_list)} hosts (first 5): {ip_list[:5]}')

    results = []

    # Ping sweep using threads
    print('[*] Starting ping sweep... (this may take time)')
    with ThreadPoolExecutor(max_workers=min(args.workers, 200)) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in ip_list}
        for fut in as_completed(futures):
            ip = futures[fut]
            alive = False
            try:
                alive = fut.result()
            except Exception:
                alive = False
            results.append({'ip': ip, 'alive': alive, 'open_ports': []})

    alive_ips = [r['ip'] for r in results if r['alive']]
    print(f'[*] Ping sweep done. Alive hosts: {len(alive_ips)}')

    # If fast mode, skip port scan
    if args.fast or not is_nmap_installed():
        print('[*] Skipping port scan (fast mode or nmap missing).')
    else:
        print('[*] Starting port scans with nmap...')
        # scan each alive host with nmap (can be parallelized but be cautious)
        with ThreadPoolExecutor(max_workers=min(args.workers, 50)) as ex:
            futures = {}
            for ip in alive_ips:
                futures[ex.submit(scan_host_nmap_xml, ip, ports=args.ports, top_ports=args.top_ports)] = ip
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    res = fut.result()
                    # find corresponding entry in results and update
                    for r in results:
                        if r['ip'] == ip:
                            r['open_ports'] = res.get('open_ports', [])
                except Exception as e:
                    print(f'[!] nmap scan failed for {ip}: {e}')

    # Generate PDF report
    output_path = args.output
    try:
        if reportlab is None:
            print('[!] reportlab not installed; printing summary to console instead.')
            # print short summary
            print('---- SUMMARY ----')
            for r in results:
                if r['alive'] or r['open_ports']:
                    print(f\"{r['ip']} - alive: {r['alive']} - open ports: {[p['port'] for p in r.get('open_ports',[])]}\")
            print('---- END ----')
        else:
            print(f'[*] Generating PDF report at: {output_path}')
            generate_pdf_report(results, network, output_path)
            print('[*] Report generated successfully.')
    except Exception as e:
        print(f'[!] Failed to generate report: {e}')

if __name__ == '__main__':
    main()
'''

path = '/mnt/data/DEEPMAP.py'
with open(path, 'w', encoding='utf-8') as f:
    f.write(script)

# Show the file content back to the user for copy-paste
print(f"Script written to: {path}\n\n--- BEGIN OF DEEPMAP.py ---\n")
with open(path, 'r', encoding='utf-8') as f:
    print(f.read())
print("\n--- END OF DEEPMAP.py ---\n\n")
print("Requirements:\n - Install nmap (system package) e.g. sudo apt install nmap\n - Install reportlab (python): pip install reportlab\n\nUsage example:\n python /mnt/data/DEEPMAP.py --network 192.168.1.0/24 --ports 22,80,443 --output /mnt/data/reports/deepmap_report.pdf\n\nNote: Only scan networks you own or are authorized to test.")