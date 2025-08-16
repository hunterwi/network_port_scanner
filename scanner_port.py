#!/usr/bin/env python3
"""
Scanner de Ports Réseau
======================

Outil Python avancé pour scanner les ports ouverts sur des hôtes réseau.
Supporte les protocoles TCP/UDP, le multithreading et la détection de services.

Auteur: EGBOHOU William Manguiliwe
Date: Aout 2025
Version: 1.0
"""

import socket
import threading
import time
import argparse
import sys
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network, ip_address
import subprocess
import re

class NetworkScanner:
    """Classe principale pour le scan de ports réseau."""
    
    def __init__(self, timeout=3, max_threads=100):
        """
        Initialise le scanner réseau.
        
        Args:
            timeout (int): Délai d'expiration des connexions en secondes
            max_threads (int): Nombre maximum de threads concurrents
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.scan_results = []
        self.services_db = self._load_services_db()
        
        # Statistiques
        self.total_ports = 0
        self.open_ports = 0
        self.closed_ports = 0
        self.scan_start_time = None
    
    def _load_services_db(self):
        """Charge la base de données des services communs."""
        return {
            # Services Web
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            8000: 'HTTP-Alt',
            3000: 'HTTP-Dev',
            
            # Services Mail
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            993: 'IMAPS',
            995: 'POP3S',
            587: 'SMTP-Submit',
            
            # Services Base de données
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            1521: 'Oracle',
            27017: 'MongoDB',
            6379: 'Redis',
            
            # Services Réseau
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            53: 'DNS',
            67: 'DHCP-Server',
            68: 'DHCP-Client',
            69: 'TFTP',
            
            # Services Windows
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB',
            3389: 'RDP',
            5985: 'WinRM-HTTP',
            5986: 'WinRM-HTTPS',
            
            # Services Unix/Linux
            111: 'RPCBind',
            512: 'Rexec',
            513: 'Rlogin',
            514: 'RSH',
            515: 'LPR',
            
            # Services de Sécurité
            161: 'SNMP',
            162: 'SNMP-Trap',
            389: 'LDAP',
            636: 'LDAPS',
            88: 'Kerberos',
            749: 'Kerberos-Admin',
            
            # Services de Partage
            2049: 'NFS',
            548: 'AFP',
            631: 'IPP',
            
            # Services Développement
            5000: 'Flask-Dev',
            3001: 'React-Dev',
            4000: 'Angular-Dev',
            8888: 'Jupyter',
            9000: 'Django-Dev',
            
            # Services Monitoring
            9090: 'Prometheus',
            3000: 'Grafana',
            9200: 'Elasticsearch',
            5601: 'Kibana',
            
            # Autres services communs
            119: 'NNTP',
            220: 'IMAP3',
            993: 'IMAPS',
            995: 'POP3S'
        }
    
    def scan_tcp_port(self, host, port):
        """
        Scan un port TCP spécifique.
        
        Args:
            host (str): Adresse IP ou nom d'hôte
            port (int): Numéro de port à scanner
        
        Returns:
            dict: Résultat du scan
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    # Port ouvert, tenter d'identifier le service
                    service_info = self._identify_service(host, port, 'tcp')
                    return {
                        'host': host,
                        'port': port,
                        'protocol': 'tcp',
                        'status': 'open',
                        'service': service_info.get('service', self.services_db.get(port, 'Unknown')),
                        'banner': service_info.get('banner', ''),
                        'version': service_info.get('version', ''),
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    return {
                        'host': host,
                        'port': port,
                        'protocol': 'tcp',
                        'status': 'closed',
                        'service': '',
                        'banner': '',
                        'version': '',
                        'timestamp': datetime.now().isoformat()
                    }
        
        except socket.gaierror:
            return {
                'host': host,
                'port': port,
                'protocol': 'tcp',
                'status': 'error',
                'service': '',
                'banner': '',
                'version': '',
                'error': 'Host resolution failed',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'host': host,
                'port': port,
                'protocol': 'tcp',
                'status': 'error',
                'service': '',
                'banner': '',
                'version': '',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def scan_udp_port(self, host, port):
        """
        Scan un port UDP spécifique.
        
        Args:
            host (str): Adresse IP ou nom d'hôte
            port (int): Numéro de port à scanner
        
        Returns:
            dict: Résultat du scan
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                
                # Envoyer un paquet de test
                test_data = b'\x00' * 4  # Données de test génériques
                sock.sendto(test_data, (host, port))
                
                try:
                    # Tenter de recevoir une réponse
                    data, addr = sock.recvfrom(1024)
                    return {
                        'host': host,
                        'port': port,
                        'protocol': 'udp',
                        'status': 'open',
                        'service': self.services_db.get(port, 'Unknown'),
                        'banner': data.decode('utf-8', errors='ignore')[:100],
                        'version': '',
                        'timestamp': datetime.now().isoformat()
                    }
                except socket.timeout:
                    # Pas de réponse = potentiellement ouvert ou filtré
                    return {
                        'host': host,
                        'port': port,
                        'protocol': 'udp',
                        'status': 'open|filtered',
                        'service': self.services_db.get(port, 'Unknown'),
                        'banner': '',
                        'version': '',
                        'timestamp': datetime.now().isoformat()
                    }
        
        except Exception as e:
            return {
                'host': host,
                'port': port,
                'protocol': 'udp',
                'status': 'error',
                'service': '',
                'banner': '',
                'version': '',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _identify_service(self, host, port, protocol):
        """
        Tente d'identifier le service et sa version.
        
        Args:
            host (str): Adresse IP ou nom d'hôte
            port (int): Numéro de port
            protocol (str): Protocole (tcp/udp)
        
        Returns:
            dict: Informations sur le service
        """
        service_info = {
            'service': self.services_db.get(port, 'Unknown'),
            'banner': '',
            'version': ''
        }
        
        if protocol != 'tcp':
            return service_info
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)  # Timeout court pour l'identification
                sock.connect((host, port))
                
                # Récupérer la bannière du service
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    service_info['banner'] = banner[:200]  # Limiter la taille
                    
                    # Analyser la bannière pour extraire des informations
                    service_info.update(self._parse_banner(banner, port))
                    
                except socket.timeout:
                    pass
                except Exception:
                    pass
        
        except Exception:
            pass
        
        return service_info
    
    def _parse_banner(self, banner, port):
        """
        Parse une bannière de service pour extraire des informations.
        
        Args:
            banner (str): Bannière du service
            port (int): Port du service
        
        Returns:
            dict: Informations extraites
        """
        info = {}
        banner_lower = banner.lower()
        
        # Détection de services spécifiques
        if port == 22 and ('ssh' in banner_lower or 'openssh' in banner_lower):
            info['service'] = 'SSH'
            # Extraire la version SSH
            ssh_match = re.search(r'openssh[_\s]+(\d+\.\d+)', banner_lower)
            if ssh_match:
                info['version'] = f"OpenSSH {ssh_match.group(1)}"
        
        elif port == 80 or port == 8080:
            info['service'] = 'HTTP'
            if 'apache' in banner_lower:
                apache_match = re.search(r'apache[/\s]+(\d+\.\d+\.\d+)', banner_lower)
                if apache_match:
                    info['version'] = f"Apache {apache_match.group(1)}"
            elif 'nginx' in banner_lower:
                nginx_match = re.search(r'nginx[/\s]+(\d+\.\d+\.\d+)', banner_lower)
                if nginx_match:
                    info['version'] = f"Nginx {nginx_match.group(1)}"
        
        elif port == 21 and 'ftp' in banner_lower:
            info['service'] = 'FTP'
            if 'vsftpd' in banner_lower:
                vsftpd_match = re.search(r'vsftpd[/\s]+(\d+\.\d+\.\d+)', banner_lower)
                if vsftpd_match:
                    info['version'] = f"vsftpd {vsftpd_match.group(1)}"
        
        elif port == 25 and ('smtp' in banner_lower or 'mail' in banner_lower):
            info['service'] = 'SMTP'
            if 'postfix' in banner_lower:
                info['version'] = 'Postfix'
            elif 'sendmail' in banner_lower:
                info['version'] = 'Sendmail'
        
        elif port == 3306 and 'mysql' in banner_lower:
            info['service'] = 'MySQL'
            mysql_match = re.search(r'(\d+\.\d+\.\d+)', banner_lower)
            if mysql_match:
                info['version'] = f"MySQL {mysql_match.group(1)}"
        
        return info
    
    def scan_host(self, host, ports, protocols=['tcp'], show_closed=False):
        """
        Scan tous les ports spécifiés sur un hôte.
        
        Args:
            host (str): Adresse IP ou nom d'hôte
            ports (list): Liste des ports à scanner
            protocols (list): Protocoles à scanner ('tcp', 'udp')
            show_closed (bool): Afficher les ports fermés
        
        Returns:
            list: Résultats de scan
        """
        results = []
        self.total_ports = len(ports) * len(protocols)
        self.scan_start_time = time.time()
        
        print(f"\n🔍 Début du scan de {host}")
        print(f"📊 Ports à scanner: {len(ports)} | Protocoles: {', '.join(protocols)}")
        print(f"🧵 Threads maximum: {self.max_threads} | Timeout: {self.timeout}s")
        print("-" * 60)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Créer les tâches de scan
            future_to_info = {}
            
            for protocol in protocols:
                for port in ports:
                    if protocol == 'tcp':
                        future = executor.submit(self.scan_tcp_port, host, port)
                    elif protocol == 'udp':
                        future = executor.submit(self.scan_udp_port, host, port)
                    else:
                        continue
                    
                    future_to_info[future] = {'host': host, 'port': port, 'protocol': protocol}
            
            # Traiter les résultats au fur et à mesure
            completed = 0
            for future in as_completed(future_to_info):
                result = future.result()
                results.append(result)
                completed += 1
                
                # Affichage en temps réel des ports ouverts
                if result['status'] == 'open' or (show_closed and result['status'] == 'closed'):
                    status_icon = self._get_status_icon(result['status'])
                    service_info = f" ({result['service']})" if result['service'] and result['service'] != 'Unknown' else ""
                    banner_info = f" - {result['banner'][:50]}..." if result['banner'] else ""
                    
                    print(f"{status_icon} {result['protocol'].upper()}/{result['port']}{service_info}{banner_info}")
                
                if result['status'] == 'open':
                    self.open_ports += 1
                else:
                    self.closed_ports += 1
                
                # Affichage du progrès
                if completed % 50 == 0 or completed == self.total_ports:
                    progress = (completed / self.total_ports) * 100
                    elapsed = time.time() - self.scan_start_time
                    print(f"📈 Progrès: {completed}/{self.total_ports} ({progress:.1f}%) - {elapsed:.1f}s")
        
        self.scan_results = results
        return results
    
    def _get_status_icon(self, status):
        """Retourne l'icône correspondant au statut."""
        icons = {
            'open': '🟢',
            'closed': '🔴',
            'filtered': '🟡',
            'open|filtered': '🟠',
            'error': '❌'
        }
        return icons.get(status, '❓')
    
    def scan_network_range(self, network_range, ports, protocols=['tcp']):
        """
        Scan une plage d'adresses IP.
        
        Args:
            network_range (str): Plage réseau (ex: 192.168.1.0/24)
            ports (list): Liste des ports à scanner
            protocols (list): Protocoles à scanner
        
        Returns:
            dict: Résultats par hôte
        """
        try:
            network = ip_network(network_range, strict=False)
            hosts_results = {}
            
            print(f"\n🌐 Scan de la plage réseau: {network_range}")
            print(f"📡 Nombre d'hôtes: {network.num_addresses}")
            print(f"🔍 Ports par hôte: {len(ports)}")
            
            # Scan de chaque hôte dans la plage
            for host_ip in network.hosts():
                host_str = str(host_ip)
                print(f"\n--- Scan de {host_str} ---")
                
                # Vérifier d'abord si l'hôte est accessible
                if self._is_host_alive(host_str):
                    results = self.scan_host(host_str, ports, protocols)
                    # Ne garder que les ports ouverts
                    open_results = [r for r in results if r['status'] == 'open']
                    if open_results:
                        hosts_results[host_str] = open_results
                else:
                    print(f"❌ Hôte {host_str} inaccessible")
            
            return hosts_results
            
        except ValueError as e:
            print(f"❌ Erreur de format réseau: {e}")
            return {}
    
    def _is_host_alive(self, host, timeout=1):
        """
        Vérifie si un hôte est accessible via ping.
        
        Args:
            host (str): Adresse IP ou nom d'hôte
            timeout (int): Timeout en secondes
        
        Returns:
            bool: True si l'hôte répond
        """
        try:
            # Commande ping selon l'OS
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), host]
            
            result = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
            return result.returncode == 0
        
        except Exception:
            return False
    
    def get_common_ports(self):
        """Retourne les ports les plus communs à scanner."""
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
        ]
    
    def get_top_ports(self, count=100):
        """
        Retourne le top N des ports les plus scannés.
        
        Args:
            count (int): Nombre de ports à retourner
        
        Returns:
            list: Liste des ports
        """
        top_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017, 1433, 1521,
            161, 162, 389, 636, 88, 749, 2049, 548, 631, 119, 220, 5000, 3000,
            4000, 8888, 9000, 9090, 9200, 5601, 587, 69, 67, 68, 512, 513, 514,
            515, 3001, 8000, 5985, 5986, 1080, 8008, 8888, 10000, 5060, 5061,
            1194, 500, 4500, 1701, 1812, 1813, 102, 502, 20000, 47808, 2222,
            2323, 8181, 8282, 9080, 9443, 7001, 7002, 8001, 8002, 8090, 8091,
            9001, 9002, 10080, 10443, 8180, 8280, 7777, 7778, 6666, 6667, 6668,
            5555, 5556, 4444, 4445, 3333, 2020, 2121, 2525, 2626, 9999, 10001
        ]
        return top_ports[:count]
    
    def generate_report(self, output_format='text', filename=None):
        """
        Génère un rapport détaillé des résultats de scan.
        
        Args:
            output_format (str): Format de sortie ('text', 'json', 'csv', 'html')
            filename (str): Nom du fichier de sortie
        
        Returns:
            str: Contenu du rapport
        """
        if not self.scan_results:
            return "Aucun résultat de scan disponible."
        
        # Calculer les statistiques
        total_scan_time = time.time() - self.scan_start_time if self.scan_start_time else 0
        open_results = [r for r in self.scan_results if r['status'] == 'open']
        
        # Grouper par hôte
        hosts = {}
        for result in open_results:
            host = result['host']
            if host not in hosts:
                hosts[host] = []
            hosts[host].append(result)
        
        # Générer le rapport selon le format
        if output_format == 'text':
            report = self._generate_text_report(hosts, total_scan_time)
        elif output_format == 'json':
            report = self._generate_json_report(hosts, total_scan_time)
        elif output_format == 'csv':
            report = self._generate_csv_report(open_results)
        elif output_format == 'html':
            report = self._generate_html_report(hosts, total_scan_time)
        else:
            report = "Format de rapport non supporté."
        
        # Sauvegarder dans un fichier si spécifié
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"📄 Rapport sauvegardé: {filename}")
            except IOError as e:
                print(f"❌ Erreur sauvegarde: {e}")
        
        return report
    
    def _generate_text_report(self, hosts, scan_time):
        """Génère un rapport au format texte."""
        report = []
        report.append("=" * 60)
        report.append("🔍 RAPPORT DE SCAN DE PORTS RÉSEAU")
        report.append("=" * 60)
        report.append(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"⏱️  Durée du scan: {scan_time:.2f} secondes")
        report.append(f"📊 Statistiques:")
        report.append(f"   • Ports totaux scannés: {self.total_ports}")
        report.append(f"   • Ports ouverts: {self.open_ports}")
        report.append(f"   • Ports fermés: {self.closed_ports}")
        report.append(f"   • Hôtes avec ports ouverts: {len(hosts)}")
        report.append("")
        
        if not hosts:
            report.append("❌ Aucun port ouvert trouvé.")
            return "\n".join(report)
        
        # Détails par hôte
        for host, results in hosts.items():
            report.append(f"🎯 HÔTE: {host}")
            report.append("-" * 40)
            
            for result in sorted(results, key=lambda x: x['port']):
                service_info = f" ({result['service']})" if result['service'] != 'Unknown' else ""
                banner_info = f"\n      Bannière: {result['banner']}" if result['banner'] else ""
                version_info = f"\n      Version: {result['version']}" if result['version'] else ""
                
                report.append(f"  🟢 {result['protocol'].upper()}/{result['port']}{service_info}{banner_info}{version_info}")
            
            report.append("")
        
        return "\n".join(report)
    
    def _generate_json_report(self, hosts, scan_time):
        """Génère un rapport au format JSON."""
        report_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'scan_duration': scan_time,
                'total_ports_scanned': self.total_ports,
                'open_ports_found': self.open_ports,
                'closed_ports': self.closed_ports,
                'hosts_with_open_ports': len(hosts)
            },
            'results': hosts
        }
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def _generate_csv_report(self, results):
        """Génère un rapport au format CSV."""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        # En-têtes
        writer.writerow(['Host', 'Port', 'Protocol', 'Status', 'Service', 'Banner', 'Version', 'Timestamp'])
        
        # Données
        for result in results:
            writer.writerow([
                result['host'],
                result['port'],
                result['protocol'],
                result['status'],
                result['service'],
                result['banner'][:100],  # Limiter la taille
                result['version'],
                result['timestamp']
            ])
        
        return output.getvalue()
    
    def _generate_html_report(self, hosts, scan_time):
        """Génère un rapport au format HTML."""
        html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Scan de Ports</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2563eb; color: white; padding: 20px; border-radius: 10px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background-color: #f3f4f6; padding: 15px; border-radius: 8px; flex: 1; text-align: center; }}
        .host {{ margin: 20px 0; border: 1px solid #e5e7eb; border-radius: 8px; padding: 15px; }}
        .port {{ margin: 5px 0; padding: 8px; background-color: #ecfdf5; border-radius: 4px; }}
        .open {{ color: #059669; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Rapport de Scan de Ports Réseau</h1>
        <p>📅 Généré le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="stats">
        <div class="stat">
            <h3>{self.total_ports}</h3>
            <p>Ports scannés</p>
        </div>
        <div class="stat">
            <h3>{self.open_ports}</h3>
            <p>Ports ouverts</p>
        </div>
        <div class="stat">
            <h3>{len(hosts)}</h3>
            <p>Hôtes actifs</p>
        </div>
        <div class="stat">
            <h3>{scan_time:.1f}s</h3>
            <p>Durée du scan</p>
        </div>
    </div>
    
    <h2>Résultats par hôte:</h2>
"""
        
        for host, results in hosts.items():
            html += f'<div class="host"><h3>🎯 {host}</h3>'
            for result in sorted(results, key=lambda x: x['port']):
                service_info = f" ({result['service']})" if result['service'] != 'Unknown' else ""
                html += f'<div class="port"><span class="open">{result["protocol"].upper()}/{result["port"]}</span>{service_info}'
                if result['banner']:
                    html += f'<br><small>Bannière: {result["banner"][:100]}</small>'
                html += '</div>'
            html += '</div>'
        
        html += "</body></html>"
        return html


def parse_port_range(port_string):
    """
    Parse une chaîne de ports en liste d'entiers.
    
    Args:
        port_string (str): Chaîne de ports (ex: "80,443,1000-2000")
    
    Returns:
        list: Liste de ports
    """
    ports = []
    
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            # Plage de ports
            start, end = part.split('-', 1)
            try:
                start_port = int(start.strip())
                end_port = int(end.strip())
                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                    ports.extend(range(start_port, end_port + 1))
            except ValueError:
                print(f"⚠️  Plage de ports invalide: {part}")
        else:
            # Port individuel
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    print(f"⚠️  Port hors limites: {port}")
            except ValueError:
                print(f"⚠️  Port invalide: {part}")
    
    return sorted(list(set(ports)))  # Supprimer les doublons et trier


def main():
    """Fonction principale avec interface en ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Scanner de Ports Réseau Avancé",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python network_scanner.py 192.168.1.1
  python network_scanner.py 192.168.1.1 -p 80,443,22
  python network_scanner.py 192.168.1.0/24 -p 1-1000
  python network_scanner.py scanme.nmap.org --top-ports 100
  python network_scanner.py 10.0.0.1 --udp -p 53,67,161
  python network_scanner.py 192.168.1.1 --report json --output scan_results.json
        """
    )
    
    parser.add_argument('target', 
                       help='Cible à scanner (IP, hostname ou réseau CIDR)')
    
    parser.add_argument('-p', '--ports',
                       default='common',
                       help='Ports à scanner (ex: "80,443,1000-2000" ou "common" ou "all")')
    
    parser.add_argument('--top-ports',
                       type=int,
                       help='Scanner les N ports les plus communs')
    
    parser.add_argument('--tcp',
                       action='store_true',
                       default=True,
                       help='Scanner les ports TCP (par défaut)')
    
    parser.add_argument('--udp',
                       action='store_true',
                       help='Scanner les ports UDP')
    
    parser.add_argument('--timeout', '-t',
                       type=int,
                       default=3,
                       help='Timeout des connexions en secondes (défaut: 3)')
    
    parser.add_argument('--threads',
                       type=int,
                       default=100,
                       help='Nombre maximum de threads (défaut: 100)')
    
    parser.add_argument('--show-closed',
                       action='store_true',
                       help='Afficher les ports fermés')
    
    parser.add_argument('--report',
                       choices=['text', 'json', 'csv', 'html'],
                       default='text',
                       help='Format du rapport (défaut: text)')
    
    parser.add_argument('--output', '-o',
                       help='Fichier de sortie pour le rapport')
    
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Mode verbose')
    
    args = parser.parse_args()
    
    print("🌐 Scanner de Ports Réseau v1.0")
    print("=" * 50)
    
    try:
        # Initialiser le scanner
        scanner = NetworkScanner(timeout=args.timeout, max_threads=args.threads)
        
        # Déterminer les ports à scanner
        if args.top_ports:
            ports = scanner.get_top_ports(args.top_ports)
            print(f"📊 Scan des {args.top_ports} ports les plus communs")
        elif args.ports == 'common':
            ports = scanner.get_common_ports()
            print(f"📊 Scan des ports communs ({len(ports)} ports)")
        elif args.ports == 'all':
            ports = list(range(1, 65536))
            print("📊 Scan de tous les ports (1-65535) - Cela peut prendre du temps !")
        else:
            ports = parse_port_range(args.ports)
            print(f"📊 Scan des ports spécifiés ({len(ports)} ports)")
        
        if not ports:
            print("❌ Aucun port valide à scanner.")
            sys.exit(1)
        
        # Déterminer les protocoles
        protocols = []
        if args.tcp:
            protocols.append('tcp')
        if args.udp:
            protocols.append('udp')
        
        if not protocols:
            protocols = ['tcp']  # Par défaut, scanner TCP
        
        # Démarrer le scan
        if '/' in args.target:
            # Scan de réseau
            results = scanner.scan_network_range(args.target, ports, protocols)
            if not results:
                print("\n❌ Aucun hôte avec ports ouverts trouvé dans le réseau.")
            else:
                print(f"\n✅ Scan terminé - {len(results)} hôte(s) avec ports ouverts trouvé(s)")
        else:
            # Scan d'un hôte unique
            results = scanner.scan_host(args.target, ports, protocols, args.show_closed)
            open_results = [r for r in results if r['status'] == 'open']
            
            if not open_results:
                print(f"\n❌ Aucun port ouvert trouvé sur {args.target}")
            else:
                print(f"\n✅ Scan terminé - {len(open_results)} port(s) ouvert(s) trouvé(s)")
        
        # Générer le rapport
        if args.output or args.verbose:
            report = scanner.generate_report(args.report, args.output)
            if args.verbose and not args.output:
                print("\n" + report)
        
        print(f"\n🎯 Résumé: {scanner.open_ports} ports ouverts sur {scanner.total_ports} scannés")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrompu par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erreur inattendue: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
