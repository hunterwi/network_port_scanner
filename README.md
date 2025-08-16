# 🌐 Scanner de Ports Réseau

## 📖 Description

Un **scanner de ports réseau** développé en Python, permettant l’identification des ports ouverts sur des hôtes distants. Il prend en charge les protocoles **TCP et UDP**, utilise le **multithreading pour des performances optimales**, et intègre une **analyse automatique des services et bannières**.



👉 **Le multithreading pour des performances optimales**, ça veut dire :

* **Multithreading** = on exécute plusieurs "fils d’exécution" (**threads**) en parallèle dans un même programme.
* Dans un **scanner de ports**, au lieu de tester les ports **un par un** (ce qui est lent), on lance **plusieurs threads en même temps**.
* Chaque thread peut tester un ou plusieurs ports **indépendamment des autres** → ce qui permet d’analyser **des dizaines ou centaines de ports en parallèle**.
* Résultat : le scan se fait **beaucoup plus vite**.

⚡ Exemple simple :

* **Sans multithreading** :

  * Tu as 1000 portes à tester → tu le fais **une par une** → ça prend longtemps.
* **Avec multithreading** :

  * Tu envoies 50 personnes (threads) qui testent chacun 20 portes en même temps → le travail est terminé **50 fois plus vite**.

Donc, quand on dit **"multithreading pour des performances optimales"**, ça veut dire que ton scanner est conçu pour **exploiter plusieurs threads afin d’accélérer fortement la vitesse de scan**, surtout sur de grandes plages de ports.




## ✨ Fonctionnalités

### 🔍 Scan Avancé
- **Protocoles multiples** : TCP et UDP
- **Scan d'hôte unique** ou **plages réseau CIDR**
- **Multithreading** configurable (jusqu'à 1000+ threads)
- **Timeout ajustable** par connexion
- **Détection d'hôtes actifs** via ping

### 🎯 Types de Scan
- **Ports spécifiques** : Liste personnalisée (ex: 80,443,22)
- **Plages de ports** : Intervalles (ex: 1000-2000)
- **Ports communs** : 24 services les plus utilisés
- **Top N ports** : 100, 1000+ ports les plus scannés
- **Scan complet** : Tous les ports (1-65535)

### 🛠️ Détection de Services
- **Base de données intégrée** : 80+ services identifiés
- **Analyse de bannières** : Extraction automatique des versions
- **Services détectés** :
  - Web : HTTP, HTTPS, Apache, Nginx
  - Mail : SMTP, POP3, IMAP, Postfix
  - Bases de données : MySQL, PostgreSQL, MongoDB
  - Systèmes : SSH, FTP, Telnet, RDP
  - Sécurité : LDAP, SNMP, Kerberos

### 📊 Rapports Complets
- **4 formats de sortie** : Text, JSON, CSV, HTML
- **Statistiques détaillées** : Temps, performances, résumés
- **Sauvegarde automatique** : Fichiers horodatés
- **Affichage temps réel** : Progrès et découvertes

## 📋 Prérequis

- **Python 3.8+**
- **Privilèges réseau** : Certains scans peuvent nécessiter des droits administrateur
- **Connectivité réseau** : Accès aux cibles de scan

## 🚀 Installation

### 1. Préparation
```bash
cd network_port_scanner

# Vérifier Python
python --version  # Doit être >= 3.8
```

### 2. Rendre le script exécutable (Linux/Mac)
```bash
chmod +x network_scanner.py
```

### 3. Test rapide
```bash
python network_scanner.py --help
```

## 💡 Utilisation

### 🎯 Commandes de Base

#### Scan d'un hôte avec ports communs
```bash
python network_scanner.py 192.168.1.1
```

#### Scan avec ports personnalisés
```bash
python network_scanner.py 192.168.1.1 -p 80,443,22,3389
```

#### Scan d'une plage de ports
```bash
python network_scanner.py 192.168.1.1 -p 1-1000
```

#### Scan d'un réseau complet
```bash
python network_scanner.py 192.168.1.0/24
```

### 🔧 Options Avancées

#### Scan UDP
```bash
python network_scanner.py 192.168.1.1 --udp -p 53,67,161
```

#### Top ports les plus communs
```bash
python network_scanner.py 192.168.1.1 --top-ports 100
```

#### Scan rapide avec plus de threads
```bash
python network_scanner.py 192.168.1.1 --threads 500 --timeout 1
```

#### Afficher les ports fermés
```bash
python network_scanner.py 192.168.1.1 --show-closed
```

### 📊 Génération de Rapports

#### Rapport JSON
```bash
python network_scanner.py 192.168.1.1 --report json --output results.json
```

#### Rapport HTML interactif
```bash
python network_scanner.py 192.168.1.1 --report html --output report.html
```

#### Rapport CSV pour analyse
```bash
python network_scanner.py 192.168.1.1 --report csv --output data.csv
```

### 🎛️ Paramètres Complets

```bash
python network_scanner.py [CIBLE] [OPTIONS]
```

**Arguments principaux :**
- `CIBLE` : IP, hostname ou réseau CIDR (ex: 192.168.1.1, google.com, 10.0.0.0/24)

**Options de scan :**
- `-p, --ports` : Ports à scanner (défaut: "common")
- `--top-ports N` : Scanner les N ports les plus communs
- `--tcp` : Scanner TCP (actif par défaut)
- `--udp` : Scanner UDP
- `--timeout T` : Timeout en secondes (défaut: 3)
- `--threads N` : Nombre de threads (défaut: 100)

**Options d'affichage :**
- `--show-closed` : Afficher les ports fermés
- `--verbose, -v` : Mode détaillé
- `--report FORMAT` : Format de rapport (text/json/csv/html)
- `--output, -o FICHIER` : Fichier de sortie

## 📁 Structure des Sorties

### 📝 Rapport Texte
```
🔍 RAPPORT DE SCAN DE PORTS RÉSEAU
================================
📅 Date: 16-08-2025 23:38
⏱️  Durée du scan: 12.34 secondes
📊 Statistiques:
   • Ports totaux scannés: 1000
   • Ports ouverts: 5
   • Ports fermés: 995
   • Hôtes avec ports ouverts: 1

🎯 HÔTE: 192.168.1.1
-------------------
  🟢 TCP/22 (SSH)
      Bannière: SSH-2.0-OpenSSH_8.9
      Version: OpenSSH 8.9
  🟢 TCP/80 (HTTP)
  🟢 TCP/443 (HTTPS)
```

### 📊 Rapport JSON
```json
{
  "scan_info": {
    "timestamp": "2025-07-27T14:30:15",
    "scan_duration": 12.34,
    "total_ports_scanned": 1000,
    "open_ports_found": 5,
    "hosts_with_open_ports": 1
  },
  "results": {
    "192.168.1.1": [
      {
        "host": "192.168.1.1",
        "port": 22,
        "protocol": "tcp",
        "status": "open",
        "service": "SSH",
        "banner": "SSH-2.0-OpenSSH_8.9",
        "version": "OpenSSH 8.9",
        "timestamp": "2025-07-27T14:30:15"
      }
    ]
  }
}
```

## 🎯 Cas d'Usage

### 🔒 Audit de Sécurité
```bash
# Scan de sécurité complet d'un serveur
python network_scanner.py server.company.com --top-ports 1000 --report html --output security_audit.html

# Vérification des services critiques
python network_scanner.py 192.168.1.0/24 -p 22,80,443,3389,1433,3306
```

### 🖥️ Administration Système
```bash
# Découverte de nouveaux équipements
python network_scanner.py 10.0.0.0/8 -p 22,80,443 --threads 1000

# Monitoring des services
python network_scanner.py critical-server.local -p 80,443,3306 --timeout 1
```

### 🌐 Analyse Réseau
```bash
# Cartographie des services réseau
python network_scanner.py 172.16.0.0/12 --top-ports 100 --report csv --output network_map.csv

# Scan UDP pour services système
python network_scanner.py 192.168.1.1 --udp -p 53,67,123,161,162
```

### 🧪 Tests de Pénétration (avec autorisation)
```bash
# Reconnaissance initiale
python network_scanner.py target.com --top-ports 1000

# Scan exhaustif
python network_scanner.py 192.168.1.100 -p all --timeout 2
```

## 🔍 Interprétation des Résultats

### États des Ports

- **🟢 Open** : Port ouvert et accessible
- **🔴 Closed** : Port fermé mais hôte accessible
- **🟡 Filtered** : Port filtré par firewall
- **🟠 Open|Filtered** : État indéterminé (UDP)
- **❌ Error** : Erreur de connexion ou résolution

### Services Détectés Automatiquement

#### Web Services
- **HTTP (80, 8080)** : Apache, Nginx, IIS
- **HTTPS (443, 8443)** : Services web sécurisés

#### Services Mail
- **SMTP (25, 587)** : Postfix, Sendmail, Exchange
- **POP3/IMAP (110, 143, 993, 995)** : Serveurs mail

#### Bases de Données
- **MySQL (3306)** : Versions détectées
- **PostgreSQL (5432)** : Serveur de base de données
- **MongoDB (27017)** : Base NoSQL

#### Services Système
- **SSH (22)** : OpenSSH avec versions
- **FTP (21)** : vsftpd, ProFTPD
- **Telnet (23)** : Accès non sécurisé

## 📈 Optimisation des Performances

### ⚡ Paramètres de Performance

#### Scan Rapide (Réseau Local)
```bash
python network_scanner.py 192.168.1.0/24 --threads 500 --timeout 1 --top-ports 50
```

#### Scan Précis (Internet)
```bash
python network_scanner.py target.com --threads 50 --timeout 5 --top-ports 1000
```

#### Scan Exhaustif (Serveur dédié)
```bash
python network_scanner.py 10.0.0.1 -p all --threads 1000 --timeout 2
```

### 🎛️ Recommandations par Contexte

| Contexte | Threads | Timeout | Ports |
|----------|---------|---------|-------|
| Réseau local | 200-500 | 1-2s | Common/Top100 |
| Internet public | 50-100 | 3-5s | Top100-1000 |
| Audit sécurité | 100-200 | 3s | Top1000-All |
| Monitoring | 50 | 1s | Spécifiques |

## 🛡️ Considérations de Sécurité

### ⚖️ Aspects Légaux
- **Utilisez uniquement sur vos propres systèmes**
- **Obtenez une autorisation écrite** pour tests externes
- **Respectez les lois locales** sur la cybersécurité
- **Évitez les scans agressifs** sur infrastructures critiques

### 🚫 Limitations Éthiques
- **Ne pas utiliser** à des fins malveillantes
- **Limiter l'impact** sur les systèmes cibles
- **Signaler les vulnérabilités** de manière responsable

### 🔐 Détection et Contre-mesures
- Les scans peuvent être **détectés par les IDS/IPS**
- **Logs système** enregistrent les tentatives de connexion
- **Rate limiting** peut ralentir ou bloquer les scans
- **Honeypots** peuvent rediriger les scanners

## 🐛 Résolution de Problèmes

### ❌ Erreurs Communes

**"Permission denied" ou "Operation not permitted"**
```bash
# Certains scans nécessitent des privilèges root
sudo python network_scanner.py 192.168.1.1 --udp
```

**"Name resolution failed"**
```bash
# Vérifier la connectivité DNS
nslookup target.com

# Utiliser l'IP directement
python network_scanner.py 8.8.8.8
```

**Scan très lent**
```bash
# Réduire le timeout et augmenter les threads
python network_scanner.py 192.168.1.1 --timeout 1 --threads 200
```

**"Too many open files"**
```bash
# Réduire le nombre de threads
python network_scanner.py 192.168.1.1 --threads 50

# Ou augmenter la limite système (Linux)
ulimit -n 2048
```

### 🔧 Mode Debug
```bash
# Activer le mode verbose pour plus d'informations
python network_scanner.py 192.168.1.1 --verbose

# Scan de test sur un port connu
python network_scanner.py google.com -p 80,443 --verbose
```

### 📊 Optimisation Réseau
```bash
# Tester la latence réseau avant scan
ping -c 4 192.168.1.1

# Adapter le timeout selon la latence
python network_scanner.py 192.168.1.1 --timeout 5  # Pour connexions lentes
```

## 🔮 Évolutions Futures

### 🚀 Fonctionnalités Prévues
- **Scan SYN** : Scans furtifs sans connexion complète
- **OS Fingerprinting** : Détection du système d'exploitation
- **Vulnérability Detection** : Identification de CVE connues
- **IPv6 Support** : Scan des réseaux IPv6
- **Scan Timing** : Templates de vitesse (T1-T5)

### 🎨 Interface Utilisateur
- **Interface graphique** : GUI avec Tkinter ou PyQt
- **Interface web** : Dashboard avec Flask/Django
- **API REST** : Intégration avec autres outils
- **Plugin système** : Extensions pour Nmap, Metasploit

### 📊 Améliorations Techniques
- **Async/Await** : Programmation asynchrone pour performances
- **Machine Learning** : Classification automatique des services
- **Database Integration** : PostgreSQL/MySQL pour gros volumes
- **Cloud Integration** : Support AWS, Azure, GCP

## 📚 Références et Ressources

### 📖 Documentation Technique
- [RFC 793 - TCP Protocol](https://tools.ietf.org/html/rfc793)
- [RFC 768 - UDP Protocol](https://tools.ietf.org/html/rfc768)
- [IANA Port Numbers](https://www.iana.org/assignments/service-names-port-numbers/)
- [Nmap Reference Guide](https://nmap.org/book/)

### 🛡️ Sécurité et Éthique
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Responsible Disclosure Guidelines](https://www.bugcrowd.com/resource/what-is-responsible-disclosure/)

### 🔧 Outils Complémentaires
- **Nmap** : Scanner de référence
- **Masscan** : Scanner ultra-rapide
- **Zmap** : Scanner à l'échelle Internet
- **Rustscan** : Scanner moderne en Rust

## 👥 Contribution et Développement

### 🛠️ Structure du Code
```python
# Classes principales
NetworkScanner          # Moteur principal de scan
parse_port_range()      # Parser de plages de ports
main()                  # Interface CLI

# Méthodes de scan
scan_tcp_port()         # Scan TCP individuel
scan_udp_port()         # Scan UDP individuel
scan_host()             # Scan complet d'un hôte
scan_network_range()    # Scan de réseau

# Analyse et rapports
_identify_service()     # Détection de service
_parse_banner()         # Analyse de bannière
generate_report()       # Génération de rapports
```

### 🧪 Tests et Validation
```bash
# Test sur localhost
python network_scanner.py 127.0.0.1 -p 22,80

# Test de performance
time python network_scanner.py 192.168.1.1 --threads 100

# Test de plage réseau
python network_scanner.py 192.168.1.0/28 -p 80,443
```

### 📝 Standards de Code
- **PEP 8** : Style de code Python
- **Type Hints** : Annotations de type
- **Docstrings** : Documentation des fonctions
- **Error Handling** : Gestion robuste des erreurs

## 📄 Licence et Utilisation

Ce projet est développé à des fins éducatives et professionnelles. L'utilisation doit respecter :

- **Lois locales** sur la cybersécurité
- **Autorisations** des propriétaires de systèmes
- **Éthique** du hacking responsable
- **Bonnes pratiques** de test de sécurité

---

**Auteur** : EGBOHOU William Manguiliwe  
**Version** : 1.0  
**Date** : Aout 2025  
**Niveau** : Débutant à Intermédiaire  
**Temps de développement** : En cours  
**Technologies** : Python, Socket, Threading, Multithreading

⚠️ **Avertissement** : Cet outil est conçu à des fins pédagogiques et professionnelles, principalement pour les administrateurs système et les chercheurs en cybersécurité. Toute utilisation en dehors d’un cadre légal ou sans autorisation explicite est strictement inte