import os
import re
import subprocess
import requests
import json
import time
import random
import string
import base64
import logging
import threading
from flask import Flask, jsonify, Response

# ========== CONFIGURATION ==========
CONFIG = {
    # X settings
    'UUID': os.environ.get('UUID', '9afd1229-b893-40c1-84dd-51e7ce204913'),
    'FILE_PATH': os.environ.get('FILE_PATH', '/tmp/.cache'),
    'SUB_PATH': os.environ.get('SUB_PATH', 'sub'),
    'PORT': int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000),
    'NAME': os.environ.get('NAME', 'vless'),
    
    # CDN settings
    'CFIP': os.environ.get('CFIP', 'www.kick.com'),
    'CFPORT': int(os.environ.get('CFPORT', 443)),
    
    # Argo Tunnel
    'ARGO_DOMAIN': os.environ.get('ARGO_DOMAIN', ''),
    'ARGO_AUTH': os.environ.get('ARGO_AUTH', ''),
    'ARGO_PORT': int(os.environ.get('ARGO_PORT', 8001)),
    
    # sb settings
    'SB_VERSION': os.environ.get('SB_VERSION', "1.11.15"),
    'SB_NAME': os.environ.get('SB_NAME', "HY2"),
    'SB_PORT': int(os.environ.get('SB_PORT') or os.environ.get('SERVER_PORT') or os.environ.get('PORT') or "2705"),
    'SB_UUID': os.environ.get('SB_UUID') or os.environ.get('UUID') or '9afd1229-b893-40c1-84dd-51e7ce204913',
    'SB_SNI': os.environ.get('SB_SNI', "time.android.com"),
    'SB_MASS_PROXY': os.environ.get('SB_MASS_PROXY', "https://www.gstatic.com"),
    'SB_DOMAIN': os.environ.get('SB_DOMAIN', os.environ.get('DOMAIN')),
    'SB_HOST': os.environ.get('SB_HOST', "127.0.0.1"),
    'SB_OBFS_PWD': os.environ.get('SB_OBFS_PWD', ''.join(random.choices(string.ascii_lowercase + string.digits, k=11)) + ''.join(random.choices(string.ascii_lowercase + string.digits, k=11)))
}

# ========== CONSTANTS ==========
COLORS = {
    'reset': '\x1b[0m',
    'bright': '\x1b[1m',
    'dim': '\x1b[2m',
    'red': '\x1b[31m',
    'green': '\x1b[32m',
    'yellow': '\x1b[33m',
    'blue': '\x1b[34m',
    'magenta': '\x1b[35m',
    'cyan': '\x1b[36m',
    'white': '\x1b[37m'
}

# ========== SYSTEM VARIABLES ==========
ARCH = 'arm64' if os.uname().machine in ['arm', 'arm64', 'aarch64'] else 'amd64'

TAR_NAME = f"sing-box-{CONFIG['SB_VERSION']}-linux-{ARCH}.tar.gz"
DOWNLOAD_URL = os.environ.get('SB_URL', f"https://github.com/SagerNet/sing-box/releases/download/v{CONFIG['SB_VERSION']}/{TAR_NAME}")

# File paths
PATHS = {
    'SB_BASE_DIR': os.path.join(CONFIG['FILE_PATH'], "sb"),
    'SB_CERT_DIR': os.path.join(CONFIG['FILE_PATH'], "sb", "cert"),
    'SB_CERT_PATH': os.path.join(CONFIG['FILE_PATH'], "sb", "cert", "cert.pem"),
    'SB_KEY_PATH': os.path.join(CONFIG['FILE_PATH'], "sb", "cert", "key.pem"),
    'SB_JSON': os.path.join(CONFIG['FILE_PATH'], "sb", "sb.json"),
    'SB_BIN': os.path.join(CONFIG['FILE_PATH'], "sb", "sb"),
    'SB_LOG_FILE': os.path.join(CONFIG['FILE_PATH'], "sb", "sb.log"),
    'X_CONFIG': os.path.join(CONFIG['FILE_PATH'], 'config.json'),
    'BOOT_LOG': os.path.join(CONFIG['FILE_PATH'], 'boot.log')
}

# Global state
state = {
    'xLinks': [],
    'sboxLinks': [],
    'xBase64': "",
    'sboxBase64': "",
    'sbProcess': None
}

# ========== LOGGER ==========
class Logger:
    @staticmethod
    def info(message):
        print(f"{COLORS['cyan']}ℹ {message}{COLORS['reset']}")

    @staticmethod
    def success(message):
        print(f"{COLORS['green']}✅ {message}{COLORS['reset']}")

    @staticmethod
    def warning(message):
        print(f"{COLORS['yellow']}⚠ {message}{COLORS['reset']}")

    @staticmethod
    def error(message):
        print(f"{COLORS['red']}❌ {message}{COLORS['reset']}")

    @staticmethod
    def step(message):
        print(f"{COLORS['blue']}➤ {message}{COLORS['reset']}")

    @staticmethod
    def header(message):
        print(f"\n{COLORS['bright']}{COLORS['magenta']}{'='.ljust(60, '=')}{COLORS['reset']}")
        print(f"{COLORS['bright']}{COLORS['magenta']}{message}{COLORS['reset']}")
        print(f"{COLORS['bright']}{COLORS['magenta']}{'='.ljust(60, '=')}{COLORS['reset']}\n")

    @staticmethod
    def divider():
        print(f"{COLORS['dim']}{'-'.ljust(60, '-')}{COLORS['reset']}")

    @staticmethod
    def config(key, value):
        print(f"  {COLORS['cyan']}{key}:{COLORS['reset']} {COLORS['yellow']}{value}{COLORS['reset']}")

# ========== SYSTEM UTILITIES ==========
class SystemUtils:
    @staticmethod
    def get_public_ip_sync():
        ip_regex = r'\b((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(?!$)|$)){4}\b'
        curl_candidates = [
            "https://ifconfig.co",
            "https://ifconfig.me/ip",
            "https://api.ipify.org",
            "https://ifconfig.io/ip",
        ]
        
        for url in curl_candidates:
            try:
                result = subprocess.run(["curl", "-sS", url], capture_output=True, text=True, timeout=8)
                if result.returncode == 0 and result.stdout:
                    match = re.search(ip_regex, result.stdout.strip())
                    if match:
                        return match.group(0)
            except:
                pass
        
        try:
            result = subprocess.run(["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"], capture_output=True, text=True, timeout=8)
            if result.returncode == 0 and result.stdout:
                match = re.search(ip_regex, result.stdout.strip())
                if match:
                    return match.group(0)
        except:
            pass
        
        return None

    @staticmethod
    def get_isp_info():
        try:
            meta_info = subprocess.run(
                'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'',
                shell=True,
                capture_output=True,
                text=True
            )
            
            if meta_info.returncode == 0 and meta_info.stdout:
                isp = meta_info.stdout.strip()
                return isp if isp and len(isp) > 0 else "UNKNOWN"
        except Exception as error:
            Logger.error(f"Failed to get ISP info: {error}")
        return "UNKNOWN"

    @staticmethod
    def ensure_directory(dir_path):
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
            Logger.success(f"Directory created: {dir_path}")

    @staticmethod
    def download_file(file_name, file_url):
        file_path = os.path.join(CONFIG['FILE_PATH'], file_name)
        try:
            response = requests.get(file_url, stream=True, timeout=30)
            response.raise_for_status()
            with open(file_path, 'wb') as writer:
                for chunk in response.iter_content(chunk_size=8192):
                    writer.write(chunk)
            os.chmod(file_path, 0o755)
            Logger.success(f"Downloaded: {file_name}")
            return file_name
        except Exception as err:
            if os.path.exists(file_path):
                os.remove(file_path)
            raise Exception(f"Download error {file_name}: {err}")

    @staticmethod
    def apply_system_optimizations():
        Logger.step("Applying system optimizations for maximum performance...")
        
        try:
            optimizations = [
                'sysctl -w net.core.rmem_max=268435456',
                'sysctl -w net.core.wmem_max=268435456',
                'sysctl -w net.ipv4.tcp_rmem="4096 87380 268435456"',
                'sysctl -w net.ipv4.tcp_wmem="4096 16384 268435456"',
                'sysctl -w net.core.netdev_max_backlog=100000',
                'sysctl -w net.core.somaxconn=65535',
                'sysctl -w net.ipv4.tcp_max_syn_backlog=65535',
                'sysctl -w net.ipv4.tcp_congestion_control=bbr',
                'sysctl -w net.ipv4.tcp_fastopen=3',
                'sysctl -w net.core.default_qdisc=fq_codel',
                'sysctl -w fs.file-max=2097152',
                'sysctl -w fs.nr_open=2097152',
                'sysctl -w net.ipv4.tcp_mem="786432 2097152 3145728"',
                'sysctl -w net.ipv4.udp_mem="786432 2097152 3145728"',
                'sysctl -w net.ipv4.tcp_slow_start_after_idle=0',
                'sysctl -w net.ipv4.tcp_tw_reuse=1',
                'sysctl -w net.ipv4.tcp_fin_timeout=30',
                'sysctl -w net.ipv4.tcp_keepalive_time=1200',
                'sysctl -w net.ipv4.tcp_keepalive_intvl=30',
                'sysctl -w net.ipv4.tcp_keepalive_probes=3'
            ]

            applied = 0
            for cmd in optimizations:
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    applied += 1
                except:
                    pass
            
            if applied > 0:
                Logger.success(f"Applied {applied} system optimizations")
            else:
                Logger.warning("Could not apply system optimizations (root privileges required)")
        except Exception as error:
            Logger.warning("Error applying system optimizations")

# ========== SB MANAGER ==========
class SbManager:
    @staticmethod
    def get_server_host():
        if CONFIG['SB_DOMAIN']:
            Logger.info(f"Using domain: {CONFIG['SB_DOMAIN']}")
            return CONFIG['SB_DOMAIN']

        public_ip = SystemUtils.get_public_ip_sync()
        if public_ip:
            Logger.info(f"Using public IP: {public_ip}")
            return public_ip
        
        Logger.warning(f"Using fallback host: {CONFIG['SB_HOST']}")
        return CONFIG['SB_HOST']

    @staticmethod
    def ensure_certificates():
        SystemUtils.ensure_directory(PATHS['SB_CERT_DIR'])
        
        # Use external certificates if provided
        external_cert = os.environ.get('EXTERNAL_CERT')
        external_key = os.environ.get('EXTERNAL_KEY')
        if external_cert and external_key and os.path.exists(external_cert) and os.path.exists(external_key):
            Logger.info("Using external TLS certificates")
            return { 
                'cert': external_cert, 
                'key': external_key 
            }

        # Generate self-signed certificates
        if not os.path.exists(PATHS['SB_CERT_PATH']) or not os.path.exists(PATHS['SB_KEY_PATH']):
            Logger.step("Generating self-signed TLS certificate")
            result = subprocess.run(["openssl",
                "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-subj", f"/CN={CONFIG['SB_SNI']}",
                "-keyout", PATHS['SB_KEY_PATH'],
                "-out", PATHS['SB_CERT_PATH'],
                "-days", "365",
            ], capture_output=True)
            
            if result.returncode != 0:
                Logger.error("Failed to generate TLS certificate")
                return {'cert': None, 'key': None}
            Logger.success("TLS certificate generated")
        
        return {'cert': PATHS['SB_CERT_PATH'], 'key': PATHS['SB_KEY_PATH']}

    @staticmethod
    def ensure_binary():
        if os.path.exists(PATHS['SB_BIN']):
            return True
        
        SystemUtils.ensure_directory(PATHS['SB_BASE_DIR'])
        Logger.step(f"Downloading sb ({ARCH})")
        
        tar_path = os.path.join(PATHS['SB_BASE_DIR'], TAR_NAME)
        
        # Download sb
        curl_result = subprocess.run(["curl", "-L", "-sS", "-o", tar_path, DOWNLOAD_URL], timeout=60)
        
        if curl_result.returncode != 0:
            Logger.error("Failed to download sb")
            return False

        # Extract archive
        try:
            import tarfile
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=PATHS['SB_BASE_DIR'], filter='tar')
        except:
            Logger.error("Failed to extract sb archive")
            return False

        # Move binary to correct location
        extracted_dir = os.path.join(PATHS['SB_BASE_DIR'], f"sing-box-{CONFIG['SB_VERSION']}-linux-{ARCH}")
        if os.path.exists(os.path.join(extracted_dir, "sing-box")):
            os.rename(os.path.join(extracted_dir, "sing-box"), PATHS['SB_BIN'])
            os.chmod(PATHS['SB_BIN'], 0o755)
            Logger.success("sb installed successfully")
            return True
        
        Logger.error("sb binary not found in archive")
        return False

    @staticmethod
    def write_configuration(cert, key):
        Logger.step("Creating sb configuration")
        
        config = {
            "log": {
                "level": "info",
                "timestamp": True
            },
            "inbounds": [
                {
                    "type": "hysteria2",
                    "tag": "hy2-in",
                    "listen": "::",
                    "listen_port": CONFIG['SB_PORT'],
                    "users": [
                        {
                            "password": CONFIG['SB_UUID']
                        }
                    ],
                    "tls": {
                        "enabled": True,
                        "server_name": CONFIG['SB_SNI'],
                        "alpn": ["h3"],
                        "certificate_path": cert,
                        "key_path": key
                    },
                    "obfs": {
                        "type": "salamander",
                        "password": CONFIG['SB_OBFS_PWD']
                    },
                    "masquerade": {
                        "type": "proxy",
                        "url": CONFIG['SB_MASS_PROXY'],
                        "rewrite_host": True
                    },
                    "ignore_client_bandwidth": False,
                    "up_mbps": 100,
                    "down_mbps": 100
                }
            ],
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "direct"
                },
                {
                    "type": "block",
                    "tag": "block"
                }
            ]
        }

        with open(PATHS['SB_JSON'], 'w') as f:
            json.dump(config, f, indent=2)
        Logger.success("sb configuration created")

    @staticmethod
    def start():
        Logger.step("Starting sb...")
        
        if not os.path.exists(PATHS['SB_BIN']):
            Logger.error("sb binary not found")
            return None

        # Validate configuration first
        check_result = subprocess.run([PATHS['SB_BIN'], "check", "-c", PATHS['SB_JSON']], capture_output=True, text=True)

        if check_result.returncode != 0:
            Logger.error(f"sb configuration error: {check_result.stderr}")
            return None

        Logger.success("sb configuration validated")

        # Start sb process
        log_file = open(PATHS['SB_LOG_FILE'], 'a')
        child = subprocess.Popen([PATHS['SB_BIN'], "run", "-c", PATHS['SB_JSON']],
                                 stdout=log_file, stderr=log_file)

        # Verify process started successfully
        time.sleep(2)
        if child.poll() is None:
            Logger.success("sb started successfully")

        return child

    @staticmethod
    def initialize():
        Logger.header("SB CONFIGURATION")
        
        # Display configuration
        Logger.config("Node Name", CONFIG['SB_NAME'])
        Logger.config("Port", CONFIG['SB_PORT'])
        Logger.config("UUID", CONFIG['SB_UUID'])
        Logger.config("SNI", CONFIG['SB_SNI'])
        Logger.config("Domain", CONFIG['SB_DOMAIN'] or 'Not set')
        Logger.config("Fallback Host", CONFIG['SB_HOST'])
        Logger.config("Version", CONFIG['SB_VERSION'])
        Logger.config("Architecture", ARCH)

        # Setup certificates
        certs = SbManager.ensure_certificates()
        if not certs['cert'] or not certs['key']:
            Logger.error("Certificate setup failed, skipping sb")
            return None

        # Download binary
        if not SbManager.ensure_binary():
            Logger.error("Binary download failed, skipping sb")
            return None

        # Create configuration and start
        SbManager.write_configuration(certs['cert'], certs['key'])
        return SbManager.start()

    @staticmethod
    def generate_links():
        isp = SystemUtils.get_isp_info()
        server_host = SbManager.get_server_host()
        insecure = "0" if os.environ.get('EXTERNAL_CERT') else "1"

        base_url = f"hysteria2://{CONFIG['SB_UUID']}@{server_host}:{CONFIG['SB_PORT']}/?sni={CONFIG['SB_SNI']}&obfs=salamander&obfs-password={CONFIG['SB_OBFS_PWD']}&insecure={insecure}#{CONFIG['SB_NAME']}-{isp}"

        state['sboxLinks'] = [base_url]
        state['sboxBase64'] = base64.b64encode(base_url.encode()).decode()
        
        return base_url

# ========== X MANAGER ==========
class XManager:
    @staticmethod
    def create_configuration():
        Logger.step("Creating X configuration")
        
        config = {
            "log": { 
                "access": '/dev/null', 
                "error": '/dev/null', 
                "loglevel": 'none' 
            },
            "inbounds": [
                { 
                    "port": CONFIG['ARGO_PORT'], 
                    "protocol": 'vless', 
                    "settings": { 
                        "clients": [{ 
                            "id": CONFIG['UUID'], 
                            "flow": 'xtls-rprx-vision' 
                        }], 
                        "decryption": 'none', 
                        "fallbacks": [
                            { "dest": 3001 }, 
                            { "path": "/vless-argo", "dest": 3002 }
                        ] 
                    }, 
                    "streamSettings": { "network": 'tcp' } 
                },
                { 
                    "port": 3001, 
                    "listen": "127.0.0.1", 
                    "protocol": "vless", 
                    "settings": { 
                        "clients": [{ "id": CONFIG['UUID'] }], 
                        "decryption": "none" 
                    }, 
                    "streamSettings": { 
                        "network": "ws", 
                        "security": "none",
                        "wsSettings": { "path": "/vless-argo" }
                    }
                },
                { 
                    "port": 3002, 
                    "listen": "127.0.0.1", 
                    "protocol": "vless", 
                    "settings": { 
                        "clients": [{ "id": CONFIG['UUID'], "level": 0 }], 
                        "decryption": "none" 
                    }, 
                    "streamSettings": { 
                        "network": "ws", 
                        "security": "none", 
                        "wsSettings": { "path": "/vless-argo" } 
                    }, 
                    "sniffing": { 
                        "enabled": True, 
                        "destOverride": ["http", "tls", "quic"], 
                        "metadataOnly": False 
                    } 
                }
            ],
            "dns": { 
                "servers": ["https+local://8.8.8.8/dns-query"] 
            },
            "outbounds": [ 
                { "protocol": "freedom", "tag": "direct" }, 
                { "protocol": "blackhole", "tag": "block" } 
            ]
        }

        with open(PATHS['X_CONFIG'], 'w') as f:
            json.dump(config, f, indent=2)
        Logger.success("X configuration created")

    @staticmethod
    def get_system_architecture():
        arch = os.uname().machine
        return 'arm' if arch in ['arm', 'arm64', 'aarch64'] else 'amd'

    @staticmethod
    def get_files_for_architecture(architecture):
        if architecture == 'arm':
            return [
                { 'fileName': "web", 'fileUrl': "https://arm64.ssss.nyc.mn/web" },
                { 'fileName': "bot", 'fileUrl': "https://arm64.ssss.nyc.mn/2go" }
            ]
        else:
            return [
                { 'fileName': "web", 'fileUrl': "https://amd64.ssss.nyc.mn/web" },
                { 'fileName': "bot", 'fileUrl': "https://amd64.ssss.nyc.mn/2go" }
            ]

    @staticmethod
    def download_and_run():
        architecture = XManager.get_system_architecture()
        files_to_download = XManager.get_files_for_architecture(architecture)

        if len(files_to_download) == 0:
            Logger.warning(f"No files found for architecture: {architecture}")
            return

        Logger.step(f"Downloading files for {architecture} architecture")
        
        try:
            for file in files_to_download:
                SystemUtils.download_file(file['fileName'], file['fileUrl'])
            Logger.success("All files downloaded successfully")
        except Exception as error:
            Logger.error(f"Download failed: {error}")
            return

        # Set file permissions
        files_to_authorize = ['./web', './bot']
        for relative_file_path in files_to_authorize:
            absolute_file_path = os.path.join(CONFIG['FILE_PATH'], relative_file_path)
            if os.path.exists(absolute_file_path):
                os.chmod(absolute_file_path, 0o755)
                Logger.success(f"Permissions set for: {absolute_file_path}")

        # Start services
        XManager.start_x_core()
        XManager.start_cloudflared()

    @staticmethod
    def start_x_core():
        command = f"nohup {os.path.join(CONFIG['FILE_PATH'], 'web')} -c {PATHS['X_CONFIG']} >/dev/null 2>&1 &"
        try:
            subprocess.run(command, shell=True)
            Logger.success('X core started')
        except Exception as error:
            Logger.error(f"Failed to start X core: {error}")

    @staticmethod
    def start_cloudflared():
        bot_path = os.path.join(CONFIG['FILE_PATH'], 'bot')
        if not os.path.exists(bot_path):
            return

        if re.match(r'^[A-Z0-9a-z=]{120,250}$', CONFIG['ARGO_AUTH']):
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token {CONFIG['ARGO_AUTH']}"
        elif 'TunnelSecret' in CONFIG['ARGO_AUTH']:
            args = f"tunnel --edge-ip-version auto --config {os.path.join(CONFIG['FILE_PATH'], 'tunnel.yml')} run"
        else:
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {PATHS['BOOT_LOG']} --loglevel info --url http://localhost:{CONFIG['ARGO_PORT']}"

        try:
            command = f"nohup {bot_path} {args} >/dev/null 2>&1 &"
            subprocess.run(command, shell=True)
            Logger.success('Cloudflared tunnel started')
        except Exception as error:
            Logger.error(f"Failed to start Cloudflared: {error}")

    @staticmethod
    def extract_domains():
        argo_domain = None

        if CONFIG['ARGO_AUTH'] and CONFIG['ARGO_DOMAIN']:
            argo_domain = CONFIG['ARGO_DOMAIN']
            Logger.config('ARGO_DOMAIN', argo_domain)
            XManager.generate_links(argo_domain)
        else:
            try:
                Logger.step("Waiting for Cloudflared to start...")
                time.sleep(8)
                
                if os.path.exists(PATHS['BOOT_LOG']):
                    with open(PATHS['BOOT_LOG'], 'r') as f:
                        file_content = f.read()
                    domains = re.findall(r'https?://([^ ]*trycloudflare\.com)/?', file_content)
                    argo_domain = domains[0] if len(domains) > 0 else "fallback.trycloudflare.com"
                    Logger.config('Argo Domain', argo_domain)
                else:
                    Logger.warning('Boot log not found, using fallback domain')
                    argo_domain = "fallback.trycloudflare.com"
                
                XManager.generate_links(argo_domain)
            except Exception as error:
                Logger.error('Error reading boot log:')
                argo_domain = "fallback.trycloudflare.com"
                XManager.generate_links(argo_domain)

        return argo_domain

    @staticmethod
    def generate_links(argo_domain):
        time.sleep(2)
        isp = SystemUtils.get_isp_info()

        vless_link = f"vless://{CONFIG['UUID']}@{CONFIG['CFIP']}:{CONFIG['CFPORT']}?encryption=none&security=tls&sni={argo_domain}&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{CONFIG['NAME']}-{isp}"
        
        state['xLinks'] = [vless_link]
        state['xBase64'] = base64.b64encode(vless_link.encode()).decode()
        
        return vless_link

# ========== HTTP SERVER ==========
class HttpServer:
    @staticmethod
    def escape_html(text):
        map_ = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        }
        return re.sub(r'[&<>"\']', lambda m: map_[m.group(0)], text)

    @staticmethod
    def get_styles():
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --secondary: #10b981;
            --dark: #1f2937;
            --darker: #111827;
            --light: #f9fafb;
            --gray: #6b7280;
            --border: #374151;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 100%);
            color: var(--light);
            min-height: 100vh;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .header {
            text-align: center;
            margin-bottom: 3rem;
        }

        .header h1 {
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        .header p {
            color: var(--gray);
            font-size: 1.2rem;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border);
            border-radius: 1rem;
            padding: 2rem;
            transition: all 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            border-color: var(--primary);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }

        .card-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .card-icon {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }

        .card-title {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .card-subtitle {
            color: var(--gray);
            font-size: 0.9rem;
        }

        .link-item {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            transition: all 0.3s ease;
        }

        .link-item:hover {
            border-color: var(--primary);
            background: rgba(99, 102, 241, 0.1);
        }

        .link-content {
            flex: 1;
            word-break: break-all;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.85rem;
            color: var(--light);
        }

        .copy-btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
            transition: all 0.3s ease;
            white-space: nowrap;
        }

        .copy-btn:hover {
            background: var(--primary-dark);
            transform: scale(1.05);
        }

        .copy-btn.copied {
            background: var(--secondary);
        }

        .base64-section {
            margin-top: 1.5rem;
        }

        .base64-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .base64-content {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1rem;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.8rem;
            line-height: 1.4;
            word-break: break-all;
            margin-bottom: 1rem;
            position: relative;
        }

        .protocol-badge {
            background: var(--primary);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            display: inline-block;
        }

        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.25rem 0.75rem;
            background: var(--secondary);
            color: white;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 1rem;
        }

        .status-indicator.offline {
            background: #ef4444;
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }

            .grid {
                grid-template-columns: 1fr;
            }

            .header h1 {
                font-size: 2rem;
            }

            .link-item {
                flex-direction: column;
                align-items: stretch;
            }

            .copy-btn {
                align-self: stretch;
                justify-content: center;
            }
        }

        .toast {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--secondary);
            color: white;
            padding: 1rem 2rem;
            border-radius: 0.75rem;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            transform: translateY(100px);
            opacity: 0;
            transition: all 0.3s ease;
            z-index: 1000;
        }

        .toast.show {
            transform: translateY(0);
            opacity: 1;
        }"""

    @staticmethod
    def get_script():
        return """
        function copyToClipboard(text, button) {
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(() => {
                    showToast(button);
                }).catch(err => {
                    console.error('Failed to copy with navigator.clipboard: ', err);
                    fallbackCopyToClipboard(text, button);
                });
            } else {
                fallbackCopyToClipboard(text, button);
            }
        }

        function fallbackCopyToClipboard(text, button) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                showToast(button);
            } catch (err) {
                console.error('Failed to copy with execCommand: ', err);
                alert('Failed to copy to clipboard. Please copy manually.');
            } finally {
                document.body.removeChild(textarea);
            }
        }

        function showToast(button) {
            const toast = document.getElementById('toast');
            toast.classList.add('show');
            setTimeout(() => {
                toast.classList.remove('show');
            }, 2000);

            if (button) {
                const originalText = button.innerHTML;
                button.innerHTML = '<i class="fas fa-check"></i> Copied!';
                button.classList.add('copied');
                setTimeout(() => {
                    button.innerHTML = originalText;
                    button.classList.remove('copied');
                }, 2000);
            }
        }

        document.addEventListener('DOMContentLoaded', () => {
            const cards = document.querySelectorAll('.card');
            cards.forEach(card => {
                card.addEventListener('click', (e) => {
                    if (!e.target.closest('.copy-btn')) {
                        card.style.transform = 'scale(0.98)';
                        setTimeout(() => {
                            card.style.transform = '';
                        }, 150);
                    }
                });
            });
        });"""

    @staticmethod
    def generate_x_card(links, base64_):
        html = """
        <div class="card">
            <div class="card-header">
                <div class="card-icon">
                    <i class="fas fa-bolt"></i>
                </div>
                <div>
                    <div class="card-title">X Protocol</div>
                    <div class="card-subtitle">VLESS Argo protocol</div>
                </div>
            </div>

            <div class="protocol-badge">Connection Link</div>
        """
        if len(links) > 0:
            for link in links:
                html += f"""
                <div class="link-item">
                    <div class="link-content">{link}</div>
                    <button class="copy-btn" onclick="copyToClipboard('{link}', this)">
                        <i class="fas fa-copy"></i> Copy
                    </button>
                </div>
                """
        else:
            html += '<div class="link-item"><div class="link-content">Links not generated yet</div></div>'

        html += """
            <div class="base64-section">
                <div class="base64-title">
                    <i class="fas fa-qrcode"></i> Base64 Configuration
                </div>
        """
        if base64_:
            html += f"""
                    <div class="base64-content">{base64_}</div>
                    <button class="copy-btn" onclick="copyToClipboard('{base64_}', this)">
                        <i class="fas fa-copy"></i> Copy Base64
                    </button>
            """
        else:
            html += '<div class="base64-content">Subscription not generated yet</div>'
        html += """
            </div>
        </div>"""
        return html

    @staticmethod
    def generate_sbox_card(links, base64_):
        html = """
        <div class="card">
            <div class="card-header">
                <div class="card-icon">
                    <i class="fas fa-rocket"></i>
                </div>
                <div>
                    <div class="card-title">HY2 Protocol</div>
                    <div class="card-subtitle">High-performance protocol</div>
                </div>
            </div>

            <div class="protocol-badge">Connection Link</div>
        """
        if len(links) > 0:
            for link in links:
                html += f"""
                <div class="link-item">
                    <div class="link-content">{link}</div>
                    <button class="copy-btn" onclick="copyToClipboard('{link}', this)">
                        <i class="fas fa-copy"></i> Copy
                    </button>
                </div>
                """
        else:
            html += '<div class="link-item"><div class="link-content">Links not generated yet</div></div>'

        html += """
            <div class="base64-section">
                <div class="base64-title">
                    <i class="fas fa-qrcode"></i> Base64 Configuration
                </div>
        """
        if base64_:
            html += f"""
                    <div class="base64-content">{base64_}</div>
                    <button class="copy-btn" onclick="copyToClipboard('{base64_}', this)">
                        <i class="fas fa-copy"></i> Copy Base64
                    </button>
            """
        else:
            html += '<div class="base64-content">Configuration not generated yet</div>'
        html += """
            </div>
        </div>"""
        return html

    @staticmethod
    def generate_html(x_links, sbox_links, x_base64, sbox_base64):
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xray-Sing</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        {HttpServer.get_styles()}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Xray-Sing</h1>
            <p>Secure and fast configurations</p>
            <div class="status-indicator">
                <i class="fas fa-circle"></i> Online
            </div>
        </div>

        <div class="grid">
            {HttpServer.generate_x_card(x_links, x_base64)}
            {HttpServer.generate_sbox_card(sbox_links, sbox_base64)}
        </div>
    </div>

    <div class="toast" id="toast">Copied to clipboard!</div>

    <script>
        {HttpServer.get_script()}
    </script>
</body>
</html>"""

# ========== MAIN APPLICATION ==========
class Application:
    @staticmethod
    def initialize():
        SystemUtils.ensure_directory(CONFIG['FILE_PATH'])
        SystemUtils.ensure_directory(PATHS['SB_BASE_DIR'])

    @staticmethod
    def start():
        Logger.header("🚀 XRAY-SING STARTUP")
        
        Application.initialize()
        
        # Apply system optimizations
        SystemUtils.apply_system_optimizations()

        # Start sb
        Logger.step("Starting sb server...")
        state['sbProcess'] = SbManager.initialize()
        
        if state['sbProcess']:
            SbManager.generate_links()
        else:
            Logger.warning("sb failed to start, skipping link generation")

        # Start X
        Logger.step("Starting X server...")
        XManager.create_configuration()
        XManager.download_and_run()

        # Wait for services to start
        Logger.step("Waiting for services to start...")
        time.sleep(5)

        # Generate links
        XManager.extract_domains()

        # Start HTTP server
        app = Flask(__name__)

        @app.route("/")
        def home():
            return jsonify({ 
                "service": "Hello World",
            })

        @app.route(f"/{CONFIG['SUB_PATH']}")
        def sub():
            safe_x_links = [HttpServer.escape_html(link) for link in state['xLinks']]
            safe_sbox_links = [HttpServer.escape_html(link) for link in state['sboxLinks']]
            safe_x_base64 = HttpServer.escape_html(state['xBase64'] or '')
            safe_sbox_base64 = HttpServer.escape_html(state['sboxBase64'] or '')
            html = HttpServer.generate_html(safe_x_links, safe_sbox_links, safe_x_base64, safe_sbox_base64)
            return Response(html, mimetype='text/html')

        # Suppress Flask logs
        log = logging.getLogger('werkzeug')
        log.disabled = True
        app.logger.disabled = True

        # Run server in thread
        server_thread = threading.Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': CONFIG['PORT'], 'debug': False, 'use_reloader': False})
        server_thread.start()

        Logger.success(f"HTTP server running on port: {CONFIG['PORT']}")
        Application.print_all_links()

    @staticmethod
    def print_all_links():
        Logger.header("🔗 CONNECTION LINKS")
        
        print(f"\n{COLORS['green']}{COLORS['bright']}📡 X LINKS:{COLORS['reset']}")
        for index, link in enumerate(state['xLinks']):
            print(f"  {COLORS['cyan']}{index + 1}.{COLORS['reset']} {COLORS['yellow']}{link}{COLORS['reset']}")
        
        print(f"\n{COLORS['blue']}{COLORS['bright']}🔗 X BASE64:{COLORS['reset']}")
        print(f"  {COLORS['white']}{state['xBase64']}{COLORS['reset']}")
        
        if len(state['sboxLinks']) > 0:
            print(f"\n{COLORS['magenta']}{COLORS['bright']}⚡ HY2 LINKS:{COLORS['reset']}")
            for index, link in enumerate(state['sboxLinks']):
                print(f"  {COLORS['cyan']}{index + 1}.{COLORS['reset']} {COLORS['yellow']}{link}{COLORS['reset']}")
            
            print(f"\n{COLORS['blue']}{COLORS['bright']}🔗 HY2 BASE64:{COLORS['reset']}")
            print(f"  {COLORS['white']}{state['sboxBase64']}{COLORS['reset']}")
        else:
            print(f"\n{COLORS['yellow']}{COLORS['bright']}⚠ HY2 LINKS: Not available{COLORS['reset']}")
        
        Logger.divider()
        Logger.success("Services are running! Use the links above to connect.")

        # Auto-clear terminal after 3 minutes
        Logger.step("Terminal will clear in 3 minutes...")
        time.sleep(3 * 60)
        print('\033c', end='')
        print('\x1B[2J\x1B[0f', end='')
        print(f"{COLORS['bright']}{COLORS['green']}Thank you for using this Xray-Sing!{COLORS['reset']}\n")

# ========== APPLICATION START ==========
try:
    Application.start()
except Exception as error:
    Logger.error(f"Application failed to start: {error}")
    exit(1)
