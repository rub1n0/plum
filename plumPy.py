# add the ability to choose what confuguration steps to run (wifi, eth, both)

import os
import csv
import time
import socket
import datetime
import requests
import ipaddress
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn
from ipaddress import ip_network
import urllib3
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import configparser
import json
from cryptography.fernet import Fernet
import warnings
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import ConnectTimeout, ConnectionError, ReadTimeout
warnings.filterwarnings("ignore", category=UserWarning)

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WPA_SECRET_FILE = os.path.join(BASE_DIR, "wpa_secrets.enc")
SALT_FILE = os.path.join(BASE_DIR, "salt.bin")
CONFIG_FILE = os.path.join(BASE_DIR, "config.ini")
ASSETS_FILE = os.path.join(BASE_DIR, "assets.csv")
LOG_FILE = os.path.join(BASE_DIR, "plumPy_error.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
    filemode="w"
)

def load_wpa_secrets(passphrase):
    try:
        if not passphrase:
            console.log("[red]L WPA_SECRET_PASSPHRASE is empty or missing.[/red]")
            logging.error("WPA_SECRET_PASSPHRASE is empty or missing.")
            return {}
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        import base64

        with open(SALT_FILE, "rb") as sf:
            salt = sf.read()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        fernet = Fernet(key)

        with open(WPA_SECRET_FILE, "rb") as ef:
            decrypted = fernet.decrypt(ef.read())

        return json.loads(decrypted.decode())
    except Exception as e:
        console.log(f"[red]L Failed to load WPA secrets: {e}[/red]")
        logging.exception("Failed to load WPA secrets.")
        return {}

results = []

# Sound tone generation functions (pygame-free)
try:
    import winsound
except ImportError:
    winsound = None

def _beep(frequency, duration_ms):
    if winsound is None:
        return
    freq = max(37, min(int(frequency), 32767))
    dur = max(1, int(duration_ms))
    winsound.Beep(freq, dur)

def play_sequence(freqs, duration=50):
    for f in freqs:
        _beep(f, duration)
        time.sleep(duration / 1000.0)

def beep_success():
    play_sequence([820, 1220, 880])
    time.sleep(0.3)

def beep_warning():
    play_sequence([180, 120, 240])
    time.sleep(0.5)

def beep_progress():
    play_sequence([100, 850])
    time.sleep(0.5)

def beep_triumph():
    play_sequence([480, 660, 780, 1050])

def robot_acknowledge():
    for f in (175, 185, 170, 180):
        _beep(f, 75)
    time.sleep(0.5)

def robot_alert():
    for f in (200, 260, 220, 280):
        _beep(f, 90)
    time.sleep(0.5)

def robot_aha():
    for f in range(400, 801, 80):
        _beep(f, 20)
    time.sleep(0.1)
    for f in (700, 760, 720, 780):
        _beep(f, 20)

def game_over_tune():
    play_sequence([784, 880, 988], duration=180)     # G5, A5, B5
    time.sleep(0.2)
    play_sequence([1046, 988, 784], duration=160)    # C6, B5, G5
    time.sleep(0.3)
    play_sequence([659, 698, 784], duration=220)     # E5, F5, G5
    time.sleep(0.2)
    play_sequence([784, 523], duration=400)          # G5, C5
    time.sleep(0.3)
    play_sequence([659, 523], duration=400)  # E5, C5

def victory_fanfare():
    play_sequence([523, 659, 784, 880], duration=180)  # C5, E5, G5, A5
    time.sleep(0.2)
    play_sequence([988, 1046], duration=200)           # B5, C6

def boss_defeated_tune():
    play_sequence([1046, 988, 880], duration=200)      # C6, B5, A5
    time.sleep(0.2)
    play_sequence([784, 659, 523], duration=250)       # G5, E5, C5

def error_alert_tune():
    play_sequence([880, 440, 880, 440], duration=150)  # A5, A4 repeated
    time.sleep(0.3)
    play_sequence([220], duration=500)                 # A3 low tone

def retry_prompt_tune():
    play_sequence([659, 784], duration=180)            # E5, G5
    time.sleep(0.1)
    play_sequence([880], duration=300)                 # A5

def task_success_tune():
    play_sequence([880, 988], duration=100)            # A5, B5
    time.sleep(0.1)
    play_sequence([1046], duration=200)                # C6

def scan_host(ip_str):
    try:
        socket.setdefaulttimeout(0.3)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((ip_str, 8443)) == 0:
                return ip_str
    except Exception as e:
        console.log(e)
    return None



def get_local_subnets(fallback="192.168.1.0/24"):
    subnets = []
    checked_interfaces = []
    EXCLUDED_IF_NAMES = {"lo", "docker0"}
    EXCLUDED_PREFIXES = ("br-", "vbox", "vmnet", "zt", "wg", "TAP", "tun", "npcap", "npf", "Loopback")

    for interface, snics in psutil.net_if_addrs().items():
        if interface in EXCLUDED_IF_NAMES or interface.startswith(EXCLUDED_PREFIXES):
            continue
        console.print(f"=[purple]Checking interface:[/purple] {interface}")
        for snic in snics:
            if snic.family == socket.AF_INET and not snic.address.startswith("127."):
                ip = snic.address
                netmask = snic.netmask
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    if network.prefixlen < 32:
                        subnet_str = str(network)
                        console.print(f"[purple]Detected subnet:[/purple] {subnet_str}")
                        subnets.append(subnet_str)
                        checked_interfaces.append((interface, subnet_str))
                except Exception:
                    continue
    show_checked_interfaces(checked_interfaces)
    return subnets if subnets else [fallback]
    


def scan_subnet(subnet, max_threads=100):
    network = ipaddress.ip_network(subnet, strict=False)
    hosts_list = list(network.hosts())
    live_hosts = []

    console.print(f"[purple]Scanning subnet:[/purple] [white]{subnet}[/white] [purple]with:[/purple] [white]{max_threads}[/white] [purple]threads...[/purple]")
    with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), TimeElapsedColumn(), transient=True) as progress:
        task = progress.add_task("[purple]=  Probing...", total=len(hosts_list))
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(scan_host, str(ip)): ip for ip in hosts_list}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
                progress.advance(task)

    return live_hosts

def get_device_name(html_text):
    match = re.search(r'var\s+deviceName\s*=\s*\"([^\"]+)\"', html_text)
    return match.group(1).strip() if match else "Unknown"

def get_serial_from_status(html_text):
    manifest_match = re.search(r'var\s+plumAPlusDeviceManifest\s*=\s*"([^"]*)"', html_text, re.DOTALL)
    if manifest_match:
        manifest = manifest_match.group(1)
        serial_match = re.search(r"Serial Number:\s*([0-9A-Za-z]+)", manifest)
        return serial_match.group(1).strip() if serial_match else None
    match = re.search(r"Serial Number:\s*([0-9A-Za-z]+)", html_text)
    return match.group(1).strip() if match else None

def get_manifest_from_status(html_text):
    manifest_match = re.search(r'var\s+plumAPlusDeviceManifest\s*=\s*"([^"]*)"', html_text, re.DOTALL)
    if manifest_match:
        return manifest_match.group(1)
    logging.error(
        "Manifest not found in status page. html_len=%s",
        len(html_text or "")
    )
    return None

def format_manifest_for_display(manifest_text):
    if not manifest_text:
        return None
    # Manifest is embedded with escaped newlines/tabs.
    pretty = manifest_text.replace("\\n", "\n").replace("\\t", "    ")
    return pretty.strip()

def is_valid_asset_number(value):
    return bool(re.fullmatch(r"\d{6}", str(value).strip()))

def prompt_for_asset_number(manifest_text=None):
    pretty_manifest = format_manifest_for_display(manifest_text)
    if pretty_manifest:
        console.print("[bold cyan]=  Device Manifest (from status page):[/bold cyan]")
        console.print(pretty_manifest)
        console.print("")
    while True:
        console.print("[bold yellow]=  Device asset number is not set. Enter the 6-digit asset number:[/bold yellow]")
        entered = input(">> ").strip()
        if is_valid_asset_number(entered):
            return entered
        console.print("[red]Invalid asset number. Please enter exactly 6 digits.[/red]")

# Load environment variables
load_dotenv(dotenv_path=os.path.join(BASE_DIR, ".env"))
USERNAME = os.getenv("DEVICE_USERNAME")
DEVICE_PASSWORD = os.getenv("DEVICE_PASSWORD")
WPA_IDENTITY = os.getenv("WPA2_IDENTITY")
WPA_PASSWORD = os.getenv("WPA2_PASSWORD")
passphrase = os.getenv("WPA_SECRET_PASSPHRASE", "")
user_subnet = os.getenv("DEFAULT_SUBNET", "")

# Load INI configuration
config = configparser.ConfigParser()
config.read(CONFIG_FILE)
SSID = os.path.expandvars(config.get("Wireless", "SSID"))
FrequencyBand = os.path.expandvars(config.get("Wireless", "FrequencyBand"))
TransmitPower = os.path.expandvars(config.get("Wireless", "TransmitPower"))
SecurityType = os.path.expandvars(config.get("Security", "SecurityType")).strip()
EAPType = os.path.expandvars(config.get("Security", "EAPType"))
Encryption = os.path.expandvars(config.get("Security", "Encryption"))
ValidateCert = os.path.expandvars(config.get("Security", "ValidateCert"))
AnonIdentity = os.path.expandvars(config.get("Security", "AnonymousIdentity"))
WEB_PASSWORD = os.path.expandvars(config.get("Admin", "WebPassword"))
CHALLENGE_QUESTION = os.path.expandvars(config.get("Admin", "ChallengeQuestion"))
CHALLENGE_RESPONSE = os.path.expandvars(config.get("Admin", "ChallengeResponse"))
HMMS_HOST = os.path.expandvars(config.get("HMMS", "Host"))
REQUEST_TIMEOUT = float(config.get("Network", "RequestTimeout", fallback="3.0"))
POST_DELAY_SEC = float(config.get("Network", "PostDelaySec", fallback="0.1"))
RETRY_TOTAL = int(config.get("Network", "RetryTotal", fallback="1"))
RETRY_BACKOFF_SEC = float(config.get("Network", "RetryBackoffSec", fallback="0.2"))
CONFIRM_BEFORE_APPLY = config.getboolean("General", "ConfirmBeforeApply", fallback=True)

# Validate configuration values
if SecurityType not in ["enterprise", "personal"]:
    raise ValueError(f"Unsupported security type: {SecurityType}")
if FrequencyBand not in ["11a", "11b/g"]:
    raise ValueError(f"Unsupported frequency band: {FrequencyBand}")

# Load asset mappings from CSV
FACILITY_MAP = {
    "Scripps Clinics and Coastal Medical Centers": "svcICUPlum360-CL",
    "Scripps Green Hospital Campus": "svcICUPlum360-GN",
    "Scripps Memorial Hospital Encinitas Campus": "svcICUPlum360-EN",
    "Scripps Mercy Hospital San Diego Campus": "svcICUPlum360-SD",
    "Scripps Memorial Hospital La Jolla Campus": "svcICUPlum360-LJ",
    "Scripps Mercy Hospital Chula Vista Campus": "svcICUPlum360-CV",
    "Scripps Center for Learning and Innovation": "svcICUPlum360-CFLI",
}

ASSET_MAP = {}
ASSET_BY_SERIAL = {}
try:
    with open(ASSETS_FILE, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                asset = row[0].strip()
                facility = row[1].strip()
                serial = row[3].strip() if len(row) > 3 else ""
                ASSET_MAP[asset] = facility
                if serial:
                    ASSET_BY_SERIAL[serial] = asset
except FileNotFoundError:
    console.log("[yellow]Warning: assets.csv not found. Falling back to default WPA2 credentials.[/yellow]")
    logging.exception("assets.csv not found.")



def resolve_credentials(device_name):
    facility = ASSET_MAP.get(device_name)
    if facility and facility in FACILITY_MAP:
        identity = FACILITY_MAP[facility]
        password = WPA_SECRETS.get(identity)
        if not password:
            console.log(f"[yellow] No encrypted password for {identity}. Falling back to WPA2_PASSWORD.[/yellow]")
            password = WPA_PASSWORD
        return identity, password
    return WPA_IDENTITY, WPA_PASSWORD

    if facility and facility in FACILITY_MAP:
        return FACILITY_MAP[facility], WPA_PASSWORD
    return WPA_IDENTITY, WPA_PASSWORD


def configure_device(ip):
    session = requests.Session()
    session.verify = False
    retries = Retry(
        total=RETRY_TOTAL,
        connect=RETRY_TOTAL,
        read=RETRY_TOTAL,
        backoff_factor=RETRY_BACKOFF_SEC,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    def post_step(url, data, step_name):
        try:
            resp = session.post(url, data=data, timeout=REQUEST_TIMEOUT)
            time.sleep(POST_DELAY_SEC)
            if resp is not None and resp.status_code >= 400:
                logging.error(
                    "POST non-OK (%s) url=%s status=%s response_len=%s",
                    step_name,
                    url,
                    resp.status_code,
                    len(resp.text or "")
                )
            return True, False
        except Exception as e:
            status = None
            try:
                status = resp.status_code  # type: ignore[name-defined]
            except Exception:
                status = None
            fatal = isinstance(e, (ConnectTimeout, ConnectionError, ReadTimeout))
            logging.exception(
                "POST failed (%s) url=%s status=%s keys=%s",
                step_name,
                url,
                status,
                ",".join(sorted(data.keys()))
            )
            return False, fatal

    def get_step(url, step_name):
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
            if resp is not None and resp.status_code >= 400:
                logging.error(
                    "GET non-OK (%s) url=%s status=%s response_len=%s",
                    step_name,
                    url,
                    resp.status_code,
                    len(resp.text or "")
                )
            return resp, False
        except Exception as e:
            fatal = isinstance(e, (ConnectTimeout, ConnectionError, ReadTimeout))
            logging.exception("GET failed (%s) url=%s", step_name, url)
            return None, fatal
    base_url = f"https://{ip}:8443"

    status = {
        "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Device IP": ip,
        "BEIC": "Unknown",
        "Login": "Failed",
        "ESSID": "Skipped",
        "WPA2 Identity": "Skipped",
        "Finalize Config": "Skipped",
        "Admin": "Skipped",
        "HMMS": "Skipped"
    }

    try:
        login_url = f"{base_url}/formLoginProc"
        login_data = {"webUser": USERNAME, "webPass": DEVICE_PASSWORD, "NextPage": "eth"}
        resp = session.post(login_url, data=login_data, timeout=REQUEST_TIMEOUT)
        if "Status" not in resp.text:
            console.print(f"[red]=  Login failed for {ip}[/red]")
            logging.error("Login failed for %s. Response length=%s", ip, len(resp.text or ""))
            error_alert_tune()
            return status

        console.print(f"[green] Login successful for {ip}[/green]")
        status["Login"] = "Success"
        device_name = re.search(r'var\s+deviceName\s*=\s*"([^"]+)"', resp.text)
        if device_name:
            device_name = device_name.group(1).strip()
        else:
            device_name = "Unknown"
            if not is_valid_asset_number(device_name):
                status_page, _status_fatal = get_step(f"{base_url}/hsp-phx-ce-status.html", "status_get")
                manifest_text = None
                if status_page and status_page.text:
                    serial = get_serial_from_status(status_page.text)
                    manifest_text = get_manifest_from_status(status_page.text)
                    if serial:
                        mapped_asset = ASSET_BY_SERIAL.get(serial)
                        if mapped_asset and is_valid_asset_number(mapped_asset):
                            console.print(f"[green]=  Resolved asset {mapped_asset} from serial {serial}[/green]")
                            device_name = mapped_asset
            if not is_valid_asset_number(device_name):
                device_name = prompt_for_asset_number(manifest_text)
        status["BEIC"] = device_name

        identity, password = resolve_credentials(device_name)

        admin_payload = {
            "webPass": WEB_PASSWORD,
            "confirmPass": WEB_PASSWORD,
            "challengeQues": CHALLENGE_QUESTION,
            "challengeRes": CHALLENGE_RESPONSE,
            "NextPage": "finish"
        }
        wlan_payload = {
            "WlanEnabled": "on",
            "WlanDhcp": "on",
            "WlanIp": "192.168.0.100",
            "WlanMask": "255.255.255.0",
            "WlanGw": "0.0.0.0",
            "WlanDns1": "0.0.0.0",
            "WlanDns2": "0.0.0.0",
            "WlanDomain": "",
            "DhcpOnAssociate": "0",
            "WlanEssid": SSID,
            "WlanFrequency": FrequencyBand,
            "WlanTransmitPower": TransmitPower,
            "NextPage": "privacy"
        }
        privacy_payload = {
            "WlanSecurityType": SecurityType,
            "WpaEncryption": Encryption,
            "WpaSharedKey": "********",
            "WpaEapType": EAPType,
            "TtlsProtocol": "EAP-MSCHAPv2",
            "PeapInnerProtocol": "EAP-MSCHAPv2",
            "WpaIdentity": identity,
            "WpaPswd": password,
            "WpaPswdConfirm": password,
            "WpaAnonIdentity": AnonIdentity,
            "ServerCertValidate": ValidateCert,
            "NextPage": "finish"
        }
        eth_payload = {
            "EthMac": "00:03:B1:51:63:33",
            "EthDhcp": "on",
            "EthIp": "192.168.0.100",
            "EthMask": "255.255.0.0",
            "EthGw": "0.0.0.0",
            "EthDns1": "0.0.0.0",
            "EthDns2": "0.0.0.0",
            "EthDomain": "",
            "NextPage": "finish"
        }

        if CONFIRM_BEFORE_APPLY:
            show_pending_changes("Admin Changes", admin_payload)
            show_pending_changes("Wireless Changes", wlan_payload)
            show_pending_changes("Security Changes", privacy_payload)
            show_pending_changes("Ethernet Changes", eth_payload)
            console.print(f"[bold yellow]= Confirm apply to device {device_name} at {ip}? (y/n)[/bold yellow]")
            confirm = input(">> ").strip().lower()
            if confirm != "y":
                status["Finalize Config"] = "Skipped"
                status["Admin"] = "Skipped"
                status["HMMS"] = "Skipped"
                return status

        admin_ok, admin_fatal = post_step(f"{base_url}/formAdminProc", admin_payload, "admin")
        status["Admin"] = "Success" if admin_ok else "Failed"
        if admin_fatal:
            status["ESSID"] = "Skipped"
            status["WPA2 Identity"] = "Skipped"
            status["Finalize Config"] = "Skipped"
            status["HMMS"] = "Skipped"
            return status

        wlan_ok, wlan_fatal = post_step(f"{base_url}/formWlanProc", wlan_payload, "wlan")
        if wlan_ok:
            status["ESSID"] = SSID
        if wlan_fatal:
            status["WPA2 Identity"] = "Skipped"
            status["Finalize Config"] = "Skipped"
            status["HMMS"] = "Skipped"
            return status

        privacy_ok, privacy_fatal = post_step(f"{base_url}/formPrivacyProc", privacy_payload, "privacy")
        if privacy_ok:
            status["WPA2 Identity"] = identity
        if privacy_fatal:
            status["Finalize Config"] = "Skipped"
            status["HMMS"] = "Skipped"
            return status

        eth_ok, eth_fatal = post_step(f"{base_url}/formEthProc", eth_payload, "eth")
        status["Finalize Config"] = "Success" if eth_ok else "Failed"
        if eth_fatal:
            status["HMMS"] = "Skipped"
            return status

        dev_type = None
        mmu_page, mmu_get_fatal = get_step(f"{base_url}/hsp-phx-ce-mmu.html", "mmu_get")
        if mmu_get_fatal:
            status["HMMS"] = "Skipped"
            return status
        if mmu_page and mmu_page.text:
            match = re.search(r'var\s+DevType\s*=\s*\"([^\"]+)\"', mmu_page.text)
            if match:
                dev_type = match.group(1).strip()

        mmu_payload = {
            "MmuUrl": HMMS_HOST,
            "DevId": device_name,
            "NextPage": "finish"
        }
        if dev_type:
            mmu_payload["DevType"] = dev_type
        if CONFIRM_BEFORE_APPLY:
            show_pending_changes("HMMS Changes", mmu_payload)
        mmu_ok, _mmu_fatal = post_step(f"{base_url}/formMmuProc", mmu_payload, "mmu")
        status["HMMS"] = "Success" if mmu_ok else "Failed"

    except Exception:
        console.print(f"[red] Error configuring {ip}[/red]")
        logging.exception("Error configuring device %s.", ip)

    return status

# Validate configuration values
if SecurityType not in ["enterprise", "personal"]:
    raise ValueError(f"Unsupported security type: {SecurityType}")
if FrequencyBand not in ["11a", "11b/g"]:
    raise ValueError(f"Unsupported frequency band: {FrequencyBand}")

def save_log(results):
    if not results:
        console.log("[yellow] No results to save.[/yellow]")
        return False
    today = datetime.date.today().strftime('%Y-%m-%d')
    filename = f"device_log_{today}.csv"
    file_exists = os.path.isfile(filename)
    with open(filename, mode="a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        if not file_exists:
            writer.writeheader()
        for entry in results:
            writer.writerow(entry)
    return True

def show_summary(results):
    table = Table(title="=  Plum Configurator Results", title_style="purple", border_style="bright_cyan")
    for k in results[0].keys():
        table.add_column(k, style="green" if "Success" in k or "IP" in k else "cyan", overflow="fold")
    for entry in results:
        table.add_row(*[entry[k] for k in entry])
    console.print(table)
    task_success_tune()

def display_colored_banner():
    banner = r"""
    =============================================================
                ____  _    _   _ __  __ ____   ___ _____ 
               |  _ \| |  | | | |  \/  | __ ) / _ \_   _|
               | |_) | |  | | | | |\/| |  _ \| | | || |  
               |  __/| |__| |_| | |  | | |_) | |_| || |  
               |_|   |_____\___/|_|  |_|____/ \___/ |_| 
                    THE CONFIG-ER-NATOR OF PLUMS!
    =============================================================
    """
    console.print(banner, style="purple")
    task_success_tune()

def get_ip_list_from_user():
    console.print("\n[bold cyan]=  Enter a comma-separated list of IPs (e.g., 192.168.1.10,192.168.1.12):[/bold cyan]")
    ip_input = input(">> ").strip()
    return [ip.strip() for ip in ip_input.split(",") if ip.strip()]

def show_checked_interfaces(interfaces, label_active=None):
    if not interfaces:
        console.print("[red]L No interfaces detected.[/red]")
        return

    table = Table(title="Checked Interfaces", title_style="bold magenta", border_style="cyan")
    table.add_column("Interface", style="green")
    table.add_column("Detected Subnet", style="cyan")
    table.add_column("Status", style="yellow")

    for iface, subnet in interfaces:
        status = " Selected" if label_active and ipaddress.ip_network(subnet) == ipaddress.ip_network(label_active) else ""
        table.add_row(iface, subnet, status)

    console.print(table)

def get_user_selected_interface(interfaces, active_subnet=None):
    if not interfaces:
        console.print("[red]L No valid interfaces found to select from.[/red]")
        return None

    table = Table(title="=  Available Interfaces", title_style="bold magenta", border_style="cyan")
    table.add_column("Index", style="yellow")
    table.add_column("Interface", style="green")
    table.add_column("Detected Subnet", style="cyan")

    for idx, (iface, subnet) in enumerate(interfaces):
        if active_subnet and ipaddress.ip_network(subnet) == ipaddress.ip_network(active_subnet):
            table.add_row(f"[bold yellow]{idx}[/bold yellow]", f"[bold green]{iface}[/bold green]", f"[bold cyan]{subnet}[/bold cyan]")
        else:
            table.add_row(str(idx), iface, subnet)

    console.print(table)
    while True:
        try:
            choice = int(input("Enter the index of the interface you want to scan: ").strip())
            if 0 <= choice < len(interfaces):
                return interfaces[choice][1]  # Return the selected subnet
            else:
                console.print("[red]Invalid choice. Try again.[/red]")
        except ValueError:
            console.print("[red]Please enter a number.[/red]")

def show_pending_changes(title, data):
    table = Table(title=title, title_style="bold magenta", border_style="cyan")
    table.add_column("Field", style="green")
    table.add_column("Value", style="cyan", overflow="fold")
    for k, v in data.items():
        table.add_row(str(k), str(v))
    console.print(table)

if __name__ == "__main__":
    console.clear()
    victory_fanfare()
    display_colored_banner()

    WPA_SECRETS = load_wpa_secrets(passphrase)
    if not WPA_SECRETS:
        console.log("[red]Fatal: WPA secrets failed to load. Exiting.[/red]")
        exit(1)

    selected_subnet = None
    manual_ips = None

    while True:
        all_detected_interfaces = []
        subnets = []
        EXCLUDED_IF_NAMES = {"lo", "docker0"}
        EXCLUDED_PREFIXES = ("br-", "vbox", "vmnet", "zt", "wg", "TAP", "tun", "npcap", "npf", "Loopback")

        for interface, snics in psutil.net_if_addrs().items():
            if interface in EXCLUDED_IF_NAMES or interface.startswith(EXCLUDED_PREFIXES):
                continue
            for snic in snics:
                if snic.family == socket.AF_INET and not snic.address.startswith("127."):
                    ip = snic.address
                    netmask = snic.netmask
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        if network.prefixlen < 32:
                            subnet_str = str(network)
                            subnets.append(subnet_str)
                            all_detected_interfaces.append((interface, subnet_str))
                    except Exception:
                        continue

        # Ask whether to target specific IPs or scan an interface
        if manual_ips is None and not selected_subnet:
            console.print("[bold yellow]= Do you want to target specific IPs instead of scanning an interface? (y/n)[/bold yellow]")
            choice = input(">> ").strip().lower()
            if choice == "y":
                manual_ips = get_ip_list_from_user()
                if not manual_ips:
                    console.print("[red]No valid IPs provided. Exiting.[/red]")
                    exit(1)
            else:
                selected_subnet = get_user_selected_interface(all_detected_interfaces, active_subnet=selected_subnet)
                if not selected_subnet:
                    console.print("[red]No interface selected. Exiting.[/red]")
                    exit(1)

        if manual_ips is not None:
            devices = manual_ips
            console.print(f"[green]=  Using manual IP targets:[/green] {', '.join(devices)}")
        else:
            console.print(f"[green]=  Scanning subnet:[/green] {selected_subnet}")
            devices = scan_subnet(selected_subnet)

        results = [configure_device(ip) for ip in devices]
        robot_alert()

        if not results:
            console.print("[blue] No devices were found or responded in this subnet.[/blue]")
            console.print("[bold yellow]= Do you want to choose a different interface? (y/n)[/bold yellow]")
            try_again = input(">> ").strip().lower()
            if try_again == "y":
                selected_subnet = None
                manual_ips = None
                continue
            else:
                break
        else:
            saved = save_log(results)
            if saved:
                show_summary(results)
            beep_triumph()

        console.print("\n[bold yellow]= Do you want to run the script again? (y/n) [type 'c' to change interface][/bold yellow]")
        answer = input(">> ").strip().lower()
        if answer == "c":
            selected_subnet = None
            manual_ips = None
            continue
        elif answer == "y":
            for iface, subnet in all_detected_interfaces:
                if ipaddress.ip_network(subnet) == ipaddress.ip_network(selected_subnet):
                    show_checked_interfaces([(iface, subnet)], label_active=selected_subnet)
                    break
            retry_prompt_tune()
            continue
        else:
            break

    beep_triumph()
    time.sleep(0.25)
    game_over_tune()
    console.print("[bold green]<  Thank you for using the Plum Config-u-rator! Goodbye![/bold green]")
