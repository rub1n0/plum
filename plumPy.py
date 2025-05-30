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
import numpy as np
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import configparser
import json
from cryptography.fernet import Fernet
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from contextlib import redirect_stdout

# Suppress pygame greeting
with open(os.devnull, 'w') as devnull:
    with redirect_stdout(devnull):
        import pygame

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize pygame mixer for sound playback
pygame.mixer.init(frequency=44100, size=-16, channels=1)
console = Console()

WPA_SECRET_FILE = 'wpa_secrets.enc'
WPA_KEY_FILE = 'secret.key'

def load_wpa_secrets(passphrase):
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        import base64

        with open('salt.bin', 'rb') as sf:
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

        with open('wpa_secrets.enc', 'rb') as ef:
            decrypted = fernet.decrypt(ef.read())

        return json.loads(decrypted.decode())
    except Exception as e:
        console.log(f"[red]❌ Failed to load WPA secrets: {e}[/red]")
        return {}

results = []

# Sound tone generation functions
def generate_tone(frequency, duration_ms, volume=0.5):
    sample_rate = 22050
    duration = duration_ms / 1000.0
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    wave = (np.sin(2 * np.pi * frequency * t) * 32767 * volume).astype(np.int16)
    stereo_wave = np.column_stack((wave, wave))
    return pygame.sndarray.make_sound(stereo_wave)

def generate_sweep(start_freq, end_freq, duration_ms, volume=0.5):
    sample_rate = 44100
    duration = duration_ms / 1000.0
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    freqs = np.linspace(start_freq, end_freq, t.size)
    wave = (np.sin(2 * np.pi * freqs * t) * 32767 * volume).astype(np.int16)
    stereo_wave = np.column_stack((wave, wave))
    return pygame.sndarray.make_sound(stereo_wave)

def generate_modulated_tone(base_freq, mod_freq, duration_ms, volume=0.5):
    sample_rate = 44100
    duration = duration_ms / 1000.0
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    modulator = np.sin(2 * np.pi * mod_freq * t)
    carrier = np.sin(2 * np.pi * base_freq * t + modulator)
    wave = (carrier * 32767 * volume).astype(np.int16)
    stereo_wave = np.column_stack((wave, wave))
    return pygame.sndarray.make_sound(stereo_wave)

def play_sequence(freqs, duration=50):
    for f in freqs:
        sound = generate_tone(f, duration)
        sound.play()
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
    generate_modulated_tone(175, 10, 300).play()
    time.sleep(0.5)

def robot_alert():
    generate_modulated_tone(200, 75, 400).play()
    time.sleep(0.5)


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
        console.log(f"[yellow]⚠️ Error connecting to {ip_str}: {e}[/yellow]")
    return None



def get_local_subnets(fallback="192.168.1.0/24"):
    subnets = []
    checked_interfaces = []
    EXCLUDED_IF_NAMES = {"lo", "docker0"}
    EXCLUDED_PREFIXES = ("br-", "vbox", "vmnet", "zt", "wg", "TAP", "tun", "npcap", "npf", "Loopback")

    for interface, snics in psutil.net_if_addrs().items():
        if interface in EXCLUDED_IF_NAMES or interface.startswith(EXCLUDED_PREFIXES):
            continue
        console.print(f"🔍 [purple]Checking interface:[/purple] {interface}")
        for snic in snics:
            if snic.family == socket.AF_INET and not snic.address.startswith("127."):
                ip = snic.address
                netmask = snic.netmask
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    if network.prefixlen < 32:
                        subnet_str = str(network)
                        console.print(f"🌐 [purple]Detected subnet:[/purple] {subnet_str}")
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

    console.print(f"🌐 [purple]Scanning subnet:[/purple] [white]{subnet}[/white] [purple]with:[/purple] [white]{max_threads}[/white] [purple]threads...[/purple]")
    with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), TimeElapsedColumn(), transient=True) as progress:
        task = progress.add_task("[purple]📡 Probing...", total=len(hosts_list))
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

# Load environment variables
load_dotenv()
USERNAME = os.getenv("DEVICE_USERNAME")
DEVICE_PASSWORD = os.getenv("DEVICE_PASSWORD")
WPA_IDENTITY = os.getenv("WPA2_IDENTITY")
WPA_PASSWORD = os.getenv("WPA2_PASSWORD")
passphrase = os.getenv("WPA_SECRET_PASSPHRASE", "")
user_subnet = os.getenv("DEFAULT_SUBNET", "")

# Load INI configuration
config = configparser.ConfigParser()
config.read("config.ini")
SSID = os.path.expandvars(config.get("Wireless", "SSID"))
FrequencyBand = os.path.expandvars(config.get("Wireless", "FrequencyBand"))
TransmitPower = os.path.expandvars(config.get("Wireless", "TransmitPower"))
SecurityType = os.path.expandvars(config.get("Security", "SecurityType")).strip()
EAPType = os.path.expandvars(config.get("Security", "EAPType"))
Encryption = os.path.expandvars(config.get("Security", "Encryption"))
ValidateCert = os.path.expandvars(config.get("Security", "ValidateCert"))
AnonIdentity = os.path.expandvars(config.get("Security", "AnonymousIdentity"))

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
}

ASSET_MAP = {}
try:
    with open("assets.csv", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                asset, facility = row[0].strip(), row[1].strip()
                ASSET_MAP[asset] = facility
except FileNotFoundError:
    console.log("[yellow]Warning: assets.csv not found. Falling back to default WPA2 credentials.[/yellow]")



def resolve_credentials(device_name):
    facility = ASSET_MAP.get(device_name)
    if facility and facility in FACILITY_MAP:
        identity = FACILITY_MAP[facility]
        password = WPA_SECRETS.get(identity)
        if not password:
            console.log(f"[yellow]⚠️ No encrypted password for {identity}. Falling back to WPA2_PASSWORD.[/yellow]")
            password = WPA_PASSWORD
        return identity, password
    return WPA_IDENTITY, WPA_PASSWORD

    if facility and facility in FACILITY_MAP:
        return FACILITY_MAP[facility], WPA_PASSWORD
    return WPA_IDENTITY, WPA_PASSWORD


def configure_device(ip):
    session = requests.Session()
    session.verify = False
    base_url = f"https://{ip}:8443"

    status = {
        "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Device IP": ip,
        "BEIC": "Unknown",
        "Login": "Failed",
        "ESSID": "Skipped",
        "WPA2 Identity": "Skipped",
        "Finalize Config": "Skipped"
    }

    try:
        login_url = f"{base_url}/formLoginProc"
        login_data = {"webUser": USERNAME, "webPass": DEVICE_PASSWORD, "NextPage": "eth"}
        resp = session.post(login_url, data=login_data)
        if "Status" not in resp.text:
            console.print(f"[red]🚫 Login failed for {ip}[/red]")
            error_alert_tune()
            return status

        console.print(f"[green]✅ Login successful for {ip}[/green]")
        status["Login"] = "Success"
        device_name = re.search(r'var\s+deviceName\s*=\s*"([^"]+)"', resp.text)
        if device_name:
            device_name = device_name.group(1).strip()
        else:
            device_name = "Unknown"
        status["BEIC"] = device_name

        identity, password = resolve_credentials(device_name)

        session.post(f"{base_url}/formWlanProc", data={
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
        })
        status["ESSID"] = SSID

        session.post(f"{base_url}/formPrivacyProc", data={
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
        })
        status["WPA2 Identity"] = identity

        session.post(f"{base_url}/formEthProc", data={
            "EthMac": "00:03:B1:51:63:33",
            "EthDhcp": "on",
            "EthIp": "192.168.0.100",
            "EthMask": "255.255.0.0",
            "EthGw": "0.0.0.0",
            "EthDns1": "0.0.0.0",
            "EthDns2": "0.0.0.0",
            "EthDomain": "",
            "NextPage": "finish"
        })
        status["Finalize Config"] = "Success"

    except Exception as e:
        console.print(f"[red]⚠️ Error configuring {ip}[/red]")
        # console.print(f"[red]⚠️ Error configuring {ip}: {e}[/red]")

    return status

# Validate configuration values
if SecurityType not in ["enterprise", "personal"]:
    raise ValueError(f"Unsupported security type: {SecurityType}")
if FrequencyBand not in ["11a", "11b/g"]:
    raise ValueError(f"Unsupported frequency band: {FrequencyBand}")

def save_log(results):
    if not results:
        console.log("[yellow]⚠️ No results to save.[/yellow]")
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
    table = Table(title="📟 Plum Configurator Results", title_style="purple", border_style="bright_cyan")
    for k in results[0].keys():
        table.add_column(k, style="green" if "Success" in k or "IP" in k else "cyan", overflow="fold")
    for entry in results:
        table.add_row(*[entry[k] for k in entry])
    console.print(table)
    task_success_tune()

def display_colored_banner():
    banner = r"""
    ██████╗ ██╗     ██╗   ██╗███╗   ███╗    ███████╗  ██████╗ ████████╗
    ██╔══██╗██║     ██║   ██║████╗ ████║    ██╔═══██╗██╔═══██╗╚══██╔══╝
    ██████╔╝██║     ██║   ██║██╔████╔██║    ███████╔╝██║   ██║   ██║   
    ██╔═══╝ ██║     ██║   ██║██║╚██╔╝██║    ██╔═══██╗██║   ██║   ██║   
    ██║     ███████╗╚██████╔╝██║ ╚═╝ ██║    ███████╔╝╚██████╔╝   ██║   
    ╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚═╝    ╚══════╝  ╚═════╝    ╚═╝   
                      THE CONFIGUNATOR OF PLUMS!
    """
    console.print(banner, style="purple")
    task_success_tune()

def get_ip_list_from_user():
    console.print("\n[bold cyan]📄 Enter a comma-separated list of IPs (e.g., 192.168.1.10,192.168.1.12):[/bold cyan]")
    ip_input = input(">> ").strip()
    return [ip.strip() for ip in ip_input.split(",") if ip.strip()]

def show_checked_interfaces(interfaces, label_active=None):
    if not interfaces:
        console.print("[red]❌ No interfaces detected.[/red]")
        return

    table = Table(title="🔍 Checked Interfaces", title_style="bold magenta", border_style="cyan")
    table.add_column("Interface", style="green")
    table.add_column("Detected Subnet", style="cyan")
    table.add_column("Status", style="yellow")

    for iface, subnet in interfaces:
        status = "✅ Selected" if label_active and ipaddress.ip_network(subnet) == ipaddress.ip_network(label_active) else ""
        table.add_row(iface, subnet, status)

    console.print(table)

def get_user_selected_interface(interfaces, active_subnet=None):
    if not interfaces:
        console.print("[red]❌ No valid interfaces found to select from.[/red]")
        return None

    table = Table(title="📡 Available Interfaces", title_style="bold magenta", border_style="cyan")
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

if __name__ == "__main__":
    console.clear()
    victory_fanfare()
    display_colored_banner()

    WPA_SECRETS = load_wpa_secrets(passphrase)
    if not WPA_SECRETS:
        console.log("[red]Fatal: WPA secrets failed to load. Exiting.[/red]")
        exit(1)

    selected_subnet = None

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

        # Prompt the user for an interface if none selected yet
        if not selected_subnet:
            selected_subnet = get_user_selected_interface(all_detected_interfaces, active_subnet=selected_subnet)
            if not selected_subnet:
                console.print("[red]No interface selected. Exiting.[/red]")
                exit(1)

        console.print(f"[green]📡 Scanning subnet:[/green] {selected_subnet}")
        devices = scan_subnet(selected_subnet)

        results = [configure_device(ip) for ip in devices]
        robot_alert()

        if not results:
            console.print("[blue]ℹ️ No devices were found or responded in this subnet.[/blue]")
            console.print("[bold yellow]🔁 Do you want to choose a different interface? (y/n)[/bold yellow]")
            try_again = input(">> ").strip().lower()
            if try_again == "y":
                selected_subnet = None
                continue
            else:
                break
        else:
            saved = save_log(results)
            if saved:
                show_summary(results)
            beep_triumph()

        console.print("\n[bold yellow]🔁 Do you want to run the script again? (y/n) [type 'c' to change interface][/bold yellow]")
        answer = input(">> ").strip().lower()
        if answer == "c":
            selected_subnet = None
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
    console.print("[bold green]🎉 Thank you for using the Plum Configurator! Goodbye![/bold green]")