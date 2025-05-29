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
import pygame
import numpy as np
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import configparser
import traceback

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize pygame mixer for sound playback
pygame.mixer.init(frequency=44100, size=-16, channels=1)
console = Console()

import json
from cryptography.fernet import Fernet

WPA_SECRET_FILE = 'wpa_secrets.enc'
WPA_KEY_FILE = 'secret.key'

def load_wpa_secrets():
    try:
        with open(WPA_KEY_FILE, 'rb') as kf:
            key = kf.read()
        fernet = Fernet(key)
        with open(WPA_SECRET_FILE, 'rb') as ef:
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

def scan_host(ip_str):
    try:
        socket.setdefaulttimeout(0.3)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((ip_str, 8443)) == 0:
                return ip_str
    except:
        pass
    return None

def get_local_subnet(fallback="192.168.1.0/24"):
    for interface, snics in psutil.net_if_addrs().items():
        console.print(f"🔍 [purple]Checking interface:[/purple] {interface}")
        for snic in snics:
            console.print(f"🔍 [purple]Checking NIC:[/purple] {snic.address}")
            if snic.family == socket.AF_INET and not snic.address.startswith("127."):
                ip = snic.address
                netmask = snic.netmask
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    if network.prefixlen < 32:
                        console.print(f"🌐 [purple]Detected local subnet:[/purple] {network}")
                        return str(network)
                except Exception:
                    continue
    return fallback

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
        console.print(f"[red]⚠️ Error configuring {ip}: {e}[/red]")

    return status

# Validate configuration values
if SecurityType not in ["enterprise", "personal"]:
    raise ValueError(f"Unsupported security type: {SecurityType}")
if FrequencyBand not in ["11a", "11b/g"]:
    raise ValueError(f"Unsupported frequency band: {FrequencyBand}")

def save_log(results):
    today = datetime.date.today().strftime('%Y-%m-%d')
    filename = f"device_log_{today}.csv"
    file_exists = os.path.isfile(filename)
    with open(filename, mode="a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        if not file_exists:
            writer.writeheader()
        for entry in results:
            writer.writerow(entry)

def show_summary(results):
    table = Table(title="📟 Plum Configurator Results", title_style="purple", border_style="bright_cyan")
    for k in results[0].keys():
        table.add_column(k, style="green" if "Success" in k or "IP" in k else "cyan", overflow="fold")
    for entry in results:
        table.add_row(*[entry[k] for k in entry])
    console.print(table)

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


def get_ip_list_from_user():
    console.print("\n[bold cyan]📄 Enter a comma-separated list of IPs (e.g., 192.168.1.10,192.168.1.12):[/bold cyan]")
    ip_input = input(">> ").strip()
    return [ip.strip() for ip in ip_input.split(",") if ip.strip()]



if __name__ == "__main__":
    console.clear()
    robot_acknowledge()
    display_colored_banner()
    beep_progress()
    WPA_SECRETS = load_wpa_secrets()

    while True:
        console.print("\n[bold magenta]📌 Choose input method:[/bold magenta]")
        console.print("[1] Scan subnet automatically")
        console.print("[2] Enter IP list manually")
        method = input(">> ").strip()

        if method == "2":
            devices = get_ip_list_from_user()
        else:
            subnet = get_local_subnet()
            devices = scan_subnet(subnet)

        beep_progress()
        results = [configure_device(ip) for ip in devices]
        robot_alert()
        save_log(results)
        show_summary(results)
        beep_triumph()

        console.print("\n[bold yellow]🔁 Do you want to run the script again? (y/n)[/bold yellow]")
        answer = input(">> ").strip().lower()
        if answer != "y":
            break