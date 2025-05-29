# Plum Configurator

🎛️ Automatically configure Plum 360 infusion devices over a subnet or via manual IP entry using a secure and flexible tool.

## Features

- 🔎 Detects devices via subnet scanning or manual IP list
- 🔐 Configures SSID, WPA2 identity, and EAP settings per facility
- 🧠 Supports encrypted vaults for facility-specific passwords using `Fernet`
- 🎨 Rich CLI interface with styled output and audio feedback using `pygame` + `rich`
- 📄 Outputs detailed configuration logs to CSV
- ♻️ Loop logic with optional rerun prompts
- 🔑 .env file supports fallback credentials
- ⚙️ Configuration is driven by `.env`, `assets.csv`, `config.ini`, and `wpa_secrets.enc`

## Files

- `plumPy.py` — main script
- `config.ini` — wireless and security configuration
- `assets.csv` — maps device names to facilities
- `.env` — contains fallback credentials (excluded via .gitignore)
- `wpa_secrets.enc` — encrypted vault of facility passwords
- `secret.key` — key used to decrypt `wpa_secrets.enc` (excluded via .gitignore)
- `device_log_*.csv` — timestamped configuration results

## Usage

Run the script and follow the interactive prompts to configure devices automatically or from a provided IP list.

```bash
python plumPy.py
```

## License

MIT


## Setup Instructions

### 1. Install Python Dependencies

Create a virtual environment (optional but recommended):

```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
```

Install required Python packages:

```bash
pip install -r requirements.txt
```

### 2. Create `.env` File

Create a `.env` file in the project root with the following format:

```env
# Device web interface login
DEVICE_USERNAME=devicelogin
DEVICE_PASSWORD=devicepassword

# Fallback WPA2-Enterprise identity and password
WPA2_IDENTITY=failed
WPA2_PASSWORD=yourfailed

# Optional fallback passwords (used if encrypted secrets are missing)
serviceaccount1_PASSWORD=password1
serviceaccount2_PASSWORD=password2
```

### 3. Create `config.ini`

Define wireless and security configuration in a file named `config.ini`:

```ini
[Wireless]
SSID = Scripps
FrequencyBand = 11a
TransmitPower = 100

[Security]
SecurityType = enterprise
Encryption = CCMP
EAPType = peap
ValidateCert = 0
AnonymousIdentity =
```

### 4. Create and Encrypt `wpa_secrets`

Prepare a JSON file `wpa_secrets.json` like:

```json
{
  "serviceaccount1": "password1",
  "serviceaccount1": "password2",
}
```

Then run the following commands:

```bash
python secrets_tool.py genkey
python secrets_tool.py encrypt
```

This will generate:
- `secret.key` (your encryption key)
- `wpa_secrets.enc` (your encrypted password vault)

> Both `secret.key` and `wpa_secrets.enc` should **never be committed to Git**. They're ignored via `.gitignore`.


## Command-Line Arguments

The script currently supports the following interactive use. CLI support can be extended further.

### Future CLI Support (Planned/Optional)

You can adapt the script to accept CLI arguments instead of interactive prompts. Here’s a pattern you could follow with argparse:

```bash
python plumPy.py --method scan       # scan the subnet
python plumPy.py --method manual --ips 192.168.1.10,192.168.1.12
```

### Suggested Extensions

Add the following to your script to support non-interactive CLI control:

```python
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--method', choices=['scan', 'manual'], help="Device discovery method")
parser.add_argument('--ips', help="Comma-separated IP list for manual mode")
args = parser.parse_args()

if args.method == 'manual' and args.ips:
    devices = [ip.strip() for ip in args.ips.split(',')]
else:
    subnet = get_local_subnet()
    devices = scan_subnet(subnet)
```

This makes the tool scriptable and easier to integrate into automation or CI/CD flows.

