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
DEVICE_USERNAME=deviceuser
DEVICE_PASSWORD=devicepass

# Fallback WPA2-Enterprise identity and password
WPA2_IDENTITY=failed
WPA2_PASSWORD=failed

# Optional fallback passwords (used if encrypted secrets are missing)
svcAcct1_PASSWORD=password1
svcAcct2_PASSWORD=password2
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
  "svcAcct1": "password1",
  "svcAcct2": "password2",
}
```

Then run the following commands:

```bash
python secrets_tool.py encrypt <yourpassphrasehere>
```

This will generate:
- `salt.bin` (your encryption key)
- `wpa_secrets.enc` (your encrypted password vault)

> Both `salt.bin` and `wpa_secrets.enc` should **never be committed to Git**. They're ignored via `.gitignore`.



---

## 🔐 About Encryption

This project uses strong encryption with a passphrase-derived key and a persistent salt:

### 🔑 Key Derivation

The WPA2 identity passwords are encrypted using a passphrase + a random salt (`salt.bin`) with PBKDF2-HMAC-SHA256 and 100,000 iterations. This avoids storing raw keys.

### 📁 Important Files

- `wpa_secrets.enc`: the encrypted password vault
- `salt.bin`: used to derive the encryption key from the passphrase

### ⚙️ Environment Variable

Your passphrase should be provided via an environment variable:

```env
WPA_SECRET_PASSPHRASE=yourSuperSecurePassphrase
```

This variable is used by the Python script to decrypt the `wpa_secrets.enc` file at runtime.

### 🚫 Do Not Delete

- Never delete or overwrite `salt.bin` unless you also re-encrypt your secrets.
- If you lose the passphrase or `salt.bin`, the encrypted secrets **cannot be recovered**.

