# Plum Configurator

A CLI tool to configure Plum 360 infusion devices over a subnet or a manual IP list. It automates admin credential setup, re-authentication, and network configuration while recording results and diagnostics.

## What It Does (Current Behavior)

- Logs in with the initial device credentials from `.env`.
- Configures **Administration** settings first (Web User, Web Password, Challenge Q/A).
- Verifies admin settings by re-fetching the admin page and checking key fields.
- Re-authenticates using the **new Web Password** (with fallback to the original password if needed, logged in `plumPy_error.log`).
- Resolves the device name:
  - Uses the login page `deviceName` when present.
  - If missing or not 6 digits, fetches the status page and extracts the serial from `plumAPlusDeviceManifest`.
  - If still missing, prompts for a 6-digit asset number and prints the manifest for operator context.
- Configures **network settings** (WLAN, security/EAP, Ethernet) only after re-authentication.
- Configures HMMS settings once network configuration completes.
- Writes a CSV log per run and a detailed error log for troubleshooting.

## Key Files

- `plumPy.py` — main script
- `config.ini` — wireless/security/admin/HMMS configuration
- `assets.csv` — device asset and facility mapping (serial in column 4)
- `.env` — device login + fallback credentials (ignored by git)
- `device_log_YYYY-MM-DD.csv` — per-run results
- `plumPy_error.log` — detailed diagnostics
- `status_dumps/` — HTML dumps when status page parsing fails

## Setup

### 1. Python Environment

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. `.env`

Create `.env` in the project root:

```env
# Initial device web interface login
DEVICE_USERNAME=biomed
DEVICE_PASSWORD=your_device_password

# Fallback WPA2-Enterprise identity/password
WPA2_IDENTITY=svcICUPlum360-XX
WPA2_PASSWORD=your_fallback_password

# Passphrase for encrypted WPA secrets
WPA_SECRET_PASSPHRASE=yourSuperSecurePassphrase

# Optional: default subnet to scan
# DEFAULT_SUBNET=192.168.1.0/24
```

### 3. `config.ini`

Example:

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

[Admin]
WebPassword = sg25fh
ChallengeQuestion = What room is Biomed in?
ChallengeResponse = c163

[HMMS]
Host = ws://sa0711v.clients.scripps.org:9292
```

### 4. WPA Secrets Vault (Optional)

If you want facility-specific WPA passwords encrypted at rest:

1. Create `wpa_secrets.json`:

```json
{
  "svcICUPlum360-LJ": "password1",
  "svcICUPlum360-SD": "password2"
}
```

2. Encrypt:

```bash
python secrets_tool.py encrypt <your_passphrase>
```

This produces:
- `wpa_secrets.enc` (encrypted vault)
- `salt.bin` (key derivation salt)

Never commit `wpa_secrets.enc` or `salt.bin`.

## Usage

```bash
python plumPy.py
```

You will be prompted to:
- Choose manual IPs or an interface scan
- Confirm admin changes
- Confirm network changes

You can exit at any prompt with `q`, `quit`, or `exit`. `Ctrl+C` exits cleanly and is logged.

## Troubleshooting

### Status page not parsed / manifest missing

If the device status page returns the **Administration** page (common when session defaults to admin), the manifest won’t be found. The script will write the returned HTML to:

```
status_dumps/status_missing_manifest_<ip>_<timestamp>.html
```

Inspect the file to confirm the page type. The error log will record the response URL, status, content type, and a snippet.

### Admin save verification

After submitting `formAdminProc`, the script fetches the admin page and verifies:
- `webUser`
- `challengeQues`

If verification fails, the run stops and logs the mismatch in `plumPy_error.log`.

### Re-authentication

If login with `WebPassword` fails, the script retries with `DEVICE_PASSWORD` and logs the fallback in `plumPy_error.log`.

## Data Expectations

`assets.csv` format (header and example):

```csv
asset,facility,state,serial
160181,Scripps Memorial Hospital La Jolla Campus,In Service,43428773
```

The script uses:
- Column 1 for asset number
- Column 2 for facility name
- Column 4 for serial number

## License

MIT
