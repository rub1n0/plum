# Plum Configurator

🎛️ Automatically configure Plum 360 devices over a subnet using a single tool.

## Features

- Detects devices via subnet scanning
- Configures SSID, WPA2, and EAP settings per-facility
- Pulls data from `.env`, `assets.csv`, `config.ini`
- Rich CLI interface with audio + ASCII feedback
- Export configuration results to CSV
- Auto-restart or exit logic

## Usage

```bash
python plumPy.py
```

## Files

- `plumPy.py` — main executable logic
- `config.ini` — wireless + security settings
- `assets.csv` — maps devices to credentials
- `.env` — contains sensitive creds (excluded)

## Build as .exe

```bash
pip install -r requirements.txt
pyinstaller plumPy.spec
```

## License

MIT
