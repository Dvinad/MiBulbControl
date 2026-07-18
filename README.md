# Bulb Control

A lightweight Windows system tray app for controlling Xiaomi / Yeelight bulbs on your local network. No cloud dependency for actual control - once your bulb's IP and token are saved, everything runs locally over your wifi.

![tray icon and popup demo](docs/demo.gif)
*(add a gif here - a few seconds of clicking the tray icon and dragging the color picker goes a long way)*

## Why

Xiaomi's own apps are heavy, cloud-dependent, and not built for quickly tweaking a light from your desktop. This is a single Python app that sits in your system tray and gives you instant local control - on/off, brightness, color, warm/cool white, and saved color presets - with a compact popup for quick changes and a fuller setup window when you need it.

## Features

- **System tray control** - lives in your tray, right-click for quick color/brightness/on-off without opening any window
- **Quick popup** - a small frameless HSV color picker + brightness slider + saved presets, opens right from the tray
- **Full setup panel** - a browser-based control panel (`localhost:5000`) for adding bulbs, scanning the network, and fine control
- **QR login** - scan a QR code with the Mi Home app on your phone to pull every bulb and token tied to your Xiaomi account automatically, no manual token hunting
- **Manual add** - or just paste in a bulb's IP and token yourself if you already have them
- **Network scan** - broadcasts on your LAN to find Yeelight devices directly
- **Multi-bulb support** - select multiple bulbs at once, every command fires at all of them together
- **Color presets** - save and delete your own swatches, synced across the popup and setup panel
- **Live status sync** - the UI reads the bulb's actual current color/brightness back so sliders never show stale values
- **Keepalive ping** - quietly pings selected bulbs every ~12s while a window is open so the bulb's wifi radio doesn't drop
- **Packaged installer** - a Windows installer build is available in [Releases](../../releases), no Python required to run it

## Requirements

- Windows
- A Yeelight-compatible bulb (Xiaomi/Yeelight) on the same wifi network as your PC
- Your bulb's IP and token, or a Xiaomi account to fetch them via QR login

## Install

**Option 1 - installer (recommended for most people)**

Download the latest installer from the [Releases page](../../releases) and run it. No Python setup needed.

**Option 2 - run from source**

```bash
git clone https://github.com/Dvinad/MiBulbControl.git
cd MiBulbControl
pip install flask python-miio requests pycryptodome qrcode pillow pywebview pystray
python bulb_control.py
```

## Usage

1. Launch the app - it starts in your system tray
2. Click the tray icon to open the quick popup, or right-click for the menu
3. First time setup: open the **Setup window** from the tray menu, then either
   - **QR login** - scan with the Mi Home app on your phone and approve, your bulbs show up with tokens filled in automatically, tap yours to save
   - **Manual** - type in your bulb's IP and token directly
   - **Scan network** - find bulbs on your wifi and auto-fill the IP
4. Once a bulb is saved and selected, use the popup or setup panel to control on/off, brightness, color, and warm/cool white
5. Save your favorite colors as presets by tapping **+** in the popup

Your PC and the bulb need to be on the same wifi network for local control to work.

## How it works

The app runs a small local Flask server (`localhost:5000`) that talks to your bulb using the [python-miio](https://github.com/rytilahti/python-miio) library over your LAN. The tray icon and popup are `pywebview` windows pointed at that local server, so there's no separate frontend build - it's all one Python file. QR login talks to Xiaomi's cloud API only to fetch device tokens; day-to-day bulb control never leaves your network.

## Contributing

Issues and pull requests are welcome - this is a single-file project right now, kept simple on purpose, but happy to look at anything that improves reliability or adds bulb support.

## License

MIT - see [LICENSE](LICENSE)
