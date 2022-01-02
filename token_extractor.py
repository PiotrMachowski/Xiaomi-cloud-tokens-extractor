import base64
import hashlib
import hmac
import json
import os
import random
import time
from sys import platform

import requests

if platform != "win32":
    import readline

class RC4:
    _idx = 0
    _jdx = 0
    _ksa: list

    def __init__(self, pwd):
        self.init_key(pwd)

    def init_key(self, pwd):
        cnt = len(pwd)
        ksa = list(range(256))
        j = 0
        for i in range(256):
            j = (j + ksa[i] + pwd[i % cnt]) & 255
            ksa[i], ksa[j] = ksa[j], ksa[i]
        self._ksa = ksa
        self._idx = 0
        self._jdx = 0

        self.init1024()

        return self

    def crypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        ksa = self._ksa
        i = self._idx
        j = self._jdx
        out = []
        for byt in data:
            i = (i + 1) & 255
            j = (j + ksa[i]) & 255
            ksa[i], ksa[j] = ksa[j], ksa[i]
            out.append(byt ^ ksa[(ksa[i] + ksa[j]) & 255])
        self._idx = i
        self._jdx = j
        self._ksa = ksa
        return bytearray(out)

    def init1024(self):
        self.crypt(bytes(1024))
        return

class XiaomiCloudConnector:

    def __init__(self, username, password):
        self._username = username
        self._password = password
        self._agent = self.generate_agent()
        self._device_id = self.generate_device_id()
        self._session = requests.session()
        self._sign = None
        self._ssecurity = None
        self._userId = None
        self._cUserId = None
        self._passToken = None
        self._location = None
        self._code = None
        self._serviceToken = None

    def login_step_1(self):
        url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        cookies = {
            "userId": self._username
        }
        response = self._session.get(url, headers=headers, cookies=cookies)
        valid = response.status_code == 200 and "_sign" in self.to_json(response.text)
        if valid:
            self._sign = self.to_json(response.text)["_sign"]
        return valid

    def login_step_2(self):
        url = "https://account.xiaomi.com/pass/serviceLoginAuth2"
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        fields = {
            "sid": "xiaomiio",
            "hash": hashlib.md5(str.encode(self._password)).hexdigest().upper(),
            "callback": "https://sts.api.io.mi.com/sts",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": self._username,
            "_sign": self._sign,
            "_json": "true"
        }
        response = self._session.post(url, headers=headers, params=fields)
        valid = response is not None and response.status_code == 200
        if valid:
            json_resp = self.to_json(response.text)
            valid = "ssecurity" in json_resp and len(str(json_resp["ssecurity"])) > 4
            if valid:
                self._ssecurity = json_resp["ssecurity"]
                self._userId = json_resp["userId"]
                self._cUserId = json_resp["cUserId"]
                self._passToken = json_resp["passToken"]
                self._location = json_resp["location"]
                self._code = json_resp["code"]
            else:
                if "notificationUrl" in json_resp:
                    print("Two factor authentication required, please use following url and restart extractor:")
                    print(json_resp["notificationUrl"])
                    print()
        return valid

    def login_step_3(self):
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        response = self._session.get(self._location, headers=headers)
        if response.status_code == 200:
            self._serviceToken = response.cookies.get("serviceToken")
        return response.status_code == 200

    def login(self):
        self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="mi.com")
        self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="xiaomi.com")
        self._session.cookies.set("deviceId", self._device_id, domain="mi.com")
        self._session.cookies.set("deviceId", self._device_id, domain="xiaomi.com")
        if self.login_step_1():
            if self.login_step_2():
                if self.login_step_3():
                    return True
                else:
                    print("Unable to get service token.")
            else:
                print("Invalid login or password.")
        else:
            print("Invalid username.")
        return False

    def get_devices(self, country):
        url = self.get_api_url(country) + "/home/device_list"
        params = {
            "data": '{"getVirtualModel":false,"getHuamiDevices":0}'
        }
        return self.execute_api_call(url, params)

    def get_beaconkey(self, country, did):
        url = self.get_api_url(country) + "/v2/device/blt_get_beaconkey"
        params = {
            "data": '{"did":"' + did + '","pdid":1}'
        }
        return self.execute_api_call(url, params)

    def execute_api_call(self, url, params):
        headers = {
            "Accept-Encoding": "gzip",
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            'MIOT-ENCRYPT-ALGORITHM': 'ENCRYPT-RC4',
        }
        cookies = {
            "userId": str(self._userId),
            "yetAnotherServiceToken": str(self._serviceToken),
            "serviceToken": str(self._serviceToken),
            "locale": "en_GB",
            "timezone": "GMT+02:00",
            "is_daylight": "1",
            "dst_offset": "3600000",
            "channel": "MI_APP_STORE"
        }
        millis = round(time.time() * 1000)
        nonce = self.generate_nonce(millis)
        signed_nonce = self.signed_nonce(nonce)
        params = self.generate_rc4_params(url.replace("/app", ""), signed_nonce, nonce, params, self._ssecurity)
        response = self._session.post(url, headers=headers, cookies=cookies, params=params)
        if response.status_code == 200:
            return json.loads(self.decrypt_data(signed_nonce, response.text).decode())
        return None

    def get_api_url(self, country):
        return "https://" + ("" if country == "cn" else (country + ".")) + "api.io.mi.com/app"

    def signed_nonce(self, nonce):
        hash_object = hashlib.sha256(base64.b64decode(self._ssecurity) + base64.b64decode(nonce))
        return base64.b64encode(hash_object.digest()).decode('utf-8')

    @staticmethod
    def generate_nonce(millis):
        nonce_bytes = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder='big')
        return base64.b64encode(nonce_bytes).decode()

    @staticmethod
    def generate_agent():
        agent_id = "".join(map(lambda i: chr(i), [random.randint(65, 69) for _ in range(13)]))
        return f"Android-7.1.1-1.0.0-ONEPLUS A3010-136-{agent_id} APP/xiaomi.smarthome APPV/62830"

    @staticmethod
    def generate_device_id():
        return "".join(map(lambda i: chr(i), [random.randint(97, 122) for _ in range(6)]))

    @staticmethod
    def generate_rc4_params(url, signed_nonce, nonce, params, ssecurity):
        params['rc4_hash__'] = XiaomiCloudConnector.sha1_sign('POST', url, params, signed_nonce)
        for k, v in params.items():
            params[k] = XiaomiCloudConnector.encrypt_data(signed_nonce, v)
        params.update({
            'signature': XiaomiCloudConnector.sha1_sign('POST', url, params, signed_nonce),
            'ssecurity': ssecurity,
            '_nonce': nonce,
        })

        return params

    @staticmethod
    def to_json(response_text):
        return json.loads(response_text.replace("&&&START&&&", ""))

    @staticmethod
    def sha1_sign(method, url, dat: dict, nonce):
        path = url.split("com")[1]
        if path[:4] == '/app/':
            path = path[4:]
        arr = [str(method).upper(), path]
        for k, v in dat.items():
            arr.append(f'{k}={v}')
        arr.append(nonce)
        raw = hashlib.sha1('&'.join(arr).encode('utf-8')).digest()
        return base64.b64encode(raw).decode()

    @staticmethod
    def encrypt_data(pwd, data):
        return base64.b64encode(RC4(base64.b64decode(pwd)).crypt(data)).decode()

    @staticmethod
    def decrypt_data(pwd, data):
        return RC4(base64.b64decode(pwd)).crypt(base64.b64decode(data))

def print_tabbed(value, tab):
    print(" " * tab + value)


def print_entry(key, value, tab):
    if value:
        print_tabbed(f'{key + ":": <10}{value}', tab)


servers = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"]
servers_str = ", ".join(servers)
print("Username (email or user ID):")
username = input()
print("Password:")
password = input()
print(f"Server (one of: {servers_str}) Leave empty to check all available:")
server = input()
while server not in ["", *servers]:
    print(f"Invalid server provided. Valid values: {servers_str}")
    print("Server:")
    server = input()

print()
if not server == "":
    servers = [server]

connector = XiaomiCloudConnector(username, password)
print("Logging in...")
logged = connector.login()
if logged:
    print("Logged in.")
    print()
    for current_server in servers:
        devices = connector.get_devices(current_server)
        if devices is not None:
            if len(devices["result"]["list"]) == 0:
                print(f"No devices found for server \"{current_server}\".")
                continue
            print(f"Devices found for server \"{current_server}\":")
            for device in devices["result"]["list"]:
                print_tabbed("---------", 3)
                if "name" in device:
                    print_entry("NAME", device["name"], 3)
                if "did" in device:
                    print_entry("ID", device["did"], 3)
                    if "blt" in device["did"]:
                        beaconkey = connector.get_beaconkey(current_server, device["did"])
                        if beaconkey and "result" in beaconkey and "beaconkey" in beaconkey["result"]:
                            print_entry("BLE KEY", beaconkey["result"]["beaconkey"], 3)
                if "localip" in device:
                    print_entry("IP", device["localip"], 3)
                if "token" in device:
                    print_entry("TOKEN", device["token"], 3)
                if "model" in device:
                    print_entry("MODEL", device["model"], 3)
            print_tabbed("---------", 3)
            print()
        else:
            print("Unable to get devices.")
else:
    print("Unable to log in.")

print()
print("Press ENTER to finish")
input()
