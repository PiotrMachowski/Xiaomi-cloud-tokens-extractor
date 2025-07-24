import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import random
import socket
import sys
import tempfile
import threading
import time
from getpass import getpass
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

try:
    from Crypto.Cipher import ARC4
except ModuleNotFoundError:
    from Cryptodome.Cipher import ARC4
from PIL import Image

if sys.platform != "win32":
    import readline

SERVERS = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"]

parser = argparse.ArgumentParser()
parser.add_argument("-ni", "--non_interactive", required=False, help="Non-nteractive mode", action="store_true")
parser.add_argument("-u", "--username", required=False, help="Username")
parser.add_argument("-p", "--password", required=False, help="Password")
parser.add_argument("-s", "--server", required=False, help="Server", choices=[*SERVERS, ""])
parser.add_argument("-l", "--log_level", required=False, help="Log level", default="CRITICAL", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
parser.add_argument("-o", "--output", required=False, help="Output file")
parser.add_argument("--host", required=False, help="Host")
args = parser.parse_args()
if args.non_interactive and (not args.username or not args.password):
    parser.error("You need to specify username and password or run as interactive.")

_LOGGER = logging.getLogger("token_extractor")
_LOGGER.level = getattr(logging, args.log_level.upper())
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
_LOGGER.addHandler(handler)


class XiaomiCloudConnector:

    def __init__(self, username, password):
        self._username = username
        self._password = password
        self._agent = self.generate_agent()
        self._device_id = self.generate_device_id()
        self._session = requests.session()
        self._sign = None
        self._ssecurity = None
        self.userId = None
        self._cUserId = None
        self._passToken = None
        self._location = None
        self._code = None
        self._serviceToken = None

    def login_step_1(self):
        _LOGGER.debug("login_step_1")
        url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        cookies = {
            "userId": self._username
        }
        response = self._session.get(url, headers=headers, cookies=cookies)
        _LOGGER.debug(response.text)
        valid = response.status_code == 200 and "_sign" in self.to_json(response.text)
        if valid:
            self._sign = self.to_json(response.text)["_sign"]
        return valid

    def login_step_2(self) -> bool:
        _LOGGER.debug("login_step_2")
        url: str = "https://account.xiaomi.com/pass/serviceLoginAuth2"
        headers: dict = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        fields: dict = {
            "sid": "xiaomiio",
            "hash": hashlib.md5(str.encode(self._password)).hexdigest().upper(),
            "callback": "https://sts.api.io.mi.com/sts",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": self._username,
            "_sign": self._sign,
            "_json": "true"
        }
        _LOGGER.debug("login_step_2: URL: %s", url)
        _LOGGER.debug("login_step_2: Fields: %s", fields)

        response = self._session.post(url, headers=headers, params=fields, allow_redirects=False)
        _LOGGER.debug("login_step_2: Response text: %s", response.text)

        valid: bool = response is not None and response.status_code == 200

        if valid:
            json_resp: dict = self.to_json(response.text)
            if "captchaUrl" in json_resp and json_resp["captchaUrl"] is not None:
                if args.non_interactive:
                    parser.error("Captcha solution required, rerun in interactive mode")
                captcha_code: str = self.handle_captcha(json_resp["captchaUrl"])
                if not captcha_code:
                    _LOGGER.debug("Could not solve captcha.")
                    return False
                # Add captcha code to the fields and retry
                fields["captCode"] = captcha_code
                _LOGGER.debug("Retrying login with captcha.")
                response = self._session.post(url, headers=headers, params=fields, allow_redirects=False)
                _LOGGER.debug("login_step_2: Retry Response text: %s", response.text[:1000])
                if response is not None and response.status_code == 200:
                    json_resp = self.to_json(response.text)
                else:
                    _LOGGER.error("Login failed even after captcha.")
                    return False
                if "code" in json_resp and json_resp["code"] == 87001:
                    print_if_interactive("Invalid captcha.")
                    return False

            valid = "ssecurity" in json_resp and len(str(json_resp["ssecurity"])) > 4
            if valid:
                self._ssecurity = json_resp["ssecurity"]
                self.userId = json_resp.get("userId", None)
                self._cUserId = json_resp.get("cUserId", None)
                self._passToken = json_resp.get("passToken", None)
                self._location = json_resp.get("location", None)
                self._code = json_resp.get("code", None)
            else:
                if "notificationUrl" in json_resp:
                    print_if_interactive("Two factor authentication required, please use following url and restart extractor:")
                    print_if_interactive(json_resp["notificationUrl"])
                    print_if_interactive()
                else:
                    _LOGGER.error("login_step_2: Login failed, server returned: %s", json_resp)
        else:
            _LOGGER.error("login_step_2: HTTP status: %s; Response: %s", response.status_code, response.text[:500])
        return valid

    def login_step_3(self):
        _LOGGER.debug("login_step_3")
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        response = self._session.get(self._location, headers=headers)
        _LOGGER.debug(response.text)
        if response.status_code == 200:
            self._serviceToken = response.cookies.get("serviceToken")
        return response.status_code == 200

    def handle_captcha(self, captcha_url: str) -> str:

        # Full URL in case it s relative
        if captcha_url.startswith("/"):
            captcha_url = "https://account.xiaomi.com" + captcha_url

        _LOGGER.debug("Downloading captcha image from: %s", captcha_url)
        response = self._session.get(captcha_url, stream=False)
        if response.status_code != 200:
            _LOGGER.error("Unable to fetch captcha image.")
            return ""

        try:
            # Try to serve an image file
            start_image_server(response.content)
            print_if_interactive(f"Captcha image URL: http://{args.host or '127.0.0.1'}:31415")
        except Exception as e1:
            _LOGGER.debug(e1)
            # Save image to a temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
                tmp.write(response.content)
                tmp_path: str = tmp.name
            print_if_interactive(f"Captcha image saved at: {tmp_path}")
            try:
                img = Image.open(tmp_path)
                img.show()
            except Exception as e2:
                _LOGGER.debug(e2)
                print_if_interactive(f"Please open {tmp_path} and solve the captcha.")

        # Ask user for a captcha solution
        captcha_solution: str = input("Enter captcha as shown in the image: ").strip()
        return captcha_solution

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
                    print_if_interactive("Unable to get service token.")
            else:
                print_if_interactive("Invalid login or password.")
        else:
            print_if_interactive("Invalid username.")
        return False

    def get_homes(self, country):
        url = self.get_api_url(country) + "/v2/homeroom/gethome"
        params = {
            "data": '{"fg": true, "fetch_share": true, "fetch_share_dev": true, "limit": 300, "app_ver": 7}'}
        return self.execute_api_call_encrypted(url, params)

    def get_devices(self, country, home_id, owner_id):
        url = self.get_api_url(country) + "/v2/home/home_device_list"
        params = {
            "data": '{"home_owner": ' + str(owner_id) +
            ',"home_id": ' + str(home_id) +
            ',  "limit": 200,  "get_split_device": true, "support_smart_home": true}'
        }
        return self.execute_api_call_encrypted(url, params)

    def get_dev_cnt(self, country):
        url = self.get_api_url(country) + "/v2/user/get_device_cnt"
        params = {
            "data": '{ "fetch_own": true, "fetch_share": true}'
        }
        return self.execute_api_call_encrypted(url, params)

    def get_beaconkey(self, country, did):
        url = self.get_api_url(country) + "/v2/device/blt_get_beaconkey"
        params = {
            "data": '{"did":"' + did + '","pdid":1}'
        }
        return self.execute_api_call_encrypted(url, params)

    def execute_api_call_encrypted(self, url, params):
        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        }
        cookies = {
            "userId": str(self.userId),
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
        fields = self.generate_enc_params(url, "POST", signed_nonce, nonce, params, self._ssecurity)
        response = self._session.post(url, headers=headers, cookies=cookies, params=fields)
        if response.status_code == 200:
            decoded = self.decrypt_rc4(self.signed_nonce(fields["_nonce"]), response.text)
            return json.loads(decoded)
        return None

    @staticmethod
    def get_api_url(country):
        return "https://" + ("" if country == "cn" else (country + ".")) + "api.io.mi.com/app"

    def signed_nonce(self, nonce):
        hash_object = hashlib.sha256(base64.b64decode(self._ssecurity) + base64.b64decode(nonce))
        return base64.b64encode(hash_object.digest()).decode('utf-8')

    @staticmethod
    def signed_nonce_sec(nonce, ssecurity):
        hash_object = hashlib.sha256(base64.b64decode(ssecurity) + base64.b64decode(nonce))
        return base64.b64encode(hash_object.digest()).decode('utf-8')

    @staticmethod
    def generate_nonce(millis):
        nonce_bytes = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder='big')
        return base64.b64encode(nonce_bytes).decode()

    @staticmethod
    def generate_agent():
        agent_id = "".join(
            map(lambda i: chr(i), [random.randint(65, 69) for _ in range(13)])
        )
        random_text = "".join(map(lambda i: chr(i), [random.randint(97, 122) for _ in range(18)]))
        return f"{random_text}-{agent_id} APP/com.xiaomi.mihome APPV/10.5.201"

    @staticmethod
    def generate_device_id():
        return "".join(map(lambda i: chr(i), [random.randint(97, 122) for _ in range(6)]))

    @staticmethod
    def generate_signature(url, signed_nonce, nonce, params):
        signature_params = [url.split("com")[1], signed_nonce, nonce]
        for k, v in params.items():
            signature_params.append(f"{k}={v}")
        signature_string = "&".join(signature_params)
        signature = hmac.new(base64.b64decode(signed_nonce), msg=signature_string.encode(), digestmod=hashlib.sha256)
        return base64.b64encode(signature.digest()).decode()

    @staticmethod
    def generate_enc_signature(url, method, signed_nonce, params):
        signature_params = [str(method).upper(), url.split("com")[1].replace("/app/", "/")]
        for k, v in params.items():
            signature_params.append(f"{k}={v}")
        signature_params.append(signed_nonce)
        signature_string = "&".join(signature_params)
        return base64.b64encode(hashlib.sha1(signature_string.encode('utf-8')).digest()).decode()

    @staticmethod
    def generate_enc_params(url, method, signed_nonce, nonce, params, ssecurity):
        params['rc4_hash__'] = XiaomiCloudConnector.generate_enc_signature(url, method, signed_nonce, params)
        for k, v in params.items():
            params[k] = XiaomiCloudConnector.encrypt_rc4(signed_nonce, v)
        params.update({
            'signature': XiaomiCloudConnector.generate_enc_signature(url, method, signed_nonce, params),
            'ssecurity': ssecurity,
            '_nonce': nonce,
        })
        return params

    @staticmethod
    def to_json(response_text):
        return json.loads(response_text.replace("&&&START&&&", ""))

    @staticmethod
    def encrypt_rc4(password, payload):
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return base64.b64encode(r.encrypt(payload.encode())).decode()

    @staticmethod
    def decrypt_rc4(password, payload):
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return r.encrypt(base64.b64decode(payload))


def print_if_interactive(value="") -> None:
    if not args.non_interactive:
        print(value)

def print_tabbed(value, tab) -> None:
    print_if_interactive(" " * tab + value)


def print_entry(key, value, tab):
    if value:
        print_tabbed(f'{key + ":": <10}{value}', tab)


def start_image_server(image: bytes) -> None:
    class ImgHttpHandler(BaseHTTPRequestHandler):

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(image)

        def log_message(self, msg, *args) -> None:
            _LOGGER.debug(msg, *args)

    httpd = HTTPServer(('', 31415), ImgHttpHandler)
    _LOGGER.info("server address: %s", httpd.server_address)
    _LOGGER.info("hostname: %s", socket.gethostname())

    thread = threading.Thread(target = httpd.serve_forever)
    thread.daemon = True
    thread.start()


def main() -> None:
    servers_str = ", ".join(SERVERS)
    if args.username:
        username = args.username
    else:
        print_if_interactive("Username (email or user ID):")
        username = input()
    if args.password:
        password = args.password
    else:
        print_if_interactive("Password:")
        password = getpass("")
    if args.server is not None:
        server = args.server
    elif args.non_interactive:
        server = ""
    else:
        print_if_interactive(f"Server (one of: {servers_str}) Leave empty to check all available:")
        server = input()
        while server not in ["", *SERVERS]:
            print_if_interactive(f"Invalid server provided. Valid values: {servers_str}")
            print_if_interactive("Server:")
            server = input()

    print_if_interactive()
    if not server == "":
        servers_to_check = [server]
    else:
        servers_to_check = [*SERVERS]
    connector = XiaomiCloudConnector(username, password)
    print_if_interactive("Logging in...")
    logged = connector.login()
    if logged:
        print_if_interactive("Logged in.")
        print_if_interactive()
        output = []
        for current_server in servers_to_check:
            all_homes = []
            homes = connector.get_homes(current_server)
            if homes is not None:
                for h in homes['result']['homelist']:
                    all_homes.append({'home_id': h['id'], 'home_owner': connector.userId})
            dev_cnt = connector.get_dev_cnt(current_server)
            if dev_cnt is not None:
                for h in dev_cnt["result"]["share"]["share_family"]:
                    all_homes.append({'home_id': h['home_id'], 'home_owner': h['home_owner']})

            if len(all_homes) == 0:
                print_if_interactive(f'No homes found for server "{current_server}".')

            for home in all_homes:
                devices = connector.get_devices(current_server, home['home_id'], home['home_owner'])
                home["devices"] = []
                if devices is not None:
                    if devices["result"]["device_info"] is None or len(devices["result"]["device_info"]) == 0:
                        print_if_interactive(f'No devices found for server "{current_server}" @ home "{home["home_id"]}".')
                        continue
                    print_if_interactive(f'Devices found for server "{current_server}" @ home "{home["home_id"]}":')
                    for device in devices["result"]["device_info"]:
                        device_data = {**device}
                        print_tabbed("---------", 3)
                        if "name" in device:
                            print_entry("NAME", device["name"], 3)
                        if "did" in device:
                            print_entry("ID", device["did"], 3)
                            if "blt" in device["did"]:
                                beaconkey = connector.get_beaconkey(current_server, device["did"])
                                if beaconkey and "result" in beaconkey and "beaconkey" in beaconkey["result"]:
                                    print_entry("BLE KEY", beaconkey["result"]["beaconkey"], 3)
                                    device_data["BLE_DATA"] = beaconkey["result"]
                        if "mac" in device:
                            print_entry("MAC", device["mac"], 3)
                        if "localip" in device:
                            print_entry("IP", device["localip"], 3)
                        if "token" in device:
                            print_entry("TOKEN", device["token"], 3)
                        if "model" in device:
                            print_entry("MODEL", device["model"], 3)
                        home["devices"].append(device_data)
                    print_tabbed("---------", 3)
                    print_if_interactive()
                else:
                    print_if_interactive(f"Unable to get devices from server {current_server}.")
            output.append({"server": current_server, "homes": all_homes})
        if args.output:
            with open(args.output, "w") as f:
                f.write(json.dumps(output, indent=4))
    else:
        print_if_interactive("Unable to log in.")

    if not args.non_interactive:
        print_if_interactive()
        print_if_interactive("Press ENTER to finish")
        input()


if __name__ == "__main__":
    main()
