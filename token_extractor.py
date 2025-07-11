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
from datetime import datetime
from getpass import getpass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs

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
parser.add_argument("-u", "--username", required=False, help="Username (email, phone number, or user ID)")
parser.add_argument("-p", "--password", required=False, help="Password")
parser.add_argument("-s", "--server", required=False, help="Server", choices=[*SERVERS, ""])
parser.add_argument("-l", "--log_level", required=False, help="Log level", default="CRITICAL", choices=list(logging.getLevelNamesMapping().keys()))
parser.add_argument("-o", "--output", required=False, help="Output file")
parser.add_argument("--host", required=False, help="Host")
parser.add_argument("--save-creds", required=False, help="Save login credentials to file", metavar="FILE")
parser.add_argument("--load-creds", required=False, help="Load login credentials from file", metavar="FILE")
args = parser.parse_args()
if args.non_interactive and (not args.username or not args.password):
    parser.error("You need to specify username and password or run as interactive.")

_LOGGER = logging.getLogger("token_extractor")
_LOGGER.level = logging.getLevelNamesMapping()[args.log_level.upper()]
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
        self._verify_url = None
        self._identity_session = None
        self._captchaIck = None
        self._identity_options = None

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
                    ntf = json_resp["notificationUrl"]
                    if ntf[:4] != 'http':
                        ntf = f"https://account.xiaomi.com{ntf}"
                    self._verify_url = ntf
                    # Check available verification methods to get identity_session
                    self._identity_options = self._check_identity_list(self._verify_url)
                    if self._identity_options:
                        if self._handle_2fa_verification():
                            # Retry login after successful 2FA
                            return self.login_step_2()
                    else:
                        # Fallback if identity check fails
                        print_if_interactive("Two factor authentication required.")
                        print_if_interactive("Please use following url and restart extractor:")
                        print_if_interactive(ntf)
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

    def _check_identity_list(self, url: str, path: str = 'identity/authStart') -> Optional[list]:
        """Check available identity verification methods."""
        if path not in url:
            return None
        
        try:
            resp = self._session.get(url.replace(path, 'identity/list'))
            self._identity_session = resp.cookies.get('identity_session')
            if not self._identity_session:
                return None
                
            data = json.loads(resp.text.replace('&&&START&&&', ''))
            flag = data.get('flag', 4)
            options = data.get('options', [flag])
            return options
        except Exception as e:
            _LOGGER.error("Failed to check identity list: %s", e)
            return None

    def _handle_2fa_verification(self) -> bool:
        """Handle 2FA verification process."""
        # ANSI color codes
        YELLOW = '\033[93m'
        RED = '\033[91m'
        GREEN = '\033[92m'
        CYAN = '\033[96m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
        
        print_if_interactive("\n" + "="*60)
        print_if_interactive(f"{YELLOW}{BOLD}Two-factor authentication required!{RESET}")
        print_if_interactive("="*60)
        print_if_interactive("\nPlease follow these steps:")
        print_if_interactive("1. Open this URL in your browser:")
        print_if_interactive(f"\n   {CYAN}{self._verify_url}{RESET}\n")
        print_if_interactive("2. Choose your verification method (SMS or Email)")
        print_if_interactive("3. You'll receive a 6-digit verification code")
        print_if_interactive(f"4. {RED}{BOLD}DO NOT enter the code on Xiaomi's website!{RESET}")
        print_if_interactive(f"5. {GREEN}Close the browser and enter the code HERE instead{RESET}")
        print_if_interactive("\n" + "-"*60 + "\n")
        
        while True:
            ticket = input("Enter the 6-digit verification code: ").strip()
            
            if not ticket:
                retry = input("\nNo code entered. Do you want to try again? (y/n): ").strip().lower()
                if retry != 'y':
                    return False
                continue
            
            print_if_interactive("\nVerifying ticket...")
            result = self._verify_ticket(ticket)
            
            if result and result.get('code') == 0:
                print_if_interactive(f"\n{GREEN}{BOLD}✓ Verification successful!{RESET}")
                # Follow location if provided (as in hass-xiaomi-miot)
                if location := result.get('location'):
                    print_if_interactive("Following redirect...")
                    try:
                        self._session.get(location, headers={"User-Agent": self._agent})
                    except Exception as e:
                        _LOGGER.debug("Redirect follow error: %s", e)
                return True
            else:
                print_if_interactive(f"\n{RED}✗ Verification failed.{RESET}")
                if result:
                    print_if_interactive(f"  Error code: {result.get('code')}")
                    print_if_interactive(f"  Message: {result.get('desc', 'Unknown error')}")
                
                retry = input("\nWould you like to try with a different code? (y/n): ").strip().lower()
                if retry != 'y':
                    return False

    def _verify_ticket(self, ticket: str) -> Optional[dict]:
        """Verify the 2FA ticket."""
        if not self._verify_url:
            return {}
            
        options = self._identity_options or []
        
        for flag in options:
            api = {
                4: '/identity/auth/verifyPhone',
                8: '/identity/auth/verifyEmail',
            }.get(flag)
            if not api:
                continue
                
            url = f"https://account.xiaomi.com{api}"
            headers = {
                "User-Agent": self._agent,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            data = {
                '_flag': flag,
                'ticket': ticket,
                'trust': 'true',
                '_json': 'true',
            }
            
            params = {
                '_dc': int(time.time() * 1000),
            }
            
            # Pass identity_session as cookie parameter
            cookies = {}
            if self._identity_session:
                cookies['identity_session'] = self._identity_session
            
            try:
                response = self._session.post(
                    url, 
                    headers=headers, 
                    data=data, 
                    params=params,
                    cookies=cookies
                )
                
                if response.status_code == 200:
                    result = json.loads(response.text.replace('&&&START&&&', ''))
                    if result.get('code') == 0:
                        self._identity_session = None
                        return result
            except Exception as e:
                _LOGGER.error("Verification failed: %s", e)
                
        return {}

    def restore_credentials(self, creds: dict) -> bool:
        """Restore saved credentials."""
        try:
            self.userId = creds.get("userId")
            self._serviceToken = creds.get("serviceToken")
            self._ssecurity = creds.get("ssecurity")
            self._cUserId = creds.get("cUserId")
            self._passToken = creds.get("passToken")
            self._location = creds.get("location")
            self._device_id = creds.get("device_id", self._device_id)
            
            # Set all required cookies as per hass-xiaomi-miot
            self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="mi.com")
            self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="xiaomi.com")
            self._session.cookies.set("deviceId", self._device_id, domain="mi.com")
            self._session.cookies.set("deviceId", self._device_id, domain="xiaomi.com")
            self._session.cookies.set("userId", str(self.userId), domain="mi.com")
            self._session.cookies.set("userId", str(self.userId), domain="xiaomi.com")
            self._session.cookies.set("serviceToken", self._serviceToken, domain="mi.com")
            self._session.cookies.set("serviceToken", self._serviceToken, domain="xiaomi.com")
            self._session.cookies.set("yetAnotherServiceToken", self._serviceToken, domain="mi.com")
            self._session.cookies.set("yetAnotherServiceToken", self._serviceToken, domain="xiaomi.com")
            
            # Test if credentials are still valid by making a properly signed request
            test_server = "cn"
            test_result = self.get_dev_cnt(test_server)
            if test_result and test_result.get("code") == 0:
                return True
            
            # If test failed, credentials are expired
            _LOGGER.info("Saved session expired or invalid")
            return False
        except Exception as e:
            _LOGGER.error(f"Failed to restore credentials: {e}")
            return False

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


def save_credentials(filepath: str, connector: 'XiaomiCloudConnector', username: str = None) -> bool:
    """Save login credentials to a file."""
    try:
        creds = {
            "username": username or connector._username,
            "userId": connector.userId,
            "serviceToken": connector._serviceToken,
            "ssecurity": connector._ssecurity,
            "cUserId": connector._cUserId,
            "passToken": connector._passToken,
            "location": connector._location,
            "device_id": connector._device_id,
            "timestamp": time.time()
        }
        with open(filepath, "w") as f:
            json.dump(creds, f, indent=2)
        return True
    except Exception as e:
        _LOGGER.error(f"Failed to save credentials: {e}")
        return False


def load_credentials(filepath: str) -> Optional[dict]:
    """Load login credentials from a file."""
    try:
        with open(filepath, "r") as f:
            creds = json.load(f)
        # Check if credentials are not too old (7 days)
        if time.time() - creds.get("timestamp", 0) > 7 * 24 * 60 * 60:
            print_if_interactive("Saved credentials are older than 7 days and may have expired.")
        return creds
    except Exception as e:
        _LOGGER.error(f"Failed to load credentials: {e}")
        return None


def find_credential_files() -> list:
    """Find potential credential files in the current directory."""
    import glob
    # Look for files matching common patterns
    patterns = [
        "*_xiaomi_creds_*.json",
        "xiaomi_creds*.json",
        "*xiaomi*.json"
    ]
    
    found_files = {}  # Use dict to avoid duplicates
    for pattern in patterns:
        files = glob.glob(pattern)
        for f in files:
            # Skip if already processed
            if f in found_files:
                continue
                
            # Check if it's actually a credential file
            try:
                with open(f, 'r') as file:
                    data = json.load(file)
                    # Check if it has expected fields
                    if all(key in data for key in ['userId', 'serviceToken', 'ssecurity']):
                        # Get file info
                        stat = os.stat(f)
                        found_files[f] = {
                            'path': f,
                            'username': data.get('username', 'Unknown'),
                            'timestamp': data.get('timestamp', 0),
                            'size': stat.st_size,
                            'modified': stat.st_mtime
                        }
            except:
                continue
    
    # Convert to list and sort by modification time (newest first)
    file_list = list(found_files.values())
    file_list.sort(key=lambda x: x['modified'], reverse=True)
    return file_list


def print_tabbed(value, tab) -> None:
    print_if_interactive(" " * tab + value)


def print_entry(key, value, tab, color=""):
    if value:
        # ANSI color codes
        CYAN = '\033[96m'
        YELLOW = '\033[93m'
        GREEN = '\033[92m'
        RESET = '\033[0m'
        BOLD = '\033[1m'
        
        # Choose color based on key
        if color:
            key_color = color
        elif key in ["NAME", "MODEL"]:
            key_color = CYAN + BOLD
        elif key in ["TOKEN", "BLE KEY"]:
            key_color = YELLOW
        elif key in ["ID", "MAC", "IP"]:
            key_color = GREEN
        else:
            key_color = ""
            
        # Calculate padding based on actual key length (without color codes)
        key_with_colon = f"{key}:"
        padding = 12 - len(key_with_colon)  # Adjust base padding for alignment
        
        formatted_key = f"{key_color}{key}:{RESET}" if key_color else f"{key}:"
        print_tabbed(f'{formatted_key}{" " * padding}{value}', tab)


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
    
    # Color codes
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Check if we should load saved credentials
    username = None
    password = None
    loaded_creds = None
    original_username = None  # Track the original username for saving
    
    # First, check if user specified a credential file
    if args.load_creds:
        print_if_interactive(f"\n{CYAN}Loading saved credentials from {args.load_creds}...{RESET}")
        loaded_creds = load_credentials(args.load_creds)
        if loaded_creds:
            original_username = loaded_creds.get("username", "unknown")
            username = "saved_session"  # Placeholder username
            password = "saved_session"  # Placeholder password
            print_if_interactive(f"{GREEN}✓ Credentials loaded successfully{RESET}")
            print_if_interactive(f"  Logged in as: {CYAN}{original_username}{RESET}")
        else:
            print_if_interactive(f"{RED}✗ Failed to load credentials{RESET}")
    # If no explicit credential file, check for existing ones
    elif not args.non_interactive and not args.username:
        found_files = find_credential_files()
        if found_files:
            print_if_interactive(f"\n{CYAN}Found saved credential file(s):{RESET}")
            for i, f in enumerate(found_files[:3], 1):  # Show max 3 files
                age_days = (time.time() - f['timestamp']) / (24 * 60 * 60)
                age_str = f"{int(age_days)} days ago" if age_days >= 1 else "today"
                print_if_interactive(f"  {i}. {f['path']} ({f['username']}, saved {age_str})")
            
            # Use the most recent file by default
            default_file = found_files[0]['path']
            print(f"\n{CYAN}Use saved credentials? [Y/n]: {RESET}", end="")
            use_saved = input().strip().lower()
            
            if use_saved != 'n':  # Default is yes
                if len(found_files) > 1:
                    print(f"Which file to use? [1-{min(3, len(found_files))}] (default: 1): ", end="")
                    choice = input().strip()
                    if choice.isdigit() and 1 <= int(choice) <= min(3, len(found_files)):
                        selected_file = found_files[int(choice) - 1]['path']
                    else:
                        selected_file = default_file
                else:
                    selected_file = default_file
                    
                print_if_interactive(f"\n{CYAN}Loading credentials from {selected_file}...{RESET}")
                loaded_creds = load_credentials(selected_file)
                if loaded_creds:
                    original_username = loaded_creds.get("username", "unknown")
                    username = "saved_session"
                    password = "saved_session"
                    print_if_interactive(f"{GREEN}✓ Credentials loaded successfully{RESET}")
                    print_if_interactive(f"  Logged in as: {CYAN}{original_username}{RESET}")
                else:
                    print_if_interactive(f"{RED}✗ Failed to load credentials{RESET}")
    
    # If no saved credentials or loading failed, get from user/args
    if not loaded_creds:
        if args.username:
            username = args.username
        else:
            print_if_interactive("Username (email, phone number, or user ID):")
            username = input()
        original_username = username  # Store for later use
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
    
    # Try to use saved credentials if available
    logged = False
    if loaded_creds:
        print_if_interactive(f"\n{CYAN}Using saved session...{RESET}")
        logged = connector.restore_credentials(loaded_creds)
        if logged:
            print_if_interactive(f"{GREEN}✓ Session restored successfully!{RESET}")
        else:
            print_if_interactive(f"{YELLOW}⚠ Saved session expired, please login again{RESET}")
            # Need to get new credentials
            if not args.non_interactive:
                print_if_interactive("\nUsername (email, phone number, or user ID):")
                username = input()
                original_username = username
                print_if_interactive("Password:")
                password = getpass("")
                # Create new connector with fresh credentials
                connector = XiaomiCloudConnector(username, password)
                print_if_interactive("\nLogging in...")
                logged = connector.login()
            else:
                print_if_interactive("\nCannot prompt for credentials in non-interactive mode.")
                return
    
    # If no saved credentials, use normal login
    if not loaded_creds and not logged:
        print_if_interactive("\nLogging in...")
        logged = connector.login()
    
    if logged:
        # Color codes already defined above
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        MAGENTA = '\033[95m'
        BLUE = '\033[94m'
        RED = '\033[91m'
        RESET = '\033[0m'
        BOLD = '\033[1m'
        
        print_if_interactive(f"{GREEN}{BOLD}✓ Logged in successfully!{RESET}")
        print_if_interactive()
        output = []
        total_device_count = 0
        
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
                        print_if_interactive(f'{YELLOW}⚠ No devices found for server "{current_server}" @ home "{home["home_id"]}".{RESET}')
                        continue
                    # Color codes
                    CYAN = '\033[96m'
                    YELLOW = '\033[93m'
                    GREEN = '\033[92m'
                    MAGENTA = '\033[95m'
                    RESET = '\033[0m'
                    BOLD = '\033[1m'
                    DIM = '\033[2m'
                    
                    print_if_interactive(f'\n{GREEN}Devices found for server "{CYAN}{current_server}{GREEN}" @ home "{CYAN}{home["home_id"]}{GREEN}":{RESET}')
                    for idx, device in enumerate(devices["result"]["device_info"], 1):
                        device_data = {**device}
                        print_if_interactive(f"\n   {BOLD}{MAGENTA}Device #{idx}{RESET}")
                        print_tabbed("   " + "═" * 50, 0)
                        
                        # Device name (most important)
                        if "name" in device:
                            print_entry("NAME", device["name"], 6)
                        
                        # Model information
                        if "model" in device:
                            print_entry("MODEL", device["model"], 6)
                        
                        # Network information
                        if "localip" in device or "mac" in device:
                            print_tabbed(f"   {DIM}── Network ──{RESET}", 3)
                            if "mac" in device:
                                print_entry("MAC", device["mac"], 6)
                            if "localip" in device:
                                print_entry("IP", device["localip"], 6)
                        
                        # Authentication information
                        print_tabbed(f"   {DIM}── Authentication ──{RESET}", 3)
                        if "did" in device:
                            print_entry("ID", device["did"], 6)
                            if "blt" in device["did"]:
                                beaconkey = connector.get_beaconkey(current_server, device["did"])
                                if beaconkey and "result" in beaconkey and "beaconkey" in beaconkey["result"]:
                                    print_entry("BLE KEY", beaconkey["result"]["beaconkey"], 6)
                                    device_data["BLE_DATA"] = beaconkey["result"]
                        if "token" in device:
                            print_entry("TOKEN", device["token"], 6)
                        
                        home["devices"].append(device_data)
                    
                    total_device_count += len(devices["result"]["device_info"])
                    print_if_interactive()
                else:
                    print_if_interactive(f"Unable to get devices from server {current_server}.")
            output.append({"server": current_server, "homes": all_homes})
        
        # Print summary
        print_if_interactive(f"\n{BLUE}{BOLD}{'='*60}{RESET}")
        print_if_interactive(f"{GREEN}{BOLD}Summary: Found {YELLOW}{total_device_count}{GREEN} device(s) across {YELLOW}{len(servers_to_check)}{GREEN} server(s){RESET}")
        print_if_interactive(f"{BLUE}{BOLD}{'='*60}{RESET}\n")
        
        if args.output:
            with open(args.output, "w") as f:
                f.write(json.dumps(output, indent=4))
            print_if_interactive(f"{GREEN}✓ Device information saved to {CYAN}{args.output}{RESET}")
        
        # Save credentials if requested
        if args.save_creds:
            if save_credentials(args.save_creds, connector, original_username):
                print_if_interactive(f"{GREEN}✓ Login credentials saved to {CYAN}{args.save_creds}{RESET}")
                print_if_interactive(f"{YELLOW}  Use --load-creds {args.save_creds} to reuse these credentials next time{RESET}")
            else:
                print_if_interactive(f"{RED}✗ Failed to save credentials{RESET}")
        elif not args.non_interactive and not loaded_creds:
            # Ask if user wants to save credentials
            print(f"\n{CYAN}Would you like to save login credentials for future use? (y/n): {RESET}", end="")
            save_choice = input().strip().lower()
            if save_choice == 'y':
                # Generate default filename
                current_date = datetime.now().strftime("%Y%m%d")
                # Extract username part (before @ for email, or full username)
                username_part = username.split('@')[0] if '@' in username else username
                # Clean username for filename (remove special chars)
                username_clean = ''.join(c for c in username_part if c.isalnum() or c in ('-', '_'))
                default_filename = f"{username_clean}_xiaomi_creds_{current_date}.json"
                
                print(f"Enter filename to save credentials (default: {default_filename}): ", end="")
                cred_file = input().strip()
                
                # Use default if empty
                if not cred_file:
                    cred_file = default_filename
                
                if save_credentials(cred_file, connector, original_username):
                    print_if_interactive(f"{GREEN}✓ Credentials saved to {CYAN}{cred_file}{RESET}")
                    print_if_interactive(f"{YELLOW}  Use --load-creds {cred_file} to reuse these credentials next time{RESET}")
                else:
                    print_if_interactive(f"{RED}✗ Failed to save credentials{RESET}")
    else:
        print_if_interactive("Unable to log in.")

    if not args.non_interactive:
        print_if_interactive()
        print_if_interactive("Press ENTER to finish")
        input()


if __name__ == "__main__":
    main()
