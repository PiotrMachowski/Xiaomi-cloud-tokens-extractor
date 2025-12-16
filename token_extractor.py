from abc import ABC, abstractmethod
import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import random
import re
import socket
import sys
import tempfile
import threading
import time
from getpass import getpass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import requests
from colorama import Fore, Style, init

try:
    from Crypto.Cipher import ARC4
except ModuleNotFoundError:
    from Cryptodome.Cipher import ARC4

from PIL import Image

if sys.platform != "win32":
    import readline

SERVERS = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"]
NAME_TO_LEVEL = {
    "CRITICAL": logging.CRITICAL,
    "FATAL": logging.FATAL,
    "ERROR": logging.ERROR,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}

parser = argparse.ArgumentParser()
parser.add_argument("-ni", "--non_interactive", required=False, help="Non-interactive mode", action="store_true")
parser.add_argument("-u", "--username", required=False, help="Username")
parser.add_argument("-p", "--password", required=False, help="Password")
parser.add_argument("-s", "--server", required=False, help="Server", choices=[*SERVERS, ""])
parser.add_argument("-l", "--log_level", required=False, help="Log level", default="CRITICAL", choices=list(NAME_TO_LEVEL.keys()))
parser.add_argument("-o", "--output", required=False, help="Output file")
parser.add_argument("--host", required=False, help="Host")
args = parser.parse_args()
if args.non_interactive and (not args.username or not args.password):
    parser.error("You need to specify username and password or run as interactive.")

init(autoreset=True)

class ColorFormatter(logging.Formatter):
    COLORS = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "FATAL": Fore.RED + Style.BRIGHT,
        "ERROR": Fore.RED,
        "WARN": Fore.YELLOW,
        "WARNING": Fore.YELLOW,
        "INFO": Fore.GREEN,
        "DEBUG": Fore.BLUE,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        return color + logging.Formatter.format(self, record)


class ColorLogger(logging.Logger):
    def __init__(self, name: str) -> None:
        level = NAME_TO_LEVEL[args.log_level.upper()]
        logging.Logger.__init__(self, name, level)
        color_formatter = ColorFormatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(color_formatter)
        self.addHandler(handler)

logging.setLoggerClass(ColorLogger)
_LOGGER = logging.getLogger("token_extractor")


class XiaomiCloudConnector(ABC):

    def __init__(self):
        self._agent = self.generate_agent()
        self._device_id = self.generate_device_id()
        self._session = requests.session()
        self._ssecurity = None
        self.userId = None
        self._serviceToken = None

    @abstractmethod
    def login(self) -> bool:
        pass

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
        return base64.b64encode(hash_object.digest()).decode("utf-8")

    @staticmethod
    def signed_nonce_sec(nonce, ssecurity):
        hash_object = hashlib.sha256(base64.b64decode(ssecurity) + base64.b64decode(nonce))
        return base64.b64encode(hash_object.digest()).decode("utf-8")

    @staticmethod
    def generate_nonce(millis):
        nonce_bytes = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder="big")
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
        return base64.b64encode(hashlib.sha1(signature_string.encode("utf-8")).digest()).decode()

    @staticmethod
    def generate_enc_params(url, method, signed_nonce, nonce, params, ssecurity):
        params["rc4_hash__"] = XiaomiCloudConnector.generate_enc_signature(url, method, signed_nonce, params)
        for k, v in params.items():
            params[k] = XiaomiCloudConnector.encrypt_rc4(signed_nonce, v)
        params.update({
            "signature": XiaomiCloudConnector.generate_enc_signature(url, method, signed_nonce, params),
            "ssecurity": ssecurity,
            "_nonce": nonce,
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


class PasswordXiaomiCloudConnector(XiaomiCloudConnector):

    def __init__(self):
        super().__init__()
        self._sign = None
        self._cUserId = None
        self._passToken = None
        self._location = None
        self._code = None

    def login(self) -> bool:
        if args.username:
            self._username = args.username
        else:
            print_if_interactive(f"Username {Fore.BLUE}(email, phone number or user ID){Style.RESET_ALL}:")
            self._username = input()
        if args.password:
            self._password = args.password
        else:
            print_if_interactive(f"Password {Fore.BLUE}(not displayed for privacy reasons){Style.RESET_ALL}:")
            self._password = getpass("")

        print_if_interactive()
        print_if_interactive(f"{Fore.BLUE}Logging in...")
        print_if_interactive()

        self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="mi.com")
        self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="xiaomi.com")
        self._session.cookies.set("deviceId", self._device_id, domain="mi.com")
        self._session.cookies.set("deviceId", self._device_id, domain="xiaomi.com")

        if not self.login_step_1():
            print_if_interactive(f"{Fore.RED}Invalid username.")
            return False

        if not self.login_step_2():
            print_if_interactive(f"{Fore.RED}Invalid login or password.")
            return False

        if self._location and not self._serviceToken and not self.login_step_3():
            print_if_interactive(f"{Fore.RED}Unable to get service token.")
            return False

        return True

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
        json_resp = self.to_json(response.text)
        if response.status_code == 200:
            if "_sign" in json_resp:
                self._sign = json_resp["_sign"]
                return True
            elif "ssecurity" in json_resp:
                self._ssecurity = json_resp["ssecurity"]
                self.userId = json_resp["userId"]
                self._cUserId = json_resp["cUserId"]
                self._passToken = json_resp["passToken"]
                self._location = json_resp["location"]
                self._code = json_resp["code"]

                return True

        return False

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
                    if args.non_interactive:
                        parser.error("2FA solution required, rerun in interactive mode")
                    verify_url = json_resp["notificationUrl"]
                    return self.do_2fa_email_flow(verify_url)
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
        # Full URL in case it's relative
        if captcha_url.startswith("/"):
            captcha_url = "https://account.xiaomi.com" + captcha_url

        _LOGGER.debug("Downloading captcha image from: %s", captcha_url)
        response = self._session.get(captcha_url, stream=False)
        if response.status_code != 200:
            _LOGGER.error("Unable to fetch captcha image.")
            return ""

        print_if_interactive(f"{Fore.YELLOW}Captcha verification required.")
        present_image_image(
            response.content,
            message_url = f"Image URL: {Fore.BLUE}http://{args.host or '127.0.0.1'}:31415",
            message_file_saved = "Captcha image saved at: {}",
            message_manually_open_file = "Please open {} and solve the captcha."
        )

        # Ask user for a captcha solution
        print_if_interactive(f"Enter captcha as shown in the image {Fore.BLUE}(case-sensitive){Style.RESET_ALL}:")
        captcha_solution: str = input().strip()
        print_if_interactive()
        return captcha_solution


    def do_2fa_email_flow(self, notification_url: str) -> bool:
        """
        Handles the email-based 2FA flow and extracts ssecurity + serviceToken.
        Robust to cases where verifyEmail returns non-JSON/empty body.
        """
        # 1) Open notificationUrl (authStart)
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        _LOGGER.debug("Opening notificationUrl (authStart): %s", notification_url)
        r = self._session.get(notification_url, headers=headers)
        _LOGGER.debug("authStart final URL: %s status=%s", r.url, r.status_code)

        # 2) Fetch identity options (list)
        context = parse_qs(urlparse(notification_url).query)["context"][0]
        list_params = {
            "sid": "xiaomiio",
            "context": context,
            "_locale": "en_US"
        }
        _LOGGER.debug("GET /identity/list params=%s", list_params)
        r = self._session.get("https://account.xiaomi.com/identity/list", params=list_params, headers=headers)
        _LOGGER.debug("identity/list status=%s body=%s", r.status_code, r.text[:1000] if r.text else "(empty)")

        # Parse identity/list response to determine verification method
        try:
            identity_info = self.to_json(r.text) if r.text.startswith("&&&START&&&") else r.json()
        except Exception:
            identity_info = {}

        # Parse options and flag from identity/list
        options = identity_info.get("options", [])
        flag = identity_info.get("flag", 8)  # default to email
        _LOGGER.debug("identity/list options=%s flag=%s", options, flag)

        # According to hass-xiaomi-miot: flag 4 -> phone, flag 8 -> email
        # Both send and verify endpoints must match
        if flag == 4:
            verification_type = "phone"
            send_endpoint = "/identity/auth/sendPhoneTicket"
            verify_endpoint = "/identity/auth/verifyPhone"
        else:
            verification_type = "email"
            send_endpoint = "/identity/auth/sendEmailTicket"
            verify_endpoint = "/identity/auth/verifyEmail"
        flag_value = str(flag)

        _LOGGER.debug("Using %s verification (flag=%s)", verification_type, flag_value)

        # 3) Request verification ticket
        send_params = {
            "_dc": str(int(time.time() * 1000)),
            "sid": "xiaomiio",
            "context": list_params["context"],
            "mask": "0",
            "_locale": "en_US"
        }
        send_data = {
            "retry": "0",
            "icode": "",
            "_json": "true",
            "ick": self._session.cookies.get("ick", "")
        }
        send_url = f"https://account.xiaomi.com{send_endpoint}"
        _LOGGER.debug("sendTicket POST url=%s params=%s", send_url, send_params)
        _LOGGER.debug("sendTicket data=%s", send_data)
        r = self._session.post(send_url, params=send_params, data=send_data, headers=headers)
        _LOGGER.debug("sendTicket response body=%s", r.text[:500] if r.text else "(empty)")
        try:
            jr = self.to_json(r.text) if r.text.startswith("&&&START&&&") else r.json()
        except Exception:
            jr = {}
        _LOGGER.debug("sendTicket response status=%s json=%s", r.status_code, jr)

        # Handle CAPTCHA requirement for sendTicket
        max_captcha_retries = 3
        captcha_retry = 0
        while jr.get("code") == 87001 and captcha_retry < max_captcha_retries:
            captcha_retry += 1
            captcha_url = jr.get("captchaUrl", "")
            if captcha_url:
                _LOGGER.debug("sendTicket requires CAPTCHA (attempt %d): %s", captcha_retry, captcha_url)
                # Fetch fresh captcha each time
                captcha_code = self.handle_captcha(captcha_url)
                if not captcha_code:
                    _LOGGER.error("Could not solve captcha for sendTicket.")
                    return False
                # Retry sendTicket with captcha - use 'icode' parameter for sendTicket endpoints
                send_data["icode"] = captcha_code
                send_params["_dc"] = str(int(time.time() * 1000))  # Fresh timestamp
                r = self._session.post(send_url, params=send_params, data=send_data, headers=headers)
                _LOGGER.debug("sendTicket retry response body=%s", r.text[:500] if r.text else "(empty)")
                try:
                    jr = self.to_json(r.text) if r.text.startswith("&&&START&&&") else r.json()
                except Exception:
                    jr = {}
                _LOGGER.debug("sendTicket retry response json=%s", jr)
            else:
                break

        if jr.get("code") == 87001:
            print_if_interactive(f"{Fore.RED}CAPTCHA verification failed after {max_captcha_retries} attempts.")
            return False

        # Check if sendTicket succeeded
        if jr.get("code") not in (0, None):
            _LOGGER.error("sendTicket failed with code=%s desc=%s", jr.get("code"), jr.get("desc", ""))
            # If phone verification failed, try email as fallback
            if verification_type == "phone":
                _LOGGER.debug("Phone ticket failed, trying email verification as fallback")
                print_if_interactive(f"{Fore.YELLOW}Phone verification failed, trying email verification...")
                verification_type = "email"
                send_endpoint = "/identity/auth/sendEmailTicket"
                verify_endpoint = "/identity/auth/verifyEmail"
                flag_value = "8"
                send_url = f"https://account.xiaomi.com{send_endpoint}"
                # Reset send_data for email
                send_data = {
                    "retry": "0",
                    "icode": "",
                    "_json": "true",
                    "ick": self._session.cookies.get("ick", "")
                }
                send_params["_dc"] = str(int(time.time() * 1000))
                r = self._session.post(send_url, params=send_params, data=send_data, headers=headers)
                try:
                    jr = self.to_json(r.text) if r.text.startswith("&&&START&&&") else r.json()
                except Exception:
                    jr = {}
                _LOGGER.debug("sendEmailTicket fallback response json=%s", jr)
                if jr.get("code") not in (0, None):
                    _LOGGER.error("Email fallback also failed with code=%s", jr.get("code"))
                    return False

        # 4) Ask user for the verification code
        if args.non_interactive:
            parser.error("Verification code required, rerun without --non_interactive")

        if verification_type == "email":
            print_if_interactive(f"{Fore.YELLOW}Two factor authentication required, please provide the code from the email.")
        else:
            print_if_interactive(f"{Fore.YELLOW}Two factor authentication required, please provide the code from SMS.")
        print_if_interactive()
        print_if_interactive("2FA Code:")
        code = input().strip()
        print_if_interactive()

        verify_params = {
            "_dc": str(int(time.time() * 1000)),
            "_json": "true",
            "sid": "xiaomiio",
            "context": list_params["context"],
            "_locale": "en_US"
        }
        verify_data = {
            "_flag": flag_value,
            "ticket": code,
            "trust": "true",
            "_json": "true",
            "ick": self._session.cookies.get("ick", "")
        }
        verify_url = f"https://account.xiaomi.com{verify_endpoint}"
        _LOGGER.debug("verify POST url=%s params=%s", verify_url, verify_params)
        _LOGGER.debug("verify POST data=%s", verify_data)

        r = self._session.post(verify_url, params=verify_params, data=verify_data, headers=headers)
        _LOGGER.debug("verifyEmail response status=%s headers=%s", r.status_code, dict(r.headers))
        _LOGGER.debug("verifyEmail response body=%s", r.text[:1000] if r.text else "(empty)")
        if r.status_code != 200:
            _LOGGER.error("verifyEmail failed: status=%s body=%s", r.status_code, r.text[:500])
            return False

        try:
            # Response may have &&&START&&& prefix, use to_json to handle it
            jr = self.to_json(r.text) if r.text.startswith("&&&START&&&") else r.json()
            _LOGGER.debug("verifyEmail response json=%s", jr)

            # code=0 means success with location
            # code=2 might mean "pending/continue" - try to proceed to result/check
            if jr.get("code") == 0:
                finish_loc = jr.get("location")
            elif jr.get("code") == 2:
                _LOGGER.debug("verifyEmail returned code=2, trying result/check directly")
                finish_loc = None  # Will trigger fallback to result/check
            else:
                _LOGGER.error("verifyEmail returned unexpected code=%s", jr.get("code"))
                return False
        except Exception as e:
            # Non-JSON or empty; try to extract from headers or body
            _LOGGER.debug("verifyEmail JSON parse failed: %s, attempting fallback extraction.", e)
            finish_loc = r.headers.get("Location")
            if not finish_loc and r.text:
                m = re.search(r'https://account\.xiaomi\.com/identity/result/check\?[^"\']+', r.text)
                if m:
                    finish_loc = m.group(0)

        # Fallback: directly hit result/check using existing identity_session/context
        if not finish_loc:
            _LOGGER.debug("Using fallback call to /identity/result/check")
            r0 = self._session.get(
                "https://account.xiaomi.com/identity/result/check",
                params={"sid": "xiaomiio", "context": context, "_locale": "en_US"},
                headers=headers,
                allow_redirects=False
            )
            _LOGGER.debug("result/check (fallback) status=%s hop-> %s", r0.status_code, r0.headers.get("Location"))
            _LOGGER.debug("result/check (fallback) body=%s", r0.text[:1000] if r0.text else "(empty)")
            if r0.status_code in (301, 302) and r0.headers.get("Location"):
                finish_loc = r0.url if "serviceLoginAuth2/end" in r0.url else r0.headers["Location"]
            elif r0.status_code == 200:
                # Check if verification is still pending (code=2) or actually complete
                try:
                    jr0 = self.to_json(r0.text) if r0.text.startswith("&&&START&&&") else {}
                    _LOGGER.debug("result/check json=%s", jr0)
                except:
                    jr0 = {}

        if not finish_loc:
            _LOGGER.error("Unable to determine finish location after verifyEmail.")
            return False

        # First hop: GET identity/result/check (do NOT follow redirects to inspect Location)
        if "identity/result/check" in finish_loc:
            r = self._session.get(finish_loc, headers=headers, allow_redirects=False)
            _LOGGER.debug("result/check status=%s hop-> %s", r.status_code, r.headers.get("Location"))
            end_url = r.headers.get("Location")
        else:
            end_url = finish_loc

        if not end_url:
            _LOGGER.error("Could not find Auth2/end URL in finish chain.")
            return False

        # 6) Call Auth2/end WITHOUT redirects to capture 'extension-pragma' header containing ssecurity
        r = self._session.get(end_url, headers=headers, allow_redirects=False)
        _LOGGER.debug("Auth2/end status=%s", r.status_code)
        _LOGGER.debug("Auth2/end body(trunc)=%s", r.text[:200])
        # Some servers return 200 first (HTML 'Tips' page), then 302 on next call.
        if r.status_code == 200 and "Xiaomi Account - Tips" in r.text:
            r = self._session.get(end_url, headers=headers, allow_redirects=False)
            _LOGGER.debug("Auth2/end(second) status=%s", r.status_code)

        ext_prag = r.headers.get("extension-pragma")
        if ext_prag:
            try:
                ep_json = json.loads(ext_prag)
                ssec = ep_json.get("ssecurity")
                psec = ep_json.get("psecurity")
                _LOGGER.debug("extension-pragma present. ssecurity=%s psecurity=%s", ssec, psec)
                if ssec:
                    self._ssecurity = ssec
            except Exception as e:
                _LOGGER.debug("Failed to parse extension-pragma: %s", e)

        if not self._ssecurity:
            _LOGGER.error("extension-pragma header missing ssecurity; cannot continue.")
            return False

        # 7) Find STS redirect and visit it (to set serviceToken cookie)
        sts_url = r.headers.get("Location")
        if not sts_url and r.text:
            idx = r.text.find("https://sts.api.io.mi.com/sts")
            if idx != -1:
                end = r.text.find('"', idx)
                if end == -1:
                    end = idx + 300
                sts_url = r.text[idx:end]
        if not sts_url:
            _LOGGER.error("Auth2/end did not provide STS redirect.")
            return False

        r = self._session.get(sts_url, headers=headers, allow_redirects=True)
        _LOGGER.debug("STS final URL: %s status=%s", r.url, r.status_code)
        if r.status_code != 200:
            _LOGGER.error("STS did not complete: status=%s body=%s", r.status_code, r.text[:200])
            return False

        # Extract serviceToken from cookie jar
        self._serviceToken = self._session.cookies.get("serviceToken", domain=".sts.api.io.mi.com")
        found = bool(self._serviceToken)
        _LOGGER.debug("STS body (trunc)=%s", r.text[:20])
        if not found:
            _LOGGER.error("Could not parse serviceToken; cannot complete login.")
            return False
        _LOGGER.debug("STS did not return JSON; assuming 'ok' style response and relying on cookies.")
        _LOGGER.debug("extract_service_token: found=%s", found)

        # Mirror serviceToken to API domains expected by Mi Cloud
        self.install_service_token_cookies(self._serviceToken)

        # Update ids from cookies if available
        self.userId = self.userId or self._session.cookies.get("userId", domain=".xiaomi.com") or self._session.cookies.get("userId", domain=".sts.api.io.mi.com")
        self._cUserId = self._cUserId or self._session.cookies.get("cUserId", domain=".xiaomi.com") or self._session.cookies.get("cUserId", domain=".sts.api.io.mi.com")
        return True

    def install_service_token_cookies(self, token: str):
        for d in [".api.io.mi.com", ".io.mi.com", ".mi.com"]:
            self._session.cookies.set("serviceToken", token, domain=d)
            self._session.cookies.set("yetAnotherServiceToken", token, domain=d)


class QrCodeXiaomiCloudConnector(XiaomiCloudConnector):

    def __init__(self):
        super().__init__()
        self._cUserId = None
        self._pass_token = None
        self._location = None
        self._qr_image_url = None
        self._login_url = None
        self._long_polling_url = None

    def login(self) -> bool:

        if not self.login_step_1():
            print_if_interactive(f"{Fore.RED}Unable to get login message.")
            return False

        if not self.login_step_2():
            print_if_interactive(f"{Fore.RED}Unable to get login QR Image.")
            return False

        if not self.login_step_3():
            print_if_interactive(f"{Fore.RED}Unable to login.")
            return False

        if not self.login_step_4():
            print_if_interactive(f"{Fore.RED}Unable to get service token.")
            return False

        return True

    def login_step_1(self) -> bool:
        _LOGGER.debug("login_step_1")
        url = "https://account.xiaomi.com/longPolling/loginUrl"
        data = {
            "_qrsize": "480",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "callback": "https://sts.api.io.mi.com/sts",
            "_hasLogo": "false",
            "sid": "xiaomiio",
            "serviceParam": "",
            "_locale": "en_GB",
            "_dc": str(int(time.time() * 1000))
        }

        response = self._session.get(url, params=data)
        _LOGGER.debug(response.text)

        if response.status_code == 200:
            response_data = self.to_json(response.text)
            if "qr" in response_data:
                self._qr_image_url = response_data["qr"]
                self._login_url = response_data["loginUrl"]
                self._long_polling_url = response_data["lp"]
                self._timeout = response_data["timeout"]
                return True
        return False

    def login_step_2(self) -> bool:
        _LOGGER.debug("login_step_2")
        url = self._qr_image_url
        _LOGGER.debug("login_step_2: Image URL: %s", url)

        response = self._session.get(url)

        valid: bool = response is not None and response.status_code == 200

        if valid:
            print_if_interactive(f"{Fore.BLUE}Please scan the following QR code to log in.")

            present_image_image(
                response.content,
                message_url = f"QR code URL: {Fore.BLUE}http://{args.host or '127.0.0.1'}:31415",
                message_file_saved = "QR code image saved at: {}",
                message_manually_open_file = "Please open {} and scan the QR code."
            )
            print_if_interactive()
            print_if_interactive(f"{Fore.BLUE}Alternatively you can visit the following URL:")
            print_if_interactive(f"{Fore.BLUE}  {self._login_url}")
            print_if_interactive()
            return True
        else:
            _LOGGER.error("login_step_2: HTTP status: %s; Response: %s", response.status_code, response.text[:500])
        return False

    def login_step_3(self) -> bool:
        _LOGGER.debug("login_step_3")

        url = self._long_polling_url
        _LOGGER.debug("Long polling URL: " + url)

        start_time = time.time()
        # Start long polling
        while True:
            try:
                response = self._session.get(url, timeout=10)
            except requests.exceptions.Timeout:
                _LOGGER.debug("Long polling timed out, retrying...")
                if time.time() - start_time > self._timeout:
                    _LOGGER.debug("Long polling timed out after {} seconds.".format(self._timeout))
                    break
                continue
            except requests.exceptions.RequestException as e:
                _LOGGER.error(f"An error occurred: {e}")
                break

            if response.status_code == 200:
                break
            else:
                _LOGGER.error("Long polling failed, retrying...")

        if response.status_code != 200:
            _LOGGER.error("Long polling failed with status code: " + str(response.status_code))
            return False

        _LOGGER.debug("Login successful!")
        _LOGGER.debug("Response data:")

        response_data = self.to_json(response.text)
        _LOGGER.debug(response_data)

        self.userId = response_data["userId"]
        self._ssecurity = response_data["ssecurity"]
        self._cUserId = response_data["cUserId"]
        self._pass_token = response_data["passToken"]
        self._location = response_data["location"]

        _LOGGER.debug("User ID: " + str(self.userId))
        _LOGGER.debug("Ssecurity: " + str(self._ssecurity))
        _LOGGER.debug("CUser ID: " + str(self._cUserId))
        _LOGGER.debug("Pass token: " + str(self._pass_token))
        _LOGGER.debug("Pass token: " + str(self._location))

        return True

    def login_step_4(self) -> bool:
        _LOGGER.debug("login_step_4")
        _LOGGER.debug("Fetching service token...")

        if not (location := self._location):
            _LOGGER.error("No location found.")
            return False

        response = self._session.get(location, headers={"content-type": "application/x-www-form-urlencoded"})
        if response.status_code != 200:
            return False

        self._serviceToken = response.cookies["serviceToken"]
        _LOGGER.debug("Service token: " + str(self._serviceToken))
        return True


def print_if_interactive(value: str="") -> None:
    if not args.non_interactive:
        print(value)

def print_tabbed(value: str, tab: int) -> None:
    print_if_interactive(" " * tab + value)


def print_entry(key: str, value: str, tab: int) -> None:
    if value:
        print_tabbed(f'{Fore.YELLOW}{key + ":": <10}{Style.RESET_ALL}{value}', tab)


def print_banner() -> None:
    print_if_interactive(Fore.YELLOW + Style.BRIGHT + r"""
                               Xiaomi Cloud
___ ____ _  _ ____ _  _ ____    ____ _  _ ___ ____ ____ ____ ___ ____ ____ 
 |  |  | |_/  |___ |\ | [__     |___  \/   |  |__/ |__| |     |  |  | |__/ 
 |  |__| | \_ |___ | \| ___]    |___ _/\_  |  |  \ |  | |___  |  |__| |  \ 
""" + Style.NORMAL +
"""                                                        by Piotr Machowski 

    """)


def start_image_server(image: bytes) -> None:
    class ImgHttpHandler(BaseHTTPRequestHandler):

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(image)

        def log_message(self, msg, *args) -> None:
            _LOGGER.debug(msg, *args)

    httpd = HTTPServer(("", 31415), ImgHttpHandler)
    _LOGGER.info("server address: %s", httpd.server_address)
    _LOGGER.info("hostname: %s", socket.gethostname())

    thread = threading.Thread(target = httpd.serve_forever)
    thread.daemon = True
    thread.start()


def present_image_image(
        image_content: bytes,
        message_url: str,
        message_file_saved: str,
        message_manually_open_file: str,
) -> None:
    try:
        # Try to serve an image file
        start_image_server(image_content)
        print_if_interactive(message_url)
    except Exception as e1:
        _LOGGER.debug(e1)
        # Save image to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
            tmp.write(image_content)
            tmp_path: str = tmp.name
        print_if_interactive(message_file_saved.format(tmp_path))
        try:
            img = Image.open(tmp_path)
            img.show()
        except Exception as e2:
            _LOGGER.debug(e2)
            print_if_interactive(message_manually_open_file.format(tmp_path))


def main() -> None:
    print_banner()
    if args.non_interactive:
        connector = PasswordXiaomiCloudConnector()
    else:
        print_if_interactive("Please select a way to log in:")
        print_if_interactive(f" p{Fore.BLUE} - using password")
        print_if_interactive(f" q{Fore.BLUE} - using QR code")
        log_in_method = ""
        while not log_in_method in ["P", "Q"]:
            log_in_method = input("p/q: ").upper()
        if log_in_method == "P":
            connector = PasswordXiaomiCloudConnector()
        else:
            connector = QrCodeXiaomiCloudConnector()
        print_if_interactive()

    logged = connector.login()
    if logged:
        print_if_interactive(f"{Fore.GREEN}Logged in.")
        print_if_interactive()
        servers_to_check = get_servers_to_check()
        print_if_interactive()
        output = []
        for current_server in servers_to_check:
            all_homes = []
            homes = connector.get_homes(current_server)
            if homes is not None:
                for h in homes["result"]["homelist"]:
                    all_homes.append({"home_id": h["id"], "home_owner": connector.userId})
            dev_cnt = connector.get_dev_cnt(current_server)
            if dev_cnt is not None:
                for h in dev_cnt["result"]["share"]["share_family"]:
                    all_homes.append({"home_id": h["home_id"], "home_owner": h["home_owner"]})

            if len(all_homes) == 0:
                print_if_interactive(f'{Fore.RED}No homes found for server "{current_server}".')

            for home in all_homes:
                devices = connector.get_devices(current_server, home["home_id"], home["home_owner"])
                home["devices"] = []
                if devices is not None:
                    if devices["result"]["device_info"] is None or len(devices["result"]["device_info"]) == 0:
                        print_if_interactive(f'{Fore.RED}No devices found for server "{current_server}" @ home "{home["home_id"]}".')
                        continue
                    print_if_interactive(f'Devices found for server "{current_server}" @ home "{home["home_id"]}":')
                    for device in devices["result"]["device_info"]:
                        device_data = {**device}
                        print_tabbed(f"{Fore.BLUE}---------", 3)
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
                    print_tabbed(f"{Fore.BLUE}---------", 3)
                    print_if_interactive()
                else:
                    print_if_interactive(f"{Fore.RED}Unable to get devices from server {current_server}.")
            output.append({"server": current_server, "homes": all_homes})
        if args.output:
            with open(args.output, "w") as f:
                f.write(json.dumps(output, indent=4))
    else:
        print_if_interactive(f"{Fore.RED}Unable to log in.")

    if not args.non_interactive:
        print_if_interactive()
        print_if_interactive("Press ENTER to finish")
        input()


def get_servers_to_check() -> list[str]:
    servers_str = ", ".join(SERVERS)
    if args.server is not None:
        server = args.server
    elif args.non_interactive:
        server = ""
    else:
        print_if_interactive(
            f"Select server {Fore.BLUE}(one of: {servers_str}; Leave empty to check all available){Style.RESET_ALL}:")
        server = input()
        while server not in ["", *SERVERS]:
            print_if_interactive(f"{Fore.RED}Invalid server provided. Valid values: {servers_str}")
            print_if_interactive("Server:")
            server = input()

    print_if_interactive()
    if not server == "":
        servers_to_check = [server]
    else:
        servers_to_check = [*SERVERS]
    return servers_to_check


if __name__ == "__main__":
    main()
