"""Public CLI acceptance coverage for targeted BLE key output.

Feature matrix:
- Retrieve only one device's BLE key through the non-interactive subprocess CLI:
  covered here with a synthetic cloud boundary.
- Owner-only, no-overwrite key output and failure when the target is absent:
  covered here.
- Non-target BLE devices are not queried, and failed targeting preserves existing
  account output: covered here.
- Existing account-wide JSON output without the new flags: covered here.
- QR login, interactive prompts, 2FA, and live Xiaomi Cloud behavior: not covered
  by this fixture and remain adaptation gaps.

The fixture replaces only the external requests package. It does not import or
call implementation details from token_extractor.py. All identities, addresses,
and keys below are explicitly synthetic test data.
"""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = Path(
    os.environ.get("TOKEN_EXTRACTOR_UNDER_TEST", REPOSITORY_ROOT / "token_extractor.py")
)
EXAMPLE_MAC = "02:00:00:00:00:01"
EXAMPLE_KEY = "00112233445566778899AABBCCDDEEFF"

FAKE_REQUESTS = textwrap.dedent(
    r'''
    import base64
    import hashlib
    import json
    import os

    try:
        from Crypto.Cipher import ARC4
    except ModuleNotFoundError:
        from Cryptodome.Cipher import ARC4


    SSECURITY = base64.b64encode(b"fixture-security").decode()


    class RequestException(Exception):
        pass


    class Timeout(RequestException):
        pass


    class _Exceptions:
        RequestException = RequestException
        Timeout = Timeout


    exceptions = _Exceptions()


    class CookieJar(dict):
        def set(self, name, value, domain=None):
            self[name] = value
            if domain is not None:
                self[(name, domain)] = value

        def get(self, name, default=None, domain=None):
            if domain is not None:
                return dict.get(self, (name, domain), default)
            return dict.get(self, name, default)


    class Response:
        def __init__(self, status_code=200, text="", content=b"", cookies=None):
            self.status_code = status_code
            self.text = text
            self.content = content
            self.cookies = cookies or CookieJar()


    def encrypted_response(fields, payload):
        signed_nonce = hashlib.sha256(
            base64.b64decode(SSECURITY) + base64.b64decode(fields["_nonce"])
        ).digest()
        cipher = ARC4.new(signed_nonce)
        cipher.encrypt(bytes(1024))
        encrypted = cipher.encrypt(json.dumps(payload).encode())
        return Response(text=base64.b64encode(encrypted).decode())


    class Session:
        def __init__(self):
            self.cookies = CookieJar()

        def get(self, url, **kwargs):
            if "/pass/serviceLogin" in url:
                return Response(text='&&&START&&&{"_sign":"fixture-sign"}')
            if url == "https://fixture.invalid/sts":
                cookies = CookieJar()
                cookies["serviceToken"] = "fixture-service-token"
                return Response(cookies=cookies)
            raise RequestException("unexpected fixture URL")

        def post(self, url, **kwargs):
            if url.endswith("/pass/serviceLoginAuth2"):
                payload = {
                    "ssecurity": SSECURITY,
                    "userId": "fixture-user",
                    "cUserId": "fixture-c-user",
                    "passToken": "fixture-pass-token",
                    "location": "https://fixture.invalid/sts",
                    "code": 0,
                }
                return Response(text="&&&START&&&" + json.dumps(payload))

            fields = kwargs["params"]
            if url.endswith("/v2/homeroom/gethome"):
                return encrypted_response(fields, {"result": {"homelist": [{"id": 7}]}})
            if url.endswith("/v2/user/get_device_cnt"):
                return encrypted_response(
                    fields,
                    {"result": {"share": {"share_family": []}}},
                )
            if url.endswith("/v2/home/home_device_list"):
                return encrypted_response(
                    fields,
                    {
                        "result": {
                            "device_info": [
                                {
                                    "did": "blt.fixture-device",
                                    "name": "Fixture sensor",
                                    "mac": "02:00:00:00:00:01",
                                    "model": "fixture.sensor",
                                },
                                {
                                    "did": "blt.fixture-other-device",
                                    "name": "Other fixture sensor",
                                    "mac": "02:00:00:00:00:02",
                                    "model": "fixture.other-sensor",
                                }
                            ]
                        }
                    },
                )
            if url.endswith("/v2/device/blt_get_beaconkey"):
                trace_path = os.environ.get("FIXTURE_BEACON_TRACE")
                if trace_path:
                    with open(trace_path, "a", encoding="utf-8") as trace_file:
                        trace_file.write("call\n")
                beacon_key = (
                    ""
                    if os.environ.get("FIXTURE_EMPTY_KEY")
                    else "00112233445566778899AABBCCDDEEFF"
                )
                return encrypted_response(
                    fields,
                    {"result": {"beaconkey": beacon_key}},
                )
            raise RequestException("unexpected fixture URL")


    def session():
        return Session()
    '''
)


class TargetedBleKeyAcceptanceTest(unittest.TestCase):
    def run_extractor(self, *arguments, environment_overrides=None, server="de"):
        with tempfile.TemporaryDirectory() as fake_module_directory:
            Path(fake_module_directory, "requests.py").write_text(
                FAKE_REQUESTS,
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.pathsep.join(
                filter(None, [fake_module_directory, environment.get("PYTHONPATH")])
            )
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment.update(environment_overrides or {})
            command = [
                sys.executable,
                str(EXTRACTOR),
                "--non_interactive",
                "--username",
                "fixture-user",
                "--password",
                "fixture-password",
            ]
            if server is not None:
                command.extend(["--server", server])
            command.extend(arguments)
            return subprocess.run(
                command,
                cwd=REPOSITORY_ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

    def test_writes_only_the_target_key_to_a_private_file(self):
        with tempfile.TemporaryDirectory() as output_directory:
            key_output = Path(output_directory, "ble-key.txt")
            beacon_trace = Path(output_directory, "beacon-calls.txt")

            result = self.run_extractor(
                "--target-mac",
                EXAMPLE_MAC,
                "--key-output",
                str(key_output),
                environment_overrides={"FIXTURE_BEACON_TRACE": str(beacon_trace)},
                server=None,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(key_output.read_text(encoding="utf-8"), EXAMPLE_KEY + "\n")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(key_output.stat().st_mode), 0o600)
            terminal_output = result.stdout + result.stderr
            self.assertNotIn(EXAMPLE_KEY, terminal_output)
            self.assertNotIn("Fixture sensor", terminal_output)
            self.assertEqual(beacon_trace.read_text(encoding="utf-8"), "call\n")

    def test_refuses_to_overwrite_an_existing_key(self):
        with tempfile.TemporaryDirectory() as output_directory:
            key_output = Path(output_directory, "ble-key.txt")
            key_output.write_text("previous key\n", encoding="utf-8")

            result = self.run_extractor(
                "--target-mac",
                EXAMPLE_MAC,
                "--key-output",
                str(key_output),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(key_output.read_text(encoding="utf-8"), "previous key\n")
            self.assertNotIn("unrecognized arguments", result.stderr)

    def test_fails_when_the_target_device_is_absent(self):
        with tempfile.TemporaryDirectory() as output_directory:
            key_output = Path(output_directory, "ble-key.txt")

            result = self.run_extractor(
                "--target-mac",
                "02:00:00:00:00:03",
                "--key-output",
                str(key_output),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(key_output.exists())
            self.assertNotIn("unrecognized arguments", result.stderr)

    def test_failed_target_does_not_overwrite_account_output(self):
        with tempfile.TemporaryDirectory() as output_directory:
            key_output = Path(output_directory, "ble-key.txt")
            data_output = Path(output_directory, "devices.json")
            data_output.write_text("previous output\n", encoding="utf-8")

            result = self.run_extractor(
                "--target-mac",
                "02:00:00:00:00:03",
                "--key-output",
                str(key_output),
                "--output",
                str(data_output),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(key_output.exists())
            self.assertEqual(
                data_output.read_text(encoding="utf-8"),
                "previous output\n",
            )

    def test_fails_when_the_target_has_no_key(self):
        with tempfile.TemporaryDirectory() as output_directory:
            key_output = Path(output_directory, "ble-key.txt")

            result = self.run_extractor(
                "--target-mac",
                EXAMPLE_MAC,
                "--key-output",
                str(key_output),
                environment_overrides={"FIXTURE_EMPTY_KEY": "1"},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(key_output.exists())
            self.assertNotIn("unrecognized arguments", result.stderr)

    def test_rejects_a_malformed_target_before_login(self):
        with tempfile.TemporaryDirectory() as output_directory:
            result = self.run_extractor(
                "--target-mac",
                "not-a-mac",
                "--key-output",
                str(Path(output_directory, "ble-key.txt")),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("must be a valid 48-bit MAC address", result.stderr)

    def test_existing_account_output_remains_available_without_target_flags(self):
        with tempfile.TemporaryDirectory() as output_directory:
            data_output = Path(output_directory, "devices.json")

            result = self.run_extractor("--output", str(data_output))

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            output = json.loads(data_output.read_text(encoding="utf-8"))
            device = output[0]["homes"][0]["devices"][0]
            self.assertEqual(device["mac"], EXAMPLE_MAC)
            self.assertEqual(device["BLE_DATA"]["beaconkey"], EXAMPLE_KEY)


if __name__ == "__main__":
    unittest.main()
