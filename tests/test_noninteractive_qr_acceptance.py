"""Public CLI acceptance coverage for non-interactive QR authentication.

Feature matrix:
- QR login with closed stdin, an atomically published image, and explicit region:
  covered here through the subprocess CLI boundary.
- QR login artifacts remain absent from terminal output at debug level: covered.
- QR authentication failures return a non-zero process status: covered.
- QR and account output files are owner-only, and failed refreshes remove stale
  QR images: covered.
- Ambiguous QR/password arguments and a missing QR destination: covered here.
- Omitted region checks every supported region without prompting: covered here.
- Existing non-interactive password validation remains the default: covered here.
- Password login, interactive prompts, 2FA, and live Xiaomi Cloud behavior: not
  covered by this fixture and remain adaptation gaps.

The fixture replaces only the external requests package. It does not import or
call implementation details from token_extractor.py.
"""

import base64
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
PNG_BYTES = b"fixture QR image bytes"

FAKE_REQUESTS = textwrap.dedent(
    r'''
    import base64
    import json
    import os


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


    class Session:
        def __init__(self):
            self.cookies = CookieJar()

        def get(self, url, **kwargs):
            if url.endswith("/longPolling/loginUrl"):
                payload = {
                    "qr": "https://fixture.invalid/qr.png",
                    "loginUrl": "https://fixture.invalid/login?ticket=fixture-login-ticket",
                    "lp": "https://fixture.invalid/poll",
                    "timeout": 10,
                }
                return Response(text="&&&START&&&" + json.dumps(payload))
            if url == "https://fixture.invalid/qr.png":
                if os.environ.get("FIXTURE_QR_FAILURE"):
                    return Response(status_code=503, text="fixture failure")
                return Response(content=b"fixture QR image bytes")
            if url == "https://fixture.invalid/poll":
                if os.environ.get("FIXTURE_POLL_EXCEPTION"):
                    raise RequestException("fixture polling failure")
                payload = {
                    "userId": "fixture-user",
                    "ssecurity": base64.b64encode(b"fixture-security").decode(),
                    "cUserId": "fixture-c-user",
                    "passToken": "fixture-pass-token",
                    "location": "https://fixture.invalid/sts",
                }
                return Response(text="&&&START&&&" + json.dumps(payload))
            if url == "https://fixture.invalid/sts":
                cookies = CookieJar()
                if not os.environ.get("FIXTURE_MISSING_SERVICE_TOKEN"):
                    cookies["serviceToken"] = "fixture-service-token"
                return Response(cookies=cookies)
            raise RequestException("unexpected fixture URL")

        def post(self, url, **kwargs):
            return Response(status_code=503)


    def session():
        return Session()
    '''
)


class NonInteractiveQrAcceptanceTest(unittest.TestCase):
    def run_extractor(self, *arguments, environment_overrides=None):
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
            return subprocess.run(
                [sys.executable, str(EXTRACTOR), *arguments],
                cwd=REPOSITORY_ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

    def test_qr_login_completes_with_closed_stdin_and_refreshes_private_image(self):
        with tempfile.TemporaryDirectory() as output_directory:
            qr_output = Path(output_directory, "login-qr.png")
            data_output = Path(output_directory, "devices.json")
            qr_output.write_bytes(b"stale image")
            qr_output.chmod(0o644)
            data_output.write_text("stale data", encoding="utf-8")
            data_output.chmod(0o644)

            result = self.run_extractor(
                "--non_interactive",
                "--auth-method",
                "qr",
                "--qr-output",
                str(qr_output),
                "--server",
                "de",
                "--output",
                str(data_output),
                "--log_level",
                "DEBUG",
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(qr_output.read_bytes(), PNG_BYTES)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(qr_output.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(data_output.stat().st_mode), 0o600)
            self.assertEqual(
                json.loads(data_output.read_text(encoding="utf-8")),
                [{"server": "de", "homes": []}],
            )
            terminal_output = result.stdout + result.stderr
            self.assertNotIn("fixture.invalid", terminal_output)
            self.assertNotIn("fixture-login-ticket", terminal_output)
            self.assertNotIn("fixture-security", terminal_output)
            self.assertNotIn(
                base64.b64encode(b"fixture-security").decode(),
                terminal_output,
            )
            self.assertNotIn("fixture-pass-token", terminal_output)
            self.assertNotIn("fixture-service-token", terminal_output)
            self.assertNotIn("fixture-user", terminal_output)
            self.assertNotIn("p/q:", terminal_output)
            self.assertNotIn("Select server", terminal_output)
            self.assertNotIn("Press ENTER", terminal_output)

    def test_qr_login_requires_an_image_destination(self):
        result = self.run_extractor(
            "--non_interactive",
            "--auth-method",
            "qr",
            "--server",
            "de",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --qr-output", result.stderr)

    def test_qr_login_checks_all_regions_without_reading_stdin(self):
        with tempfile.TemporaryDirectory() as output_directory:
            qr_output = Path(output_directory, "login-qr.png")
            data_output = Path(output_directory, "devices.json")

            result = self.run_extractor(
                "--non_interactive",
                "--auth-method",
                "qr",
                "--qr-output",
                str(qr_output),
                "--output",
                str(data_output),
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                [
                    entry["server"]
                    for entry in json.loads(data_output.read_text(encoding="utf-8"))
                ],
                ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"],
            )
            self.assertNotIn("Select server", result.stdout + result.stderr)

    def test_qr_authentication_failure_returns_a_failure_status(self):
        with tempfile.TemporaryDirectory() as output_directory:
            qr_output = Path(output_directory, "login-qr.png")
            qr_output.write_bytes(b"stale image")

            result = self.run_extractor(
                "--non_interactive",
                "--auth-method",
                "qr",
                "--qr-output",
                str(qr_output),
                "--server",
                "de",
                environment_overrides={"FIXTURE_QR_FAILURE": "1"},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(qr_output.exists())
            self.assertNotIn("unrecognized arguments", result.stderr)
            self.assertNotIn("fixture failure", result.stdout + result.stderr)

    def test_qr_login_rejects_password_credentials(self):
        result = self.run_extractor(
            "--non_interactive",
            "--auth-method",
            "qr",
            "--qr-output",
            "unused.png",
            "--username",
            "fixture-user",
            "--password",
            "fixture-password",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot be used with QR authentication", result.stderr)

    def test_polling_connection_failure_is_reported_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as output_directory:
            qr_output = Path(output_directory, "login-qr.png")

            result = self.run_extractor(
                "--non_interactive",
                "--auth-method",
                "qr",
                "--qr-output",
                str(qr_output),
                "--server",
                "de",
                environment_overrides={"FIXTURE_POLL_EXCEPTION": "1"},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(qr_output.exists())
            self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_missing_service_token_fails_without_leaving_the_qr_image(self):
        with tempfile.TemporaryDirectory() as output_directory:
            qr_output = Path(output_directory, "login-qr.png")

            result = self.run_extractor(
                "--non_interactive",
                "--auth-method",
                "qr",
                "--qr-output",
                str(qr_output),
                "--server",
                "de",
                environment_overrides={"FIXTURE_MISSING_SERVICE_TOKEN": "1"},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(qr_output.exists())
            self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_password_login_rejects_a_qr_destination(self):
        result = self.run_extractor(
            "--non_interactive",
            "--username",
            "fixture-user",
            "--password",
            "fixture-password",
            "--qr-output",
            "unused.png",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --auth-method qr", result.stderr)

    def test_non_interactive_password_validation_remains_the_default(self):
        result = self.run_extractor("--non_interactive")

        self.assertEqual(result.returncode, 2)
        self.assertIn("specify username and password", result.stderr)


if __name__ == "__main__":
    unittest.main()
