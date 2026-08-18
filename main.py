import argparse
import hashlib
import sys
import requests


class MiniIntruder:

    def __init__(self, url, method="GET", wordlist=None,
                 parameter="username", headers=None,
                 cookies=None, verbose=False):

        self.url = url
        self.method = method.upper()
        self.wordlist = wordlist
        self.parameter = parameter
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.verbose = verbose

        self.baseline = None

    def fingerprint(self, response):
        """
        یک fingerprint ساده از Response می‌سازد.
        """

        body = response.text

        return {
            "status": response.status_code,
            "length": len(response.content),
            "hash": hashlib.sha256(
                body.encode(errors="ignore")
            ).hexdigest()
        }

    def is_different(self, fingerprint):
        if self.baseline is None:
            return False

        return (
            fingerprint["status"] != self.baseline["status"]
            or fingerprint["length"] != self.baseline["length"]
            or fingerprint["hash"] != self.baseline["hash"]
        )

    def send_request(self, payload):

        if self.method == "GET":

            params = {
                self.parameter: payload
            }

            return requests.get(
                self.url,
                params=params,
                headers=self.headers,
                cookies=self.cookies,
                timeout=10
            )

        elif self.method == "POST":

            data = {
                self.parameter: payload
            }

            return requests.post(
                self.url,
                data=data,
                headers=self.headers,
                cookies=self.cookies,
                timeout=10
            )

        else:
            raise ValueError(
                f"Unsupported method: {self.method}"
            )

    def print_request_info(self, number, payload):

        print()
        print("=" * 70)
        print(f"[REQUEST #{number}]")
        print(f"Payload : {payload}")
        print(f"Method  : {self.method}")
        print(f"URL     : {self.url}")
        print("=" * 70)

    def print_response(self, response, fingerprint, different):

        print(f"Status Code   : {response.status_code}")
        print(f"Content Length: {fingerprint['length']}")
        print(f"SHA256        : {fingerprint['hash']}")

        if self.baseline is None:
            print("Baseline      : CREATED")
        elif different:
            print("Result        : !!! DIFFERENT RESPONSE !!!")
        else:
            print("Result        : same as baseline")

        if self.verbose:

            print()
            print("--- RESPONSE HEADERS ---")

            for key, value in response.headers.items():
                print(f"{key}: {value}")

            print()
            print("--- RESPONSE BODY ---")
            print(response.text)
            print("--- END RESPONSE ---")

    def run(self):

        try:
            with open(
                self.wordlist,
                "r",
                encoding="utf-8"
            ) as file:

                payloads = [
                    line.strip()
                    for line in file
                    if line.strip()
                ]

        except FileNotFoundError:
            print("Wordlist not found.")
            sys.exit(1)

        print()
        print("Mini Intruder")
        print("-" * 70)
        print(f"Target : {self.url}")
        print(f"Method : {self.method}")
        print(f"Payload: {self.parameter}")
        print(f"Items  : {len(payloads)}")
        print("-" * 70)

        for number, payload in enumerate(payloads, start=1):

            self.print_request_info(
                number,
                payload
            )

            try:

                response = self.send_request(payload)

                fingerprint = self.fingerprint(
                    response
                )

                if self.baseline is None:
                    self.baseline = fingerprint

                different = self.is_different(
                    fingerprint
                )

                self.print_response(
                    response,
                    fingerprint,
                    different
                )

            except requests.RequestException as error:

                print()
                print(f"Request failed: {error}")


def parse_arguments():

    parser = argparse.ArgumentParser(
        description="Educational Mini Burp Intruder"
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL"
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        required=True,
        help="Username wordlist"
    )

    parser.add_argument(
        "-m",
        "--method",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP method"
    )

    parser.add_argument(
        "-p",
        "--parameter",
        default="username",
        help="Parameter to fuzz"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show full response"
    )

    return parser.parse_args()


def main():

    args = parse_arguments()

    intruder = MiniIntruder(
        url=args.url,
        method=args.method,
        wordlist=args.wordlist,
        parameter=args.parameter,
        verbose=args.verbose
    )

    intruder.run()


if __name__ == "__main__":
    main()
