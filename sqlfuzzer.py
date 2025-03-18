#!/usr/bin/env python3
"""
SQLFuzzer - A MySQL SQL Injection fuzzing tool
"""

import argparse
import sys
import datetime
from urllib.parse import urlparse

from modules.url_parser import URLParser
from modules.payload_generator import PayloadGenerator
from modules.request_handler import RequestHandler
from modules.response_analyzer import ResponseAnalyzer


class SQLFuzzer:
    def __init__(self, args):
        self.url = args.url
        self.method = "GET"  # Currently focusing on GET parameters
        self.threads = args.threads
        self.timeout = args.timeout
        self.verbose = args.verbose
        self.output = args.output
        self.delay = args.delay
        self.user_agent = args.user_agent
        self.cookies = args.cookies
        self.proxy = args.proxy

        # Initialize modules
        self.url_parser = URLParser()
        self.payload_generator = PayloadGenerator()
        self.request_handler = RequestHandler(
            timeout=self.timeout,
            user_agent=self.user_agent,
            cookies=self.cookies,
            proxy=self.proxy,
            delay=self.delay
        )
        self.response_analyzer = ResponseAnalyzer(verbose=self.verbose)

        # Results storage
        self.vulnerabilities = []

    def validate_url(self):
        """Validate the provided URL"""
        try:
            parsed = urlparse(self.url)
            if not all([parsed.scheme, parsed.netloc]):
                print(
                    "[!] Error: Invalid URL format. Please use format: http(s)://example.com/path?param=value")
                return False
            return True
        except Exception as e:
            print(f"[!] Error parsing URL: {e}")
            return False

    def run(self):
        """Main execution flow of the fuzzer"""
        if not self.validate_url():
            return False

        print(f"[*] Starting SQL injection fuzzing on: {self.url}")
        print(f"[*] Method: {self.method}")

        # Parse URL to extract parameters
        url_info = self.url_parser.parse(self.url)
        print(f"[DEBUG] URL Info: {url_info}")
        if not url_info['parameters']:
            print(
                "[!] No parameters found in the URL. SQL injection testing requires parameters.")
            return False

        print(f"[*] Found {len(url_info['parameters'])} parameter(s) to test")

        # Generate payloads
        payloads = self.payload_generator.generate_mysql_payloads()
        print(f"[*] Loaded {len(payloads)} SQL injection payloads")
        print(f"[DEBUG] Payloads: {payloads}")

        # Test each parameter with each payload
        total_tests = len(url_info['parameters']) * len(payloads)
        print(f"[*] Preparing to run {total_tests} tests")

        count = 0
        for param_name in url_info['parameters']:
            for payload in payloads:
                count += 1
                if self.verbose:
                    print(
                        f"[*] Test {count}/{total_tests}: Parameter '{param_name}' with payload: {payload}")

                # Create test URL with injected payload
                test_url = self.url_parser.inject_payload(
                    self.url, param_name, payload)
                print(f"[DEBUG] Test URL: {test_url}")

                # Send request
                response = self.request_handler.send_request(test_url)
                if not response:
                    continue

                # Analyze response
                result = self.response_analyzer.analyze(response, payload)
                if result['vulnerable']:
                    vuln = {
                        'parameter': param_name,
                        'payload': payload,
                        'url': test_url,
                        'details': result['details']
                    }
                    self.vulnerabilities.append(vuln)
                    print(
                        f"[+] Possible SQL injection found in parameter '{param_name}'")
                    print(f"    Payload: {payload}")
                    print(f"    URL: {test_url}")
                    print(f"    Details: {result['details']}")

        # Summary
        if self.vulnerabilities:
            print(
                f"\n[+] Found {len(self.vulnerabilities)} potential SQL injection vulnerabilities")
            if self.output:
                self.save_results()
        else:
            print("\n[-] No SQL injection vulnerabilities found")

        return True

    def save_results(self):
        """Save results to output file"""
        try:
            with open(self.output, 'w') as f:
                f.write(f"SQL Injection Fuzzing Results for: {self.url}\n")
                f.write(
                    f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                for i, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"Vulnerability #{i}:\n")
                    f.write(f"  Parameter: {vuln['parameter']}\n")
                    f.write(f"  Payload: {vuln['payload']}\n")
                    f.write(f"  URL: {vuln['url']}\n")
                    f.write(f"  Details: {vuln['details']}\n\n")

            print(f"[*] Results saved to {self.output}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="SQLFuzzer - A MySQL SQL Injection fuzzing tool")

    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (e.g., http://example.com/page.php?id=1)")
    parser.add_argument("-t", "--threads", type=int, default=1,
                        help="Number of concurrent threads (default: 1)")
    parser.add_argument("-to", "--timeout", type=int, default=10,
                        help="Connection timeout in seconds (default: 10)")
    parser.add_argument("-v", "--verbose",
                        action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("-d", "--delay", type=float, default=0,
                        help="Delay between requests in seconds (default: 0)")
    parser.add_argument("-a", "--user-agent", default="SQLFuzzer/1.0",
                        help="Custom User-Agent (default: SQLFuzzer/1.0)")
    parser.add_argument("-c", "--cookies",
                        help="Cookies to include with HTTP requests")
    parser.add_argument(
        "-p", "--proxy", help="Use proxy (format: http://host:port)")

    return parser.parse_args()


def main():

    args = parse_arguments()
    fuzzer = SQLFuzzer(args)

    try:
        fuzzer.run()
    except KeyboardInterrupt:
        print("\n[!] User interrupted the process")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
