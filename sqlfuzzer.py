#!/usr/bin/env python3
"""
SQLFuzzer - A MySQL SQL Injection fuzzing tool
"""

import argparse
import sys
import datetime
import re
import time
import json
from urllib.parse import urlparse

from modules.url_parser import URLParser
from modules.payload_generator import PayloadGenerator
from modules.request_handler import RequestHandler
from modules.response_analyzer import ResponseAnalyzer
from modules.post_data_handler import PostDataHandler
from modules.test_runner import TestRunner

# ANSI color codes for console output


class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class SQLFuzzer:
    def __init__(self, args):
        self.url = args.url
        self.method = args.method.upper()
        self.post_data = args.data
        self.post_data_file = args.data_file
        self.content_type = args.content_type
        self.verbose = args.verbose
        self.user_agent = args.user_agent
        self.cookies = args.cookies
        self.timeout = args.timeout
        self.delay = args.delay
        self.no_color = args.no_color
        self.max_tests = args.max_tests
        self.stop_on_first = args.stop_on_first
        self.headers = self._parse_headers(
            args.headers) if args.headers else {}

        # Initialize request configuration
        self.proxy = args.proxy

        # Process and validate the method
        if self.method not in ["GET", "POST"]:
            self.print_error(
                f"Unsupported HTTP method: {self.method}. Only GET and POST are supported.")
            sys.exit(1)

        # For POST requests, ensure we have data
        if self.method == "POST" and not self.post_data and not self.post_data_file:
            self.print_error(
                "POST method requires data. Use --data or --data-file.")
            sys.exit(1)

        # Load POST data from file if specified
        if self.post_data_file:
            try:
                with open(self.post_data_file, 'r') as f:
                    self.post_data = f.read().strip()
            except Exception as e:
                self.print_error(f"Error reading POST data file: {e}")
                sys.exit(1)

        # Initialize modules
        self.url_parser = URLParser()
        self.payload_generator = PayloadGenerator()
        self.post_data_handler = PostDataHandler()
        self.request_handler = RequestHandler(
            timeout=self.timeout,
            user_agent=self.user_agent,
            cookies=self.cookies,
            proxy=self.proxy,
            delay=self.delay
        )
        self.response_analyzer = ResponseAnalyzer(verbose=self.verbose)

        # Initialize the test runner
        self.test_runner = TestRunner(
            url_parser=self.url_parser,
            request_handler=self.request_handler,
            response_analyzer=self.response_analyzer,
            post_data_handler=self.post_data_handler,
            verbose=self.verbose
        )

        # Results storage
        self.vulnerabilities = []

    def _parse_headers(self, headers_str):
        """Parse custom headers from command line"""
        headers = {}
        if headers_str:
            for header in headers_str.split(','):
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        return headers

    def print_info(self, message):
        """Print informational message"""
        if self.no_color:
            print(f"[*] {message}")
        else:
            print(f"{Colors.BLUE}[*]{Colors.RESET} {message}")

    def print_success(self, message):
        """Print success message"""
        if self.no_color:
            print(f"[+] {message}")
        else:
            print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")

    def print_error(self, message):
        """Print error message"""
        if self.no_color:
            print(f"[!] {message}")
        else:
            print(f"{Colors.RED}[!]{Colors.RESET} {message}")

    def print_warning(self, message):
        """Print warning message"""
        if self.no_color:
            print(f"[-] {message}")
        else:
            print(f"{Colors.YELLOW}[-]{Colors.RESET} {message}")

    def print_detail(self, title, value):
        """Print detailed information"""
        if self.no_color:
            print(f"    {title}: {value}")
        else:
            print(f"    {Colors.CYAN}{title}{Colors.RESET}: {value}")

    def validate_url(self):
        """Validate the provided URL"""
        try:
            parsed = urlparse(self.url)
            if not all([parsed.scheme, parsed.netloc]):
                self.print_error(
                    "Error: Invalid URL format. Please use format: http(s)://example.com/path?param=value")
                return False
            return True
        except Exception as e:
            self.print_error(f"Error parsing URL: {e}")
            return False

    def banner(self):
        """Display tool banner"""
        banner_text = """
 ____   ___  _     _____                         
/ ___| / _ \| |   |  ___|   _ _______  ___ _ __ 
\___ \| | | | |   | |_ | | | |_  / _ \/ _ \ '__|
 ___) | |_| | |___|  _|| |_| |/ /  __/  __/ |   
|____/ \__\_\_____|_|   \__,_/___\___|\___|_|   
                                             
        SQL Injection Fuzzing Tool
        """

        if not self.no_color:
            print(f"{Colors.CYAN}{banner_text}{Colors.RESET}")
        else:
            print(banner_text)

        print(f"Version: 2.0.0")
        print(
            f"Started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    def run(self):
        """Main execution flow of the fuzzer"""
        self.banner()

        if not self.validate_url():
            return False

        self.print_info(f"Starting SQL injection fuzzing on: {self.url}")
        self.print_info(f"Method: {self.method}")

        # If POST, show some info about the data
        if self.method == "POST":
            if self.content_type:
                self.print_info(f"Content-Type: {self.content_type}")
            else:
                self.print_info(
                    "Content-Type not specified, will try to auto-detect")

            # Show a preview of the POST data (truncated if too long)
            if self.post_data:
                preview = self.post_data[:50] + \
                    "..." if len(self.post_data) > 50 else self.post_data
                self.print_info(f"POST data: {preview}")

        # Parse URL to extract parameters for GET or POST data for POST
        if self.method == "GET":
            url_info = self.url_parser.parse(self.url)
            if not url_info['parameters']:
                self.print_error(
                    "No parameters found in the URL. SQL injection testing requires parameters.")
                return False
        else:  # POST
            url_info = {'original_url': self.url, 'parameters': {}}

            # Let's parse the post data to get parameters
            post_data_info = self.post_data_handler.parse_post_data(
                self.post_data, self.content_type)
            if not post_data_info['parameters']:
                self.print_error(
                    "No parameters found in the POST data. SQL injection testing requires parameters.")
                return False

        # Generate payloads by type
        payloads = {
            'error_based': self.payload_generator.generate_error_based_payloads(),
            'boolean_based': self.payload_generator.generate_boolean_based_payloads(),
            'time_based': self.payload_generator.generate_time_based_payloads(),
            'auth_bypass': self.payload_generator.generate_authentication_bypass_payloads()
        }

        total_payloads = sum(len(payload_list)
                             for payload_list in payloads.values())
        self.print_info(f"Loaded {total_payloads} SQL injection payloads")

        # Run tests using the TestRunner
        vulnerabilities = self.test_runner.run_tests(
            target_info=url_info,
            payloads=payloads,
            method=self.method,
            content_type=self.content_type,
            data=self.post_data
        )

        # Store the results
        self.vulnerabilities = vulnerabilities

        # Summary
        if self.vulnerabilities:
            self.print_success(
                f"\nFound {len(self.vulnerabilities)} potential SQL injection vulnerabilities")

            # Display vulnerabilities by type
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vuln_type = vuln['type']
                if vuln_type in vuln_types:
                    vuln_types[vuln_type] += 1
                else:
                    vuln_types[vuln_type] = 1

            for vuln_type, count in vuln_types.items():
                self.print_success(f"- {vuln_type}: {count}")

            # Report the first found vulnerability if stop_on_first is true
            if self.stop_on_first and self.test_runner.found_vulnerability:
                self.print_success(
                    f"Stopped fuzzing after finding {self.test_runner.found_vulnerability} vulnerability")
        else:
            self.print_warning("\nNo SQL injection vulnerabilities found")

        return True

    def save_report(self, output_file):
        """Save test results to a file"""
        if not output_file:
            return

        try:
            report = {
                'target': self.url,
                'method': self.method,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'vulnerabilities': self.vulnerabilities,
                'total_vulnerabilities': len(self.vulnerabilities),
                'scan_info': {
                    'user_agent': self.user_agent,
                    'timeout': self.timeout,
                    'delay': self.delay
                }
            }

            if self.method == "POST":
                report['content_type'] = self.content_type
                # Don't include full post data in report for privacy/security
                report['post_data_preview'] = self.post_data[:50] + \
                    "..." if len(self.post_data) > 50 else self.post_data

            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)

            self.print_success(f"Report saved to: {output_file}")
        except Exception as e:
            self.print_error(f"Error saving report: {e}")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="SQLFuzzer - A SQL Injection fuzzing tool"
    )

    # Target options
    target_group = parser.add_argument_group('Target')
    target_group.add_argument("-u", "--url", required=True,
                              help="Target URL (e.g., http://example.com/page.php?id=1)")
    target_group.add_argument("-m", "--method", default="GET",
                              choices=["GET", "POST", "get", "post"],
                              help="HTTP method (GET or POST, default: GET)")
    target_group.add_argument("-d", "--data",
                              help="POST data (e.g., 'username=admin&password=test')")
    target_group.add_argument("--data-file",
                              help="File containing POST data")
    target_group.add_argument("-H", "--headers",
                              help="Custom HTTP headers (comma-separated, e.g. 'X-Forwarded-For: 127.0.0.1,Accept: application/json')")
    target_group.add_argument("-c", "--cookies",
                              help="Cookies to include with HTTP requests")
    target_group.add_argument("--content-type",
                              help="Content-Type header for POST requests (e.g., application/json, application/x-www-form-urlencoded)")

    # Request options
    request_group = parser.add_argument_group('Request')
    request_group.add_argument("-a", "--user-agent", default="SQLFuzzer/2.0",
                               help="Custom User-Agent (default: SQLFuzzer/2.0)")
    request_group.add_argument("-t", "--timeout", type=int, default=10,
                               help="Request timeout in seconds (default: 10)")
    request_group.add_argument("--delay", type=float, default=0,
                               help="Delay between requests in seconds (default: 0)")
    request_group.add_argument("-p", "--proxy",
                               help="Proxy to use (e.g., http://127.0.0.1:8080)")

    # Output options
    output_group = parser.add_argument_group('Output')
    output_group.add_argument("-v", "--verbose", action="store_true",
                              help="Verbose output")
    output_group.add_argument("--no-color", action="store_true",
                              help="Disable colored output")
    output_group.add_argument("-o", "--output",
                              help="Save results to output file (JSON format)")

    # Fuzzing options
    fuzzing_group = parser.add_argument_group('Fuzzing')
    fuzzing_group.add_argument("--max-tests", type=int, default=0,
                               help="Maximum number of tests to run (0 for unlimited)")
    fuzzing_group.add_argument("--stop-on-first", action="store_true",
                               help="Stop testing after finding first vulnerability")

    return parser.parse_args()


def main():
    args = parse_arguments()
    fuzzer = SQLFuzzer(args)

    try:
        fuzzer.run()

        # Save report if output file is specified
        if args.output:
            fuzzer.save_report(args.output)

    except KeyboardInterrupt:
        if args.no_color:
            print("\n[!] User interrupted the process")
        else:
            print(
                f"\n{Colors.RED}[!]{Colors.RESET} User interrupted the process")

        # Save partial report if output file is specified
        if args.output:
            fuzzer.save_report(args.output + ".partial")

        sys.exit(1)
    except Exception as e:
        if args.no_color:
            print(f"\n[!] An error occurred: {e}")
        else:
            print(f"\n{Colors.RED}[!]{Colors.RESET} An error occurred: {e}")

        # For debugging in verbose mode
        if args.verbose:
            import traceback
            traceback.print_exc()

        sys.exit(1)


if __name__ == "__main__":
    main()
