#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Scanner module - Reflected XSS only
"""

import time
import re
import urllib.parse
import uuid
from bs4 import BeautifulSoup

from ..common.url_parser import URLParser
from ..common.request_handler import RequestHandler
from ..common.post_data_handler import PostDataHandler
from ..common.utils import Output
from .payload_generator import XSSPayloadGenerator


class XSSScanner:
    def __init__(self, urls=None, url=None, method="GET", data=None,
                 headers=None, timeout=10, delay=0,
                 user_agent=None, cookies=None, proxy=None,
                 callback_url=None, injection_types=None, verbose=False, no_color=False, verify_ssl=False):
        """
        Initialize the XSS Scanner

        Args:
            urls (list): List of URLs to scan
            url (str): Single URL to scan (alternative to urls)
            method (str): HTTP method (GET or POST)
            data (str): POST data
            headers (dict): Custom HTTP headers
            timeout (int): Request timeout in seconds
            delay (float): Delay between requests in seconds
            user_agent (str): Custom User-Agent
            cookies (str): Cookies to include with requests
            proxy (str): Proxy to use
            callback_url (str): Callback URL for blind XSS testing
            injection_types (list): List of XSS types to test (reflected only)
            verbose (bool): Verbose output
            no_color (bool): Disable colored output
            verify_ssl (bool): Whether to verify SSL certificates
        """
        self.urls = urls or []
        if url and url not in self.urls:
            self.urls.append(url)

        self.method = method.upper()
        self.data = data
        self.headers = headers or {}
        self.timeout = timeout
        self.delay = delay
        self.callback_url = callback_url
        self.verbose = verbose
        self.no_color = no_color

        # Only support reflected XSS now
        self.injection_types = ['reflected']

        # Initialize common modules
        self.url_parser = URLParser()
        self.request_handler = RequestHandler(
            timeout=timeout,
            user_agent=user_agent,
            cookies=cookies,
            headers=self.headers,
            proxy=proxy,
            delay=delay,
            verify_ssl=verify_ssl
        )

        self.post_data_handler = PostDataHandler()
        self.payload_generator = XSSPayloadGenerator()

        # Output formatting
        self.output = Output(no_color=no_color)

        # Results storage
        self.vulnerabilities = []
        self.scan_results = {}
        self.failed_urls = []

        # Generate unique ID for blind XSS testing
        self.unique_id = str(uuid.uuid4())[:8]

    def scan(self):
        """
        Scan URLs for XSS vulnerabilities

        Returns:
            dict: Scan results
        """
        if not self.urls:
            return {'vulnerabilities': [], 'scan_info': {'urls_scanned': 0}}

        results = {
            'scan_info': {
                'start_time': time.time(),
                'urls_scanned': 0,
                'params_tested': 0,
                'payloads_tested': 0
            },
            'vulnerabilities': []
        }

        # Get payloads
        reflected_payloads = self.payload_generator.get_reflected_payloads()

        # Generate unique identifier for this scan
        scan_id = str(uuid.uuid4())[:8]

        output = Output(no_color=self.no_color)

        # For each URL
        for url in self.urls:
            try:
                output.print_info(f"Scanning {url} for XSS vulnerabilities")

                # Parse URL to extract parameters
                parsed_url = self.url_parser.parse(url)
                parameters = parsed_url['parameters']

                # For POST requests, parse the data
                post_params = {}
                if self.method == "POST" and self.data:
                    try:
                        post_params = self.post_data_handler.parse(self.data)
                    except Exception as e:
                        output.print_error(
                            f"Error parsing POST data: {str(e)}")

                # Combine parameters from URL and POST data
                all_params = {**parameters, **post_params}

                if not all_params:
                    output.print_warning(f"No parameters found in {url}")
                    continue

                output.print_info(
                    f"Testing {len(all_params)} parameter(s) for XSS")

                # Get baseline response
                if self.method == "GET":
                    baseline_response = self.request_handler.send_request(url)
                else:  # POST
                    baseline_response = self.request_handler.send_request(
                        url, method="POST", data=self.data)

                if not baseline_response:
                    output.print_error(
                        f"Failed to get baseline response for {url}")
                    continue

                # Track parameters tested
                results['scan_info']['params_tested'] += len(all_params)

                # For each parameter, test for XSS
                for param_name, param_value in all_params.items():
                    output.print_info(f"Testing parameter: {param_name}")

                    # Test for reflected XSS
                    self._scan_reflected_xss(
                        url, param_name, reflected_payloads, baseline_response)

                results['scan_info']['urls_scanned'] += 1

            except Exception as e:
                output.print_error(f"Error scanning {url}: {str(e)}")

            # Add delay between URLs if specified
            if self.delay > 0:
                time.sleep(self.delay)

        # Calculate scan duration
        results['scan_info']['end_time'] = time.time()
        results['scan_info']['duration'] = results['scan_info']['end_time'] - \
            results['scan_info']['start_time']
        results['vulnerabilities'] = self.get_vulnerabilities()

        output.print_success(
            f"XSS scan completed in {results['scan_info']['duration']:.2f} seconds")
        output.print_info(
            f"Found {len(results['vulnerabilities'])} XSS vulnerabilities")

        return results

    def _scan_reflected_xss(self, url, param_name, payloads, baseline_response):
        """
        Scan for reflected XSS vulnerabilities

        Args:
            url (str): Target URL
            param_name (str): Parameter name to test
            payloads (list): XSS payloads to test
            baseline_response (requests.Response): Baseline response
        """
        output = Output(no_color=self.no_color)
        output.print_info(
            f"Testing parameter '{param_name}' for reflected XSS")

        # Store original parameter value
        original_value = ""
        parsed_url = self.url_parser.parse(url)

        if param_name in parsed_url['parameters']:
            original_value = parsed_url['parameters'][param_name]
            in_url = True
        elif self.method == "POST" and self.data:
            # Check if parameter is in POST data
            post_params = self.post_data_handler.parse(self.data)
            if param_name in post_params:
                original_value = post_params[param_name]
                in_url = False
            else:
                output.print_warning(
                    f"Parameter '{param_name}' not found in request")
                return
        else:
            output.print_warning(f"Parameter '{param_name}' not found in URL")
            return

        # Test each payload
        for payload in payloads:
            try:
                # Generate test URL or POST data with payload
                if in_url:
                    test_url = self.url_parser.inject_payload(
                        url, param_name, payload)
                    response = self.request_handler.send_request(test_url)
                else:
                    # Inject payload into POST data
                    modified_data = self.data.replace(
                        f"{param_name}={original_value}", f"{param_name}={payload}")
                    response = self.request_handler.send_request(
                        url, method="POST", data=modified_data)

                if not response:
                    continue

                # Check if payload is reflected in response
                is_vulnerable, evidence = self._detect_reflected_xss(
                    response.text, payload)

                if is_vulnerable:
                    vuln = {
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': evidence,
                        'type': 'Reflected XSS'
                    }

                    self.vulnerabilities.append(vuln)

                    output.print_success(
                        f"Reflected XSS found in {url}, parameter: {param_name}")
                    output.print_success(f"Payload: {payload}")
                    output.print_success(f"Evidence: {evidence}")

                    # Break after finding vulnerability for parameter
                    break

            except Exception as e:
                output.print_error(f"Error testing payload: {str(e)}")

    def _detect_reflected_xss(self, response_text, payload):
        """
        Detect if an XSS payload is reflected in the response

        Args:
            response_text (str): Response content
            payload (str): XSS payload

        Returns:
            tuple: (is_vulnerable, evidence)
        """
        evidence = ""

        # Check for exact payload reflection
        if payload in response_text:
            # Look for the context of reflection
            index = response_text.find(payload)
            start = max(0, index - 40)
            end = min(len(response_text), index + len(payload) + 40)
            evidence = response_text[start:end]

            # Check if the payload is in a script context
            if '<script' in response_text[:index] and '</script>' in response_text[index+len(payload):]:
                return True, evidence

            # Check if the payload is in an attribute context
            if re.search(r'<[^>]+(src|href|onerror|onload)\s*=\s*[\'"]', response_text[:index]):
                return True, evidence

            # Check if the payload appears to be executed
            if '<img' in payload and 'onerror' in payload:
                return True, evidence

            # Check for script tags
            if '<script' in payload and '<script' in response_text:
                return True, evidence

            # For other contexts, just report as potential XSS
            return True, evidence

        # Check for encoded payloads
        encoded_payload = urllib.parse.quote(payload)
        if encoded_payload != payload and encoded_payload in response_text:
            index = response_text.find(encoded_payload)
            start = max(0, index - 40)
            end = min(len(response_text), index + len(encoded_payload) + 40)
            evidence = response_text[start:end]
            return True, evidence

        # HTML entity encoding
        entity_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if entity_payload != payload and entity_payload in response_text:
            index = response_text.find(entity_payload)
            start = max(0, index - 40)
            end = min(len(response_text), index + len(entity_payload) + 40)
            evidence = response_text[start:end]
            return True, evidence

        return False, evidence

    def _is_valid_url(self, url):
        """Check if URL is valid"""
        try:
            parsed = urllib.parse.urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False

    def get_results(self):
        """Get scan results"""
        return self.scan_results

    def get_vulnerabilities(self):
        """Get discovered vulnerabilities"""
        return self.vulnerabilities
