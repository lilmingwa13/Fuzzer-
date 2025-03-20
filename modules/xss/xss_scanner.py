#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Scanner module
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
    def __init__(self, urls=None, url=None, timeout=10, delay=0,
                 user_agent=None, cookies=None, proxy=None,
                 callback_url=None, verbose=False, no_color=False):
        """
        Initialize the XSS Scanner

        Args:
            urls (list): List of URLs to scan
            url (str): Single URL to scan (alternative to urls)
            timeout (int): Request timeout in seconds
            delay (float): Delay between requests in seconds
            user_agent (str): Custom User-Agent
            cookies (str): Cookies to include with requests
            proxy (str): Proxy to use
            callback_url (str): Callback URL for blind XSS testing
            verbose (bool): Verbose output
            no_color (bool): Disable colored output
        """
        self.urls = urls or []
        if url and url not in self.urls:
            self.urls.append(url)

        self.timeout = timeout
        self.delay = delay
        self.callback_url = callback_url
        self.verbose = verbose

        # Initialize common modules
        self.url_parser = URLParser()
        self.request_handler = RequestHandler(
            timeout=timeout,
            user_agent=user_agent,
            cookies=cookies,
            proxy=proxy,
            delay=delay
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
        Start XSS scanning on the specified URLs

        Returns:
            dict: Scanning results
        """
        if not self.urls:
            self.output.print_error("No URLs provided for XSS scanning")
            return False

        self.output.banner("XSS Scanner", "1.0.0")
        self.output.print_info(f"Target URLs: {len(self.urls)}")

        start_time = time.time()
        total_params_tested = 0

        for url in self.urls:
            self.output.print_info(f"Scanning URL: {url}")

            if not self._is_valid_url(url):
                self.output.print_error(f"Invalid URL: {url}")
                self.failed_urls.append(url)
                continue

            # Parse URL and extract parameters
            url_info = self.url_parser.parse(url)

            if not url_info['parameters']:
                self.output.print_warning(f"No parameters found in URL: {url}")
                continue

            self.output.print_info(
                f"Found {len(url_info['parameters'])} parameter(s) to test")

            # Get baseline response
            baseline_response = self.request_handler.send_request(url)
            if not baseline_response:
                self.output.print_error(
                    f"Failed to get baseline response: {url}")
                self.failed_urls.append(url)
                continue

            # Test each parameter
            for param_name, param_value in url_info['parameters'].items():
                self.output.print_info(f"Testing parameter: {param_name}")
                total_params_tested += 1

                # Get reflected XSS payloads
                payloads = self.payload_generator.get_reflected_payloads()

                # Scan for reflected XSS
                self._scan_reflected_xss(
                    url, param_name, payloads, baseline_response)

            # Check for DOM-based XSS (this is more complex and often requires browser automation)
            # For the scope of this example, we'll just use a simplified approach
            self._scan_dom_xss(url, baseline_response)

        # Calculate statistics
        elapsed_time = time.time() - start_time

        self.output.print_success(
            f"XSS scanning completed in {elapsed_time:.2f} seconds")
        self.output.print_success(
            f"Tested {len(self.urls)} URLs and {total_params_tested} parameters")

        if self.vulnerabilities:
            self.output.print_success(
                f"Found {len(self.vulnerabilities)} XSS vulnerabilities")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                self.output.print_success(
                    f"{i}. {vuln['url']} - {vuln['type']}")
                self.output.print_detail("Parameter", vuln['parameter'])
                self.output.print_detail("Payload", vuln['payload'])
                self.output.print_detail("Evidence", vuln['evidence'])
        else:
            self.output.print_info("No XSS vulnerabilities found")

        # Prepare result summary
        self.scan_results = {
            'start_time': start_time,
            'end_time': time.time(),
            'duration_seconds': elapsed_time,
            'urls_scanned': len(self.urls),
            'parameters_tested': total_params_tested,
            'vulnerabilities_found': len(self.vulnerabilities),
            'failed_urls': self.failed_urls,
            'vulnerabilities': self.vulnerabilities
        }

        return self.scan_results

    def _scan_reflected_xss(self, url, param_name, payloads, baseline_response):
        """
        Scan for reflected XSS in a specific parameter

        Args:
            url (str): Target URL
            param_name (str): Parameter name to test
            payloads (list): XSS payloads to test
            baseline_response (Response): Baseline response
        """
        baseline_content = baseline_response.text

        for payload in payloads:
            if self.verbose:
                self.output.print_info(f"Trying payload: {payload}")

            # Create test URL with injected payload
            test_url = self.url_parser.inject_payload(url, param_name, payload)

            # Send request
            response = self.request_handler.send_request(test_url)
            if not response:
                continue

            # Check for payload reflection
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

                self.output.print_success(
                    f"Reflected XSS found in parameter '{param_name}'")
                self.output.print_detail("URL", url)
                self.output.print_detail("Payload", payload)
                self.output.print_detail("Evidence", evidence)

                # Stop testing this parameter after finding a vulnerability
                # Uncomment if you want to find only the first vulnerability per parameter
                # break

    def _scan_dom_xss(self, url, baseline_response):
        """
        Scan for DOM-based XSS

        Args:
            url (str): Target URL
            baseline_response (Response): Baseline response
        """
        # Get DOM-based payloads
        payloads = self.payload_generator.get_dom_based_payloads()

        # Check if page has potential DOM-based XSS sinks
        dom_sinks = self._find_dom_sinks(baseline_response.text)

        if not dom_sinks:
            if self.verbose:
                self.output.print_info("No potential DOM XSS sinks found")
            return

        self.output.print_info(
            f"Found {len(dom_sinks)} potential DOM XSS sinks")

        # Simplistic DOM XSS testing - in a real-world scenario,
        # you'd use browser automation to detect actual execution
        for sink in dom_sinks:
            self.output.print_info(f"Testing DOM sink: {sink}")

            # Test fragment/hash-based payloads
            for payload in payloads:
                if payload.startswith('#'):
                    test_url = url + payload

                    if self.verbose:
                        self.output.print_info(
                            f"Testing DOM payload: {payload}")

                    # This would ideally be tested with a headless browser
                    # For our simplified scanner, we'll just note it as a potential vulnerability
                    if 'location.hash' in baseline_response.text:
                        vuln = {
                            'url': url,
                            'parameter': 'DOM/fragment',
                            'payload': payload,
                            'evidence': f"Potential DOM XSS sink: {sink}",
                            'type': 'Potential DOM XSS'
                        }

                        self.vulnerabilities.append(vuln)

                        self.output.print_success(
                            f"Potential DOM XSS found in URL: {url}")
                        self.output.print_detail("Sink", sink)
                        self.output.print_detail("Payload", payload)
                        self.output.print_detail(
                            "Note", "DOM XSS requires browser verification")

                        # Break after finding first vulnerability for this sink
                        break

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

    def _find_dom_sinks(self, html_content):
        """
        Find potential DOM XSS sinks in HTML content

        Args:
            html_content (str): HTML content

        Returns:
            list: Potential DOM XSS sinks
        """
        sinks = []

        # Look for common DOM XSS sinks in JavaScript code
        dom_sink_patterns = [
            r'document\.write\s*\(',
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'\.insertAdjacentHTML\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'location\.hash',
            r'location\.href',
            r'location\.search',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.location',
            r'\.createContextualFragment\s*\('
        ]

        # Extract all script tags
        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = soup.find_all('script')

        script_content = ""
        for script in scripts:
            if script.string:
                script_content += script.string + "\n"

        # Also check for inline event handlers
        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if attr.startswith('on'):
                    # Found an event handler
                    sinks.append(f"{tag.name} [{attr}]")

        # Check for DOM sinks in script content
        for pattern in dom_sink_patterns:
            matches = re.findall(pattern, script_content)
            for match in matches:
                sinks.append(match)

        return sinks

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
