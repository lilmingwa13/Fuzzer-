#!/usr/bin/env python3
"""
Request Handler module for the SQL Injection Fuzzer
"""

import time
import requests
from requests.exceptions import RequestException


class RequestHandler:
    def __init__(self, timeout=10, user_agent=None, cookies=None, proxy=None, delay=0):
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent or "SQLFuzzer/1.0"
        self.cookies = self._parse_cookies(cookies) if cookies else {}
        self.proxies = self._setup_proxy(proxy) if proxy else {}

        # Configure requests session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent
        })

        if self.cookies:
            self.session.cookies.update(self.cookies)

    def _parse_cookies(self, cookies_str):
        """
        Parse cookies string into a dictionary

        Args:
            cookies_str (str): Cookies in format "name1=value1; name2=value2"

        Returns:
            dict: Parsed cookies
        """
        try:
            cookies = {}
            if cookies_str:
                for cookie in cookies_str.split(';'):
                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookies[name] = value
            return cookies
        except Exception as e:
            print(f"[!] Error parsing cookies: {e}")
            return {}

    def _setup_proxy(self, proxy):
        """
        Setup proxy configuration

        Args:
            proxy (str): Proxy string in format "http://host:port"

        Returns:
            dict: Proxy configuration for requests
        """
        try:
            proxies = {
                'http': proxy,
                'https': proxy
            }
            return proxies
        except Exception as e:
            print(f"[!] Error setting up proxy: {e}")
            return {}

    def send_request(self, url, method="GET", data=None, headers=None):
        """
        Send HTTP request to the specified URL

        Args:
            url (str): Target URL
            method (str, optional): HTTP method. Defaults to "GET".
            data (dict, optional): POST data. Defaults to None.
            headers (dict, optional): Additional headers. Defaults to None.

        Returns:
            requests.Response or None: Response object or None on failure
        """
        try:
            # Apply delay if specified
            if self.delay > 0:
                time.sleep(self.delay)

            # Set up custom headers if provided
            request_headers = {}
            if headers:
                request_headers.update(headers)

            # Send the request with the appropriate method
            if method.upper() == "GET":
                response = self.session.get(
                    url,
                    headers=request_headers,
                    proxies=self.proxies,
                    timeout=self.timeout,
                    verify=False  # Disable SSL verification
                )
            elif method.upper() == "POST":
                response = self.session.post(
                    url,
                    data=data,
                    headers=request_headers,
                    proxies=self.proxies,
                    timeout=self.timeout,
                    verify=False  # Disable SSL verification
                )
            else:
                print(f"[!] Unsupported HTTP method: {method}")
                return None

            return response

        except RequestException as e:
            print(f"[!] Request failed: {e}")
            return None
        except Exception as e:
            print(f"[!] Error sending request: {e}")
            return None

    def check_connection(self, url):
        """
        Check if the target is reachable

        Args:
            url (str): Target URL

        Returns:
            bool: True if target is reachable, False otherwise
        """
        try:
            response = self.send_request(url)
            return response is not None and response.status_code < 500
        except Exception:
            return False
