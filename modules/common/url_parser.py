#!/usr/bin/env python3
"""
URL Parser module for the Web Security Fuzzer
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class URLParser:
    def __init__(self):
        pass

    def parse(self, url):
        """
        Parse a URL and extract its components and parameters

        Args:
            url (str): The URL to parse

        Returns:
            dict: A dictionary containing URL components and parameters
        """
        result = {
            'original_url': url,
            'components': {},
            'parameters': {}
        }

        try:
            # Parse URL components
            parsed_url = urlparse(url)
            result['components'] = {
                'scheme': parsed_url.scheme,
                'netloc': parsed_url.netloc,
                'path': parsed_url.path,
                'params': parsed_url.params,
                'query': parsed_url.query,
                'fragment': parsed_url.fragment
            }

            # Parse query parameters
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                # Convert values from lists to single values
                for param, values in query_params.items():
                    result['parameters'][param] = values[0] if values else ''

        except Exception as e:
            print(f"[!] Error parsing URL: {e}")

        return result

    def inject_payload(self, url, param_name, payload):
        """
        Inject a payload into a specific parameter of a URL

        Args:
            url (str): The original URL
            param_name (str): The parameter to inject the payload into
            payload (str): The payload to inject

        Returns:
            str: The URL with the injected payload
        """
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # Make a copy of the parameters where each param has a single value (not a list)
            params = {k: v[0] if v else '' for k, v in query_params.items()}

            # Inject the payload
            params[param_name] = payload

            # Reconstruct the URL with the injected payload
            # Allow special characters
            new_query = urlencode(params, safe="*()'-=<>\"{}[];:,./?")
            url_parts = list(parsed_url)
            url_parts[4] = new_query

            return urlunparse(url_parts)

        except Exception as e:
            print(f"[!] Error injecting payload: {e}")
            return url

    def extract_base_url(self, url):
        """
        Extract the base URL (scheme + netloc + path) without query parameters

        Args:
            url (str): The URL to extract from

        Returns:
            str: The base URL
        """
        try:
            parsed_url = urlparse(url)
            url_parts = list(parsed_url)
            url_parts[4] = ''  # empty query string
            url_parts[5] = ''  # empty fragment

            return urlunparse(url_parts)

        except Exception as e:
            print(f"[!] Error extracting base URL: {e}")
            return url

    def get_domain(self, url):
        """
        Extract the domain from a URL

        Args:
            url (str): The URL to extract from

        Returns:
            str: The domain
        """
        try:
            parsed_url = urlparse(url)
            return parsed_url.netloc
        except Exception as e:
            print(f"[!] Error extracting domain: {e}")
            return ""

    def is_same_domain(self, url1, url2):
        """
        Check if two URLs are from the same domain

        Args:
            url1 (str): First URL
            url2 (str): Second URL

        Returns:
            bool: True if URLs are from the same domain
        """
        try:
            domain1 = self.get_domain(url1)
            domain2 = self.get_domain(url2)
            return domain1 == domain2
        except Exception as e:
            print(f"[!] Error comparing domains: {e}")
            return False

    def get_path(self, url):
        """
        Extract the path from a URL

        Args:
            url (str): The URL to extract from

        Returns:
            str: The path
        """
        try:
            parsed_url = urlparse(url)
            return parsed_url.path
        except Exception as e:
            print(f"[!] Error extracting path: {e}")
            return ""
