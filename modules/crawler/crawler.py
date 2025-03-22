#!/usr/bin/env python3
"""
Web Crawler module for the Web Security Fuzzer
"""

import time
import re
import urllib.parse
import os
from collections import deque
from bs4 import BeautifulSoup

from ..common.url_parser import URLParser
from ..common.request_handler import RequestHandler
from ..common.utils import Output


class WebCrawler:
    def __init__(self, url, max_depth=3, same_domain_only=True,
                 exclude_patterns=None, include_forms=False, timeout=10, delay=0, user_agent=None,
                 cookies=None, headers=None, proxy=None, verbose=False, no_color=False, verify_ssl=False):
        self.start_url = url
        self.max_depth = max_depth
        self.same_domain_only = same_domain_only
        self.exclude_patterns = exclude_patterns or []
        self.include_forms = include_forms
        self.visited_urls = set()
        self.url_queue = deque([(url, 0)])  # (url, depth)
        self.discovered_urls = {url: 0}  # url -> depth
        self.failed_urls = set()
        self.form_urls = set()  # URLs with forms
        self.parameterized_urls = set()  # URLs with parameters

        # Dictionary to track parameters: { path: { param_name: url } }
        # This allows us to track one URL per parameter name for each path
        self.unique_parameter_urls = {}

        # Initialize common modules
        self.url_parser = URLParser()
        self.request_handler = RequestHandler(
            timeout=timeout,
            user_agent=user_agent,
            cookies=cookies,
            headers=headers,
            proxy=proxy,
            delay=delay,
            verify_ssl=verify_ssl
        )

        # Output formatting
        self.verbose = verbose
        self.output = Output(no_color=no_color)

        # Extract base domain and root URL parts from starting URL
        self.base_domain = self.url_parser.get_domain(url)
        parsed_url = urllib.parse.urlparse(url)

        # Get the root path (exclude query parameters and fragments)
        path_parts = parsed_url.path.split('/')
        # If the last part looks like a file
        if path_parts and path_parts[-1] and '.' in path_parts[-1]:
            self.root_path = '/'.join(path_parts[:-1])
            if not self.root_path.endswith('/'):
                self.root_path += '/'
        else:
            self.root_path = parsed_url.path
            if not self.root_path.endswith('/'):
                self.root_path += '/'

        # Build the root URL (scheme + netloc + root_path)
        self.root_url = f"{parsed_url.scheme}://{parsed_url.netloc}{self.root_path}"

        # Log file path - use the hostname for the log file name
        self.log_file = f"{parsed_url.netloc.replace(':', '_')}_parameterized_urls.log"

    def crawl(self):
        """
        Start crawling from the specified URL up to max_depth
        Only collect URLs within the same subdomain and root path that have parameters

        Returns:
            dict: Crawling results with discovered URLs and statistics
        """
        self.output.print_info(f"Starting web crawl from: {self.start_url}")
        self.output.print_info(f"Maximum depth: {self.max_depth}")
        self.output.print_info(f"Only crawling URLs within: {self.root_url}")
        self.output.print_info(
            f"Collecting only URLs with parameters (one URL per parameter name)")
        self.output.print_info(
            f"Parameterized URLs will be saved to: {self.log_file}")

        start_time = time.time()
        count = 0

        # Process URLs until the queue is empty
        while self.url_queue:
            current_url, current_depth = self.url_queue.popleft()

            # Skip if already visited
            if current_url in self.visited_urls:
                continue

            # Skip if depth limit reached
            if current_depth > self.max_depth:
                continue

            # Skip URL if it matches any exclude pattern
            if self._is_excluded(current_url):
                continue

            # Mark as visited
            self.visited_urls.add(current_url)
            count += 1

            if self.verbose:
                self.output.print_info(
                    f"Crawling ({current_depth}/{self.max_depth}): {current_url}")
            elif count % 10 == 0:
                self.output.print_info(f"Crawled {count} URLs...")

            # Fetch the URL
            response = self.request_handler.send_request(current_url)
            if not response:
                self.failed_urls.add(current_url)
                continue

            # Skip non-HTML responses
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type.lower():
                continue

            # Check for forms
            if '<form' in response.text.lower():
                self.form_urls.add(current_url)

            # Check if URL has parameters and add to parameterized_urls
            if '?' in current_url and '=' in current_url:
                parsed = urllib.parse.urlparse(current_url)
                if parsed.query:
                    # Add to global list of parameterized URLs
                    self.parameterized_urls.add(current_url)

                    # Process for unique parameter tracking
                    self._track_unique_parameter_url(current_url, parsed)

                    if self.verbose:
                        self.output.print_success(
                            f"Found URL with parameters: {current_url}")

            # Extract links
            links = self.request_handler.get_links_from_html(response.text)

            # Process discovered links
            for link in links:
                absolute_url = self.request_handler.normalize_url(
                    current_url, link)

                # Skip invalid URLs, fragments, javascript:, mailto:, etc.
                if not self._is_valid_url(absolute_url):
                    continue

                # Only include URLs that are within the same root URL
                if not self._is_same_root_url(absolute_url):
                    continue

                # Add to queue if not already discovered
                if absolute_url not in self.discovered_urls:
                    self.discovered_urls[absolute_url] = current_depth + 1
                    self.url_queue.append((absolute_url, current_depth + 1))

        # Save parameterized URLs to log file
        self.save_parameterized_urls_to_log()

        # Calculate statistics
        elapsed_time = time.time() - start_time

        # Count unique parameter URLs
        unique_param_count = sum(len(params)
                                 for params in self.unique_parameter_urls.values())

        self.output.print_success(
            f"Crawling completed in {elapsed_time:.2f} seconds")
        self.output.print_success(
            f"Discovered {len(self.discovered_urls)} URLs ({len(self.form_urls)} with forms)")
        self.output.print_success(
            f"Found {len(self.parameterized_urls)} URLs with parameters")
        self.output.print_success(
            f"After deduplication: {unique_param_count} unique parameter patterns")
        self.output.print_success(f"Visited {len(self.visited_urls)} URLs")
        self.output.print_success(
            f"Parameterized URLs saved to: {self.log_file}")

        if self.failed_urls:
            self.output.print_warning(
                f"Failed to fetch {len(self.failed_urls)} URLs")

        # Return results as dictionary
        return {
            'start_url': self.start_url,
            'root_url': self.root_url,
            'base_domain': self.base_domain,
            'max_depth': self.max_depth,
            'stats': {
                'discovered': len(self.discovered_urls),
                'visited': len(self.visited_urls),
                'failed': len(self.failed_urls),
                'with_forms': len(self.form_urls),
                'with_parameters': len(self.parameterized_urls),
                'unique_parameters': unique_param_count,
                'time_seconds': elapsed_time
            },
            'urls': {url: depth for url, depth in self.discovered_urls.items()},
            'form_urls': list(self.form_urls),
            'parameterized_urls': list(self.parameterized_urls),
            'unique_parameter_urls': self._get_unique_parameter_urls_list(),
            'failed_urls': list(self.failed_urls),
            'log_file': self.log_file
        }

    def _track_unique_parameter_url(self, url, parsed_url=None):
        """
        Track one URL per parameter name for each path
        """
        if not parsed_url:
            parsed_url = urllib.parse.urlparse(url)

        # Get the path (without query parameters)
        path = parsed_url.path

        # Parse query parameters
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # Make sure the path entry exists in our tracking dictionary
        if path not in self.unique_parameter_urls:
            self.unique_parameter_urls[path] = {}

        # Add each parameter if it's not already tracked
        for param_name in query_params.keys():
            if param_name not in self.unique_parameter_urls[path]:
                self.unique_parameter_urls[path][param_name] = url

    def _get_unique_parameter_urls_list(self):
        """
        Get a flattened list of all URLs with unique parameters
        """
        result = []
        for path_params in self.unique_parameter_urls.values():
            result.extend(path_params.values())
        return result

    def _is_same_root_url(self, url):
        """
        Check if URL is within the same root URL
        This restricts crawling to the specific subdomain and root path
        """
        parsed = urllib.parse.urlparse(url)
        url_base = f"{parsed.scheme}://{parsed.netloc}"

        # Check if it starts with the root URL
        return url.startswith(self.root_url)

    def save_parameterized_urls_to_log(self):
        """
        Save discovered URLs with parameters to a log file
        Only saving one URL per parameter name for each path
        """
        try:
            with open(self.log_file, 'w') as f:
                f.write(f"# Parameterized URLs for {self.root_url}\n")
                f.write(f"# Crawl started from: {self.start_url}\n")
                f.write(f"# Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

                # Count unique parameter URLs
                unique_urls = self._get_unique_parameter_urls_list()

                f.write(
                    f"# Total unique parameter patterns: {len(unique_urls)}\n\n")

                # Sort and write the unique parameter URLs
                for url in sorted(unique_urls):
                    f.write(f"{url}\n")

            return True
        except Exception as e:
            self.output.print_error(f"Error saving to log file: {str(e)}")
            return False

    def get_crawled_urls(self, with_forms_only=False, with_parameters_only=False, up_to_depth=None):
        """
        Get list of crawled URLs, optionally filtered by depth, form presence, or parameters

        Args:
            with_forms_only (bool): Return only URLs with forms
            with_parameters_only (bool): Return only URLs with parameters
            up_to_depth (int): Return URLs up to specified depth

        Returns:
            list: List of URLs
        """
        if with_forms_only:
            urls = self.form_urls
        elif with_parameters_only:
            if hasattr(self, 'unique_parameter_urls'):
                urls = self._get_unique_parameter_urls_list()
            else:
                urls = self.parameterized_urls
        else:
            urls = self.discovered_urls.keys()

        if up_to_depth is not None:
            return [url for url in urls if self.discovered_urls.get(url, 0) <= up_to_depth]
        else:
            return list(urls)

    def get_parameterized_urls(self):
        """
        Get list of URLs with parameters (deduplicated by parameter name)

        Returns:
            list: List of unique parameter URLs
        """
        return self._get_unique_parameter_urls_list()

    def _is_valid_url(self, url):
        """Check if URL is valid for crawling"""
        if not url:
            return False

        # Parse URL
        parsed = urllib.parse.urlparse(url)

        # Must have scheme and netloc
        if not all([parsed.scheme, parsed.netloc]):
            return False

        # Only allow HTTP and HTTPS
        if parsed.scheme not in ['http', 'https']:
            return False

        return True

    def _is_excluded(self, url):
        """Check if URL matches any exclude pattern"""
        for pattern in self.exclude_patterns:
            if re.search(pattern, url):
                return True
        return False
