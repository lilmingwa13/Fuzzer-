#!/usr/bin/env python3
"""
Web Crawler module for the Web Security Fuzzer
"""

import time
import re
import urllib.parse
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

        # Extract base domain from starting URL
        self.base_domain = self.url_parser.get_domain(url)

    def crawl(self):
        """
        Start crawling from the specified URL up to max_depth

        Returns:
            dict: Crawling results with discovered URLs and statistics
        """
        self.output.print_info(f"Starting web crawl from: {self.start_url}")
        self.output.print_info(f"Maximum depth: {self.max_depth}")

        if self.same_domain_only:
            self.output.print_info(
                f"Crawling same domain only: {self.base_domain}")

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

            # Extract links
            links = self.request_handler.get_links_from_html(response.text)

            # Process discovered links
            for link in links:
                absolute_url = self.request_handler.normalize_url(
                    current_url, link)

                # Skip invalid URLs, fragments, javascript:, mailto:, etc.
                if not self._is_valid_url(absolute_url):
                    continue

                # Apply same-domain policy if enabled
                if self.same_domain_only and not self.url_parser.is_same_domain(self.start_url, absolute_url):
                    continue

                # Add to queue if not already discovered
                if absolute_url not in self.discovered_urls:
                    self.discovered_urls[absolute_url] = current_depth + 1
                    self.url_queue.append((absolute_url, current_depth + 1))

        # Calculate statistics
        elapsed_time = time.time() - start_time

        self.output.print_success(
            f"Crawling completed in {elapsed_time:.2f} seconds")
        self.output.print_success(
            f"Discovered {len(self.discovered_urls)} URLs ({len(self.form_urls)} with forms)")
        self.output.print_success(f"Visited {len(self.visited_urls)} URLs")

        if self.failed_urls:
            self.output.print_warning(
                f"Failed to fetch {len(self.failed_urls)} URLs")

        # Return results as dictionary
        return {
            'start_url': self.start_url,
            'base_domain': self.base_domain,
            'max_depth': self.max_depth,
            'stats': {
                'discovered': len(self.discovered_urls),
                'visited': len(self.visited_urls),
                'failed': len(self.failed_urls),
                'with_forms': len(self.form_urls),
                'time_seconds': elapsed_time
            },
            'urls': {url: depth for url, depth in self.discovered_urls.items()},
            'form_urls': list(self.form_urls),
            'failed_urls': list(self.failed_urls)
        }

    def get_crawled_urls(self, with_forms_only=False, up_to_depth=None):
        """
        Get list of crawled URLs, optionally filtered by depth or form presence

        Args:
            with_forms_only (bool): Return only URLs with forms
            up_to_depth (int): Return URLs up to specified depth

        Returns:
            list: List of URLs
        """
        if with_forms_only:
            urls = self.form_urls
        else:
            urls = self.discovered_urls.keys()

        if up_to_depth is not None:
            return [url for url in urls if self.discovered_urls.get(url, 0) <= up_to_depth]
        else:
            return list(urls)

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
