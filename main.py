#!/usr/bin/env python3
"""
Web Security Fuzzer - A versatile web application security testing tool
Supporting SQL injection, XSS, and web crawling capabilities
"""

import sys
import os
import json
import argparse
import time
from datetime import datetime

# Import modules
from modules.sql.sql_scanner import SQLScanner
from modules.xss.xss_scanner import XSSScanner
from modules.crawler.crawler import WebCrawler
from modules.common.utils import Output, Colors

# Version information
VERSION = "1.0.0"


def banner():
    """Display the tool banner"""
    banner_text = f"""
    {Colors.BLUE}╔══════════════════════════════════════════════════════════╗
    ║                 {Colors.GREEN}Web Security Fuzzer v{VERSION}{Colors.BLUE}                 ║
    ║  {Colors.YELLOW}SQL Injection | XSS | Web Crawler | Authentication Bypass{Colors.BLUE}  ║
    ╚══════════════════════════════════════════════════════════╝{Colors.RESET}
    """
    print(banner_text)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Web Security Fuzzer - A versatile web application security testing tool",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Target options
    target_group = parser.add_argument_group("Target")
    target_options = target_group.add_mutually_exclusive_group(required=True)
    target_options.add_argument("-u", "--url", help="Target URL")
    target_options.add_argument(
        "-f", "--file", help="File containing target URLs (one per line)")

    # Module selection
    module_group = parser.add_argument_group("Module Selection")
    module_group.add_argument(
        "--sql", action="store_true", help="SQL Injection testing")
    module_group.add_argument("--xss", action="store_true", help="XSS testing")
    module_group.add_argument(
        "--crawl", action="store_true", help="Web crawling")
    module_group.add_argument(
        "--all", action="store_true", help="Run all modules")

    # Crawler options
    crawler_group = parser.add_argument_group("Crawler Options")
    crawler_group.add_argument(
        "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    crawler_group.add_argument(
        "--same-domain", action="store_true", help="Only crawl URLs within the same domain")
    crawler_group.add_argument(
        "--exclude", help="Exclude URLs matching these patterns (comma-separated)")
    crawler_group.add_argument(
        "--include-forms", action="store_true", help="Include forms in crawling results")

    # SQL Scanner options
    sql_group = parser.add_argument_group("SQL Injection Options")
    sql_group.add_argument("--sql-types", default="error,boolean,time,union,auth",
                           help="Types of SQL injection to test (default: error,boolean,time,union,auth)")

    # XSS Scanner options
    xss_group = parser.add_argument_group("XSS Options")
    xss_group.add_argument("--xss-types", default="reflected",
                           help="Types of XSS to test (default: reflected)")
    xss_group.add_argument(
        "--callback-url", help="Callback URL for blind XSS testing")

    # Request options
    request_group = parser.add_argument_group("Request Options")
    request_group.add_argument("-m", "--method", default="GET", choices=["GET", "POST"],
                               help="HTTP method (default: GET)")
    request_group.add_argument(
        "-d", "--data", help="POST data (e.g. 'param1=value1&param2=value2')")
    request_group.add_argument(
        "-H", "--headers", help="Custom HTTP headers (e.g. 'Header1:value1,Header2:value2')")
    request_group.add_argument(
        "-c", "--cookies", help="HTTP cookies (e.g. 'cookie1=value1;cookie2=value2')")
    request_group.add_argument("-A", "--user-agent", help="Custom User-Agent")
    request_group.add_argument(
        "-p", "--proxy", help="Proxy URL (e.g. 'http://127.0.0.1:8080')")
    request_group.add_argument("-t", "--timeout", type=int,
                               default=10, help="Request timeout in seconds (default: 10)")
    request_group.add_argument("--delay", type=float, default=0,
                               help="Delay between requests in seconds (default: 0)")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o", "--output", help="Save results to file (JSON format)")
    output_group.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output")
    output_group.add_argument(
        "--no-color", action="store_true", help="Disable colored output")

    # Parse arguments
    return parser.parse_args()


def load_targets(args):
    """Load target URLs from command line arguments or file"""
    urls = []

    if args.url:
        urls.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error loading targets from file: {str(e)}")
            sys.exit(1)

    return urls


def parse_headers(headers_str):
    """Parse headers from string format"""
    if not headers_str:
        return {}

    headers = {}
    for header in headers_str.split(','):
        if ':' in header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()

    return headers


def parse_cookies(cookies_str):
    """Parse cookies from string format"""
    if not cookies_str:
        return {}

    cookies = {}
    for cookie in cookies_str.split(';'):
        if '=' in cookie:
            key, value = cookie.split('=', 1)
            cookies[key.strip()] = value.strip()

    return cookies


def run_crawler(urls, args, output):
    """Run the web crawler module"""
    output.info("Starting web crawler...")

    # Parse exclude patterns
    exclude_patterns = []
    if args.exclude:
        exclude_patterns = [pattern.strip()
                            for pattern in args.exclude.split(',')]

    # Setup crawler
    crawler = WebCrawler(
        url=urls[0],  # Use the first URL as the starting point
        max_depth=args.depth,
        same_domain_only=args.same_domain,
        exclude_patterns=exclude_patterns,
        include_forms=args.include_forms,
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent,
        cookies=parse_cookies(args.cookies),
        headers=parse_headers(args.headers),
        proxy=args.proxy,
        verbose=args.verbose,
        no_color=args.no_color
    )

    # Start crawling
    output.info(f"Crawling {urls[0]} with max depth {args.depth}...")
    start_time = time.time()
    crawler.crawl()
    end_time = time.time()

    # Get results
    crawled_urls = crawler.get_crawled_urls()

    # Print results
    output.success(
        f"Crawling completed in {end_time - start_time:.2f} seconds")
    output.info(f"Found {len(crawled_urls)} URLs")

    # Return list of discovered URLs
    return crawled_urls


def run_sql_scanner(urls, args, output):
    """Run the SQL injection scanner module"""
    output.info("Starting SQL Injection scanner...")

    # Parse SQL injection types
    sql_types = [t.strip() for t in args.sql_types.split(',')
                 ] if args.sql_types else None

    # Setup SQL scanner
    sql_scanner = SQLScanner(
        urls=urls,
        method=args.method,
        data=args.data,
        headers=parse_headers(args.headers),
        cookies=parse_cookies(args.cookies),
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent,
        proxy=args.proxy,
        injection_types=sql_types,
        verbose=args.verbose,
        no_color=args.no_color
    )

    # Start scanning
    output.info(
        f"Scanning {len(urls)} URL(s) for SQL injection vulnerabilities...")
    start_time = time.time()
    results = sql_scanner.scan()
    end_time = time.time()

    # Print results
    vulnerabilities = sql_scanner.get_vulnerabilities()
    output.success(
        f"SQL Injection scan completed in {end_time - start_time:.2f} seconds")
    output.info(f"Found {len(vulnerabilities)} vulnerabilities")

    return results


def run_xss_scanner(urls, args, output):
    """Run the XSS scanner module"""
    output.info("Starting XSS scanner...")

    # Parse XSS types
    xss_types = [t.strip() for t in args.xss_types.split(',')
                 ] if args.xss_types else None

    # Setup XSS scanner
    xss_scanner = XSSScanner(
        urls=urls,
        method=args.method,
        data=args.data,
        headers=parse_headers(args.headers),
        cookies=parse_cookies(args.cookies),
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent,
        proxy=args.proxy,
        injection_types=xss_types,
        callback_url=args.callback_url,
        verbose=args.verbose,
        no_color=args.no_color
    )

    # Start scanning
    output.info(f"Scanning {len(urls)} URL(s) for XSS vulnerabilities...")
    start_time = time.time()
    results = xss_scanner.scan()
    end_time = time.time()

    # Print results
    vulnerabilities = xss_scanner.get_vulnerabilities()
    output.success(
        f"XSS scan completed in {end_time - start_time:.2f} seconds")
    output.info(f"Found {len(vulnerabilities)} vulnerabilities")

    return results


def save_results(results, output_file, output):
    """Save results to a file"""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        output.success(f"Results saved to {output_file}")
    except Exception as e:
        output.error(f"Error saving results to file: {str(e)}")


def main():
    """Main function"""
    # Display banner
    banner()

    # Parse arguments
    args = parse_arguments()

    # Setup output handler
    output = Output(no_color=args.no_color)

    # Load target URLs
    urls = load_targets(args)
    if not urls:
        output.error("No target URLs provided")
        sys.exit(1)

    output.info(f"Loaded {len(urls)} target URL(s)")

    # Initialize results
    results = {
        'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'targets': urls,
        'modules': []
    }

    # Run modules based on arguments
    discovered_urls = []

    # Run web crawler if selected
    if args.crawl or args.all:
        results['modules'].append('crawler')
        crawler_results = run_crawler(urls, args, output)
        results['crawler'] = {
            'urls_discovered': len(crawler_results),
            'urls': crawler_results
        }

        # Add discovered URLs to the target list for other scanners if requested
        discovered_urls.extend(
            [url for url in crawler_results if url not in urls])

    # Run SQL injection scanner if selected
    if args.sql or args.all:
        results['modules'].append('sql')
        # Include discovered URLs if available
        scan_urls = urls + discovered_urls if discovered_urls else urls
        sql_results = run_sql_scanner(scan_urls, args, output)
        results['sql'] = sql_results

    # Run XSS scanner if selected
    if args.xss or args.all:
        results['modules'].append('xss')
        # Include discovered URLs if available
        scan_urls = urls + discovered_urls if discovered_urls else urls
        xss_results = run_xss_scanner(scan_urls, args, output)
        results['xss'] = xss_results

    # Save results if output file specified
    if args.output:
        save_results(results, args.output, output)

    # Print summary
    output.success("Scan completed")

    # If no modules were selected
    if not results['modules']:
        output.warning(
            "No modules were selected. Use --sql, --xss, --crawl, or --all")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)
