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
import urllib.parse

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
    ║               {Colors.YELLOW}SQL Injection | XSS | Web Crawler |   ║
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
    target_group.add_argument("-u", "--url", required=True, help="Target URL")

    # Module selection
    module_group = parser.add_argument_group("Module Selection")
    module_group.add_argument(
        "--sql", action="store_true", help="SQL Injection testing")
    module_group.add_argument("--xss", action="store_true", help="XSS testing")
    module_group.add_argument(
        "--crawl", action="store_true", help="Web crawling")

    # Crawler options
    crawler_group = parser.add_argument_group("Crawler Options")
    crawler_group.add_argument(
        "--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")

    # SQL Scanner options
    sql_group = parser.add_argument_group("SQL Injection Options")
    sql_group.add_argument("--params",
                           help="Specify parameters to test for SQL injection (comma-separated)")

    # Request options
    request_group = parser.add_argument_group("Request Options")
    request_group.add_argument(
        "-H", "--headers", help="Custom HTTP headers (e.g. 'Header1:value1,Header2:value2')")
    request_group.add_argument(
        "-c", "--cookies", help="HTTP cookies (e.g. 'cookie1=value1;cookie2=value2')")
    request_group.add_argument("-A", "--user-agent", help="Custom User-Agent")
    request_group.add_argument("--no-verify-ssl", action="store_true",
                               help="Disable SSL certificate verification for HTTPS connections")

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
    """Load target URL from command line arguments"""
    urls = []

    if args.url:
        urls.append(args.url)

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


def save_crawler_log(crawler_results, crawled_urls, log_file, target_url, output):
    """Save crawler results to a log file

    Args:
        crawler_results (list): List of URLs with parameters
        crawled_urls (set): Set of all crawled URLs
        log_file (str): Path to log file
        target_url (str): Target URL
        output (Output): Output handler
    """
    try:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Append to log file
        mode = 'a' if os.path.exists(log_file) else 'w'
        with open(log_file, mode) as f:
            # If new file, write header
            if mode == 'w':
                f.write(
                    "============================================================\n")
                f.write(
                    "||           Web Security Fuzzer - Vulnerability Log        ||\n")
                f.write(
                    "============================================================\n\n")
                f.write(
                    f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target URL: {target_url}\n\n")
                f.write(
                    "------------------------------------------------------------\n\n")

            # Write crawler section header
            f.write(f"\n{'='*60}\n")
            f.write(
                f"|| CRAWLER RESULTS ||\n")
            f.write(f"{'='*60}\n")
            f.write(
                f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Write results
            f.write(f"Total URLs discovered: {len(crawled_urls)}\n")
            f.write(f"URLs with parameters found: {len(crawler_results)}\n\n")

            if crawler_results:
                f.write("URLs with parameters:\n")
                for i, url in enumerate(crawler_results, 1):
                    f.write(f"{i}. {url}\n")
                f.write("\n")

            # Add summary
            f.write(
                f"\nSummary: Found {len(crawled_urls)} total URLs and {len(crawler_results)} URLs with parameters from {target_url}\n")
            f.write(f"{'='*60}\n\n")

        output.success(f"Crawler results logged to: {log_file}")
        return True
    except Exception as e:
        output.error(f"Error saving crawler results to log file: {str(e)}")
        return False


def run_crawler(urls, args, output):
    """Run the web crawler module"""
    output.info("Starting web crawler...")

    crawler = WebCrawler(
        start_url=urls[0]
    )

    output.info(f"Crawling {urls[0]} with max depth {args.depth}...")
    start_time = time.time()
    urls_with_params = crawler.crawl(max_depth=args.depth)
    end_time = time.time()

    output.success(
        f"Crawling completed in {end_time - start_time:.2f} seconds")
    output.info(f"Found {len(crawler.crawled_urls)} total URLs")
    output.success(f"Found {len(urls_with_params)} URLs with parameters")

    if urls_with_params:
        output.info("URLs with parameters:")
        for i, url in enumerate(urls_with_params, 1):
            output.info(f"  {i}. {url}")

    results = {
        'urls': urls_with_params
    }

    return urls_with_params, crawler.crawled_urls


def run_sql_scanner(urls, args, output):
    """Run the SQL injection scanner module"""
    output.info("Starting SQL Injection scanner...")

    # Parse target parameters if specified
    target_params = None
    if args.params:
        target_params = [p.strip() for p in args.params.split(',')]
        output.info(f"Testing specific parameters: {', '.join(target_params)}")

    # Setup SQL scanner
    sql_scanner = SQLScanner(
        urls=urls,
        method="GET",
        data=None,
        headers=parse_headers(args.headers),
        cookies=parse_cookies(args.cookies),
        user_agent=args.user_agent,
        verbose=args.verbose,
        no_color=args.no_color,
        target_params=target_params,
        verify_ssl=not args.no_verify_ssl
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

    # Setup XSS scanner
    xss_scanner = XSSScanner(
        urls=urls,
        method="GET",
        data=None,
        headers=parse_headers(args.headers),
        cookies=parse_cookies(args.cookies),
        user_agent=args.user_agent,
        injection_types=["reflected"],
        verbose=args.verbose,
        no_color=args.no_color,
        verify_ssl=not args.no_verify_ssl
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


def save_vulnerabilities_log(vulnerabilities, log_file, scan_type, target_url, output):
    """Save vulnerabilities to a log file

    Args:
        vulnerabilities (list): List of vulnerabilities
        log_file (str): Path to log file
        scan_type (str): Type of scan (SQL, XSS, etc.)
        target_url (str): Target URL
        output (Output): Output handler
    """
    try:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Append to log file
        mode = 'a' if os.path.exists(log_file) else 'w'
        with open(log_file, mode) as f:
            # If new file, write header
            if mode == 'w':
                f.write(
                    "============================================================\n")
                f.write(
                    "||           Web Security Fuzzer - Vulnerability Log        ||\n")
                f.write(
                    "============================================================\n\n")
                f.write(
                    f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target URL: {target_url}\n\n")
                f.write(
                    "------------------------------------------------------------\n\n")

            # Write scan section header
            f.write(f"\n{'='*60}\n")
            f.write(
                f"|| {scan_type.upper()} VULNERABILITIES SCAN RESULTS ||\n")
            f.write(f"{'='*60}\n")
            f.write(
                f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            if not vulnerabilities:
                f.write("No vulnerabilities found.\n")
            else:
                f.write(
                    f"Found {len(vulnerabilities)} {scan_type.upper()} vulnerabilities:\n\n")
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"{'-'*60}\n")
                    f.write(f"Vulnerability #{i}:\n")
                    f.write(f"{'-'*60}\n")

                    if scan_type.lower() == 'sql':
                        f.write(f"URL: {vuln['url']}\n")
                        f.write(f"Parameter: {vuln['parameter']}\n")
                        f.write(f"Type: {vuln['type']}\n")
                        f.write(f"Payload: {vuln['payload']}\n")
                        if 'evidence' in vuln:
                            # Format evidence to make it more readable
                            evidence = vuln['evidence']
                            if len(evidence) > 200:
                                evidence = evidence[:197] + "..."
                            f.write(f"Evidence: {evidence}\n")
                        f.write(f"Severity: {vuln.get('severity', 'High')}\n")
                        f.write(f"DBMS: {vuln.get('dbms', 'Unknown')}\n")
                    elif scan_type.lower() == 'xss':
                        f.write(f"URL: {vuln['url']}\n")
                        f.write(f"Parameter: {vuln['parameter']}\n")
                        f.write(f"Type: {vuln['type']}\n")
                        f.write(f"Payload: {vuln['payload']}\n")
                        if 'evidence' in vuln:
                            # Format evidence to make it more readable
                            evidence = vuln['evidence']
                            if len(evidence) > 200:
                                evidence = evidence[:197] + "..."
                            f.write(f"Evidence: {evidence}\n")
                        f.write(f"Severity: {vuln.get('severity', 'High')}\n")

                    # Add exploitation notes
                    if scan_type.lower() == 'sql':
                        f.write("\nExploitation Notes:\n")
                        f.write(
                            "- This parameter is vulnerable to SQL Injection attacks\n")
                        f.write(
                            "- An attacker could extract database information or manipulate queries\n")
                        f.write(
                            "- Consider using prepared statements or parameterized queries\n")
                    elif scan_type.lower() == 'xss':
                        f.write("\nExploitation Notes:\n")
                        f.write(
                            "- This parameter is vulnerable to Cross-Site Scripting (XSS) attacks\n")
                        f.write(
                            "- An attacker could execute malicious JavaScript in users' browsers\n")
                        f.write(
                            "- Consider implementing input validation and output encoding\n")

                    f.write("\n")

                # Add summary at the end
                f.write(
                    f"\nSummary: Found {len(vulnerabilities)} {scan_type} vulnerabilities in {target_url}\n")
                f.write(f"{'='*60}\n\n")

        output.success(f"{scan_type} vulnerabilities logged to: {log_file}")
        return True
    except Exception as e:
        output.error(f"Error saving vulnerabilities to log file: {str(e)}")
        return False


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
        output.error("No target URL provided")
        sys.exit(1)

    output.info(f"Loaded {len(urls)} target URL")

    # Create vulnerability log filename based on first URL and timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_domain = urllib.parse.urlparse(urls[0]).netloc.replace(':', '_')
    vuln_log_file = f"{target_domain}_{timestamp}_vulnerabilities.log"

    output.info(f"Vulnerabilities will be logged to: {vuln_log_file}")

    # Initialize results
    results = {
        'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'targets': urls,
        'modules': []
    }

    # Run modules based on arguments
    discovered_urls = []

    # Run web crawler if selected
    if args.crawl:
        results['modules'].append('crawler')
        crawler_results, crawled_urls = run_crawler(urls, args, output)
        results['crawler'] = {
            'urls_discovered': len(crawled_urls),
            'urls_with_params': len(crawler_results),
            'urls': crawler_results
        }

        # Add discovered URLs to the target list for other scanners if requested
        discovered_urls.extend(
            [url for url in crawler_results if url not in urls])

        # Save crawler results to log
        save_crawler_log(crawler_results, crawled_urls,
                         vuln_log_file, urls[0], output)

    # Run SQL injection scanner if selected
    if args.sql:
        results['modules'].append('sql')
        # Include discovered URLs if available
        scan_urls = urls + discovered_urls if discovered_urls else urls
        sql_results = run_sql_scanner(scan_urls, args, output)
        results['sql'] = sql_results

        # Log SQL vulnerabilities if found
        if 'vulnerabilities' in sql_results and sql_results['vulnerabilities']:
            save_vulnerabilities_log(
                sql_results['vulnerabilities'],
                vuln_log_file,
                'SQL',
                urls[0],
                output
            )

    # Run XSS scanner if selected
    if args.xss:
        results['modules'].append('xss')
        # Include discovered URLs if available
        scan_urls = urls + discovered_urls if discovered_urls else urls
        xss_results = run_xss_scanner(scan_urls, args, output)
        results['xss'] = xss_results

        # Log XSS vulnerabilities if found
        if 'vulnerabilities' in xss_results and xss_results['vulnerabilities']:
            save_vulnerabilities_log(
                xss_results['vulnerabilities'],
                vuln_log_file,
                'XSS',
                urls[0],
                output
            )

    # Save results if output file specified
    if args.output:
        save_results(results, args.output, output)

    # Print summary
    output.success("Scan completed")
    output.info(f"All results logged to: {vuln_log_file}")

    # If no modules were selected
    if not results['modules']:
        output.warning(
            "No modules were selected. Use --sql, --xss, --crawl")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)