# Web Security Fuzzer

A versatile web application security testing tool supporting SQL injection, XSS (Cross-Site Scripting), and web crawling capabilities.

## Features

- **Web Crawler**: Discover URLs on a target website with configurable depth
- **SQL Injection Scanner**: Test for various SQL injection vulnerabilities
  - Error-based SQL injection
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection
  - UNION-based SQL injection
  - Authentication bypass
- **Enhanced MySQL Detection**: Specialized payloads and detection patterns for MySQL
  - Custom MySQL error patterns
  - Advanced MySQL injection techniques (EXTRACTVALUE, UPDATEXML)
  - MySQL UNION-based data extraction
- **XSS Scanner**: Test for Cross-Site Scripting vulnerabilities
  - Reflected XSS
  - DOM-based XSS
  - Stored XSS
- **Flexible**: Support for both GET and POST requests
- **Customizable**: Configure headers, cookies, User-Agent, proxies and more
- **Report Generation**: Save scan results in JSON format

## Installation

1. Clone the repository:

```
git clone https://github.com/yourusername/web-security-fuzzer.git
cd web-security-fuzzer
```

2. Install the required dependencies:

```
pip install -r requirements.txt
```

## Usage

### Basic Usage

```
python main.py -u "http://example.com/page.php?id=1" --sql
```

### Module Selection

- Use `--sql` for SQL injection testing
- Use `--xss` for XSS testing
- Use `--crawl` for web crawling
- Use `--all` to run all modules

### Examples

#### Basic SQL Injection Scan

```
python main.py -u "http://example.com/page.php?id=1" --sql
```

#### MySQL-Specific SQL Injection Testing

```
python main.py -u "http://example.com/page.php?id=1" --sql --sql-types=error,boolean,time,union
```

#### Crawl a Website and Test Discovered URLs for XSS

```
python main.py -u "http://example.com/" --crawl --xss --depth 3
```

#### Test a POST Request for SQL Injection

```
python main.py -u "http://example.com/login.php" --sql -m POST -d "username=admin&password=pass"
```

#### Run All Scans with Detailed Output

```
python main.py -u "http://example.com/" --all -v -o results.json
```

#### Scan Multiple URLs from a File

```
python main.py -f urls.txt --sql --xss -v
```

### Crawler Options

```
--depth N              Maximum crawl depth (default: 2)
--same-domain          Only crawl URLs within the same domain
--exclude PATTERNS     Exclude URLs matching these patterns (comma-separated)
--include-forms        Include forms in crawling results
```

### SQL Injection Options

```
--sql-types TYPES      Types of SQL injection to test (default: error,boolean,time,union,auth)
```

### MySQL-Specific Testing

The tool now includes enhanced capabilities for detecting MySQL-specific SQL injection vulnerabilities:

#### Error-based MySQL Injection

The scanner uses specialized MySQL payloads to detect error-based vulnerabilities:

- EXTRACTVALUE and UPDATEXML functions for error-based data extraction
- Custom regex patterns to detect specific MySQL errors
- Advanced data extraction from error messages

Example:

```
python main.py -u "http://example.com/page.php?id=1" --sql --sql-types=error
```

#### Union-based MySQL Injection

Enhanced UNION-based testing with MySQL-specific queries:

- Information_schema database exploration
- Column enumeration techniques
- Data extraction using GROUP_CONCAT and other MySQL functions

Example:

```
python main.py -u "http://example.com/page.php?id=1" --sql --sql-types=union
```

#### Time-based MySQL Injection

Specialized time-based testing using MySQL's timing functions:

- SLEEP() function testing
- BENCHMARK() function testing
- Advanced timing analysis algorithms

Example:

```
python main.py -u "http://example.com/page.php?id=1" --sql --sql-types=time
```

### XSS Options

```
--xss-types TYPES      Types of XSS to test (default: reflected,dom,stored)
--callback-url URL     Callback URL for blind XSS testing
```

### Request Options

```
-m, --method METHOD    HTTP method (GET or POST, default: GET)
-d, --data DATA        POST data (e.g. 'param1=value1&param2=value2')
-H, --headers HEADERS  Custom HTTP headers (e.g. 'Header1:value1,Header2:value2')
-c, --cookies COOKIES  HTTP cookies (e.g. 'cookie1=value1;cookie2=value2')
-A, --user-agent AGENT Custom User-Agent
-p, --proxy PROXY      Proxy URL (e.g. 'http://127.0.0.1:8080')
-t, --timeout SECONDS  Request timeout in seconds (default: 10)
--delay SECONDS        Delay between requests in seconds (default: 0)
```

### Output Options

```
-o, --output FILE      Save results to file (JSON format)
-v, --verbose          Verbose output
--no-color             Disable colored output
```

## Full Command Reference

```
python main.py [-h] (-u URL | -f FILE) [--sql] [--xss] [--crawl] [--all]
               [--depth DEPTH] [--same-domain] [--exclude EXCLUDE]
               [--include-forms] [--sql-types SQL_TYPES]
               [--xss-types XSS_TYPES] [--callback-url CALLBACK_URL]
               [-m {GET,POST}] [-d DATA] [-H HEADERS] [-c COOKIES]
               [-A USER_AGENT] [-p PROXY] [-t TIMEOUT] [--delay DELAY]
               [-o OUTPUT] [-v] [--no-color]
```

## Examples

### Crawl a Website and Test for SQL Injection

```
python main.py -u "http://testphp.vulnweb.com/" --crawl --sql --depth 2
```

### Test a Login Form for SQL Injection and XSS

```
python main.py -u "http://testphp.vulnweb.com/login.php" --sql --xss -m POST -d "uname=test&pass=test"
```

### Scan with Custom Headers and Cookies

```
python main.py -u "http://example.com/page.php?id=1" --all -H "Referer:http://example.com/,X-Forwarded-For:127.0.0.1" -c "session=abc123;logged_in=true"
```

### Test MySQL-Specific SQL Injection

```
python main.py -u "http://example.com/page.php?id=1" --sql --sql-types=error,union -v
```

## Project Structure

```
web-security-fuzzer/
├── main.py                # Main entry point
├── requirements.txt       # Python dependencies
├── modules/               # Modules directory
│   ├── common/            # Common utilities
│   │   ├── __init__.py
│   │   ├── request_handler.py
│   │   ├── url_parser.py
│   │   ├── post_data_handler.py
│   │   └── utils.py
│   ├── sql/               # SQL injection modules
│   │   ├── __init__.py
│   │   ├── sql_scanner.py
│   │   ├── payload_generator.py
│   │   ├── mysql_payloads.py # MySQL-specific payloads and patterns
│   │   └── response_analyzer.py
│   ├── xss/               # XSS modules
│   │   ├── __init__.py
│   │   ├── xss_scanner.py
│   │   └── payload_generator.py
│   └── crawler/           # Web crawler modules
│       ├── __init__.py
│       └── crawler.py
```

## Disclaimer

This tool is for educational purposes and authorized security testing only. Do not use it against websites without explicit permission. Unauthorized scanning of websites may be illegal in your jurisdiction.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contribution

Contributions are welcome! Please feel free to submit a Pull Request.
