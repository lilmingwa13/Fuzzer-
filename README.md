# SQLFuzzer - SQL Injection Fuzzing Tool

SQLFuzzer là công cụ fuzzing SQL injection mạnh mẽ hỗ trợ cả phương thức GET và POST. Công cụ được thiết kế để phát hiện các lỗ hổng SQL injection trong các ứng dụng web.

## Tính năng

- Hỗ trợ cả phương thức GET và POST
- Phát hiện nhiều loại SQL injection:
  - Error-based injection
  - Boolean-based injection
  - Time-based injection
- Hỗ trợ nhiều định dạng dữ liệu POST:
  - application/x-www-form-urlencoded
  - application/json
  - multipart/form-data (hỗ trợ cơ bản)
- Tùy chỉnh User-Agent, cookies, headers
- Hỗ trợ delay giữa các request
- Tùy chọn lưu báo cáo dưới dạng JSON
- Hỗ trợ proxy

## Cài đặt

```bash
# Clone repository
git clone https://github.com/your-username/sqlfuzzer.git
cd sqlfuzzer

# Cài đặt dependencies
pip install -r requirements.txt
```

## Cách sử dụng

### Cấu trúc câu lệnh cơ bản

```bash
python sqlfuzzer.py -u <URL> [OPTIONS]
```

### Kiểm tra SQL injection với phương thức GET

```bash
python sqlfuzzer.py -u "http://example.com/page.php?id=1" -v
```

### Kiểm tra SQL injection với phương thức POST

```bash
# POST với form data
python sqlfuzzer.py -u "http://example.com/login.php" -m POST -d "username=admin&password=test"

# POST với JSON data
python sqlfuzzer.py -u "http://example.com/api/user" -m POST -d '{"username":"admin","password":"test"}' --content-type "application/json"

# POST với dữ liệu từ file
python sqlfuzzer.py -u "http://example.com/api/user" -m POST --data-file post_data.txt
```

### Tùy chọn đầu ra

```bash
# Chế độ verbose (chi tiết)
python sqlfuzzer.py -u "http://example.com/page.php?id=1" -v

# Lưu kết quả vào file
python sqlfuzzer.py -u "http://example.com/page.php?id=1" -o report.json

# Không sử dụng màu sắc trong output
python sqlfuzzer.py -u "http://example.com/page.php?id=1" --no-color
```

### Tùy chọn request

```bash
# Thiết lập User-Agent
python sqlfuzzer.py -u "http://example.com/page.php?id=1" -a "Mozilla/5.0"

# Thiết lập cookie
python sqlfuzzer.py -u "http://example.com/page.php?id=1" -c "session=abc123"

# Thiết lập timeout
python sqlfuzzer.py -u "http://example.com/page.php?id=1" -t 15

# Thêm delay giữa các request
python sqlfuzzer.py -u "http://example.com/page.php?id=1" --delay 1.5

# Sử dụng proxy
python sqlfuzzer.py -u "http://example.com/page.php?id=1" -p "http://127.0.0.1:8080"

# Thêm custom headers
python sqlfuzzer.py -u "http://example.com/page.php?id=1" -H "X-Forwarded-For: 127.0.0.1,Accept: application/json"
```

### Tùy chọn fuzzing

```bash
# Dừng sau khi tìm thấy lỗ hổng đầu tiên
python sqlfuzzer.py -u "http://example.com/page.php?id=1" --stop-on-first

# Giới hạn số lượng tests
python sqlfuzzer.py -u "http://example.com/page.php?id=1" --max-tests 100
```

## Tham số đầy đủ

```
Tham số Target:
  -u URL, --url URL     Target URL (e.g., http://example.com/page.php?id=1)
  -m METHOD, --method METHOD
                        HTTP method (GET or POST, default: GET)
  -d DATA, --data DATA  POST data (e.g., 'username=admin&password=test')
  --data-file DATA_FILE
                        File containing POST data
  -H HEADERS, --headers HEADERS
                        Custom HTTP headers (comma-separated, e.g. 'X-Forwarded-For: 127.0.0.1,Accept: application/json')
  -c COOKIES, --cookies COOKIES
                        Cookies to include with HTTP requests
  --content-type CONTENT_TYPE
                        Content-Type header for POST requests (e.g., application/json, application/x-www-form-urlencoded)

Tham số Request:
  -a USER_AGENT, --user-agent USER_AGENT
                        Custom User-Agent (default: SQLFuzzer/2.0)
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 10)
  --delay DELAY         Delay between requests in seconds (default: 0)
  -p PROXY, --proxy PROXY
                        Proxy to use (e.g., http://127.0.0.1:8080)

Tham số Output:
  -v, --verbose         Verbose output
  --no-color            Disable colored output
  -o OUTPUT, --output OUTPUT
                        Save results to output file (JSON format)

Tham số Fuzzing:
  --max-tests MAX_TESTS
                        Maximum number of tests to run (0 for unlimited)
  --stop-on-first       Stop testing after finding first vulnerability
```

## Ví dụ output

```
 ____   ___  _     _____
/ ___| / _ \| |   |  ___|   _ _______  ___ _ __
\___ \| | | | |   | |_ | | | |_  / _ \/ _ \ '__|
 ___) | |_| | |___|  _|| |_| |/ /  __/  __/ |
|____/ \__\_\_____|_|   \__,_/___\___|\___|_|

        SQL Injection Fuzzing Tool

Version: 2.0.0
Started at: 2023-08-29 15:30:21

[*] Starting SQL injection fuzzing on: http://example.com/page.php?id=1
[*] Method: GET
[*] Found 1 parameter(s) to test with GET
[*] Loaded 49 SQL injection payloads

[*] Testing parameter: id

[*] Testing error-based injections for parameter 'id'
[*] Trying payload: '

[+] Error-based SQL injection found in parameter 'id'
    Payload: '
    URL: http://example.com/page.php?id='
    Method: GET
    Details: MySQL error detected: You have an error in your SQL syntax

[+] Found 1 potential SQL injection vulnerabilities
[+] - error-based: 1
[+] Stopped fuzzing after finding error-based vulnerability
[+] Report saved to: report.json
```

## Giấy phép

Công cụ này được phát hành dưới giấy phép MIT.

## Tuyên bố từ chối trách nhiệm

Công cụ này chỉ được sử dụng cho mục đích kiểm tra bảo mật hợp pháp. Người dùng chịu hoàn toàn trách nhiệm về cách sử dụng công cụ này. Tác giả không chịu trách nhiệm về bất kỳ thiệt hại nào gây ra bởi việc sử dụng sai mục đích của công cụ.
