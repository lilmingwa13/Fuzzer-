# SQLFuzzer - SQL Injection Fuzzing Tool

SQLFuzzer là một công cụ dùng để kiểm tra lỗ hổng SQL Injection, tập trung vào MySQL và các tham số GET.

## Tính năng

- Phân tích URL và các tham số tự động
- Tập trung vào fuzzing MySQL
- Hỗ trợ nhiều loại tấn công SQL Injection:
  - Error-based
  - Boolean-based
  - Time-based
  - Union-based
  - Authentication bypass
- Tùy chọn đầu vào linh hoạt
- Thiết kế theo hướng đối tượng với cấu trúc module rõ ràng

## Cài đặt

```bash
# Clone repository
git clone https://github.com/yourusername/sqlfuzzer.git
cd sqlfuzzer

# Cài đặt các thư viện phụ thuộc
pip install -r requirements.txt
```

## Sử dụng

```bash
python sqlfuzzer.py -u http://example.com/page.php?id=1 -v
```

### Các tùy chọn

```
-u, --url         URL đích (ví dụ: http://example.com/page.php?id=1)
-t, --threads     Số luồng đồng thời (mặc định: 1)
-to, --timeout    Thời gian timeout kết nối tính bằng giây (mặc định: 10)
-v, --verbose     Xuất kết quả chi tiết
-o, --output      Lưu kết quả vào file
-d, --delay       Độ trễ giữa các request tính bằng giây (mặc định: 0)
-a, --user-agent  User-Agent tùy chỉnh (mặc định: SQLFuzzer/1.0)
-c, --cookies     Cookies để sử dụng trong các request HTTP
-p, --proxy       Sử dụng proxy (định dạng: http://host:port)
```

### Ví dụ

Kiểm tra một ứng dụng web:

```bash
python sqlfuzzer.py -u http://testphp.vulnweb.com/listproducts.php?cat=1 -v
```

Sử dụng proxy và lưu kết quả:

```bash
python sqlfuzzer.py -u http://example.com/page.php?id=1 -p http://127.0.0.1:8080 -o results.txt
```

Thêm độ trễ để tránh phát hiện:

```bash
python sqlfuzzer.py -u http://example.com/page.php?id=1 -d 1.5
```

## Cấu trúc dự án

- `sqlfuzzer.py`: Module chính xử lý luồng thực thi
- `modules/url_parser.py`: Phân tích URL và các tham số
- `modules/payload_generator.py`: Tạo các payload SQL Injection
- `modules/request_handler.py`: Xử lý các HTTP request
- `modules/response_analyzer.py`: Phân tích phản hồi để phát hiện lỗ hổng

## Lưu ý

Công cụ này chỉ nên được sử dụng cho mục đích kiểm tra bảo mật với sự đồng ý của chủ sở hữu hệ thống. Việc sử dụng trái phép có thể vi phạm pháp luật.

## Giấy phép

MIT License
