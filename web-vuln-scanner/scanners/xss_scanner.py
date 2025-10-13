import requests

class XSSScanner:
    def __init__(self):
        self.payloads = [
            "<script>alert(1)</script>",
            "'> <svg/onload=alert(1)]"
        ]

    def scan(self, url):
        results = []
        for payload in self.payloads:
            # Tạo URL kiểm thử: chèn payload vào tham số 'q' (ví dụ: http://target.com?q=<payload>)
            test_url = f"{url}?q={payload}"
            try:
                # Gửi yêu cầu GET đến URL kiểm thử với thời gian chờ 5 giây
                resp = requests.get(test_url, timeout=5)

                # Kiểm tra phản hồi: Nếu chuỗi payload được tìm thấy trong nội dung phản hồi (resp.text)
                if payload in resp.text:
                    results.append({
                        "type": "XSS",
                        "payload": payload,
                        "url": test_url,
                        "risk": "HIGH"
                    })
            except Exception as e:
                # Bỏ qua nếu có lỗi xảy ra trong quá trình gửi request (ví dụ: timeout, lỗi kết nối)
                pass

        return results