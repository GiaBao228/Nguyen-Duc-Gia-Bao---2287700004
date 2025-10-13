import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request
from scanners.xss_scanner import XSSScanner
from scanners.sql_injection_tester import SQLInjectionTester
from scanners.csrf_detector import CSRFDetector # Đã scan ở ảnh bf1267.png
from scanners.ssrf_tester import SSRFTester
from report.report_generator import ReportGenerator

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Lấy dữ liệu từ form
        url = request.form.get("url")
        options = request.form.getlist("scanner")
        results = []

        # Logic quét dựa trên các tùy chọn
        if "xss" in options:
            xss = XSSScanner()
            results.append(xss.scan(url))

        if "sql" in options:
            sql = SQLInjectionTester()
            results.append(sql.scan(url))

        if "csrf" in options:
            csrf = CSRFDetector()
            # **Lưu ý:** Giả định nội dung HTML cho CSRF là một form rỗng
            html = "<html><form></form></html>" 
            results.append([csrf.scan(html)]) # Kết quả CSRF được bọc trong danh sách

        if "ssrf" in options:
            ssrf = SSRFTester()
            results.append(ssrf.scan(url))

        # Tạo báo cáo và hiển thị
        report = ReportGenerator().generate(results)
        return render_template("result.html", report=report)

    # Hiển thị trang chính khi là phương thức GET
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)