import unittest
from report.report_generator import ReportGenerator

class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = ReportGenerator()

    def test_generate_report_with_list(self):
        findings_list = [
            [{'param': 'input', 'desc': 'XSS found', 'risk': 'High'}],
            [{'param': 'id', 'desc': 'SQL Injection', 'risk': 'Critical'}]
        ]
        
        report = self.generator.generate(findings_list)
        
        # Khẳng định 1: Tổng số lỗ hổng được ghi nhận phải là 2.
        self.assertEqual(len(report['vulnerabilities']), 2) 
        
        # Khẳng định 2: Đảm bảo một trong các lỗ hổng có mô tả 'XSS found'.
        self.assertTrue(any(v['desc'] == 'XSS found' 
                            for v in report['vulnerabilities']))

    def test_generate_report_with_dict(self):
        findings_dict = {'param': 'url', 'desc': 'SSRF found', 'risk': 'High'}
        
        # Giả định: Phương thức 'generate' có thể xử lý danh sách chứa một dict đơn lẻ.
        report = self.generator.generate([findings_dict]) 
        
        # Khẳng định 1: Tổng số lỗ hổng được ghi nhận phải là 1.
        self.assertEqual(len(report['vulnerabilities']), 1)
        
        # Khẳng định 2: Tham số của lỗ hổng đầu tiên phải là 'url'.
        self.assertEqual(report['vulnerabilities'][0]['param'], 'url')

if __name__ == '__main__':
    unittest.main()