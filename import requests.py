import requests
import re

class WebVulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()

    def check_sql_injection(self):
        print("Checking for SQL Injection...")
        payload = "' OR '1'='1"
        test_url = f"{self.url}?input={payload}"
        response = self.session.get(test_url)
        if "syntax" in response.text or "error" in response.text.lower():
            print("[!] Possible SQL Injection vulnerability detected!")
        else:
            print("[+] No SQL Injection vulnerability found.")

    def check_xss(self):
        print("Checking for XSS...")
        payload = "<script>alert('XSS')</script>"
        response = self.session.get(self.url, params={"input": payload})
        if payload in response.text:
            print("[!] Possible XSS vulnerability detected!")
        else:
            print("[+] No XSS vulnerability found.")

    def scan(self):
        print(f"Starting scan for {self.url}")
        self.check_sql_injection()
        self.check_xss()

if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    scanner = WebVulnerabilityScanner(target_url)
    scanner.scan()
