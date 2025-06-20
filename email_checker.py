#!/usr/bin/env python3

import re, dns.resolver, smtplib, socket
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

@dataclass
class EmailStatus:
    email: str
    is_deliverable: bool

class ColdEmailValidator:
    def __init__(self):
        self.sender_domain = "example.com"
        self.sender_email = f"test@{self.sender_domain}"
        self.timeout = 10
        self.mx_cache = {}
        self.catch_all_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'icloud.com', 'aol.com', 'live.com', 'msn.com'
        }

    def validate_syntax(self, email: str) -> bool:
        pattern = r'^[a-zA-Z0-9][\w.+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def check_mx_records(self, domain: str) -> Tuple[bool, List[str]]:
        if domain in self.mx_cache:
            return self.mx_cache[domain]
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_hosts = [str(mx.exchange).rstrip('.') for mx in sorted(mx_records, key=lambda x: x.preference)]
            result = (True, mx_hosts)
        except:
            result = (False, [])
        self.mx_cache[domain] = result
        return result

    def smtp_verify_mailbox(self, email: str, mx_hosts: List[str]) -> bool:
        domain = email.split('@')[1]
        if domain in self.catch_all_domains:
            return True
        for mx in mx_hosts[:3]:
            for port in [25, 587]:
                try:
                    with smtplib.SMTP(timeout=self.timeout) as server:
                        server.connect(mx, port)
                        server.helo(self.sender_domain)
                        server.mail(self.sender_email)
                        code, _ = server.rcpt(email)
                        return code in [250, 251]
                except:
                    continue
        return False

    def validate_email(self, email: str) -> EmailStatus:
        email = email.strip().lower()
        if not self.validate_syntax(email):
            return EmailStatus(email=email, is_deliverable=False)
        domain = email.split('@')[1]
        mx_valid, mx_hosts = self.check_mx_records(domain)
        if not mx_valid:
            return EmailStatus(email=email, is_deliverable=False)
        deliverable = self.smtp_verify_mailbox(email, mx_hosts)
        return EmailStatus(email=email, is_deliverable=deliverable)

    def validate_bulk(self, emails: List[str], max_workers: int = 5) -> List[EmailStatus]:
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.validate_email, email) for email in emails if email.strip()]
            for future in futures:
                results.append(future.result())
        return results

if __name__ == "__main__":
    validator = ColdEmailValidator()
    print("Enter emails (one per line). Empty line to finish:")
    emails = []
    while True:
        line = input().strip()
        if not line:
            break
        emails.append(line)

    print("\n🕵️ Validating emails...\n")
    results = validator.validate_bulk(emails)

    for res in results:
        status = "✅ Deliverable" if res.is_deliverable else "❌ Undeliverable"
        print(f"{res.email} --> {status}")
