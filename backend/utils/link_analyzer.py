import validators
import whois
import ssl
import socket
import datetime
from urllib.parse import urlparse
import requests

class LinkAnalyzer:
    def __init__(self):
        self.suspicious_tlds = ['.xyz', '.top', '.work', '.loan', '.click']

    async def analyze(self, url):
        """
        Analyze URL for legitimacy and security concerns
        """
        result = {
            'is_valid_url': False,
            'domain_age': None,
            'ssl_valid': False,
            'suspicious_tld': False,
            'domain_info': {},
            'risk_score': 0,
            'warnings': []
        }

        try:
            # Basic URL validation
            if not validators.url(url):
                result['warnings'].append("Invalid URL format")
                return result

            result['is_valid_url'] = True
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            # Check domain age
            try:
                w = whois.whois(domain)
                if w.creation_date:
                    creation_date = w.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    domain_age = (datetime.datetime.now() - creation_date).days
                    result['domain_age'] = domain_age
                    result['domain_info'] = {
                        'registrar': w.registrar,
                        'creation_date': str(w.creation_date),
                        'expiration_date': str(w.expiration_date),
                        'registered_to': w.name
                    }
                    
                    # Check if domain is too new (less than 30 days)
                    if domain_age < 30:
                        result['warnings'].append("Domain is very new")
                        result['risk_score'] += 20
            except Exception as e:
                result['warnings'].append(f"Could not verify domain age: {str(e)}")
                result['risk_score'] += 10

            # Check SSL certificate
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        result['ssl_valid'] = True
                        result['ssl_info'] = {
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'expires': cert['notAfter']
                        }
            except Exception as e:
                result['warnings'].append("Invalid or missing SSL certificate")
                result['risk_score'] += 30

            # Check TLD
            tld = '.' + domain.split('.')[-1].lower()
            if tld in self.suspicious_tlds:
                result['suspicious_tld'] = True
                result['warnings'].append(f"Suspicious TLD: {tld}")
                result['risk_score'] += 15

            # Try to access the website
            try:
                response = requests.head(url, allow_redirects=True, timeout=5)
                if response.status_code != 200:
                    result['warnings'].append(f"Website returned status code: {response.status_code}")
                    result['risk_score'] += 10
                
                # Check for too many redirects
                if len(response.history) > 2:
                    result['warnings'].append(f"Multiple redirects detected: {len(response.history)}")
                    result['risk_score'] += 15
            except requests.exceptions.RequestException as e:
                result['warnings'].append(f"Could not access website: {str(e)}")
                result['risk_score'] += 25

            # Calculate final risk assessment
            result['risk_level'] = self._calculate_risk_level(result['risk_score'])

        except Exception as e:
            result['warnings'].append(f"Analysis error: {str(e)}")
            result['risk_score'] = 100
            result['risk_level'] = "High"

        return result

    def _calculate_risk_level(self, risk_score):
        if risk_score < 20:
            return "Low"
        elif risk_score < 50:
            return "Medium"
        else:
            return "High"
