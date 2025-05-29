import pyppeteer
import asyncio
import os
from urllib.parse import urlparse
import json

class BrowserChecker:
    def __init__(self):
        self.screenshot_dir = "screenshots"
        os.makedirs(self.screenshot_dir, exist_ok=True)

    async def check(self, url):
        """
        Perform headless browser checks on the URL
        """
        result = {
            'redirects': [],
            'final_url': url,
            'security_headers': {},
            'forms_found': [],
            'external_resources': [],
            'javascript_errors': [],
            'screenshot_path': None,
            'warnings': [],
            'risk_score': 0
        }

        try:
            browser = await pyppeteer.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            page = await browser.newPage()

            # Collect all console messages
            page.on('console', lambda msg: result['javascript_errors'].append(msg.text))

            # Collect all requests
            external_resources = set()
            base_domain = urlparse(url).netloc
            
            async def handle_request(request):
                req_url = request.url
                req_domain = urlparse(req_url).netloc
                if req_domain and req_domain != base_domain:
                    external_resources.add(f"{req_domain} ({request.resourceType})")
            
            page.on('request', handle_request)

            # Enable request interception for security headers
            await page.setRequestInterception(True)
            
            @page.on('request')
            async def intercept_request(request):
                if request.resourceType == 'document':
                    result['redirects'].append(request.url)
                await request.continue_()

            # Set viewport and user agent
            await page.setViewport({'width': 1920, 'height': 1080})
            await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')

            # Navigate to URL with timeout
            response = await page.goto(url, {
                'waitUntil': 'networkidle0',
                'timeout': 30000
            })

            # Get final URL after potential redirects
            result['final_url'] = page.url

            # Check security headers
            security_headers = response.headers
            important_headers = [
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Referrer-Policy'
            ]

            for header in important_headers:
                if header.lower() in security_headers:
                    result['security_headers'][header] = security_headers[header.lower()]
                else:
                    result['warnings'].append(f"Missing security header: {header}")
                    result['risk_score'] += 5

            # Analyze forms
            forms = await page.evaluate('''() => {
                const forms = document.forms;
                return Array.from(forms).map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.elements).map(el => ({
                        type: el.type,
                        name: el.name,
                        id: el.id
                    }))
                }));
            }''')

            result['forms_found'] = forms
            
            # Check for suspicious form actions
            for form in forms:
                if form['action'] and urlparse(form['action']).netloc != base_domain:
                    result['warnings'].append(f"Form submitting to external domain: {form['action']}")
                    result['risk_score'] += 15

            # Take screenshot
            screenshot_path = os.path.join(self.screenshot_dir, f"{base_domain}.png")
            await page.screenshot({'path': screenshot_path, 'fullPage': True})
            result['screenshot_path'] = screenshot_path

            # Add external resources to result
            result['external_resources'] = list(external_resources)

            # Check for excessive external resources
            if len(external_resources) > 20:
                result['warnings'].append(f"High number of external resources: {len(external_resources)}")
                result['risk_score'] += 10

            # Check for suspicious JavaScript behavior
            js_errors = len(result['javascript_errors'])
            if js_errors > 0:
                result['warnings'].append(f"JavaScript errors detected: {js_errors}")
                result['risk_score'] += js_errors * 2

            # Calculate risk level
            result['risk_level'] = self._calculate_risk_level(result['risk_score'])

            await browser.close()

        except pyppeteer.errors.TimeoutError:
            result['warnings'].append("Page load timeout - site might be slow or unresponsive")
            result['risk_score'] += 30
            result['risk_level'] = "High"

        except Exception as e:
            result['warnings'].append(f"Browser check error: {str(e)}")
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
