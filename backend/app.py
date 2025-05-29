from flask import Flask, request, jsonify, render_template
from utils.link_analyzer import LinkAnalyzer
from utils.dns_inspector import DNSInspector
from utils.browser_checker import BrowserChecker
from utils.shodan_scanner import ShodanScanner
from utils.report_generator import ReportGenerator
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__, 
    template_folder='../frontend/templates',
    static_folder='../frontend/static'
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
async def analyze_url():
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Initialize analyzers
        link_analyzer = LinkAnalyzer()
        dns_inspector = DNSInspector()
        browser_checker = BrowserChecker()
        shodan_scanner = ShodanScanner(api_key=os.getenv('SHODAN_API_KEY'))
        report_generator = ReportGenerator()

        # Perform analysis
        link_analysis = await link_analyzer.analyze(url)
        dns_analysis = await dns_inspector.inspect(url)
        browser_analysis = await browser_checker.check(url)
        shodan_analysis = await shodan_scanner.scan(url)

        # Generate final report
        report = report_generator.generate(
            url=url,
            link_analysis=link_analysis,
            dns_analysis=dns_analysis,
            browser_analysis=browser_analysis,
            shodan_analysis=shodan_analysis
        )

        return jsonify(report)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
