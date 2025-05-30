# Link Sentinel

Link Sentinel is a comprehensive web application security analyzer that helps users determine if a website is safe to visit. It performs multiple layers of security analysis including link validation, DNS inspection, browser-based security checks, and server vulnerability scanning.

## Features

- **URL Validation and Analysis**
  - Domain age verification
  - SSL certificate validation
  - Suspicious TLD detection
  - Redirect chain analysis

- **DNS Analysis**
  - Complete DNS record inspection (A, AAAA, MX, NS, TXT)
  - WHOIS information retrieval
  - Reverse DNS lookup
  - Geographic location detection

- **Browser Security Analysis**
  - Headless browser inspection using pyppeteer
  - Security headers verification
  - Form submission target analysis
  - JavaScript execution monitoring
  - Resource loading verification

- **Server Intelligence**
  - Shodan integration for vulnerability scanning
  - Open ports detection
  - Server technology stack analysis
  - Historical security incidents check

- **Comprehensive Reporting**
  - Overall safety verdict
  - Detailed security analysis
  - Risk assessment scoring
  - Actionable recommendations

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Node.js (for pyppeteer)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Prashithshetty/Link-Sentinel.git
cd Link-Sentinel
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the root directory with the following content:
```
SHODAN_API_KEY=your_shodan_api_key_here
```

5. Install the GeoLite2 database:
- Download the GeoLite2 City database from MaxMind
- Place the `GeoLite2-City.mmdb` file in the project root directory

## Usage

1. Start the Flask application:
```bash
python backend/app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

3. Enter a URL in the input field and click "Analyze" to start the security analysis.

## API Endpoints

### Analyze URL
- **Endpoint**: `/api/analyze`
- **Method**: POST
- **Body**:
```json
{
    "url": "https://example.com"
}
```
- **Response**: Comprehensive security analysis report

## Security Considerations

- The application requires a Shodan API key for vulnerability scanning
- Some features may be blocked by website security measures
- Use responsibly and respect website terms of service
- Do not use for malicious purposes

## Contributing

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Shodan](https://www.shodan.io/) for server intelligence
- [pyppeteer](https://github.com/pyppeteer/pyppeteer) for headless browser automation
- [MaxMind](https://www.maxmind.com/) for GeoIP database

## Disclaimer

This tool is for educational and security research purposes only. Users are responsible for complying with applicable laws and regulations. The developers assume no liability for misuse or damage caused by this tool.
