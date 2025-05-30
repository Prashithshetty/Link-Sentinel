# Link Sentinel

Link Sentinel is a comprehensive web application security analyzer that helps users determine if a website is safe to visit. It performs multiple layers of security analysis including link validation, DNS inspection, browser-based security checks, and server vulnerability scanning.

## Features

- **URL Validation and Analysis**
  - Domain age verification through WHOIS
  - SSL certificate validation and chain analysis
  - Suspicious TLD detection with risk categorization
  - Redirect chain tracking and analysis
  - Security header verification

- **DNS Analysis**
  - Complete DNS record inspection (A, AAAA, MX, NS, TXT)
  - WHOIS information retrieval and validation
  - DNSSEC configuration verification
  - Geographic location detection
  - DNS security scoring

- **Browser Security Analysis**
  - Headless browser inspection
  - Security headers verification
  - Form submission target analysis
  - JavaScript execution monitoring
  - Resource loading verification

- **Server Intelligence**
  - Shodan integration for vulnerability scanning
  - Port and service identification
  - Technology stack analysis
  - SSL/TLS configuration assessment
  - Service misconfiguration detection
  - Historical security incident tracking

- **Security Assessment**
  - Overall safety verdict with confidence level
  - Component-wise risk scoring
  - Prioritized security recommendations
  - Critical issue identification
  - Detailed technical analysis
  - Custom risk scoring algorithm

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Node.js (for frontend dependencies)
- Shodan API key
- GeoLite2 database

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

## API Documentation

### Analyze URL
- **Endpoint**: `/api/analyze`
- **Method**: POST
- **Body**:
```json
{
    "url": "https://example.com"
}
```
- **Response**: Comprehensive security analysis report including:
  - Overall safety verdict
  - Component-wise risk scores
  - Security issues by severity
  - Prioritized recommendations
  - Technical details

## Security Considerations

- The application requires a Shodan API key for vulnerability scanning
- Some features may be blocked by website security measures
- Use responsibly and respect website terms of service
- Regular updates recommended for security databases
- API key rotation and secure storage required

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request with documentation

## Technical Documentation

For detailed technical information about the system architecture, analysis process, and implementation details, please refer to [EXPLAIN.md](EXPLAIN.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Shodan](https://www.shodan.io/) for server intelligence
- [MaxMind](https://www.maxmind.com/) for GeoIP database
- Open source security tools and libraries

## Disclaimer

This tool is for educational and security research purposes only. Users are responsible for complying with applicable laws and regulations. The developers assume no liability for misuse or damage caused by this tool.
