import dns.resolver
import socket
import geoip2.database
import whois
from urllib.parse import urlparse
import asyncio
from concurrent.futures import ThreadPoolExecutor

class DNSInspector:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.executor = ThreadPoolExecutor(max_workers=4)

    async def inspect(self, url):
        """
        Perform comprehensive DNS analysis of the given URL
        """
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if not domain:
                return {"error": "Invalid URL format"}

            # Gather all DNS information asynchronously
            tasks = [
                self._get_a_records(domain),
                self._get_aaaa_records(domain),
                self._get_mx_records(domain),
                self._get_ns_records(domain),
                self._get_txt_records(domain),
                self._get_whois_info(domain),
                self._get_reverse_dns(domain),
                self._get_geo_location(domain)
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            return {
                "domain": domain,
                "a_records": results[0],
                "aaaa_records": results[1],
                "mx_records": results[2],
                "ns_records": results[3],
                "txt_records": results[4],
                "whois_info": results[5],
                "reverse_dns": results[6],
                "geo_location": results[7],
                "analysis": self._analyze_dns_results(results)
            }

        except Exception as e:
            return {"error": f"DNS inspection failed: {str(e)}"}

    async def _get_a_records(self, domain):
        """Get IPv4 addresses"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                self.executor,
                lambda: [str(r) for r in self.resolver.resolve(domain, 'A')]
            )
            return records
        except Exception as e:
            return [f"Error retrieving A records: {str(e)}"]

    async def _get_aaaa_records(self, domain):
        """Get IPv6 addresses"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                self.executor,
                lambda: [str(r) for r in self.resolver.resolve(domain, 'AAAA')]
            )
            return records
        except Exception:
            return []  # IPv6 might not be available

    async def _get_mx_records(self, domain):
        """Get mail server records"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                self.executor,
                lambda: [str(r.exchange) for r in self.resolver.resolve(domain, 'MX')]
            )
            return records
        except Exception:
            return []

    async def _get_ns_records(self, domain):
        """Get nameserver records"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                self.executor,
                lambda: [str(r) for r in self.resolver.resolve(domain, 'NS')]
            )
            return records
        except Exception:
            return []

    async def _get_txt_records(self, domain):
        """Get TXT records"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                self.executor,
                lambda: [str(r) for r in self.resolver.resolve(domain, 'TXT')]
            )
            return records
        except Exception:
            return []

    async def _get_whois_info(self, domain):
        """Get WHOIS information"""
        try:
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(self.executor, whois.whois, domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails
            }
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {str(e)}"}

    async def _get_reverse_dns(self, domain):
        """Get reverse DNS records"""
        try:
            ip = socket.gethostbyname(domain)
            loop = asyncio.get_event_loop()
            hostname = await loop.run_in_executor(
                self.executor,
                socket.gethostbyaddr,
                ip
            )
            return {
                "ip": ip,
                "hostname": hostname[0],
                "aliases": hostname[1]
            }
        except Exception as e:
            return {"error": f"Reverse DNS lookup failed: {str(e)}"}

    async def _get_geo_location(self, domain):
        """Get geolocation information for the domain"""
        try:
            ip = socket.gethostbyname(domain)
            # Note: You need to download the GeoLite2 database and specify the correct path
            reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            response = reader.city(ip)
            
            return {
                "country": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone
            }
        except Exception as e:
            return {"error": f"Geolocation lookup failed: {str(e)}"}

    def _analyze_dns_results(self, results):
        """Analyze DNS results for potential issues"""
        analysis = {
            "warnings": [],
            "recommendations": []
        }

        # Check for missing records
        if not results[0]:  # A records
            analysis["warnings"].append("No IPv4 addresses found")
        
        if not results[2]:  # MX records
            analysis["warnings"].append("No mail servers configured")
            analysis["recommendations"].append("Configure MX records if email is needed")

        if not results[3]:  # NS records
            analysis["warnings"].append("No nameservers found")
            analysis["recommendations"].append("Configure proper nameservers")

        # Check for SPF and DMARC records
        txt_records = results[4]
        has_spf = any("v=spf1" in str(record).lower() for record in txt_records)
        has_dmarc = any("v=dmarc1" in str(record).lower() for record in txt_records)

        if not has_spf:
            analysis["warnings"].append("No SPF record found")
            analysis["recommendations"].append("Add SPF record to prevent email spoofing")

        if not has_dmarc:
            analysis["warnings"].append("No DMARC record found")
            analysis["recommendations"].append("Add DMARC record to enhance email security")

        return analysis
