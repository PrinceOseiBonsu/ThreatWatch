# threat_intel.py
# ThreatWatch - Threat Intelligence Engine

import requests
import os

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
IPINFO_API_KEY = os.environ.get("IPINFO_API_KEY", "")

def check_virustotal(query, query_type):
    """Check IP, domain or file hash against VirusTotal"""
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        if query_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
        elif query_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{query}"
        elif query_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{query}"
        else:
            return None

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            return None

        data = response.json()
        stats = data['data']['attributes'].get('last_analysis_stats', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total = malicious + suspicious + harmless + undetected

        # Get additional info
        attributes = data['data']['attributes']

        result = {
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'undetected': undetected,
            'total_engines': total,
            'verdict': 'MALICIOUS' if malicious >= 3 else 'SUSPICIOUS' if malicious >= 1 or suspicious >= 3 else 'CLEAN',
            'reputation': attributes.get('reputation', 0),
        }

        # Add type specific info
        if query_type == "ip":
            result['country'] = attributes.get('country', 'Unknown')
            result['asn'] = attributes.get('asn', 'Unknown')
            result['as_owner'] = attributes.get('as_owner', 'Unknown')
        elif query_type == "domain":
            result['registrar'] = attributes.get('registrar', 'Unknown')
            result['creation_date'] = attributes.get('creation_date', 'Unknown')
        elif query_type == "hash":
            result['file_name'] = attributes.get('meaningful_name', 'Unknown')
            result['file_type'] = attributes.get('type_description', 'Unknown')
            result['file_size'] = attributes.get('size', 0)

        return result

    except Exception as e:
        return {'error': str(e)}

def check_abuseipdb(ip):
    """Check IP against AbuseIPDB"""
    try:
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code != 200:
            return None

        data = response.json()['data']

        return {
            'abuse_score': data.get('abuseConfidenceScore', 0),
            'total_reports': data.get('totalReports', 0),
            'last_reported': data.get('lastReportedAt', 'Never'),
            'country': data.get('countryCode', 'Unknown'),
            'isp': data.get('isp', 'Unknown'),
            'domain': data.get('domain', 'Unknown'),
            'is_tor': data.get('isTor', False),
            'is_public': data.get('isPublic', False),
            'verdict': 'MALICIOUS' if data.get('abuseConfidenceScore', 0) >= 50 else
                      'SUSPICIOUS' if data.get('abuseConfidenceScore', 0) >= 20 else 'CLEAN'
        }

    except Exception as e:
        return {'error': str(e)}

def check_ipinfo(ip):
    """Get geolocation and network info for IP"""
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}",
            headers={"Authorization": f"Bearer {IPINFO_API_KEY}"},
            timeout=10
        )

        if response.status_code != 200:
            return None

        data = response.json()

        return {
            'ip': data.get('ip', ip),
            'city': data.get('city', 'Unknown'),
            'region': data.get('region', 'Unknown'),
            'country': data.get('country', 'Unknown'),
            'org': data.get('org', 'Unknown'),
            'timezone': data.get('timezone', 'Unknown'),
            'loc': data.get('loc', '0,0')
        }

    except Exception as e:
        return {'error': str(e)}

def detect_query_type(query):
    """Detect if query is IP, domain or hash"""
    import re

    # Check if IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, query):
        return 'ip'

    # Check if hash (MD5, SHA1, SHA256)
    hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
    if re.match(hash_pattern, query):
        return 'hash'

    # Default to domain
    return 'domain'

def calculate_threat_score(vt_result, abuse_result):
    """Calculate overall threat score 0-100"""
    score = 0

    if vt_result and 'error' not in vt_result:
        malicious = vt_result.get('malicious', 0)
        suspicious = vt_result.get('suspicious', 0)
        total = vt_result.get('total_engines', 1)

        if total > 0:
            score += (malicious / total) * 60
            score += (suspicious / total) * 20

    if abuse_result and 'error' not in abuse_result:
        score += abuse_result.get('abuse_score', 0) * 0.2

    return min(100, round(score))

def get_threat_level(score):
    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    elif score >= 5:
        return "LOW"
    else:
        return "CLEAN"

def run_threat_scan(query):
    """Run full threat intelligence scan"""
    query = query.strip()
    query_type = detect_query_type(query)

    results = {
        'query': query,
        'query_type': query_type,
        'virustotal': None,
        'abuseipdb': None,
        'ipinfo': None,
        'threat_score': 0,
        'threat_level': 'CLEAN'
    }

    # Run VirusTotal check
    results['virustotal'] = check_virustotal(query, query_type)

    # Run IP specific checks
    if query_type == 'ip':
        results['abuseipdb'] = check_abuseipdb(query)
        results['ipinfo'] = check_ipinfo(query)

    # Calculate threat score
    results['threat_score'] = calculate_threat_score(
        results['virustotal'],
        results['abuseipdb']
    )
    results['threat_level'] = get_threat_level(results['threat_score'])

    return results

if __name__ == "__main__":
    test = run_threat_scan("185.220.101.45")
    print(f"Query: {test['query']}")
    print(f"Type: {test['query_type']}")
    print(f"Threat Score: {test['threat_score']}")
    print(f"Threat Level: {test['threat_level']}")
    if test['virustotal']:
        print(f"VT Malicious: {test['virustotal'].get('malicious', 0)}")
        print(f"VT Suspicious: {test['virustotal'].get('suspicious', 0)}")
    if test['abuseipdb']:
        print(f"Abuse Score: {test['abuseipdb'].get('abuse_score', 0)}")
        print(f"Total Reports: {test['abuseipdb'].get('total_reports', 0)}")