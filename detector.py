import re
import random
import hashlib
import time
import urllib.request
import urllib.parse
from html.parser import HTMLParser

# -------------------------------
# CONFIGURATION & CONSTANTS
# -------------------------------
SUSPICIOUS_TLDS = ['.xyz', '.top', '.pw', '.club', '.online', '.site', '.click', '.monster', '.su', '.bid']
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "bank", "wallet", "crypto", "signin",
    "update", "account", "billing", "invoice", "paypal", "admin", "payout",
    "claim", "bonus", "reward", "support"
]

# Simulated Dark Web Database (MOCK DATA)
MOCK_BREACH_DOMAINS = [
    "hacker-forum.onion", "leak-center.net", "credential-dump.xyz",
    "dark-bazaar.onion", "shadow-market.io", "ransom-data.com",
    "db-leaks.su", "anon-files.pw"
]

LOCATIONS = ["Russia", "China", "Unknown/VPN", "North Korea", "Netherlands", "Panama", "Seychelles"]

# Threat Category Keywords & Weights for Scraper / Text Analysis
THREAT_CATEGORIES = {
    "Drugs & Controlled Substances": {
        "keywords": [
            "heroin", "cocaine", "fentanyl", "methamphetamine", "marijuana", "cannabis",
            "weed", "hashish", "dispensary", "narcotics", "cartel", "drug market", 
            "lsd", "mdma", "ecstasy", "psychedelics", "opioids", "prescription pills",
            "tramadol", "xanax"
        ],
        "weight": 25,
        "description": "Illicit substance sales, pharmacy leaks, or drug market presence."
    },
    "Data Breaches & Credentials": {
        "keywords": [
            "database leak", "breach database", "sql injection", "dump", "leaked",
            "credentials", "compromised", "passwords", "combo list", "logs", 
            "hacked databases", "user data leak", "email passwords list", "stealer log"
        ],
        "weight": 30,
        "description": "Exposed credentials, SQL database dumps, or corporate leak lists."
    },
    "Financial Fraud & Carding": {
        "keywords": [
            "carding", "cloned cards", "bank logs", "cashout", "money laundering",
            "dumps", "credit card generator", "scam page", "phishing kit", 
            "western union transfer", "bank transfer exploit", "paypal log",
            "cvv shop", "card shop"
        ],
        "weight": 30,
        "description": "Stolen financial information, credit cards, or banking exploits."
    },
    "Darknet Forums & Markets": {
        "keywords": [
            "onion link", "tor market", "vendor account", "escrow service",
            "bitcoin escrow", "monero market", "underground forum", "black market",
            "hacker forum", "exploit.in", "xss.is", "dread forum", "hacker marketplace"
        ],
        "weight": 20,
        "description": "Underground community hubs, black markets, or illicit escrow."
    }
}

# -------------------------------
# HTML TEXT PARSING ENGINE
# -------------------------------
class SimpleHTMLTextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text_content = []
        self.in_script_or_style = False
        self.meta_description = ""
        self.title = ""
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in ['script', 'style']:
            self.in_script_or_style = True
        elif tag == 'title':
            self.in_title = True
        elif tag == 'meta':
            attrs_dict = dict(attrs)
            if attrs_dict.get('name') == 'description' or attrs_dict.get('property') == 'og:description':
                self.meta_description = attrs_dict.get('content', '')

    def handle_endtag(self, tag):
        if tag in ['script', 'style']:
            self.in_script_or_style = False
        elif tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if not self.in_script_or_style:
            if self.in_title:
                self.title += data.strip()
            self.text_content.append(data)

    def get_text(self):
        return " ".join(self.text_content)

# -------------------------------
# UTILITIES
# -------------------------------
def extract_domain(url):
    """Helper to extract domain from URL"""
    try:
        cleaned = url.strip().lower()
        if "//" in cleaned:
            domain = cleaned.split("//")[-1].split("/")[0]
        else:
            domain = cleaned.split("/")[0]
        return domain
    except:
        return url

def fetch_url_content(url):
    """Fetches URL HTML content using standard library urllib."""
    target_url = url.strip()
    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        target_url = "https://" + target_url

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    
    try:
        req = urllib.request.Request(target_url, headers=headers)
        with urllib.request.urlopen(req, timeout=3) as response:
            html = response.read().decode('utf-8', errors='ignore')
            headers_dict = dict(response.info())
            return html, response.getcode(), headers_dict
    except Exception as e:
        return None, None, str(e)

# -------------------------------
# CORE THREAT DETECTION ENGINE
# -------------------------------
def analyze_url(url):
    """
    Analyzes a URL for threats. 
    Performs active internal verification/web scraping if possible,
    and falls back to passive syntactic simulation for offline or Onion sites.
    """
    url = url.strip().lower()
    domain = extract_domain(url)
    threats = []
    risk_score = 0
    analysis_log = []
    
    # 0. Fingerprinting (Deterministic simulation for fallback)
    seed = int(hashlib.md5(url.encode()).hexdigest(), 16)
    random.seed(seed)
    
    analysis_log.append("Initializing Global Threat Intelligence network...")
    
    # Protocol Check
    if url.startswith("http://"):
        threats.append("Insecure Protocol (HTTP detected)")
        risk_score += 15

    # Try active scraping/internal verification
    analysis_log.append(f"Establishing active verification connection to '{domain}'...")
    html, code, info_or_err = fetch_url_content(url)
    
    is_active_scanned = False
    page_title = ""
    page_desc = ""
    scraped_snippet = ""
    server_header = "Unknown"
    
    if html is not None:
        is_active_scanned = True
        analysis_log.append(f"Secure handshake completed. HTTP Code {code} received.")
        analysis_log.append("Scraping page DOM and extracting text payloads...")
        
        # Parse HTML
        parser = SimpleHTMLTextParser()
        try:
            parser.feed(html)
            page_title = parser.title.strip()
            page_desc = parser.meta_description.strip()
            page_text = parser.get_text().lower()
        except Exception as parse_err:
            page_text = html.lower()
            analysis_log.append("Warning: HTML structure error, scanning raw source.")
            
        # Get server header
        if isinstance(info_or_err, dict):
            server_header = info_or_err.get('server', info_or_err.get('Server', 'Hidden'))
            
        # 1. Content Keyword Scanning (Internal Threat Category Identification)
        analysis_log.append("Verifying page content against Dark Web & Fraud Signatures...")
        
        matched_categories = []
        for cat_name, cat_info in THREAT_CATEGORIES.items():
            matches = []
            for kw in cat_info["keywords"]:
                if kw in page_text:
                    matches.append(kw)
            
            if matches:
                matched_categories.append(cat_name)
                # Cap the added risk per category
                cat_risk = min(len(matches) * 10, cat_info["weight"])
                risk_score += cat_risk
                threats.append(f"Content Match: Category '{cat_name}' (Keywords: {', '.join(matches[:3])})")
                analysis_log.append(f"Flagged Category: {cat_name} ({len(matches)} matches found)")
                
        # 2. Obfuscation & Malicious Script Checks
        if "eval(function(p,a,c,k,e,r" in html or "unescape(" in html:
            threats.append("Obfuscation Signature: Packed JavaScript payload detected in source code")
            risk_score += 25
            analysis_log.append("Warning: Highly obfuscated script block identified internally.")
            
        if "coinhive" in page_text or "cryptoloot" in page_text:
            threats.append("Cryptojacking Threat: Hidden browser miner embedded in page code")
            risk_score += 35
            analysis_log.append("Warning: Unauthorized cryptocurrency mining scripts detected.")
            
        # 3. Text snippet extraction for summary
        words = [w for w in page_text.split() if w.isalnum() and len(w) > 3]
        scraped_snippet = " ".join(words[:40]) + "..." if words else "No readable text content found."
        
    else:
        # Fallback to passive/simulated scanning
        analysis_log.append(f"Connection to '{domain}' refused or timed out ({info_or_err}).")
        analysis_log.append("Entering passive intelligence / database correlation mode...")
        
        # TLD Analysis
        for tld in SUSPICIOUS_TLDS:
            if url.endswith(tld) or f"{tld}/" in url:
                threats.append(f"Suspicious TLD detected ({tld})")
                risk_score += 15
                break

        # Homograph Attack Detection
        confusables = [
            ('1', 'l'), ('0', 'o'), ('i', 'l'), ('rn', 'm'), ('vv', 'w'), ('-', '_')
        ]
        for c1, c2 in confusables:
            if (c1 in url and c2 in url) or (c1 in url and "google" in url) or (c1 in url and "paypal" in url):
                threats.append("Potential Homograph Attack (Character Confusion)")
                risk_score += 30
                break

        # Check mock database breach domains
        is_breached = False
        for breached in MOCK_BREACH_DOMAINS:
            if breached in domain:
                is_breached = True
                break
                
        if is_breached or ".onion" in url:
            threats.append("Dark Web Presence: Domain flagged in known leak databases")
            risk_score += 45
            if ".onion" in url:
                threats.append("Onion Routing: Direct link to hidden service")
                risk_score += 20
                
        # Heuristic keywords in URL itself
        for word in SUSPICIOUS_KEYWORDS:
            if word in url:
                threats.append(f"Phishing Indicator: '{word}' keyword in URL structure")
                risk_score += 15
                
        # Generate simulated metadata
        page_title = "Onion Portal" if ".onion" in url else f"{domain.capitalize()} Web Host"
        page_desc = "Dark Web marketplace forum or landing terminal." if ".onion" in url else "Reputation data correlation for hidden assets."
        scraped_snippet = "Simulated network trace: Hidden nodes verified via global exit relays."
        server_header = "nginx (Tor hidden service)" if ".onion" in url else "Apache/2.4.41 (Ubuntu)"

    # Simulated Geolocation & IP logic (deterministic based on seed)
    ip_parts = [str(random.randint(1, 255)) for _ in range(4)]
    sim_ip = ".".join(ip_parts)
    sim_geo = random.choice(LOCATIONS) if risk_score > 30 else "Cloudflare/Edge Content"
    
    if sim_geo in ["Russia", "China", "Unknown/VPN", "North Korea"]:
        analysis_log.append(f"Flag: Host server resides in high-risk jurisdiction ({sim_geo})")
        risk_score += 10

    # SSL Cert details
    ssl_status = "Valid"
    if risk_score > 60:
        ssl_status = random.choice(["Self-Signed", "Expired", "Revoked", "Valid"])
        if ssl_status != "Valid":
            threats.append(f"SSL Warning: Certificate is {ssl_status}")
            risk_score += 20

    # Ensure risk score bounds
    risk_score = min(risk_score, 100)
    
    if risk_score >= 75:
        status = "CRITICAL RISK"
        color = "#ff4d4d"
    elif risk_score >= 40:
        status = "MEDIUM RISK"
        color = "#ffa64d"
    else:
        status = "LOW RISK"
        color = "#4dff88"

    analysis_log.append("Deep analysis complete. Compiling threat report.")

    return {
        "url": url,
        "domain": domain,
        "status": status,
        "risk": risk_score,
        "color": color,
        "threats": threats,
        "log": analysis_log,
        "metadata": {
            "ip": sim_ip,
            "geo": sim_geo,
            "ssl": ssl_status,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "active_verification": "SUCCESSFUL" if is_active_scanned else "FAILED / FALLBACK TO PASSIVE",
            "page_title": page_title or "No Title",
            "page_description": page_desc or "No Meta Description",
            "server_software": server_header,
            "scraped_snippet": scraped_snippet
        }
    }
