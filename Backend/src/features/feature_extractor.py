"""
Feature Extractor - Production-ready URL feature extraction engine.

This module extracts 30 features from a URL for phishing detection.
Features parallel network requests, SSRF protection, proper error handling,
and FAILURE TRACKING for explainability.

CRITICAL CHANGES (v2):
- Removed all -1 magic values (network failures now return 0 = neutral)
- Added failure_flags dict tracking which features failed
- Added get_failure_report() for transparency
- Added get_feature_explanations() for human-readable output
- Failure indicators are separate from feature values
"""

import re
import ssl
import socket
import ipaddress
import logging
import math
import hashlib
from datetime import date, datetime
from typing import List, Optional, Tuple, Any, Dict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from functools import lru_cache

import requests
import tldextract
import dns.resolver
from bs4 import BeautifulSoup

# Homoglyph mapping for lookalike character detection
HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',  # Cyrillic
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ᴀ': 'a', 'ʙ': 'b',  # Other scripts
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',  # Numbers
    'ɡ': 'g', 'ɩ': 'i', 'ν': 'v', 'ω': 'w',  # Greek
}

# Popular brands for homoglyph detection
PROTECTED_BRANDS = (
    'google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix',
    'instagram', 'twitter', 'linkedin', 'github', 'dropbox', 'chase', 'bank',
    'wellsfargo', 'citibank', 'americanexpress', 'visa', 'mastercard'
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Timeout for network requests (seconds) - reduced from 5 to 3 for speed
REQUEST_TIMEOUT = 3

# Blocked IP ranges for SSRF protection
BLOCKED_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),      # Loopback
    ipaddress.ip_network('10.0.0.0/8'),       # Private Class A
    ipaddress.ip_network('172.16.0.0/12'),    # Private Class B
    ipaddress.ip_network('192.168.0.0/16'),   # Private Class C
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local
    ipaddress.ip_network('0.0.0.0/8'),        # Current network
]

# URL shortener domains
SHORTENER_DOMAINS = (
    'bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co',
    'tinyurl.com', 'tr.im', 'is.gd', 'cli.gs', 'yfrog.com', 'migre.me',
    'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl',
    'snipurl.com', 'short.to', 'budurl.com', 'ping.fm', 'post.ly',
    'just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com',
    'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do',
    'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'bitly.com', 'cur.lv', 'ity.im',
    'q.gs', 'po.st', 'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com',
    'cutt.us', 'u.bb', 'yourls.org', 'prettylinkpro.com', 'scrnch.me',
    'filoops.info', 'vzturl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd',
    'link.zip.net'
)

# Known phishing stats report domains
STATS_REPORT_DOMAINS = (
    'at.ua', 'usa.cc', 'baltazarpresentes.com.br', 'pe.hu', 'esy.es',
    'hol.es', 'sweddy.com', 'myjino.ru', '96.lt', 'ow.ly'
)

# Feature names for explainability (30 features)
FEATURE_NAMES = [
    "using_ip_address",          # 1
    "url_length",                # 2
    "is_shortener",              # 3
    "has_at_symbol",             # 4
    "has_double_slash_redirect", # 5
    "has_dash_in_domain",        # 6
    "subdomain_count",           # 7
    "has_https",                 # 8
    "domain_registration_length",# 9
    "external_favicon",          # 10
    "non_standard_port",         # 11
    "https_in_domain_name",      # 12
    "external_resources_ratio",  # 13
    "unsafe_anchors_ratio",      # 14
    "external_scripts_ratio",    # 15
    "suspicious_form_handler",   # 16
    "has_mailto_links",          # 17
    "abnormal_url_whois",        # 18
    "redirect_count",            # 19
    "status_bar_manipulation",   # 20
    "right_click_disabled",      # 21
    "popup_windows",             # 22
    "iframe_present",            # 23
    "domain_age",                # 24
    "has_dns_record",            # 25
    "url_entropy",               # 26 - Replaced dead website_traffic
    "homoglyph_detected",        # 27 - Replaced dead page_rank
    "certificate_age",           # 28 - Replaced dead google_index
    "external_links_count",      # 29
    "statistical_report_match",  # 30
]

# Feature descriptions for explanations
FEATURE_DESCRIPTIONS = {
    "using_ip_address": "URL uses IP address instead of domain name",
    "url_length": "URL length exceeds normal thresholds",
    "is_shortener": "URL uses a known URL shortening service",
    "has_at_symbol": "URL contains @ symbol (can hide real destination)",
    "has_double_slash_redirect": "URL has suspicious // redirect pattern",
    "has_dash_in_domain": "Domain name contains dash (common in phishing)",
    "subdomain_count": "Excessive number of subdomains",
    "has_https": "Site uses HTTPS encryption",
    "domain_registration_length": "Domain registration period",
    "external_favicon": "Favicon loaded from external domain",
    "non_standard_port": "Site uses non-standard port number",
    "https_in_domain_name": "Domain name contains 'https' text (deceptive)",
    "external_resources_ratio": "High ratio of external resources",
    "unsafe_anchors_ratio": "Links point to external or suspicious targets",
    "external_scripts_ratio": "Scripts loaded from external sources",
    "suspicious_form_handler": "Form submits data to external server",
    "has_mailto_links": "Page contains mailto links",
    "abnormal_url_whois": "WHOIS data appears abnormal",
    "redirect_count": "Multiple redirects before final page",
    "status_bar_manipulation": "JavaScript manipulates browser status bar",
    "right_click_disabled": "Right-click functionality disabled",
    "popup_windows": "Page opens popup windows",
    "iframe_present": "Page contains iframes (can hide content)",
    "domain_age": "Domain is newly registered",
    "has_dns_record": "Domain has valid DNS records",
    "url_entropy": "Domain name has high randomness (suspicious)",
    "homoglyph_detected": "Domain contains lookalike characters mimicking brands",
    "certificate_age": "SSL certificate age (newly issued = suspicious)",
    "external_links_count": "Number of external links on page",
    "statistical_report_match": "Domain/IP matches known phishing patterns",
}


@dataclass
class FailureFlags:
    """Tracks which network operations failed during feature extraction."""
    http_failed: bool = False
    http_error: Optional[str] = None
    whois_failed: bool = False
    whois_error: Optional[str] = None
    dns_failed: bool = False
    dns_error: Optional[str] = None
    
    def any_failed(self) -> bool:
        """Check if any network operation failed."""
        return self.http_failed or self.whois_failed or self.dns_failed
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "http_failed": self.http_failed,
            "http_error": self.http_error,
            "whois_failed": self.whois_failed,
            "whois_error": self.whois_error,
            "dns_failed": self.dns_failed,
            "dns_error": self.dns_error,
            "any_failed": self.any_failed()
        }
    
    def get_failure_indicators(self) -> List[int]:
        """
        Return binary failure indicators for model input.
        These are ADDITIONAL features that inform the model about failures.
        """
        return [
            1 if self.http_failed else 0,
            1 if self.whois_failed else 0,
            1 if self.dns_failed else 0
        ]


@dataclass
class FeatureExplanation:
    """Explanation for a single feature's contribution."""
    feature_name: str
    feature_index: int
    value: int
    description: str
    contribution: str  # "phishing", "safe", or "neutral"
    failed: bool = False


class FeatureExtractor:
    """
    Extracts 30 features from a URL for phishing detection.
    
    Features are returned as a list of integers: 
    - -1: phishing indicator (BUT NOT for failures!)
    - 0: neutral / unknown / failed
    - 1: safe indicator
    
    CRITICAL: Network failures ALWAYS return 0 (neutral), NEVER -1.
    This prevents failure bias from influencing phishing predictions.
    """
    
    def __init__(self, url: str):
        """
        Initialize the feature extractor with a URL.
        
        Args:
            url: The URL to analyze
            
        Raises:
            ValueError: If URL is invalid, local, or uses blocked scheme
        """
        self.url = self._sanitize_url(url)
        self._validate_url()
        
        # Parse URL components
        self.parsed_url = urlparse(self.url)
        self.domain = self.parsed_url.netloc
        self.tld_info = tldextract.extract(self.url)
        
        # Network data (populated concurrently)
        self.response: Optional[requests.Response] = None
        self.soup: Optional[BeautifulSoup] = None
        self.whois_data: Optional[Any] = None
        self.dns_records: Optional[List] = None
        
        # CRITICAL: Track network failures for transparency
        self.failure_flags = FailureFlags()
        
        # Run network checks in parallel
        self._fetch_network_data()
        
        # Extract all features
        self.features = self._extract_all_features()
    
    def _sanitize_url(self, url: str) -> str:
        """Ensure URL has proper scheme."""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def _validate_url(self) -> None:
        """
        Validate URL for security (SSRF protection).
        
        Raises:
            ValueError: If URL is invalid or blocked
        """
        parsed = urlparse(self.url)
        
        # Check scheme
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
        
        # Check for valid hostname
        hostname = parsed.netloc.split(':')[0]
        if not hostname:
            raise ValueError("Invalid URL: no hostname")
        
        # Resolve hostname and check against blocked ranges
        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            for blocked_range in BLOCKED_IP_RANGES:
                if ip_obj in blocked_range:
                    raise ValueError(f"SSRF Protection: Blocked local/private IP address")
        except socket.gaierror:
            # Can't resolve - might be valid domain, let it through
            pass
    
    def _fetch_network_data(self) -> None:
        """Fetch network data (HTTP, WHOIS, DNS) concurrently with failure tracking."""
        
        def fetch_http() -> Tuple[Optional[requests.Response], Optional[BeautifulSoup]]:
            try:
                resp = requests.get(
                    self.url, 
                    timeout=REQUEST_TIMEOUT,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'},
                    allow_redirects=True
                )
                soup = BeautifulSoup(resp.text, 'html.parser')
                return resp, soup
            except Exception as e:
                logger.warning(f"HTTP fetch failed: {e}")
                self.failure_flags.http_failed = True
                self.failure_flags.http_error = str(e)
                return None, None
        
        def fetch_whois() -> Optional[Any]:
            try:
                import whois
                return whois.whois(self.domain)
            except Exception as e:
                logger.warning(f"WHOIS lookup failed: {e}")
                self.failure_flags.whois_failed = True
                self.failure_flags.whois_error = str(e)
                return None
        
        def fetch_dns() -> Optional[List]:
            try:
                answers = dns.resolver.resolve(self.domain, 'A')
                return [str(rdata) for rdata in answers]
            except Exception as e:
                logger.warning(f"DNS lookup failed: {e}")
                self.failure_flags.dns_failed = True
                self.failure_flags.dns_error = str(e)
                return None
        
        # Run all network requests in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(fetch_http): 'http',
                executor.submit(fetch_whois): 'whois',
                executor.submit(fetch_dns): 'dns'
            }
            
            for future in as_completed(futures):
                task = futures[future]
                try:
                    if task == 'http':
                        self.response, self.soup = future.result()
                    elif task == 'whois':
                        self.whois_data = future.result()
                    elif task == 'dns':
                        self.dns_records = future.result()
                except Exception as e:
                    logger.error(f"Task {task} failed: {e}")
    
    def _extract_all_features(self) -> List[int]:
        """Extract all 30 features in order."""
        return [
            self._using_ip(),              # 1
            self._long_url(),              # 2
            self._short_url(),             # 3
            self._symbol_at(),             # 4
            self._redirecting(),           # 5
            self._prefix_suffix(),         # 6
            self._sub_domains(),           # 7
            self._https(),                 # 8
            self._domain_reg_len(),        # 9
            self._favicon(),               # 10
            self._non_std_port(),          # 11
            self._https_domain_url(),      # 12
            self._request_url(),           # 13
            self._anchor_url(),            # 14
            self._links_in_script_tags(),  # 15
            self._server_form_handler(),   # 16
            self._info_email(),            # 17
            self._abnormal_url(),          # 18
            self._website_forwarding(),    # 19
            self._status_bar_cust(),       # 20
            self._disable_right_click(),   # 21
            self._using_popup_window(),    # 22
            self._iframe_redirection(),    # 23
            self._age_of_domain(),         # 24
            self._dns_recording(),         # 25
            self._url_entropy(),           # 26 - High-signal: random domains
            self._homoglyph_detection(),   # 27 - High-signal: lookalike chars
            self._certificate_age(),       # 28 - High-signal: new certs
            self._links_pointing_to_page(), # 29
            self._stats_report()           # 30
        ]
    
    def get_features(self) -> List[int]:
        """Return the extracted features (30 values)."""
        return self.features
    
    def get_features_with_failure_indicators(self) -> List[int]:
        """
        Return features + failure indicators (33 values).
        The additional 3 values indicate HTTP, WHOIS, DNS failures.
        """
        return self.features + self.failure_flags.get_failure_indicators()
    
    def get_failure_report(self) -> Dict[str, Any]:
        """Return detailed failure report for transparency."""
        return self.failure_flags.to_dict()
    
    def get_feature_explanations(self) -> Dict[str, Any]:
        """
        Generate human-readable explanations for all features.
        
        Returns:
            Dict with:
            - phishing_signals: List of features indicating phishing
            - safe_signals: List of features indicating safety
            - neutral_signals: List of neutral/unknown features
            - failed_features: List of features that failed due to network issues
        """
        phishing_signals = []
        safe_signals = []
        neutral_signals = []
        failed_features = []
        
        for idx, (name, value) in enumerate(zip(FEATURE_NAMES, self.features)):
            explanation = FeatureExplanation(
                feature_name=name,
                feature_index=idx,
                value=value,
                description=FEATURE_DESCRIPTIONS.get(name, ""),
                contribution="neutral"
            )
            
            # Check if this feature failed due to network issues
            is_failed = False
            if name in ["external_favicon", "external_resources_ratio", "unsafe_anchors_ratio",
                       "external_scripts_ratio", "suspicious_form_handler", "has_mailto_links",
                       "status_bar_manipulation", "right_click_disabled", "popup_windows",
                       "iframe_present"] and self.failure_flags.http_failed:
                is_failed = True
            elif name in ["domain_registration_length", "abnormal_url_whois", 
                         "domain_age"] and self.failure_flags.whois_failed:
                is_failed = True
            elif name == "has_dns_record" and self.failure_flags.dns_failed:
                is_failed = True
            
            if is_failed:
                explanation.failed = True
                explanation.contribution = "neutral"
                failed_features.append({
                    "name": name,
                    "description": FEATURE_DESCRIPTIONS.get(name, ""),
                    "reason": "Network failure during extraction"
                })
            elif value == -1:
                explanation.contribution = "phishing"
                phishing_signals.append({
                    "name": name,
                    "description": FEATURE_DESCRIPTIONS.get(name, ""),
                    "severity": "high" if name in ["using_ip_address", "is_shortener"] else "medium"
                })
            elif value == 1:
                explanation.contribution = "safe"
                safe_signals.append({
                    "name": name,
                    "description": FEATURE_DESCRIPTIONS.get(name, "")
                })
            else:
                neutral_signals.append({
                    "name": name,
                    "description": FEATURE_DESCRIPTIONS.get(name, "")
                })
        
        return {
            "phishing_signals": phishing_signals,
            "safe_signals": safe_signals,
            "neutral_signals": neutral_signals,
            "failed_features": failed_features,
            "total_phishing": len(phishing_signals),
            "total_safe": len(safe_signals),
            "total_failed": len(failed_features)
        }
    
    # ========== FEATURE EXTRACTION METHODS ==========
    # CRITICAL: All methods return 0 (neutral) on failure, NEVER -1
    
    def _using_ip(self) -> int:
        """Feature 1: Check if URL uses IP address instead of domain."""
        try:
            hostname = self.parsed_url.netloc.split(':')[0]
            ipaddress.ip_address(hostname)
            return -1  # Using IP = suspicious
        except ValueError:
            return 1   # Using domain name = safe
    
    def _long_url(self) -> int:
        """Feature 2: URL length check."""
        length = len(self.url)
        if length < 54:
            return 1
        elif length <= 75:
            return 0
        return -1
    
    def _short_url(self) -> int:
        """Feature 3: Check if URL is from a known shortener."""
        if any(short in self.url.lower() for short in SHORTENER_DOMAINS):
            return -1
        return 1
    
    def _symbol_at(self) -> int:
        """Feature 4: Check for @ symbol in URL."""
        return -1 if '@' in self.url else 1
    
    def _redirecting(self) -> int:
        """Feature 5: Check for // redirect in URL path."""
        if self.url.rfind('//') > 6:
            return -1
        return 1
    
    def _prefix_suffix(self) -> int:
        """Feature 6: Check for dash in domain name."""
        return -1 if '-' in self.domain else 1
    
    def _sub_domains(self) -> int:
        """Feature 7: Count subdomains."""
        subdomain = self.tld_info.subdomain
        dot_count = subdomain.count('.') if subdomain else 0
        
        if dot_count == 0:
            return 1
        elif dot_count == 1:
            return 0
        return -1
    
    def _https(self) -> int:
        """Feature 8: Check for HTTPS."""
        return 1 if self.parsed_url.scheme == 'https' else -1
    
    def _domain_reg_len(self) -> int:
        """Feature 9: Domain registration length."""
        # CRITICAL: Return 0 (neutral) on failure, not -1
        if self.failure_flags.whois_failed or not self.whois_data:
            return 0  # NEUTRAL on failure
        
        try:
            creation = self.whois_data.creation_date
            expiration = self.whois_data.expiration_date
            
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(expiration, list):
                expiration = expiration[0]
            
            if creation and expiration:
                age_months = (expiration.year - creation.year) * 12 + (expiration.month - creation.month)
                return 1 if age_months >= 12 else -1
        except Exception as e:
            logger.warning(f"Domain reg len check failed: {e}")
        return 0  # NEUTRAL on failure
    
    def _favicon(self) -> int:
        """Feature 10: Check favicon source."""
        # CRITICAL: Return 0 (neutral) on failure
        if self.failure_flags.http_failed or not self.soup:
            return 0
        
        try:
            for link in self.soup.find_all('link', rel=lambda x: x and 'icon' in x):
                href = link.get('href', '')
                if href and self.domain not in href and not href.startswith('/'):
                    return -1
            return 1
        except Exception as e:
            logger.warning(f"Favicon check failed: {e}")
            return 0
    
    def _non_std_port(self) -> int:
        """Feature 11: Check for non-standard port."""
        return -1 if ':' in self.domain.split('.')[-1] else 1
    
    def _https_domain_url(self) -> int:
        """Feature 12: HTTPS token in domain."""
        domain_without_port = self.domain.split(':')[0]
        return -1 if 'https' in domain_without_port.lower() else 1
    
    def _request_url(self) -> int:
        """Feature 13: Percentage of external resources."""
        if self.failure_flags.http_failed or not self.soup:
            return 0  # NEUTRAL on failure
        
        try:
            total = 0
            external = 0
            
            for tag in self.soup.find_all(['img', 'audio', 'video', 'embed', 'source']):
                src = tag.get('src', '')
                if src:
                    total += 1
                    if src.startswith('http') and self.domain not in src:
                        external += 1
            
            if total == 0:
                return 0
            
            percent = (external / total) * 100
            if percent < 22:
                return 1
            elif percent < 61:
                return 0
            return -1
        except Exception as e:
            logger.warning(f"Request URL check failed: {e}")
            return 0
    
    def _anchor_url(self) -> int:
        """Feature 14: Percentage of unsafe anchors."""
        if self.failure_flags.http_failed or not self.soup:
            return 0  # NEUTRAL on failure
        
        try:
            total = 0
            unsafe = 0
            
            for a in self.soup.find_all('a', href=True):
                total += 1
                href = a['href']
                if '#' in href or 'javascript' in href.lower() or 'mailto' in href.lower():
                    unsafe += 1
                elif not (self.domain in href or href.startswith('/')):
                    unsafe += 1
            
            if total == 0:
                return 0
            
            percent = (unsafe / total) * 100
            if percent < 31:
                return 1
            elif percent < 67:
                return 0
            return -1
        except Exception as e:
            logger.warning(f"Anchor URL check failed: {e}")
            return 0
    
    def _links_in_script_tags(self) -> int:
        """Feature 15: External links in script/link tags."""
        if self.failure_flags.http_failed or not self.soup:
            return 0  # NEUTRAL on failure
        
        try:
            total = 0
            internal = 0
            
            for tag in self.soup.find_all(['script', 'link']):
                src = tag.get('src') or tag.get('href')
                if src:
                    total += 1
                    if self.domain in src or src.startswith('/'):
                        internal += 1
            
            if total == 0:
                return 0
            
            percent = (internal / total) * 100
            if percent >= 81:
                return 1
            elif percent >= 17:
                return 0
            return -1
        except Exception as e:
            logger.warning(f"Links in script check failed: {e}")
            return 0
    
    def _server_form_handler(self) -> int:
        """Feature 16: Check form action handlers."""
        if self.failure_flags.http_failed or not self.soup:
            return 0  # NEUTRAL on failure
        
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            
            for form in forms:
                action = form.get('action', '')
                if action in ('', 'about:blank'):
                    return -1
                if self.domain not in action and not action.startswith('/'):
                    return 0
            return 1
        except Exception as e:
            logger.warning(f"Form handler check failed: {e}")
            return 0
    
    def _info_email(self) -> int:
        """Feature 17: Check for mailto links."""
        if self.failure_flags.http_failed or not self.response:
            return 0  # NEUTRAL on failure
        
        try:
            return -1 if 'mailto:' in self.response.text else 1
        except Exception as e:
            logger.warning(f"Info email check failed: {e}")
            return 0
    
    def _abnormal_url(self) -> int:
        """Feature 18: Check if domain not in WHOIS."""
        if self.failure_flags.whois_failed:
            return 0  # NEUTRAL on failure
        
        try:
            if not self.whois_data or not self.whois_data.domain_name:
                return 0  # NEUTRAL when data unavailable
            return 1
        except Exception as e:
            logger.warning(f"Abnormal URL check failed: {e}")
            return 0
    
    def _website_forwarding(self) -> int:
        """Feature 19: Count redirects."""
        if self.failure_flags.http_failed or not self.response:
            return 0  # NEUTRAL on failure
        
        try:
            redirects = len(self.response.history)
            if redirects <= 1:
                return 1
            elif redirects <= 4:
                return 0
            return -1
        except Exception as e:
            logger.warning(f"Forwarding check failed: {e}")
            return 0
    
    def _status_bar_cust(self) -> int:
        """Feature 20: Check for status bar manipulation."""
        if self.failure_flags.http_failed or not self.response:
            return 0  # NEUTRAL on failure
        
        try:
            return -1 if 'onmouseover' in self.response.text.lower() else 1
        except Exception as e:
            logger.warning(f"Status bar check failed: {e}")
            return 0
    
    def _disable_right_click(self) -> int:
        """Feature 21: Check for right-click disable."""
        if self.failure_flags.http_failed or not self.response:
            return 0  # NEUTRAL on failure
        
        try:
            return -1 if 'event.button==2' in self.response.text.replace(' ', '') else 1
        except Exception as e:
            logger.warning(f"Right click check failed: {e}")
            return 0
    
    def _using_popup_window(self) -> int:
        """Feature 22: Check for popup windows."""
        if self.failure_flags.http_failed or not self.response:
            return 0  # NEUTRAL on failure
        
        try:
            text = self.response.text.lower()
            return -1 if 'window.open(' in text or 'alert(' in text else 1
        except Exception as e:
            logger.warning(f"Popup check failed: {e}")
            return 0
    
    def _iframe_redirection(self) -> int:
        """Feature 23: Check for iframes."""
        if self.failure_flags.http_failed or not self.soup:
            return 0  # NEUTRAL on failure
        
        try:
            iframes = self.soup.find_all('iframe')
            return -1 if iframes else 1
        except Exception as e:
            logger.warning(f"Iframe check failed: {e}")
            return 0
    
    def _age_of_domain(self) -> int:
        """Feature 24: Check domain age."""
        if self.failure_flags.whois_failed or not self.whois_data:
            return 0  # NEUTRAL on failure
        
        try:
            creation = self.whois_data.creation_date
            if not creation:
                return 0
            
            if isinstance(creation, list):
                creation = creation[0]
            
            if not isinstance(creation, (date, datetime)):
                return 0
            
            today = date.today()
            age_months = (today.year - creation.year) * 12 + (today.month - creation.month)
            return 1 if age_months >= 6 else -1
        except Exception as e:
            logger.warning(f"Domain age check failed: {e}")
            return 0
    
    def _dns_recording(self) -> int:
        """Feature 25: Check for DNS records."""
        if self.failure_flags.dns_failed:
            return 0  # NEUTRAL on failure
        
        if self.dns_records:
            return 1
        return 0  # NEUTRAL when no records (not -1)
    
    def _url_entropy(self) -> int:
        """
        Feature 26: URL entropy - measures randomness in domain name.
        High entropy indicates randomly generated domain (common in phishing).
        """
        try:
            domain = self.tld_info.domain.lower()
            if not domain:
                return 0
            
            # Calculate Shannon entropy
            freq = {}
            for char in domain:
                freq[char] = freq.get(char, 0) + 1
            
            entropy = 0.0
            for count in freq.values():
                p = count / len(domain)
                entropy -= p * math.log2(p)
            
            # Normalize by max possible entropy
            max_entropy = math.log2(len(domain)) if len(domain) > 1 else 1
            normalized = entropy / max_entropy if max_entropy > 0 else 0
            
            # High entropy = suspicious (random-looking domain)
            if normalized > 0.85:
                return -1  # Very random = phishing indicator
            elif normalized > 0.70:
                return 0   # Somewhat random = neutral
            return 1       # Normal domain = safe
        except Exception as e:
            logger.warning(f"URL entropy check failed: {e}")
            return 0
    
    def _homoglyph_detection(self) -> int:
        """
        Feature 27: Homoglyph detection - finds lookalike characters.
        Phishing sites often use Cyrillic/Greek letters that look like Latin.
        """
        try:
            domain = self.tld_info.domain.lower()
            
            # Check for homoglyphs
            has_homoglyph = any(char in HOMOGLYPH_MAP for char in domain)
            
            if has_homoglyph:
                # Normalize domain by replacing homoglyphs
                normalized = ''.join(HOMOGLYPH_MAP.get(c, c) for c in domain)
                
                # Check if normalized domain looks like a protected brand
                for brand in PROTECTED_BRANDS:
                    if brand in normalized and brand not in domain:
                        return -1  # Impersonating a brand = phishing
                
                return 0  # Has homoglyphs but not targeting known brand
            
            return 1  # No homoglyphs = safe
        except Exception as e:
            logger.warning(f"Homoglyph check failed: {e}")
            return 0
    
    def _certificate_age(self) -> int:
        """
        Feature 28: SSL certificate age - new certs are suspicious.
        Phishing sites often use newly issued certificates.
        """
        try:
            hostname = self.domain.split(':')[0]
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_OPTIONAL
            
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert and 'notBefore' in cert:
                        # Parse certificate date
                        not_before = datetime.strptime(
                            cert['notBefore'], '%b %d %H:%M:%S %Y %Z'
                        )
                        age_days = (datetime.now() - not_before).days
                        
                        if age_days < 30:
                            return -1  # Very new cert = suspicious
                        elif age_days < 90:
                            return 0   # Fairly new = neutral
                        return 1       # Established cert = safe
            
            return 0  # No cert info = neutral
        except Exception as e:
            logger.debug(f"Certificate age check failed: {e}")
            return 0  # NEUTRAL on failure
    
    def _links_pointing_to_page(self) -> int:
        """Feature 29: Count external links pointing to page."""
        if self.failure_flags.http_failed or not self.response:
            return 0  # NEUTRAL on failure
        
        try:
            links = len(re.findall(r'<a\s+href=', self.response.text, re.I))
            if links == 0:
                return 1
            elif links <= 2:
                return 0
            return -1
        except Exception as e:
            logger.warning(f"Links pointing check failed: {e}")
            return 0
    
    def _stats_report(self) -> int:
        """Feature 30: Check against known phishing domains/IPs."""
        try:
            # Check domain against known stats report domains
            if any(bad in self.url.lower() for bad in STATS_REPORT_DOMAINS):
                return -1
            
            # Check resolved IP against known bad IPs
            if self.dns_records:
                known_bad_ips = [
                    '146.112.61.108', '213.174.157.151', '121.50.168.88',
                    '192.185.217.116', '78.46.211.158', '181.174.165.13'
                ]
                for ip in self.dns_records:
                    if ip in known_bad_ips:
                        return -1
            return 1
        except Exception as e:
            logger.warning(f"Stats report check failed: {e}")
            return 0
