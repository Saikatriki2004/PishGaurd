"""
Trusted Domain Gating Module - Pre-ML Safety Gate

This module provides a trusted-domain allowlist that MUST be checked BEFORE
any ML inference. Trusted domains bypass ML entirely and are forced to SAFE.

SECURITY RATIONALE:
- ML models can produce false positives on legitimate domains
- Network failures during feature extraction can bias predictions
- Trusted domains should NEVER show phishing verdicts

USAGE:
    from trusted_domains import TrustedDomainChecker
    
    checker = TrustedDomainChecker()
    result = checker.check("accounts.google.com")
    
    if result.is_trusted:
        # Skip ML, force SAFE verdict
        verdict = "SAFE"
        risk_score = min(risk_score, 30.0)
"""

from dataclasses import dataclass
from typing import Optional, Set
import tldextract
import logging

logger = logging.getLogger(__name__)


@dataclass
class TrustCheckResult:
    """Result of trusted domain check."""
    is_trusted: bool
    registered_domain: str
    matched_domain: Optional[str] = None
    reason: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "is_trusted": self.is_trusted,
            "registered_domain": self.registered_domain,
            "matched_domain": self.matched_domain,
            "reason": self.reason
        }


# ============================================================================
# TRUSTED DOMAINS ALLOWLIST
# ============================================================================
# This list contains domains that should NEVER be flagged as phishing.
# Domains are stored as registered domain only (no subdomains).
# Sources: Tranco Top 1000, Major tech companies, Financial institutions
# ============================================================================

TRUSTED_DOMAINS: Set[str] = {
    # Search Engines & Tech Giants
    "google.com",
    "google.co.in",
    "google.co.uk",
    "google.de",
    "google.fr",
    "google.es",
    "google.it",
    "google.ca",
    "google.com.au",
    "google.co.jp",
    "google.com.br",
    "googleapis.com",
    "googleusercontent.com",
    "googlevideo.com",
    "gstatic.com",
    "youtube.com",
    "youtu.be",
    "bing.com",
    "microsoft.com",
    "microsoftonline.com",
    "live.com",
    "outlook.com",
    "office.com",
    "office365.com",
    "azure.com",
    "windows.com",
    "windowsupdate.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "amazon.co.uk",
    "amazon.de",
    "amazon.fr",
    "amazon.in",
    "amazon.co.jp",
    "amazonaws.com",
    "aws.amazon.com",
    
    # Social Media
    "facebook.com",
    "fb.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "reddit.com",
    "pinterest.com",
    "tiktok.com",
    "snapchat.com",
    "whatsapp.com",
    "telegram.org",
    "discord.com",
    "discordapp.com",
    "twitch.tv",
    
    # Development & Tech
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "stackexchange.com",
    "npmjs.com",
    "pypi.org",
    "python.org",
    "nodejs.org",
    "rust-lang.org",
    "golang.org",
    "docker.com",
    "kubernetes.io",
    "cloudflare.com",
    "cloudflare-dns.com",
    "netlify.com",
    "vercel.com",
    "heroku.com",
    "digitalocean.com",
    
    # E-commerce & Retail
    "ebay.com",
    "walmart.com",
    "target.com",
    "bestbuy.com",
    "alibaba.com",
    "aliexpress.com",
    "shopify.com",
    "etsy.com",
    "flipkart.com",
    
    # Financial Services
    "paypal.com",
    "stripe.com",
    "visa.com",
    "mastercard.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "capitalone.com",
    "americanexpress.com",
    
    # Media & Entertainment
    "netflix.com",
    "spotify.com",
    "hulu.com",
    "disneyplus.com",
    "hbomax.com",
    "primevideo.com",
    "crunchyroll.com",
    
    # Communication & Productivity
    "zoom.us",
    "slack.com",
    "dropbox.com",
    "box.com",
    "notion.so",
    "atlassian.com",
    "jira.com",
    "confluence.com",
    "trello.com",
    "asana.com",
    "monday.com",
    "salesforce.com",
    "hubspot.com",
    "zendesk.com",
    
    # News & Information
    "wikipedia.org",
    "wikimedia.org",
    "bbc.com",
    "bbc.co.uk",
    "cnn.com",
    "nytimes.com",
    "washingtonpost.com",
    "theguardian.com",
    "reuters.com",
    "bloomberg.com",
    "forbes.com",
    "medium.com",
    
    # Education
    "coursera.org",
    "udemy.com",
    "edx.org",
    "khanacademy.org",
    "mit.edu",
    "stanford.edu",
    "harvard.edu",
    
    # Security & Infrastructure
    "cloudflare.com",
    "akamai.com",
    "fastly.com",
    "letsencrypt.org",
    "digicert.com",
    "godaddy.com",
    "namecheap.com",
    
    # CDNs & Services
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "bootstrapcdn.com",
    "jquery.com",
    "fontawesome.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    
    # Government & Official
    "gov",  # All .gov domains
    "gov.uk",
    "gov.in",
    "irs.gov",
    "usa.gov",
}


class TrustedDomainChecker:
    """
    Checks if a domain is in the trusted allowlist.
    
    This class uses tldextract to properly parse domains and extract
    the registered domain (domain + suffix), ignoring subdomains.
    
    Example:
        accounts.google.com → google.com (trusted)
        evil-google.com → evil-google.com (NOT trusted)
    """
    
    def __init__(self, additional_domains: Optional[Set[str]] = None):
        """
        Initialize the checker with optional additional domains.
        
        Args:
            additional_domains: Optional set of additional trusted domains
        """
        self.trusted_domains = TRUSTED_DOMAINS.copy()
        if additional_domains:
            self.trusted_domains.update(additional_domains)
        
        logger.info(f"[TRUSTED DOMAINS] Loaded {len(self.trusted_domains)} trusted domains")
    
    def _extract_registered_domain(self, url_or_domain: str) -> str:
        """
        Extract the registered domain from a URL or domain string.
        
        Args:
            url_or_domain: URL or domain to parse
            
        Returns:
            Registered domain (e.g., "google.com")
        """
        # Remove protocol if present
        domain = url_or_domain.lower().strip()
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        
        # Remove path if present
        domain = domain.split("/", 1)[0]
        
        # Remove port if present
        domain = domain.split(":", 1)[0]
        
        # Extract using tldextract
        extracted = tldextract.extract(domain)
        
        # Build registered domain
        if extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return extracted.domain
    
    def check(self, url_or_domain: str) -> TrustCheckResult:
        """
        Check if a URL or domain is trusted.
        
        Args:
            url_or_domain: URL or domain to check
            
        Returns:
            TrustCheckResult with trust status and details
        """
        try:
            registered_domain = self._extract_registered_domain(url_or_domain)
            
            # Direct match
            if registered_domain in self.trusted_domains:
                return TrustCheckResult(
                    is_trusted=True,
                    registered_domain=registered_domain,
                    matched_domain=registered_domain,
                    reason=f"Domain '{registered_domain}' is in trusted allowlist"
                )
            
            # Check for TLD-only matches (e.g., ".gov")
            extracted = tldextract.extract(url_or_domain.lower())
            if extracted.suffix in self.trusted_domains:
                return TrustCheckResult(
                    is_trusted=True,
                    registered_domain=registered_domain,
                    matched_domain=extracted.suffix,
                    reason=f"TLD '.{extracted.suffix}' is in trusted allowlist"
                )
            
            # Not trusted
            return TrustCheckResult(
                is_trusted=False,
                registered_domain=registered_domain,
                matched_domain=None,
                reason="Domain not in trusted allowlist"
            )
            
        except Exception as e:
            logger.error(f"[TRUSTED DOMAINS] Error checking domain: {e}")
            return TrustCheckResult(
                is_trusted=False,
                registered_domain=url_or_domain,
                matched_domain=None,
                reason=f"Error parsing domain: {str(e)}"
            )
    
    def is_trusted(self, url_or_domain: str) -> bool:
        """
        Simple boolean check if domain is trusted.
        
        Args:
            url_or_domain: URL or domain to check
            
        Returns:
            True if domain is trusted, False otherwise
        """
        return self.check(url_or_domain).is_trusted
    
    def add_domain(
        self, 
        domain: str,
        added_by: str = "unknown",
        reason: str = "Runtime addition"
    ) -> None:
        """
        Add a domain to the trusted list at runtime.
        
        GOVERNANCE INTEGRATION:
        - Asserts system is not frozen
        - Consumes override budget
        - Creates audit log entry
        """
        from src.governance.safety_governance import get_governance_controller
        from src.governance.policy_audit import get_audit_logger, OverrideEventType
        
        controller = get_governance_controller()
        
        # FAIL-CLOSED: Block if frozen
        controller.assert_not_frozen("add_trusted_domain")
        
        # Consume budget (may trigger freeze if exhausted)
        controller.consume_override_budget(f"add_domain:{domain}")
        
        normalized = self._extract_registered_domain(domain)
        self.trusted_domains.add(normalized)
        
        # Audit log
        get_audit_logger().log_override(
            event_type=OverrideEventType.ALLOWLIST_MODIFICATION,
            override_flag=True,
            affected_domains=[normalized],
            context="runtime_add_domain",
            reason=reason,
            additional_data={"added_by": added_by}
        )
        
        logger.warning(f"[TRUSTED DOMAINS] Domain '{normalized}' added by {added_by}: {reason}")
    
    def remove_domain(
        self, 
        domain: str,
        removed_by: str = "unknown",
        reason: str = "Runtime removal"
    ) -> None:
        """
        Remove a domain from the trusted list at runtime.
        
        GOVERNANCE INTEGRATION:
        - Asserts system is not frozen
        - Consumes override budget
        - Creates audit log entry
        """
        from src.governance.safety_governance import get_governance_controller
        from src.governance.policy_audit import get_audit_logger, OverrideEventType
        
        controller = get_governance_controller()
        
        # FAIL-CLOSED: Block if frozen
        controller.assert_not_frozen("remove_trusted_domain")
        
        # Consume budget (may trigger freeze if exhausted)
        controller.consume_override_budget(f"remove_domain:{domain}")
        
        normalized = self._extract_registered_domain(domain)
        self.trusted_domains.discard(normalized)
        
        # Audit log
        get_audit_logger().log_override(
            event_type=OverrideEventType.ALLOWLIST_MODIFICATION,
            override_flag=True,
            affected_domains=[normalized],
            context="runtime_remove_domain",
            reason=reason,
            additional_data={"removed_by": removed_by}
        )
        
        logger.warning(f"[TRUSTED DOMAINS] Domain '{normalized}' removed by {removed_by}: {reason}")


# Singleton instance for easy access
_default_checker: Optional[TrustedDomainChecker] = None


def get_trusted_domain_checker() -> TrustedDomainChecker:
    """Get the default TrustedDomainChecker instance."""
    global _default_checker
    if _default_checker is None:
        _default_checker = TrustedDomainChecker()
    return _default_checker


def is_trusted_domain(url_or_domain: str) -> bool:
    """Convenience function to check if a domain is trusted."""
    return get_trusted_domain_checker().is_trusted(url_or_domain)


def check_trusted_domain(url_or_domain: str) -> TrustCheckResult:
    """Convenience function to get full trust check result."""
    return get_trusted_domain_checker().check(url_or_domain)
