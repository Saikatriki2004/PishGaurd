"""
Blocklist Integration - Real-time phishing URL blocklist checking.

This module provides integration with live phishing blocklists:
- OpenPhish (free feed)
- PhishTank (free API)
- URLhaus (abuse.ch)

The blocklist is cached in memory with a configurable refresh interval.
"""

import logging
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Optional, Set, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
import tldextract

logger = logging.getLogger(__name__)

# ============================================================================
# BLOCKLIST SOURCES
# ============================================================================

BLOCKLIST_SOURCES = {
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "type": "url_list",
        "refresh_hours": 1,
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "url_list", 
        "refresh_hours": 1,
    },
    # PhishTank requires API key, using their lite feed instead
    "phishtank_lite": {
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "type": "csv",
        "url_column": 1,  # 0-indexed
        "refresh_hours": 6,
    },
}

# Cache refresh interval
CACHE_REFRESH_HOURS = 1


@dataclass
class BlocklistResult:
    """Result from blocklist check."""
    is_blocked: bool
    source: Optional[str] = None
    matched_url: Optional[str] = None
    matched_domain: Optional[str] = None
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_blocked": self.is_blocked,
            "source": self.source,
            "matched_url": self.matched_url,
            "matched_domain": self.matched_domain,
            "confidence": self.confidence,
        }


class BlocklistChecker:
    """
    Real-time phishing blocklist checker with caching.
    
    Features:
    - Multiple blocklist sources
    - In-memory caching with periodic refresh
    - URL and domain matching
    - Thread-safe operations
    """
    
    def __init__(self, auto_refresh: bool = True):
        """
        Initialize the blocklist checker.
        
        Args:
            auto_refresh: If True, automatically refresh blocklists periodically
        """
        self._blocked_urls: Set[str] = set()
        self._blocked_domains: Set[str] = set()
        self._last_refresh: Optional[datetime] = None
        self._lock = threading.Lock()
        self._source_stats: Dict[str, int] = {}
        
        # Initial load
        self.refresh()
        
        logger.info(
            f"[BLOCKLIST] Initialized with {len(self._blocked_urls)} URLs, "
            f"{len(self._blocked_domains)} domains"
        )
    
    def refresh(self) -> None:
        """Refresh all blocklists from sources."""
        new_urls: Set[str] = set()
        new_domains: Set[str] = set()
        
        for source_name, config in BLOCKLIST_SOURCES.items():
            try:
                urls = self._fetch_source(source_name, config)
                new_urls.update(urls)
                
                # Extract domains from URLs
                for url in urls:
                    try:
                        extracted = tldextract.extract(url)
                        domain = f"{extracted.domain}.{extracted.suffix}"
                        if domain and domain != ".":
                            new_domains.add(domain.lower())
                    except Exception:
                        pass
                
                self._source_stats[source_name] = len(urls)
                logger.info(f"[BLOCKLIST] Loaded {len(urls)} URLs from {source_name}")
                
            except Exception as e:
                logger.warning(f"[BLOCKLIST] Failed to load {source_name}: {e}")
                self._source_stats[source_name] = 0
        
        # Atomic update
        with self._lock:
            self._blocked_urls = new_urls
            self._blocked_domains = new_domains
            self._last_refresh = datetime.now()
    
    def _fetch_source(self, name: str, config: Dict) -> Set[str]:
        """Fetch URLs from a blocklist source."""
        urls: Set[str] = set()
        
        resp = requests.get(config["url"], timeout=30)
        resp.raise_for_status()
        
        if config["type"] == "url_list":
            for line in resp.text.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.add(self._normalize_url(line))
        
        elif config["type"] == "csv":
            lines = resp.text.strip().split("\n")
            col = config.get("url_column", 0)
            for line in lines[1:]:  # Skip header
                parts = line.split(",")
                if len(parts) > col:
                    url = parts[col].strip().strip('"')
                    if url.startswith("http"):
                        urls.add(self._normalize_url(url))
        
        return urls
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent matching."""
        url = url.lower().strip()
        # Remove trailing slash
        if url.endswith("/"):
            url = url[:-1]
        return url
    
    def _needs_refresh(self) -> bool:
        """Check if blocklist needs refresh."""
        if self._last_refresh is None:
            return True
        age = datetime.now() - self._last_refresh
        return age > timedelta(hours=CACHE_REFRESH_HOURS)
    
    def check(self, url: str) -> BlocklistResult:
        """
        Check if a URL is on any blocklist.
        
        Args:
            url: URL to check
            
        Returns:
            BlocklistResult with match details
        """
        # Refresh if needed
        if self._needs_refresh():
            try:
                self.refresh()
            except Exception as e:
                logger.warning(f"[BLOCKLIST] Refresh failed: {e}")
        
        normalized_url = self._normalize_url(url)
        
        with self._lock:
            # Check exact URL match
            if normalized_url in self._blocked_urls:
                return BlocklistResult(
                    is_blocked=True,
                    source="blocklist",
                    matched_url=normalized_url,
                    confidence=0.99,
                )
            
            # Check domain match
            try:
                extracted = tldextract.extract(url)
                domain = f"{extracted.domain}.{extracted.suffix}".lower()
                
                if domain in self._blocked_domains:
                    return BlocklistResult(
                        is_blocked=True,
                        source="blocklist_domain",
                        matched_domain=domain,
                        confidence=0.85,  # Lower confidence for domain-only match
                    )
            except Exception:
                pass
        
        return BlocklistResult(is_blocked=False)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get blocklist statistics."""
        with self._lock:
            return {
                "total_urls": len(self._blocked_urls),
                "total_domains": len(self._blocked_domains),
                "last_refresh": self._last_refresh.isoformat() if self._last_refresh else None,
                "sources": self._source_stats.copy(),
            }


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

_checker: Optional[BlocklistChecker] = None
_checker_lock = threading.Lock()


def get_blocklist_checker() -> BlocklistChecker:
    """Get or create the global blocklist checker instance."""
    global _checker
    
    with _checker_lock:
        if _checker is None:
            _checker = BlocklistChecker()
        return _checker


def is_blocked(url: str) -> BlocklistResult:
    """
    Check if a URL is on any blocklist.
    
    This is the main entry point for blocklist checking.
    
    Args:
        url: URL to check
        
    Returns:
        BlocklistResult with match details
    """
    checker = get_blocklist_checker()
    return checker.check(url)
