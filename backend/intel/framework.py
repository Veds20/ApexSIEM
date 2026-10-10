from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime


class ThreatCategory(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class IntelSource(str, Enum):
    ABUSE_IPDB = "abuseipdb"
    ALIENVAULT_OTX = "alienvault_otx"
    VIRUSTOTAL = "virustotal"
    SHODAN = "shodan"
    CENSYS = "censys"
    GREYNOISE = "greynoise"
    CUSTOM = "custom"


class ThreatIntel(BaseModel):
    indicator: str = Field(..., description="IOC value (IP, domain, hash, etc.)")
    indicator_type: str = Field(..., description="Type: ip, domain, url, hash, email")
    category: ThreatCategory = ThreatCategory.UNKNOWN
    confidence: int = Field(default=0, ge=0, le=100, description="Confidence score 0-100")
    severity: int = Field(default=0, ge=0, le=10, description="Severity 0-10")
    source: IntelSource = IntelSource.CUSTOM
    tags: List[str] = Field(default_factory=list)
    description: str = Field(default="", description="Human-readable description")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    references: List[str] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    enriched_at: datetime = Field(default_factory=datetime.utcnow)


class ThreatIntelEnricher:
    """Base class for threat intelligence enrichment providers."""

    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout

    async def enrich_ip(self, ip: str) -> Optional[ThreatIntel]:
        raise NotImplementedError

    async def enrich_domain(self, domain: str) -> Optional[ThreatIntel]:
        raise NotImplementedError

    async def enrich_hash(self, hash_value: str) -> Optional[ThreatIntel]:
        raise NotImplementedError


class AbuseIPDBEnricher(ThreatIntelEnricher):
    """AbuseIPDB enrichment provider."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    async def enrich_ip(self, ip: str) -> Optional[ThreatIntel]:
        if not self.api_key:
            return None

        import httpx
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.BASE_URL}/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                    headers={"Key": self.api_key, "Accept": "application/json"}
                )
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    return ThreatIntel(
                        indicator=ip,
                        indicator_type="ip",
                        category=ThreatCategory.MALICIOUS if score > 50 else ThreatCategory.SUSPICIOUS,
                        confidence=score,
                        severity=min(score // 10, 10),
                        source=IntelSource.ABUSE_IPDB,
                        tags=data.get("tags", []),
                        description=f"AbuseIPDB: {data.get('totalReports', 0)} reports, {score}% confidence",
                        first_seen=None,
                        last_seen=None,
                        references=[f"https://www.abuseipdb.com/check/{ip}"],
                        raw_data=data
                    )
        except Exception:
            # Provider errors should not prevent the analyst from reviewing the alert.
            return None
        return None


class ThreatIntelManager:
    """Manages providers and caches results in-process."""

    def __init__(self):
        self.providers: List[ThreatIntelEnricher] = []
        self.cache: Dict[str, ThreatIntel] = {}
        self.cache_ttl = 3600

    def add_provider(self, provider: ThreatIntelEnricher):
        self.providers.append(provider)

    async def enrich_ip(self, ip: str) -> Optional[ThreatIntel]:
        return await self._enrich("ip", ip, "enrich_ip")

    async def enrich_domain(self, domain: str) -> Optional[ThreatIntel]:
        return await self._enrich("domain", domain, "enrich_domain")

    async def enrich_hash(self, hash_value: str) -> Optional[ThreatIntel]:
        return await self._enrich("hash", hash_value, "enrich_hash")

    async def _enrich(self, kind: str, value: str, method_name: str) -> Optional[ThreatIntel]:
        cache_key = f"{kind}:{value}"
        cached = self.cache.get(cache_key)
        if cached and (datetime.utcnow() - cached.enriched_at).total_seconds() < self.cache_ttl:
            return cached
        for provider in self.providers:
            result = await getattr(provider, method_name)(value)
            if result:
                self.cache[cache_key] = result
                return result
        return None


threat_intel_manager = ThreatIntelManager()

import os
if os.getenv("ABUSEIPDB_API_KEY"):
    threat_intel_manager.add_provider(AbuseIPDBEnricher(api_key=os.getenv("ABUSEIPDB_API_KEY")))


async def enrich_ip(ip: str) -> Optional[ThreatIntel]:
    return await threat_intel_manager.enrich_ip(ip)


async def enrich_domain(domain: str) -> Optional[ThreatIntel]:
    return await threat_intel_manager.enrich_domain(domain)


async def enrich_hash(hash_value: str) -> Optional[ThreatIntel]:
    return await threat_intel_manager.enrich_hash(hash_value)
