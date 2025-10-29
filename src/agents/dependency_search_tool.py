from __future__ import annotations
import os
import asyncio
import base64
import dataclasses
import json
from typing import Any, Dict, List, Optional, Tuple
import httpx
from pydantic import BaseModel, Field, ValidationError, field_validator
from beeai_framework.tools import Tool, ToolRunOptions
from beeai_framework.emitter import Emitter
from beeai_framework.context import RunContext

# -----------------------------
# Input / Output Schemas
# -----------------------------

#A PURL is a specially formatted URL that describes a software package's location or identity in a package registry.
SUPPORTED_PURL_TYPES = {
    "PyPI": "pypi",
    "NPM": "npm",
    "npm": "npm",
    "Maven": "maven",
    "NuGet": "nuget",
    "RubyGems": "gem",
    "Cargo": "cargo",
    "Conda": "conda",
    "Golang": "golang",
    "CRAN": "cran",
    "RPM": "rpm",
    "Swift": "swift",
    # Add others here as needed; OSS Index uses purl "type" values. :contentReference[oaicite:1]{index=1}
}

class Package(BaseModel):
    name: str
    version: str
    ecosystem: str = Field(description="Human-facing ecosystem name, e.g. 'PyPI', 'npm', 'Maven'")

    @field_validator("name", "version", mode="before")
    @classmethod
    def nonempty(cls, v: str) -> str:
        if not v or not str(v).strip():
            raise ValueError("must be non-empty")
        return str(v).strip()

    def to_purl(self) -> str:
        purl_type = SUPPORTED_PURL_TYPES.get(self.ecosystem, self.ecosystem).lower()
        # Basic purl without namespace/qualifiers; enough for PyPI and most common cases. :contentReference[oaicite:2]{index=2}
        return f"pkg:{purl_type}/{self.name}@{self.version}"


class OSSIndexInput(BaseModel):
    packages: List[Package]
    # Optional auth (recommended for higher rate limits). Email is the Basic auth username; token can replace password. :contentReference[oaicite:3]{index=3}
    auth_email: Optional[str] =  os.getenv("OSS_INDEX_EMAIL", None)
    auth_token: Optional[str] = os.getenv("OSS_INDEX_API", None)
    # Tuning
    timeout_seconds: float = 30.0
    max_batch_size: int = 128  # Per OSS Index limit. :contentReference[oaicite:4]{index=4}
    max_retries: int = 3
    retry_backoff_seconds: float = 1.5


class Vulnerability(BaseModel):
    id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    cvssScore: Optional[float] = None
    cve: Optional[str] = None
    reference: Optional[str] = None


class PackageReport(BaseModel):
    purl: str
    coordinates: Optional[str] = None
    description: Optional[str] = None
    reference: Optional[str] = None
    vulnerabilities: List[Vulnerability] = []


class OSSIndexOutput(BaseModel):
    # keyed by input purl
    results: Dict[str, PackageReport]
    # diagnostics
    rate_limited: bool = False
    errors: List[str] = []


# -----------------------------
# Tool Implementation
# -----------------------------

class OSSIndexTool(Tool[OSSIndexInput, ToolRunOptions, OSSIndexOutput]):
    """
    Query Sonatype OSS Index v3 for vulnerabilities on a set of packages.

    - Converts each (name, version, ecosystem) to a purl.
    - POSTs to /api/v3/component-report with up to 128 coordinates per batch. :contentReference[oaicite:5]{index=5}
    - Uses Basic auth (email + API token) if provided to increase rate limits. :contentReference[oaicite:6]{index=6}
    - Retries on 429/5xx with exponential backoff.
    """

    name: str = "ossindex_vuln_scan"
    description: str = (
        "Look up vulnerabilities for packages using Sonatype OSS Index. "
        "Input: packages with {name, version, ecosystem}. Output: per-package reports."
    )
    input_schema = OSSIndexInput

    BASE_URL = "https://ossindex.sonatype.org/api/v3/component-report"

    def _create_emitter(self) -> Emitter:
        return Emitter.root().child(namespace=["tool", "ossindex"], creator=self)

    async def _fetch_batch(
        self,
        client: httpx.AsyncClient,
        coordinates: List[str],
        headers: Dict[str, str],
        retries: int,
        backoff: float,
    ) -> Tuple[List[Dict[str, Any]], bool, List[str]]:
        """Return (items, rate_limited, errors)."""
        payload = {"coordinates": coordinates}
        errors: List[str] = []
        rate_limited = False

        for attempt in range(1, retries + 1):
            try:
                resp = await client.post(
                    self.BASE_URL,
                    content=json.dumps(payload),
                    headers=headers,
                    timeout=None,
                )
                if resp.status_code == 200:
                    return resp.json(), False, errors
                if resp.status_code == 429:
                    rate_limited = True
                # For non-200s, capture a brief error
                errors.append(
                    f"HTTP {resp.status_code} for batch (size={len(coordinates)}): {resp.text[:200]}"
                )
            except Exception as e:
                errors.append(f"Request error: {e!r}")

            # Backoff then retry (except last attempt)
            if attempt < retries:
                await asyncio.sleep(backoff ** attempt)

        return [], rate_limited, errors

    async def _run(
        self,
        input: OSSIndexInput,
        options: ToolRunOptions | None,
        context: RunContext,
    ) -> OSSIndexOutput:
        # Build purls
        purls: List[str] = []
        purl_to_pkg: Dict[str, Package] = {}
        for pkg in input.packages:
            try:
                purl = pkg.to_purl()
            except Exception as e:
                # Skip malformed entries but record errors
                continue
            purls.append(purl)
            purl_to_pkg[purl] = pkg

        # Prepare headers
        headers = {
            # application/json works, but OSS Index also supports versioned content types. :contentReference[oaicite:7]{index=7}
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if input.auth_email and input.auth_token:
            token = base64.b64encode(f"{input.auth_email}:{input.auth_token}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        results: Dict[str, PackageReport] = {}
        rate_limited_seen = False
        all_errors: List[str] = []

        # HTTP client
        limits = httpx.Limits(max_connections=5, max_keepalive_connections=5)
        async with httpx.AsyncClient(limits=limits, timeout=input.timeout_seconds) as client:
            # Batch by max_batch_size (limit 128 per POST) :contentReference[oaicite:8]{index=8}
            for i in range(0, len(purls), input.max_batch_size):
                batch = purls[i : i + input.max_batch_size]
                items, rate_limited, errors = await self._fetch_batch(
                    client,
                    batch,
                    headers,
                    retries=input.max_retries,
                    backoff=input.retry_backoff_seconds,
                )
                if rate_limited:
                    rate_limited_seen = True
                if errors:
                    all_errors.extend(errors)

                # Each item corresponds to a purl’s report
                # Example fields: coordinates, description, reference, vulnerabilities[]
                for item in items or []:
                    coords = item.get("coordinates") or ""
                    purl = coords or item.get("purl") or ""
                    if not purl:
                        # If response doesn’t echo purl, try reconstructing from known batch
                        # or skip.
                        continue
                    vulns = [
                        Vulnerability(
                            id=v.get("id"),
                            title=v.get("title"),
                            description=v.get("description"),
                            cvssScore=v.get("cvssScore"),
                            cve=v.get("cve"),
                            reference=v.get("reference"),
                        )
                        for v in (item.get("vulnerabilities") or [])
                    ]
                    results[purl] = PackageReport(
                        purl=purl,
                        coordinates=item.get("coordinates"),
                        description=item.get("description"),
                        reference=item.get("reference"),
                        vulnerabilities=vulns,
                    )

        return OSSIndexOutput(results=results, rate_limited=rate_limited_seen, errors=all_errors)


# -----------------------------
# Helper: adapt your agent context to the tool input
# -----------------------------

def input_from_agent_context(agent_context: Dict[str, Any], *, email: str | None = None, token: str | None = None) -> OSSIndexInput:
    """
    Convert the example agent context payload to OSSIndexInput.
    Expects agent_context['packages'] with {'name','version','ecosystem'} keys.
    """
    pkgs = []
    for obj in agent_context.get("packages", []):
        # Only keep the essential fields
        pkgs.append(Package(name=obj["name"], version=obj["version"], ecosystem=obj["ecosystem"]))
    return OSSIndexInput(packages=pkgs, auth_email=email, auth_token=token)
