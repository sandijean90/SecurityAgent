# beeai_github_uvlock_reader_url_minimal.py
import base64
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, field_validator

from beeai_framework.context import RunContext
from beeai_framework.emitter import Emitter
from beeai_framework.tools import JSONToolOutput, Tool, ToolError, ToolRunOptions


# ---------- Utilities ----------

def pep503_normalize(name: str) -> str:
    # PEP 503 normalization: lowercase + collapse runs of [-_.] to single '-'
    n = name.strip().lower()
    return re.sub(r"[-_.]+", "-", n)


def try_load_toml(text: str) -> Optional[Dict[str, Any]]:
    try:
        try:
            import tomllib  # py3.11+
        except ModuleNotFoundError:
            import tomli as tomllib  # fallback
        return tomllib.loads(text)
    except Exception:
        return None


# ---------- Input & Output Schemas ----------

class UvLockReaderInput(BaseModel):
    repo_url: str = Field(
        description=(
            "GitHub repo URL. Examples:\n"
            "- https://github.com/OWNER/REPO\n"
            "- https://github.com/OWNER/REPO/\n"
            "- https://github.com/OWNER/REPO.git\n"
            "- https://github.com/OWNER/REPO/tree/BRANCH_OR_TAG"
        )
    )

    @field_validator("repo_url")
    @classmethod
    def _must_be_github(cls, v: str) -> str:
        parsed = urlparse(v)
        if not parsed.scheme.startswith("http") or "github.com" not in parsed.netloc:
            raise ValueError("repo_url must be an https://github.com/... URL")
        return v


class MinimalPackage(BaseModel):
    # For released packages (preferred for vuln queries)
    name: Optional[str] = None       # normalized
    version: Optional[str] = None
    ecosystem: Optional[str] = None  # "PyPI"

    # For VCS/URL dependencies (when no version available)
    type: Optional[str] = None       # "vcs" | "local" | "url"
    vcs: Optional[str] = None        # "git" etc.
    repo_url: Optional[str] = None
    commit: Optional[str] = None

    # Lightweight metadata
    scope: Optional[str] = None      # "default", "dev", etc.
    direct: Optional[bool] = None
    paths: List[str] = Field(default_factory=list)  # lockfile paths referencing this package


class MinimalResult(BaseModel):
    repo: str                   # "owner/repo"
    ref: str                    # "HEAD" or branch/tag/sha
    files_scanned: List[str]
    packages: List[MinimalPackage]
    stats: Dict[str, Any]       # {"unique_pkgs": int, "skipped_local": int, "truncated": bool}


class MinimalOutput(JSONToolOutput[MinimalResult]):
    pass


# ---------- Tool Implementation ----------

class GitHubUvLockReaderURLMinimal(Tool[UvLockReaderInput, ToolRunOptions, MinimalOutput]):
    """
    Given a GitHub repository URL, return a compact, deduplicated package list extracted
    from all `uv.lock` files suitable for vulnerability queries (OSV, GHSA, etc.).

    No auth (public repos). If the URL includes `/tree/<ref>`, use that ref; else use HEAD.
    """
    name = "GitHubUvLockReaderURLMinimal"
    description = (
        "Parses uv.lock files from a public GitHub repo URL and returns minimal package data "
        "for vulnerability checks (name, version, ecosystem or VCS commit). Uses Git Trees + Contents."
    )
    input_schema = UvLockReaderInput

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)

    def _create_emitter(self) -> Emitter:
        return Emitter.root().child(namespace=["tool", "github", "uvlock_reader_url_minimal"], creator=self)

    # --- URL parsing ---

    @staticmethod
    def _parse_repo_url(repo_url: str) -> Tuple[str, str, str]:
        """
        Parse https://github.com/<owner>/<repo>[/tree/<ref>][...]
        Returns (owner, repo, ref). If no ref provided, returns "HEAD".
        """
        p = urlparse(repo_url)
        parts = [seg for seg in p.path.split("/") if seg]
        if len(parts) < 2:
            raise ToolError("Could not parse owner/repo from repo_url.")
        owner = parts[0]
        repo = parts[1].removesuffix(".git")
        ref = "HEAD"
        if len(parts) >= 4 and parts[2] == "tree" and parts[3]:
            ref = parts[3]
        return owner, repo, ref

    # --- uv.lock parsing ---

    def _extract_packages_from_uv_lock(
        self, text: str, path: str, context: RunContext
    ) -> List[MinimalPackage]:
        """
        Best-effort extractor:
        1) Try TOML parse and look for a `package` array of tables (uv-compatible).
        2) Fallback: regex for name/version pin lines (very small & robust).
        """
        pkgs: List[MinimalPackage] = []

        data = try_load_toml(text)
        if isinstance(data, dict) and isinstance(data.get("package"), list):
            # uv lockfiles commonly store packages as [[package]]
            for entry in data["package"]:
                if not isinstance(entry, dict):
                    continue

                # Direct released package:
                name = entry.get("name")
                version = entry.get("version")
                source = entry.get("source") or {}
                # uv sometimes encodes sources like {"type":"registry","url":"..."} or {"type":"git", ...}
                src_type = (source.get("type") or "").lower() if isinstance(source, dict) else ""

                scope = None
                # uv often has groups/categories; keep one small scope label if present
                if "groups" in entry and isinstance(entry["groups"], list) and entry["groups"]:
                    scope = str(entry["groups"][0])
                elif "category" in entry:
                    scope = str(entry["category"])

                # Infer directness if available (heuristic; uv can include "optional"/"dev" etc.)
                direct = entry.get("direct")
                if isinstance(direct, str):
                    # some tools encode as "true"/"false"
                    direct = direct.lower() == "true"
                if not isinstance(direct, bool):
                    direct = None

                if name and version:
                    pkgs.append(MinimalPackage(
                        name=pep503_normalize(str(name)),
                        version=str(version),
                        ecosystem="PyPI",
                        scope=scope,
                        direct=direct,
                        paths=[path],
                    ))
                    continue

                # VCS/URL dependency path
                if src_type in {"git", "vcs"} or entry.get("vcs"):
                    vcs = "git"
                    repo_url = None
                    commit = None

                    if isinstance(source, dict):
                        repo_url = source.get("url") or source.get("repository") or source.get("repo")
                        commit = source.get("resolved_reference") or source.get("commit") or source.get("rev")

                    # Some uv locks may put VCS info directly on the entry
                    repo_url = repo_url or entry.get("url")
                    commit = commit or entry.get("commit")

                    pkgs.append(MinimalPackage(
                        type="vcs",
                        vcs=vcs,
                        repo_url=repo_url,
                        commit=commit,
                        scope=scope,
                        direct=direct,
                        paths=[path],
                    ))
                    continue

                # Local/path deps or unrecognized forms: tag as local so the scanner can skip
                if entry.get("path"):
                    pkgs.append(MinimalPackage(
                        type="local",
                        scope=scope,
                        direct=direct,
                        paths=[path],
                    ))
            return pkgs

        # ---- Fallback: tiny regex extractor for lines like "name = 'pkg', version = '1.2.3'" ----
        # This is intentionally minimal; it won’t pull extras/markers, just name/version pairs.
        # It reduces to usable vuln queries even if TOML structure differs.
        name_version_pairs = re.findall(
            r"""(?mi)^\s*name\s*=\s*["']([^"']+)["'].*?^\s*version\s*=\s*["']([^"']+)["']""",
            text,
            flags=re.MULTILINE | re.DOTALL,
        )
        for name, version in name_version_pairs:
            pkgs.append(MinimalPackage(
                name=pep503_normalize(name),
                version=version,
                ecosystem="PyPI",
                paths=[path],
            ))
        return pkgs

    # --- Dedup across all lockfiles ---

    @staticmethod
    def _dedupe_global(packages: List[MinimalPackage]) -> List[MinimalPackage]:
        # Two keys: released packages vs VCS deps
        released_key = lambda p: ("released", p.name or "", p.version or "", p.ecosystem or "")
        vcs_key = lambda p: ("vcs", p.vcs or "", p.repo_url or "", p.commit or "")

        seen: Dict[Tuple[str, str, str, str], MinimalPackage] = {}

        for p in packages:
            if p.type == "vcs" or (p.repo_url and p.commit):
                key = vcs_key(p)
            elif p.name and p.version:
                key = released_key(p)
            else:
                # local/unknown — keep by a simple tuple to avoid collapsing dissimilar items
                key = ("other", p.type or "", p.name or "", p.version or "")

            if key in seen:
                # merge paths, prefer existing small metadata footprint
                existing = seen[key]
                merged_paths = list({*existing.paths, *p.paths})
                existing.paths = merged_paths
                # prefer keeping a defined scope/direct if one is missing in the other
                if existing.scope is None and p.scope is not None:
                    existing.scope = p.scope
                if existing.direct is None and p.direct is not None:
                    existing.direct = p.direct
            else:
                seen[key] = p

        return list(seen.values())

    # --- Core run ---

    async def _run(
        self,
        input: UvLockReaderInput,
        options: ToolRunOptions | None,
        context: RunContext
    ) -> MinimalOutput:
        owner, repo, ref = self._parse_repo_url(input.repo_url)
        headers = {"Accept": "application/vnd.github+json"}

        async with httpx.AsyncClient(timeout=30) as client:
            # 1) Recursive tree fetch (fast path)
            tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}?recursive=1"
            t_resp = await client.get(tree_url, headers=headers)
            if t_resp.status_code == 404:
                raise ToolError(f"Repo or ref not found: {owner}/{repo}@{ref}")
            t_resp.raise_for_status()
            t_json = t_resp.json()

            paths: List[str] = []
            truncated = bool(t_json.get("truncated"))
            for e in t_json.get("tree", []) or []:
                if e.get("type") == "blob" and str(e.get("path", "")).endswith("uv.lock"):
                    paths.append(e["path"])

            # 1b) Fallback traversal if truncated
            if truncated and not paths:
                root_id = t_json.get("sha") or ref
                queue: List[str] = [root_id]
                seen: set[str] = set()
                while queue:
                    node = queue.pop()
                    if node in seen:
                        continue
                    seen.add(node)
                    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{node}"
                    r = await client.get(url, headers=headers)
                    if r.status_code == 404:
                        continue
                    r.raise_for_status()
                    j = r.json()
                    for e in j.get("tree", []) or []:
                        etype = e.get("type")
                        epath = e.get("path", "")
                        if etype == "tree" and e.get("sha"):
                            queue.append(e["sha"])
                        elif etype == "blob" and epath.endswith("uv.lock"):
                            paths.append(epath)

            files_scanned: List[str] = []
            all_packages: List[MinimalPackage] = []
            skipped_local = 0

            # 2) Fetch + parse each lockfile
            for p in paths:
                contents_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{p}"
                if ref and ref != "HEAD":
                    contents_url += f"?ref={ref}"

                c_resp = await client.get(contents_url, headers=headers)
                if c_resp.status_code == 404:
                    continue
                c_resp.raise_for_status()
                cj = c_resp.json()

                encoded = cj.get("content")
                if not encoded or cj.get("encoding") != "base64":
                    context.emitter.info(f"Skipping non-base64 or empty content at {p}")
                    continue

                raw = base64.b64decode(encoded)
                text = raw.decode("utf-8", errors="replace")

                pkgs = self._extract_packages_from_uv_lock(text, p, context)
                if pkgs:
                    files_scanned.append(p)
                    all_packages.extend(pkgs)

            # 3) Global de-dup + tiny stats
            deduped = self._dedupe_global(all_packages)
            # Count how many are clearly local/path-only (not useful for public vuln feeds)
            for pkg in deduped:
                if pkg.type == "local" and not (pkg.name and pkg.version):
                    skipped_local += 1

            result = MinimalResult(
                repo=f"{owner}/{repo}",
                ref=ref,
                files_scanned=files_scanned,
                packages=deduped,
                stats={
                    "unique_pkgs": len(deduped),
                    "skipped_local": skipped_local,
                    "truncated": bool(truncated),
                },
            )
            return MinimalOutput(result)


# (Optional) quick local test runner
if __name__ == "__main__":
    import asyncio

    async def demo():
        tool = GitHubUvLockReaderURLMinimal()
        # With explicit branch
        out1 = await tool.run(UvLockReaderInput(repo_url="https://github.com/sandijean90/VulnerabilityAgent/tree/main"))
        print("[1]", out1.result.model_dump())

        # Default branch (HEAD)
        out2 = await tool.run(UvLockReaderInput(repo_url="https://github.com/i-am-bee/beeai-framework-py-starter"))
        print("[2]", out2.result.model_dump())

    asyncio.run(demo())
