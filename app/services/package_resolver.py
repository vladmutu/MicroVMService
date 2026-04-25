import hashlib
from dataclasses import dataclass

import httpx

from app.core.config import Settings
from app.services.errors import PackageResolutionError


@dataclass(slots=True)
class ResolvedPackage:
    ecosystem: str
    package_name: str
    package_version: str
    download_url: str
    expected_sha256: str | None
    artifact_bytes: bytes


class PackageResolver:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def resolve(self, ecosystem: str, package_name: str, package_version: str) -> ResolvedPackage:
        timeout = httpx.Timeout(self._settings.package_download_timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            if ecosystem == "pypi":
                url, expected = await self._resolve_pypi(client, package_name, package_version)
            elif ecosystem == "npm":
                url, expected = await self._resolve_npm(client, package_name, package_version)
            else:
                raise PackageResolutionError(f"Unsupported ecosystem: {ecosystem}")

            payload = await self._download(client, url)
            digest = hashlib.sha256(payload).hexdigest()
            if expected and digest != expected:
                raise PackageResolutionError("Artifact checksum mismatch")

            return ResolvedPackage(
                ecosystem=ecosystem,
                package_name=package_name,
                package_version=package_version,
                download_url=url,
                expected_sha256=expected,
                artifact_bytes=payload,
            )

    async def _resolve_pypi(self, client: httpx.AsyncClient, package_name: str, package_version: str) -> tuple[str, str | None]:
        meta_url = f"https://pypi.org/pypi/{package_name}/{package_version}/json"
        response = await client.get(meta_url)
        if response.status_code != 200:
            raise PackageResolutionError("PyPI package version not found")

        data = response.json()
        urls = data.get("urls", [])
        if not urls:
            raise PackageResolutionError("PyPI distribution URLs missing")

        preferred = next((item for item in urls if item.get("packagetype") == "sdist"), urls[0])
        return preferred["url"], preferred.get("digests", {}).get("sha256")

    async def _resolve_npm(self, client: httpx.AsyncClient, package_name: str, package_version: str) -> tuple[str, str | None]:
        meta_url = f"https://registry.npmjs.org/{package_name}/{package_version}"
        response = await client.get(meta_url)
        if response.status_code != 200:
            raise PackageResolutionError("npm package version not found")

        data = response.json()
        dist = data.get("dist") or {}
        tarball = dist.get("tarball")
        if not tarball:
            raise PackageResolutionError("npm tarball URL missing")
        return tarball, None

    async def _download(self, client: httpx.AsyncClient, url: str) -> bytes:
        response = await client.get(url)
        if response.status_code != 200:
            raise PackageResolutionError("Artifact download failed")

        payload = response.content
        if len(payload) > self._settings.package_download_max_bytes:
            raise PackageResolutionError("Artifact exceeds max allowed size")
        return payload
