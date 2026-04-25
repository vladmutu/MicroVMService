from abc import ABC, abstractmethod

from app.models.contracts import AnalyzeRequest
from app.services.package_resolver import ResolvedPackage
from app.services.telemetry import Telemetry


class SandboxRunner(ABC):
    @abstractmethod
    async def run(
        self,
        request: AnalyzeRequest,
        package: ResolvedPackage,
        timeout_seconds: float,
        job_id: str | None = None,
    ) -> Telemetry:
        raise NotImplementedError
