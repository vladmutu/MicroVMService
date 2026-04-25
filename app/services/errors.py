class AnalysisError(Exception):
    """Base class for analysis workflow exceptions."""


class ProtocolError(AnalysisError):
    pass


class PackageResolutionError(AnalysisError):
    pass


class SandboxInfraError(AnalysisError):
    pass


class SandboxTimeoutError(AnalysisError):
    pass
