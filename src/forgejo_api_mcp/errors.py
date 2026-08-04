"""Domain exceptions shared by the catalog, adapter, and MCP boundary."""


class ForgejoMCPError(Exception):
    """Base class for expected Forgejo MCP failures."""


class InputValidationError(ForgejoMCPError, ValueError):
    """Raised when invocation data violates the bundled Swagger contract."""


class ConfigurationError(ForgejoMCPError, ValueError):
    """Raised when runtime configuration is unsafe or invalid."""
