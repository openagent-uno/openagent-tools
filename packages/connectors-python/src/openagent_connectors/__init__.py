"""Shared connectors; host products supply authorization and credential storage."""
from .runner import ConnectorRunner, ConnectorError

__all__ = ["ConnectorRunner", "ConnectorError"]
