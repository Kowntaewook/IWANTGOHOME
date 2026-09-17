"""Deterministic, offline scouts over already-sanitized immutable records."""

from .auth_tenant import AuthTenantScout
from .browser_trust import BrowserTrustScout
from .capability import CapabilityScout
from .hidden_api import HiddenAPIScout
from .outbound import OutboundHTTPScout
from .parser_boundary import ParserBoundaryScout
from .temporal import TemporalChangeScout


SCOUTS = (
    AuthTenantScout,
    CapabilityScout,
    ParserBoundaryScout,
    OutboundHTTPScout,
    HiddenAPIScout,
    BrowserTrustScout,
    TemporalChangeScout,
)

__all__ = ["SCOUTS", *(scout.__name__ for scout in SCOUTS)]
