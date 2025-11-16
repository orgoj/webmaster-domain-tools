"""DNS resolver utilities for analyzers."""

import logging

import dns.resolver

from ..constants import DEFAULT_DNS_PUBLIC_SERVERS

logger = logging.getLogger(__name__)


def create_resolver(
    nameservers: list[str] | None = None,
    timeout: float = 5.0,
) -> dns.resolver.Resolver:
    """
    Create a DNS resolver with fallback to public DNS servers.

    This utility centralizes DNS resolver creation logic that was previously
    duplicated across multiple analyzers. It handles:
    - System DNS configuration with fallback
    - Custom nameserver configuration
    - Public DNS fallback when system DNS is unavailable
    - Timeout configuration

    Args:
        nameservers: Custom nameservers to use (optional).
                    If None, will try system DNS first, then fallback to public DNS.
        timeout: DNS query timeout in seconds (default: 5.0)

    Returns:
        Configured DNS resolver ready for use

    Example:
        >>> resolver = create_resolver(timeout=10.0)
        >>> answers = resolver.resolve('example.com', 'A')
    """
    # Try to create resolver with system config, fallback to manual config
    try:
        resolver = dns.resolver.Resolver()
        # Check if we have nameservers
        if not resolver.nameservers:
            raise dns.resolver.NoResolverConfiguration("no nameservers")
    except (dns.resolver.NoResolverConfiguration, OSError):
        # System DNS not available, create unconfigured resolver
        resolver = dns.resolver.Resolver(configure=False)
        logger.debug("System DNS not available, using public DNS servers")

    # Override with provided nameservers or use public DNS
    if nameservers:
        resolver.nameservers = nameservers
        logger.debug(f"Using custom nameservers: {', '.join(nameservers)}")
    elif not resolver.nameservers:
        # Use public DNS servers as fallback
        resolver.nameservers = DEFAULT_DNS_PUBLIC_SERVERS
        logger.debug(
            f"Using fallback public DNS servers: {', '.join(DEFAULT_DNS_PUBLIC_SERVERS)}"
        )

    # Set timeout
    resolver.timeout = timeout
    resolver.lifetime = timeout

    return resolver
