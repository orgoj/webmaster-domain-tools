"""Constants and default values used across the application."""

# DNS Constants
DEFAULT_DNS_TIMEOUT = 5.0  # DNS query timeout in seconds
DEFAULT_DNS_PUBLIC_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]  # Google and Cloudflare DNS

# HTTP Constants
DEFAULT_HTTP_TIMEOUT = 5.0  # HTTP request timeout in seconds (reduced from 10s for faster analysis)
DEFAULT_HTTP_MAX_REDIRECTS = 10  # Maximum number of redirects to follow
MAX_REDIRECT_WARNING = 3  # Warn if redirect chain exceeds this number
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (compatible; WebmasterDomainTool/0.1; "
    "+https://github.com/orgoj/webmaster-domain-tool)"
)

# SSL/TLS Constants
DEFAULT_SSL_PORT = 443
DEFAULT_SSL_TIMEOUT = (
    5.0  # SSL connection timeout in seconds (reduced from 10s for faster analysis)
)
DEFAULT_SSL_EXPIRY_WARNING_DAYS = 14  # Warn if cert expires within this many days
DEFAULT_SSL_EXPIRY_CRITICAL_DAYS = 7  # Critical if cert expires within this many days

# Email Security Constants
DEFAULT_EMAIL_TIMEOUT = 5.0  # DNS query timeout for email records
SPF_MAX_INCLUDES_WARNING = 8  # Warn if SPF includes exceed this number
SPF_MAX_INCLUDES_LIMIT = 10  # SPF RFC 7208 limit for DNS lookups
DEFAULT_DKIM_SELECTORS = [
    "default",
    "google",
    "k1",
    "k2",
    "selector1",
    "selector2",
    "dkim",
    "mail",
    "s1",
    "s2",
]

# RBL Constants
DEFAULT_RBL_TIMEOUT = 5.0  # RBL DNS query timeout in seconds
DEFAULT_RBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
]

# Site Verification Constants
DEFAULT_SITE_VERIFICATION_TIMEOUT = (
    5.0  # HTTP request timeout in seconds (reduced from 10s for faster analysis)
)
MAX_SAN_DISPLAY = 5  # Maximum number of SAN entries to display before truncating

# Tracking code patterns (Google specific - legacy)
# Format: (pattern, description)
TRACKING_PATTERNS = {
    "GTM": (r"GTM-[A-Z0-9]+", "Google Tag Manager"),
    "GA4": (r"G-[A-Z0-9]+", "Google Analytics 4"),
    "GAds": (r"AW-[0-9]+", "Google Ads Conversion"),
    "UA": (r"UA-[0-9]+-[0-9]+", "Universal Analytics"),
    "Google Optimize": (r"OPT-[A-Z0-9]+", "Google Optimize"),
    "Google AdSense": (r"ca-pub-[0-9]+", "Google AdSense"),
}

# Output Display Constants
MAX_TABLE_WIDTH = 120  # Maximum width for Rich tables
