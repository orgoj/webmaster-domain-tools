# Webmaster Domain Tools - Analyzers Architecture Analysis

## Overview
This document provides a detailed analysis of three key analyzers and how to use them as dependencies for building new validators.

---

## 1. DNS Analyzer (`analyzers/dns_analyzer.py`)

### Purpose
Performs comprehensive DNS analysis including record lookups, DNSSEC validation, PTR checks, and MX validation.

### Metadata
| Property | Value |
|----------|-------|
| `analyzer_id` | `"dns"` |
| `name` | `"DNS Analysis"` |
| `category` | `"general"` |
| `depends_on` | `[]` (no dependencies) |
| `timeout_default` | 5.0 seconds |

### Configuration (`DNSConfig`)
```python
class DNSConfig(AnalyzerConfig):
    nameservers: list[str] | None = None  # Custom nameservers (uses system default if None)
    check_dnssec: bool = True              # Enable/disable DNSSEC validation
    warn_www_not_cname: bool = False       # Warn if www uses A/AAAA instead of CNAME
    skip_www: bool = False                 # Skip www subdomain checking
    timeout: float = 5.0                   # DNS query timeout
```

### DNS Records Collected
The analyzer queries the following record types:
```
["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "CNAME"]
```

### Result Data Structure (`DNSAnalysisResult`)

#### Main Fields
```python
@dataclass
class DNSAnalysisResult:
    domain: str                           # Domain analyzed
    records: dict[str, list[DNSRecord]]  # Keyed by "domain:RECORDTYPE"
    ptr_records: dict[str, str]          # IP -> PTR hostname mapping
    dnssec: DNSSECInfo | None            # DNSSEC validation info
    info_messages: list[str]             # Informational messages
    errors: list[str]                    # Critical errors
    warnings: list[str]                  # Warnings
```

#### Record Keys Format
- `"example.com:A"` → List of A records
- `"example.com:AAAA"` → List of IPv6 records
- `"example.com:MX"` → List of mail server records
- `"example.com:CNAME"` → Canonical name records
- `"example.com:CNAME_A"` → A records resolved from CNAME target
- `"example.com:TXT"` → Text records
- `"example.com:NS"` → Nameserver records
- `"example.com:SOA"` → Start of Authority record
- `"example.com:CAA"` → Certificate Authority Authorization records
- `"www.example.com:*"` → Same structure for www subdomain

#### DNSRecord Dataclass
```python
@dataclass
class DNSRecord:
    record_type: str  # "A", "MX", "CNAME", etc.
    name: str         # Full domain name
    value: str        # Record value (formatted)
    ttl: int | None   # Time to live in seconds
```

#### DNSSECInfo Dataclass
```python
@dataclass
class DNSSECInfo:
    enabled: bool                    # DNSSEC is configured
    valid: bool                      # DNSSEC validation passed
    has_dnskey: bool                # DNSKEY records present
    has_ds: bool                    # DS records in parent zone present
    errors: list[str] = []          # Errors in DNSSEC config
    warnings: list[str] = []        # Warnings about DNSSEC
```

### Special DNS Rules Implemented

1. **CNAME/A Record Coexistence Rule**
   - If domain has CNAME record, A/AAAA records are automatically removed
   - Prevents showing both (DNS doesn't allow them to coexist)
   - Uses key `"domain:CNAME_A"` to show resolved A records from CNAME target

2. **WWW CNAME Best Practice**
   - When `warn_www_not_cname=True`, warns if www subdomain uses direct A/AAAA records
   - Recommends using CNAME for easier management

3. **MX Record Validation**
   - Validates that MX hosts actually resolve
   - Reports warnings for unresolvable mail servers

4. **PTR Record Checking**
   - Performs reverse DNS (PTR) lookups for all A records
   - Validates forward/reverse DNS consistency
   - Stores in `ptr_records` dict as IP → hostname mapping

### Example: Accessing DNS Data
```python
# Get all A records for the main domain
a_records = result.records.get("example.com:A", [])
for record in a_records:
    print(f"IP: {record.value}, TTL: {record.ttl}")

# Get A records resolved from CNAME
if "example.com:CNAME" in result.records:
    cname_records = result.records["example.com:CNAME"]
    resolved_a = result.records.get("example.com:CNAME_A", [])
    print(f"CNAME: {cname_records[0].value} → A: {resolved_a[0].value}")

# Check DNSSEC status
if result.dnssec:
    if result.dnssec.valid:
        print("DNSSEC properly configured")
    elif result.dnssec.warnings:
        for warning in result.dnssec.warnings:
            print(f"DNSSEC Warning: {warning}")

# Check reverse DNS
for ip, hostname in result.ptr_records.items():
    print(f"{ip} → {hostname}")
```

---

## 2. Email Security Analyzer (`analyzers/email_security.py`)

### Purpose
Analyzes email authentication and security records including SPF, DKIM, DMARC, BIMI, MTA-STS, and TLS-RPT.

### Metadata
| Property | Value |
|----------|-------|
| `analyzer_id` | `"email"` |
| `name` | `"Email Security"` |
| `category` | `"security"` |
| `depends_on` | `["dns"]` (needs DNS TXT records) |

### Configuration (`EmailConfig`)
```python
class EmailConfig(AnalyzerConfig):
    dkim_selectors: list[str] = [         # Selectors to check
        "default", "google", "k1", "k2",   # Defaults defined in constants
        "selector1", "selector2", "dkim", "mail", "s1", "s2"
    ]
    check_bimi: bool = True                # Enable BIMI checking
    check_mta_sts: bool = True             # Enable MTA-STS checking
    check_tls_rpt: bool = True             # Enable TLS-RPT checking
    nameservers: list[str] | None = None   # Custom nameservers
    timeout: float = 5.0                   # DNS query timeout
```

### Result Data Structure (`EmailSecurityResult`)

#### Main Fields
```python
@dataclass
class EmailSecurityResult:
    domain: str                           # Domain analyzed
    spf: SPFRecord | None                # SPF record info
    dkim: dict[str, DKIMRecord]          # Keyed by selector (e.g., {"default": DKIMRecord})
    dmarc: DMARCRecord | None            # DMARC record info
    dkim_selectors_searched: list[str]   # Which selectors were checked
    bimi: BIMIRecord | None              # BIMI record info
    mta_sts: MTASTSRecord | None         # MTA-STS info
    tls_rpt: TLSRPTRecord | None         # TLS-RPT info
    errors: list[str]                    # Errors
    warnings: list[str]                  # Warnings
```

### SPF Record Structure

#### SPFRecord Dataclass
```python
@dataclass
class SPFRecord:
    record: str                  # Full SPF record text
    mechanisms: list[str]        # Parsed mechanisms (e.g., ["include:sendgrid.net", "ip4:192.168.1.1"])
    qualifier: str = "~all"      # Final qualifier: "+all", "-all", "~all", "?all"
    is_valid: bool = True        # Record validity
    errors: list[str] = []       # Parsing/validation errors
    warnings: list[str] = []     # Warnings (weak policies, etc.)
```

#### SPF Parsing Details
- Extracts mechanisms starting with: `ip4:`, `ip6:`, `a:`, `mx:`, `include:`, `exists:`
- Identifies qualifier: `+all` (pass all), `-all` (hard fail), `~all` (soft fail), `?all` (neutral)
- Validates:
  - Warns if using `+all` (allows all senders, insecure)
  - Warns if using `?all` (neutral, not recommended)
  - Warns if include count > 8 (SPF limit is 10 DNS lookups)
  - Warns if no mechanisms defined

#### Example SPF Parsing
```python
# Raw: "v=spf1 include:sendgrid.net ip4:192.168.1.1 ~all"
# Parsed to:
spf.mechanisms = ["include:sendgrid.net", "ip4:192.168.1.1"]
spf.qualifier = "~all"
```

### DKIM Record Structure

#### DKIMRecord Dataclass
```python
@dataclass
class DKIMRecord:
    selector: str              # DKIM selector (e.g., "default")
    record: str                # Full DKIM TXT record
    version: str = ""          # v= tag value (usually "DKIM1")
    key_type: str = ""         # k= tag (usually "rsa" or "ed25519")
    public_key: str = ""       # p= tag (base64 encoded public key)
    is_valid: bool = True      # Record validity
    errors: list[str] = []     # Errors (missing p= tag, etc.)
    warnings: list[str] = []   # Warnings (unknown version, deprecated key type)
```

#### DKIM Location
- DNS query: `{selector}._domainkey.{domain}`
- Example: `default._domainkey.example.com`

#### DKIM Parsing Details
- Splits record by semicolons and parses `key=value` pairs
- Extracts:
  - `v=` → version (usually "DKIM1")
  - `k=` → key type (rsa, ed25519)
  - `p=` → public key (base64, can be empty for revoked keys)
- Validates:
  - Must have `p=` tag (even if empty for revoked)
  - Warns about unknown versions
  - Warns about non-standard key types

#### Example DKIM Record
```
default._domainkey.example.com TXT:
"v=DKIM1; k=rsa; p=MIGfMA0GCS..."

# Parsed to:
dkim["default"].version = "DKIM1"
dkim["default"].key_type = "rsa"
dkim["default"].public_key = "MIGfMA0GCS..."
```

### DMARC Record Structure

#### DMARCRecord Dataclass
```python
@dataclass
class DMARCRecord:
    record: str                 # Full DMARC TXT record
    policy: str = ""            # p= value: "reject", "quarantine", "none"
    subdomain_policy: str = ""  # sp= value (subdomain policy)
    percentage: int = 100       # pct= value (% of messages policy applies to)
    rua: list[str] = []         # Aggregate report addresses (rua= tag)
    ruf: list[str] = []         # Forensic report addresses (ruf= tag)
    is_valid: bool = True       # Record validity
    errors: list[str] = []      # Errors (missing policy, etc.)
    warnings: list[str] = []    # Warnings (weak policy, missing reporting, etc.)
```

#### DMARC Location
- DNS query: `_dmarc.{domain}`
- Example: `_dmarc.example.com`

#### DMARC Parsing Details
- Splits record by semicolons and parses `key=value` pairs
- Extracts:
  - `p=` → policy (required)
  - `sp=` → subdomain policy
  - `pct=` → percentage (defaults to 100)
  - `rua=` → comma-separated aggregate report addresses
  - `ruf=` → comma-separated forensic report addresses
- Validates:
  - Errors if no policy defined
  - Warns if policy is "none" (monitoring only, should use quarantine/reject)
  - Warns if percentage < 100 (partial policy application)
  - Warns if no rua address configured (important for monitoring)

#### Example DMARC Record
```
_dmarc.example.com TXT:
"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com"

# Parsed to:
dmarc.policy = "reject"
dmarc.rua = ["mailto:dmarc@example.com"]
dmarc.ruf = ["mailto:forensics@example.com"]
```

### BIMI Record Structure

#### BIMIRecord Dataclass
```python
@dataclass
class BIMIRecord:
    domain: str                 # Domain analyzed
    record_found: bool = False  # If record exists
    record_value: str | None = None  # Full BIMI record
    logo_url: str | None = None      # l= tag (logo URL)
    vmc_url: str | None = None       # a= tag (Verified Mark Certificate URL)
    errors: list[str] = []      # Errors
    warnings: list[str] = []    # Warnings
```

#### BIMI Location
- DNS query: `default._bimi.{domain}`
- Example: `default._bimi.example.com`

### MTA-STS Record Structure

#### MTASTSRecord Dataclass
```python
@dataclass
class MTASTSRecord:
    domain: str                  # Domain analyzed
    record_found: bool = False   # If DNS record exists
    record_value: str | None = None  # Full DNS record (v=STSv1)
    policy_found: bool = False   # If policy file was found
    policy_content: str | None = None  # Full policy file content
    policy_mode: str | None = None     # testing, enforce, or none
    policy_max_age: int | None = None  # Max age in seconds
    mx_patterns: list[str] = []  # MX hostname patterns from policy
    errors: list[str] = []       # Errors
    warnings: list[str] = []     # Warnings
```

#### MTA-STS Lookup Process
1. DNS lookup: `_mta-sts.{domain}` for TXT record
2. If found, fetch: `https://mta-sts.{domain}/.well-known/mta-sts.txt`
3. Parses policy:
   - `mode:` → enforce, testing, or none
   - `max_age:` → seconds
   - `mx:` → hostname patterns (can have wildcards)

### TLS-RPT Record Structure

#### TLSRPTRecord Dataclass
```python
@dataclass
class TLSRPTRecord:
    domain: str                  # Domain analyzed
    record_found: bool = False   # If record exists
    record_value: str | None = None  # Full TLS-RPT record
    reporting_addresses: list[str] = []  # rua= addresses
    errors: list[str] = []       # Errors
    warnings: list[str] = []     # Warnings
```

#### TLS-RPT Location
- DNS query: `_smtp._tls.{domain}`
- Example: `_smtp._tls.example.com`

### Example: Accessing Email Data
```python
# Check SPF
if result.spf:
    if result.spf.is_valid:
        print(f"SPF Qualifier: {result.spf.qualifier}")
        print(f"Mechanisms: {result.spf.mechanisms}")
    if result.spf.warnings:
        print(f"SPF Warnings: {result.spf.warnings}")

# Check DKIM
if result.dkim:
    for selector, dkim_record in result.dkim.items():
        print(f"DKIM[{selector}]: v={dkim_record.version}, k={dkim_record.key_type}")
        if dkim_record.errors:
            print(f"  Errors: {dkim_record.errors}")

# Check DMARC
if result.dmarc:
    print(f"DMARC Policy: {result.dmarc.policy}")
    print(f"Reporting: {result.dmarc.rua}")
    if result.dmarc.percentage < 100:
        print(f"Policy applies to {result.dmarc.percentage}% of messages")

# Check MTA-STS
if result.mta_sts and result.mta_sts.policy_found:
    print(f"MTA-STS Mode: {result.mta_sts.policy_mode}")
    print(f"MX Patterns: {result.mta_sts.mx_patterns}")
```

---

## 3. HTTP Analyzer (`analyzers/http_analyzer.py`)

### Purpose
Analyzes HTTP/HTTPS responses, redirect chains, SSL verification, and can check specific file paths.

### Metadata
| Property | Value |
|----------|-------|
| `analyzer_id` | `"http"` |
| `name` | `"HTTP/HTTPS Analysis"` |
| `category` | `"general"` |
| `depends_on` | `["dns"]` (needs DNS resolution) |

### Configuration (`HTTPConfig`)
```python
class HTTPConfig(AnalyzerConfig):
    timeout: float = 5.0                    # Request timeout
    max_redirects: int = 10                 # Max redirects to follow
    user_agent: str = "Mozilla/5.0..."      # Custom user agent
    skip_www: bool = False                  # Skip www subdomain testing
```

### Result Data Structure (`HTTPAnalysisResult`)

#### Main Fields
```python
@dataclass
class HTTPAnalysisResult:
    domain: str                           # Domain analyzed
    chains: list[RedirectChain]           # All redirect chains tested
    preferred_final_url: str | None       # Best final URL (HTTPS www preferred)
    path_check_result: PathCheckResult | None  # Result of path check if performed
    errors: list[str]                    # Errors
    warnings: list[str]                  # Warnings
```

### Redirect Chain Structure

#### RedirectChain Dataclass
```python
@dataclass
class RedirectChain:
    start_url: str                    # Initial URL tested
    final_url: str                    # Final URL after redirects
    responses: list[HTTPResponse]     # All responses in chain
    total_time: float = 0.0           # Total request time
```

#### HTTPResponse Dataclass
```python
@dataclass
class HTTPResponse:
    url: str                          # Current URL
    status_code: int                  # HTTP status (200, 301, 302, etc.)
    headers: dict[str, str]           # Response headers
    redirect_to: str | None = None    # Location header if redirect
    response_time: float = 0.0        # Request time in seconds
    ssl_verified: bool = True         # SSL verification status
    error: str | None = None          # Error message if request failed
```

### URLs Tested by Default
```
http://example.com
https://example.com
http://www.example.com         (unless skip_www=True)
https://www.example.example.com (unless skip_www=True)
```

### Path Checking

#### PathCheckResult Dataclass
```python
@dataclass
class PathCheckResult:
    path: str                    # Path checked (e.g., "/.wdt.test.txt")
    full_url: str               # Complete URL tested
    status_code: int | None = None  # HTTP response code
    content_length: int | None = None  # Response content length in bytes
    response_time: float = 0.0  # Request time in seconds
    error: str | None = None    # Error message if failed
    success: bool = False       # Whether check succeeded (200 + non-empty content)
```

#### check_path() Method
```python
# Public method to check a specific file/path
result = http_analyzer.check_path(
    base_url="https://example.com",
    path="/.well-known/robots.txt",
    config=http_config
)

if result.success:
    print(f"Found: {result.full_url} ({result.content_length} bytes)")
else:
    print(f"Error: {result.error}")
```

### Preferred URL Selection Priority
The analyzer automatically selects the best final URL in this order:
1. `https://www.{domain}` with 200 status
2. `https://{domain}` with 200 status
3. `http://www.{domain}` with 200 status
4. `http://{domain}` with 200 status
5. First successful URL if none above match

### Validation & Warnings

The analyzer validates redirect chains and adds warnings for:
1. **HTTP on final URL** - Site doesn't use HTTPS
2. **No HTTPS redirect** - HTTP doesn't redirect to HTTPS
3. **Too many redirects** - Chain > 3 responses
4. **302 instead of 301** - Using temporary instead of permanent redirects

### Example: Accessing HTTP Data
```python
# Check if any endpoint succeeded
successful_chains = [
    c for c in result.chains
    if c.responses and c.responses[-1].status_code == 200
]
print(f"{len(successful_chains)} successful endpoints")

# Check redirect chain
for chain in result.chains:
    if len(chain.responses) > 1:
        print(f"Redirect: {chain.start_url} → {chain.final_url}")
        for resp in chain.responses:
            if resp.redirect_to:
                print(f"  {resp.status_code} → {resp.redirect_to}")
            else:
                print(f"  {resp.status_code} (final)")

# Check preferred URL
if result.preferred_final_url:
    print(f"Site runs at: {result.preferred_final_url}")

# Check for SSL errors
for chain in result.chains:
    for response in chain.responses:
        if not response.ssl_verified:
            print(f"SSL Error: {response.url}: {response.error}")
```

---

## 4. Using Analyzers as Dependencies

### How Dependency Resolution Works

When an analyzer declares dependencies, the registry automatically ensures they run first:

```python
@registry.register
class MyValidator:
    analyzer_id = "my-validator"
    depends_on = ["dns", "http", "email"]  # These run FIRST

    def analyze(self, domain: str, config: MyConfig) -> MyResult:
        # Results from dependencies are available in CLI/registry context
        # BUT: Each analyzer is called independently with just domain string
        # Dependencies are resolved by CLI/registry, not passed as parameters
```

### Important: Dependencies Don't Receive Other Results

The `analyze()` method signature is always:
```python
def analyze(self, domain: str, config: MyConfig) -> MyResult:
```

**Dependencies are NOT passed as parameters!** Instead:
- The registry ensures execution order
- Each analyzer is independent and queries fresh data
- This maintains modularity and prevents tight coupling

### Example: Building a Validator That Uses DNS Data

If you want to build a validator that checks DNS consistency:

```python
from dataclasses import dataclass, field
from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor

class DNSValidationConfig(AnalyzerConfig):
    """Validates DNS configuration consistency."""
    pass

@dataclass
class DNSValidationResult:
    domain: str
    a_records_exist: bool = False
    cname_exists: bool = False
    has_cname_a_mismatch: bool = False
    issues: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

@registry.register
class DNSValidator:
    analyzer_id = "dns-validator"
    name = "DNS Validation"
    description = "Validates DNS record consistency"
    category = "general"
    icon = "check"
    config_class = DNSValidationConfig
    depends_on = ["dns"]  # Ensures DNS runs first

    def analyze(self, domain: str, config: DNSValidationConfig) -> DNSValidationResult:
        """
        Validate DNS records.

        Note: We query DNS again independently - dependencies don't pass results!
        """
        result = DNSValidationResult(domain=domain)

        # Create our own DNS analyzer to check consistency
        from .dns_analyzer import DNSAnalyzer, DNSConfig
        from .dns_utils import create_resolver

        dns_analyzer = DNSAnalyzer()
        dns_config = DNSConfig()
        dns_result = dns_analyzer.analyze(domain, dns_config)

        # Now validate using DNS results
        a_key = f"{domain}:A"
        cname_key = f"{domain}:CNAME"
        cname_a_key = f"{domain}:CNAME_A"

        if a_key in dns_result.records and dns_result.records[a_key]:
            result.a_records_exist = True

        if cname_key in dns_result.records and dns_result.records[cname_key]:
            result.cname_exists = True

            # Check if CNAME is properly resolved
            if cname_a_key not in dns_result.records:
                result.has_cname_a_mismatch = True
                result.issues.append("CNAME found but A records not resolved")

        if result.cname_exists and result.a_records_exist:
            result.errors.append("Both CNAME and A records found (DNS rule violation)")

        return result

    def describe_output(self, result: DNSValidationResult) -> OutputDescriptor:
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        if result.cname_exists:
            descriptor.add_row(
                label="CNAME",
                value="Found",
                style_class="success",
                severity="info"
            )

        if result.a_records_exist:
            descriptor.add_row(
                label="A Records",
                value="Found",
                style_class="success",
                severity="info"
            )

        for issue in result.issues:
            descriptor.add_row(
                value=issue,
                style_class="warning",
                severity="warning"
            )

        for error in result.errors:
            descriptor.add_row(
                value=error,
                style_class="error",
                severity="error"
            )

        return descriptor

    def to_dict(self, result: DNSValidationResult) -> dict:
        return {
            "domain": result.domain,
            "a_records_exist": result.a_records_exist,
            "cname_exists": result.cname_exists,
            "has_cname_a_mismatch": result.has_cname_a_mismatch,
            "issues": result.issues,
            "errors": result.errors,
            "warnings": result.warnings,
        }
```

### Key Design Principles for Dependencies

1. **Independent Execution**: Each analyzer runs independently
   - Don't expect dependency results to be passed
   - Instantiate and call dependent analyzers if needed
   - This maintains decoupling

2. **Dependency Declaration**:
   - Used only for execution ordering
   - Tells system: "I need these to run first"
   - Doesn't affect what data you receive

3. **Module Imports**:
   ```python
   # DON'T do this at module level (tight coupling):
   from .dns_analyzer import DNSAnalyzer  # Circular imports possible

   # DO this at method level (loose coupling):
   def analyze(self, domain: str, config):
        from .dns_analyzer import DNSAnalyzer  # Import only when needed
   ```

4. **Result Access Pattern**:
   - You must query the data yourself
   - Use public methods (analyzer.analyze())
   - Create fresh instances if needed
   - This maintains test isolation

---

## Summary Table: Analyzer Capabilities

| Feature | DNS | Email | HTTP |
|---------|-----|-------|------|
| Record Types | A, AAAA, MX, TXT, NS, SOA, CAA, CNAME | SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT | Redirect chains, SSL status |
| Dependencies | None | DNS (TXT records) | DNS (for resolution) |
| Key Validations | DNSSEC, CNAME rules, PTR lookups | SPF mechanisms, DMARC policy, DKIM keys | Redirect chains, HTTPS usage, SSL verification |
| Path Checking | No | No | Yes (check_path method) |
| CNAME Resolution | Yes | No | No |
| External HTTP Calls | No | Yes (MTA-STS policy fetch) | Yes |
| Result Complexity | Medium | High (6 record types) | Medium |

---

## Key Takeaways for Building New Analyzers

1. **Use Existing Analyzers as Dependencies**
   - Declare in `depends_on = ["dns", "http"]`
   - Import and instantiate the analyzer class
   - Call `analyze()` method with domain and config

2. **Don't Expect Results to be Passed**
   - Dependencies are execution ordering only
   - Query fresh data if needed
   - Import analyzer classes locally to avoid circular imports

3. **Follow the Protocol**
   - Implement: `analyze()`, `describe_output()`, `to_dict()`
   - Use semantic styling (no hardcoded colors)
   - Track errors/warnings properly

4. **Access Dependency Data**
   ```python
   # Pattern for accessing dependency data
   def analyze(self, domain: str, config: MyConfig) -> MyResult:
       # Import locally to avoid circular imports
       from .dns_analyzer import DNSAnalyzer, DNSConfig

       # Create instances
       dns_analyzer = DNSAnalyzer()
       dns_config = DNSConfig()

       # Call analyze
       dns_result = dns_analyzer.analyze(domain, dns_config)

       # Use the result data
       if "example.com:A" in dns_result.records:
           # Process A records

       return my_result
   ```

5. **Error Handling**
   - Dependencies may fail (DNS timeout, network issues)
   - Check `result.errors` and `result.warnings`
   - Add your own validation errors appropriately
