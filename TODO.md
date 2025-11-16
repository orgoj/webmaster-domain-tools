# TODO - Webmaster Domain Tools

This file tracks planned improvements and enhancements identified during code reviews.

## High Priority

### Testing
- [ ] Add comprehensive unit tests for all analyzer modules
  - [ ] HTTP analyzer tests with mocked responses
  - [ ] SSL analyzer tests with certificate validation
  - [ ] Email security analyzer tests (SPF/DKIM/DMARC)
  - [ ] RBL checker tests with mocked DNS
  - [ ] Security headers analyzer tests
  - [ ] Site verification analyzer tests
- [ ] Add integration tests for full analysis workflow
- [ ] Add edge case tests (malformed domains, network failures)
- [ ] Add performance benchmarks

### Performance Optimizations
- [ ] Implement async/await for network operations
  - [ ] Convert DNS queries to asyncio
  - [ ] Use httpx async client for HTTP requests
  - [ ] Parallelize RBL checks across servers
- [ ] Add connection pooling for HTTP analyzer
  - [ ] Use httpx.Client with connection pooling
  - [ ] Reuse connections between requests
- [ ] Parallel DNS queries using asyncio.gather()
  - Potential improvement: 3-5x faster DNS analysis

### IPv6 Support
- [ ] Add IPv6 support for RBL checks
  - Location: `src/webmaster_domain_tool/analyzers/rbl_checker.py:164`
  - Currently only IPv4 is supported

## Medium Priority

### Enhanced Features
- [ ] Add rate limiting to prevent overwhelming target servers
  - Useful for batch domain checking
  - Configurable requests per second
- [ ] Add export formats for automation
  - [ ] JSON export option
  - [ ] CSV export option
  - [ ] Machine-readable output format
- [ ] Add user-agent rotation for web scraping resistance
- [ ] Add batch domain checking mode
  - Process multiple domains from file
  - Parallel processing with rate limiting

### Code Quality
- [ ] Reduce duplication in OutputFormatter methods
  - Consider template method pattern
  - Consolidate quiet/compact/verbose output logic
- [ ] Resolve type ignore comment in cli.py:249
  - Find proper type solution instead of `# type: ignore`
- [ ] Consider cleaner approach for rich.panel monkey-patching
  - Location: `cli.py:13-23`

### Documentation
- [ ] Add architecture diagram to README.md
- [ ] Add troubleshooting section to README.md
- [ ] Add examples for batch processing
- [ ] Add contributing guidelines

## Low Priority

### Nice to Have
- [ ] Add caching layer for DNS results
  - Reduce redundant queries
  - Configurable TTL
- [ ] Add progress bars for long-running operations
- [ ] Add colored diff output for comparison mode
- [ ] Add webhook/notification support for monitoring
- [ ] Add plugin system for custom analyzers
- [ ] Add YAML configuration format support
- [ ] Add interactive mode with prompts

### Observability
- [ ] Add metrics collection (optional)
- [ ] Add structured logging option
- [ ] Add trace IDs for request correlation
- [ ] Add performance profiling mode

## Completed ✅
- [x] Fix PTR record classification from warnings to info messages
- [x] Fix inconsistent error handling in SSL analyzer
- [x] Extract hardcoded timeouts to configuration
- [x] Create constants.py module for magic numbers and thresholds
- [x] Consolidate regex patterns in site_verification_analyzer.py

---

**Note**: This TODO list is maintained based on code reviews and user feedback. Items are prioritized based on impact and effort required.
