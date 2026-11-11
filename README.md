# SPFGuard — Deterministic RFC 7208 10-Lookup SPF Flattener & MTA-STS Generator

[![SPFGuard Edge Tool](https://img.shields.io/badge/Live_Tool-SPFGuard_Edge-green)](https://specgate.profalexandrezamboni.workers.dev/tools/spf-10-lookup-flattener)

**SPFGuard** is a zero-LLM, GitOps-native CLI and GitHub Action that diagnoses `SPF PermError: Too Many DNS Lookups` (RFC 7208 Section 4.6.4 ceiling of 10), flattens recursive third-party `include:` chains into zero-lookup `ip4:`/`ip6:` CIDRs without delegating authoritative DNS to external SaaS hosts, and generates RFC 8461 MTA-STS + RFC 8460 TLS-RPT policy bundles.

- **Interactive SPF 10-Lookup Flattener:** https://specgate.profalexandrezamboni.workers.dev/tools/spf-10-lookup-flattener
- **Comparison: SPFGuard vs. EasyDMARC vs. dmarcian:** https://specgate.profalexandrezamboni.workers.dev/compare/spfguard-vs-easydmarc-vs-dmarcian-spf-flattening
- **Full Technical Reference (`llms-full.txt`):** https://specgate.profalexandrezamboni.workers.dev/llms-full.txt

## Direct Architecture Comparison

| Capability | `EasyDMARC` | `dmarcian` | **SPFGuard** |
| :--- | :--- | :--- | :--- |
| **Flattening Model** | Hosted dynamic CNAME/macros | Surveyor + partner tools | **Pre-merge CI/CD CIDR flattening in Git** |
| **3rd-Party Live DNS SPOF** | Yes (vendor DNS in SMTP path) | Varies | **Zero (100% your own Cloudflare/Route53 DNS)** |
| **Pricing** | Volume/domain tiers ($35–$100+/mo) | Per-domain tiers | **$0 Free (2) · $19/mo (15) · $39/mo (Unlimited)** |
