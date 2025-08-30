# Overwrite the README with a simplified Phase 0 section (no detailed commands)
readme = """# Real IP Detection (Origin-IP Hunter)

A comprehensive toolkit to detect **origin IP addresses** hidden behind CDN/WAF providers (Cloudflare, Akamai, AWS CloudFront, Fastly, Azure Front Door, etc.).

Designed for **Attack Surface Management (ASM)** and **Internet Perimeter workflows** (e.g., NAB operations, Kali + AWS EC2 runners). The system supports multi-phase **prepare → discovery → validation → WAF-bypass probing** with structured outputs and per-domain logs.

---

## 🚀 Key Features

* **Phase 0 – Prepare**: ingest weekly **WAF-detected domains**, clean & dedupe, scope-filter, and produce a ready-to-scan list.
* **Multi-source IP collection** (ViewDNS, crt.sh, Shodan, VirusTotal, SecurityTrails, internal DNS data).
* **Automated filtering** of CDN/WAF ranges via prefix lists + RDNS heuristics.
* **Direct validation** with forced `curl --resolve` requests and content similarity checks.
* **WAF bypass probes** with controlled payloads (LFI, SQLi, XSS).
* **Structured outputs** in JSON (`result.json`, `waf_bypass.json`) with per-domain logs.
* Ready for automation via **AWS EC2** runner scripts.

---

## 🏗️ System Architecture (Pipeline View)

```mermaid
flowchart LR
    Z[Phase 0: Prepare <br> Intake from WAF Detection] --> A[Input Domains <br> -d / -i]
    A --> B[Phase 1: Collect <br> Gather candidate IPs]
    B --> C[Phase 2: Filter <br> CDN/WAF Heuristics]
    C --> D[Phase 3: Validate <br> HTTP/HTML Matching]
    D --> E[Phase 4: WAF Bypass Probes]
    E --> F[Outputs <br> result.json, waf_bypass.json, logs/]
