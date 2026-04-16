# Threat Intelligence Analysis Platform

A high-fidelity platform for collecting, extracting, and enriching threat intelligence data.

## 🚀 Features

- **Multi-Source Collection**: Automated extraction from various threat feeds.
- **IOC Extraction**: Advanced extraction of IPs, Domains, URLs, and CVEs.
- **Geolocalisation Enrichment**: Integrated local geolocalisation using IP ranges and cache.
- **NLP Summarisation**: Contextual analysis and summary of threat reports.
- **Interactive Dashboard**: Modern SOC-style interface for real-time monitoring.

## 🌍 Geolocalisation Sources

The platform uses a hybrid approach for geolocalisation, combining a local cache with high-performance IP range lookups. The following sources are used or recommended for enrichment:

- **[IP2Location DB1](https://www.ip2location.com/databases/db1-ip-country)**: Used for precise IP-to-Country mapping (Sample data included).
- **[IPVerse Country IP Blocks](https://github.com/ipverse/country-ip-blocks)**: Aggregated CIDR lists for per-country blocking and identification.
- **[RIR Delegations Stats](https://www-public.telecom-sudparis.eu/~maigron/rir-stats/rir-delegations/ip-lists/)**: Regional Internet Registry delegation lists for global IP distribution tracking.

## 🛠️ Technical Architecture

### Geolocalisation Manager (`GeoManager`)
The `GeoManager` handles geolocalisation requests by:
1. Checking a local **fast-access cache** of previously resolved IPs.
2. Performing a **Binary Search** on sorted IP ranges (from IP2Location and other sources) for millisecond-level precision.
3. Synchronizing data across enriched files to maintain a consistent threat landscape view.

## 📂 Project Structure

- `/backend`: FastAPI service for intelligence processing.
- `/frontend`: React + Vite dashboard.
- `/enrichment`: Core enrichment logic (NLP, Geolocation, Whois).
- `/extraction_ioc_cve`: Scripts for processing raw intelligence feeds.
- `/output_enrichment`: Normalized and enriched JSON datasets.

---
*(c) 2026 Cyber-HUD - Advanced Threat Intelligence Orchestration*
