# VulnScan

A Python web security assessment interface for TCP port discovery, HTTP security observations, TLS inspection, and LOTM integration.

## Features
- Asynchronous TCP port discovery
- HTTP security-header observations
- TLS protocol and certificate inspection
- Structured findings and CSV/JSON exports
- Streamlit interface
- LOTM integration

## Technology
Python, Streamlit, asyncio, pandas, and aiohttp.

## Run locally
Install the project dependencies, then run:
`streamlit run scanner.py`

## Responsible use
Only assess systems you own or have explicit permission to test. Validate automated findings before treating them as vulnerabilities.
