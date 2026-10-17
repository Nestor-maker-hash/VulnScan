import asyncio
import http.client
import json
import socket
import ssl
import time
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOTM_ROOT = PROJECT_ROOT / "LOTM"

if str(LOTM_ROOT) not in sys.path:
    sys.path.insert(0, str(LOTM_ROOT))

from lotm.pathways.web import crawl_website
from lotm.pathways.guardian import guardian_scan
from lotm.pathways.savant import fingerprint

from crawler import github_audit, PATHWAYS

st.set_page_config(
    page_title="Vulnerability Scanner Pro",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Automated Web Vulnerability Scanner [Pro]")
st.caption(
    "Scan systems you own or have explicit permission to test "
    "with asynchronous speed."
)

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

def normalize_target(target):
    target = target.strip()
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if not parsed.hostname:
        raise ValueError("Invalid domain or IP address.")
    return parsed.hostname

async def check_port_async(host, port, timeout=1.5):
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        return True
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return False
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

async def scan_ports_async(host, intensity):
    if intensity == "Quick Audit":
        ports = [22, 80, 443, 8080, 8443]
    elif intensity == "Full System Scan":
        ports = list(COMMON_PORTS.keys())
    else:
        ports = list(range(1, 1025))

    tasks = [check_port_async(host, port) for port in ports]
    results = await asyncio.gather(*tasks)
    findings = []

    for port, is_open in zip(ports, results):
        if is_open:
            findings.append({
                "Port": port,
                "Service": COMMON_PORTS.get(port, "Unknown"),
                "Status": "Open",
                "Finding": "TCP service reachable",
                "Severity": "Info",
                "CVSS": 0.0,
                "Evidence": f"{host}:{port} accepted a TCP connection.",
            })
    return findings

def inspect_http(host, port, use_https=False):
    findings = []
    connection = None
    connection_class = http.client.HTTPSConnection if use_https else http.client.HTTPConnection
    service_name = "HTTPS" if use_https else "HTTP"

    try:
        connection = connection_class(host, port, timeout=5)
        connection.request("GET", "/", headers={"User-Agent": "Vendora-Security-Audit-Pro/2.0"})
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}

        findings.append({
            "Port": port,
            "Service": service_name,
            "Status": "Observed",
            "Finding": "HTTP response received",
            "Severity": "Info",
            "CVSS": 0.0,
            "Evidence": f"HTTP status: {response.status} {response.reason}",
        })

        if "server" in headers:
            findings.append({
                "Port": port,
                "Service": service_name,
                "Status": "Observed",
                "Finding": "Server header exposed",
                "Severity": "Low",
                "CVSS": 2.0,
                "Evidence": f"Server: {headers['server']}",
            })

        if "x-powered-by" in headers:
            findings.append({
                "Port": port,
                "Service": service_name,
                "Status": "Observed",
                "Finding": "Technology header exposed",
                "Severity": "Low",
                "CVSS": 2.0,
                "Evidence": f"X-Powered-By: {headers['x-powered-by']}",
            })

        security_headers = {
            "content-security-policy": "Content-Security-Policy",
            "strict-transport-security": "Strict-Transport-Security",
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "referrer-policy": "Referrer-Policy",
        }

        for header, display_name in security_headers.items():
            if header not in headers:
                findings.append({
                    "Port": port,
                    "Service": service_name,
                    "Status": "Missing",
                    "Finding": f"Missing {display_name}",
                    "Severity": "Low",
                    "CVSS": 3.1,
                    "Evidence": f"{display_name} was not present in the HTTP response.",
                })

        raw_cookies = response.msg.get_all("set-cookie") or []
        for cookie in raw_cookies:
            cookie_lower = cookie.lower()
            missing_flags = []
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")

            if missing_flags:
                severity = "Medium" if use_https else "Low"
                cvss = 5.3 if use_https else 3.1
                cookie_preview = cookie[:80].replace("\n", " ")
                missing_str = ", ".join(missing_flags)
                findings.append({
                    "Port": port,
                    "Service": service_name,
                    "Status": "Insecure",
                    "Finding": "Cookie missing security flags",
                    "Severity": severity,
                    "CVSS": cvss,
                    "Evidence": f"Missing: {missing_str}; Cookie: {cookie_preview}...",
                })

        if not use_https and response.status in (301, 302, 307, 308):
            location = headers.get("location", "")
            if location.lower().startswith("https://"):
                findings.append({
                    "Port": port,
                    "Service": "HTTP",
                    "Status": "Protected",
                    "Finding": "HTTP redirects to HTTPS",
                    "Severity": "Info",
                    "CVSS": 0.0,
                    "Evidence": f"Redirect location: {location}",
                })

    except Exception as exc:
        findings.append({
            "Port": port,
            "Service": service_name,
            "Status": "Error",
            "Finding": "HTTP inspection failed",
            "Severity": "Info",
            "CVSS": 0.0,
            "Evidence": str(exc),
        })
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
    return findings

def inspect_tls(host, port=443):
    findings = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_socket:
                version = tls_socket.version()
                cipher = tls_socket.cipher()
                certificate = tls_socket.getpeercert()

                findings.append({
                    "Port": port,
                    "Service": "HTTPS",
                    "Status": "Observed",
                    "Finding": "TLS connection successful",
                    "Severity": "Info",
                    "CVSS": 0.0,
                    "Evidence": f"TLS version: {version}; Cipher: {cipher[0] if cipher else 'Unknown'}",
                })

                if version in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "Port": port,
                        "Service": "HTTPS",
                        "Status": "Weak",
                        "Finding": f"Legacy TLS version enabled: {version}",
                        "Severity": "Medium",
                        "CVSS": 5.3,
                        "Evidence": f"Negotiated protocol: {version}",
                    })

                if certificate:
                    issuer = str(certificate.get("issuer", []))
                    subject = str(certificate.get("subject", []))
                    findings.append({
                        "Port": port,
                        "Service": "HTTPS",
                        "Status": "Observed",
                        "Finding": "TLS certificate detected",
                        "Severity": "Info",
                        "CVSS": 0.0,
                        "Evidence": f"Subject={subject[:100]}; Issuer={issuer[:100]}",
                    })
    except Exception as exc:
        findings.append({
            "Port": port,
            "Service": "HTTPS",
            "Status": "Error",
            "Finding": "TLS inspection failed",
            "Severity": "Info",
            "CVSS": 0.0,
            "Evidence": str(exc),
        })
    return findings

def run_scan(target, intensity):
    host = normalize_target(target)

    results = asyncio.run(
        scan_ports_async(host, intensity)
    )

    open_ports = {
        item["Port"]
        for item in results
    }

    if 80 in open_ports:
        results.extend(
            inspect_http(
                host,
                80,
                use_https=False,
            )
        )

    if 443 in open_ports:
        results.extend(
            inspect_http(
                host,
                443,
                use_https=True,
            )
        )
        results.extend(
            inspect_tls(
                host,
                443,
            )
        )

    if not results:
        results.append({
            "Port": "-",
            "Service": "-",
            "Status": "No result",
            "Finding": "No tested TCP services were reachable",
            "Severity": "Info",
            "CVSS": 0.0,
            "Evidence": "No tested ports accepted a TCP connection.",
        })

    return pd.DataFrame(results)

# ============================================================
# SECURITY & INTELLIGENCE PLATFORM UI
# ============================================================
import asyncio
import aiohttp
import time
import json
import pandas as pd
import streamlit as st
st.sidebar.header("⚙️ Platform Settings")
scan_type = st.sidebar.selectbox(
    "Security Scan Profile",
    ["Quick Audit", "Full System Scan", "Deep Port Scan"],
)
report_format = st.sidebar.selectbox(
    "Report Format",
    ["CSV", "JSON"],
)
st.title("🛡️ Vulnerability Scanner Pro")
st.caption(
    "Security scanning and technical intelligence in one workspace. "
    "Use only against systems you own or are authorized to assess."
)
st.divider()
# ------------------------------------------------------------
# GLOBAL TARGET
# ------------------------------------------------------------
st.subheader("🎯 Target")
target_input = st.text_input(
    "Target domain, IP address, or website",
    placeholder="example.com or https://example.com",
    key="global_target",
)
target = target_input.strip()
if target and "://" not in target:
    web_target = "https://" + target
else:
    web_target = target
if target:
    st.caption(f"Active target: `{target}`")
st.divider()
# ============================================================
# HIGH-THROUGHPUT ASYNC RATE-LIMIT ENGINE
# ============================================================
async def _async_rate_test(url, request_count, concurrency, method, timeout, live_placeholder):
    results = []
    completed = 0
    started = time.time()
    status_counts = {}
    semaphore = asyncio.Semaphore(concurrency)
    session_headers = {"User-Agent": "Vulnerability-Scanner-Pro/2.0"}
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(connector=connector, headers=session_headers) as session:
        async def worker(index):
            nonlocal completed
            async with semaphore:
                req_start = time.time()
                try:
                    async with session.request(method, url, timeout=client_timeout, allow_redirects=False) as response:
                        await response.read()
                        elapsed_ms = (time.time() - req_start) * 1000
                        status = str(response.status)
                        res_item = {
                            "request": index,
                            "status": status,
                            "latency_ms": round(elapsed_ms, 2),
                            "error": "",
                            "retry_after": response.headers.get("Retry-After", ""),
                            "rate_limit_headers": {
                                k: v for k, v in response.headers.items()
                                if "rate" in k.lower() or "retry" in k.lower()
                            },
                        }
                except Exception as exc:
                    elapsed_ms = (time.time() - req_start) * 1000
                    status = "ERROR"
                    res_item = {
                        "request": index,
                        "status": "ERROR",
                        "latency_ms": round(elapsed_ms, 2),
                        "error": str(exc),
                        "retry_after": "",
                        "rate_limit_headers": {},
                    }
                results.append(res_item)
                completed += 1
                status_counts[status] = status_counts.get(status, 0) + 1
                # Update live UI every 5 completed requests to reduce render overhead
                if completed % 5 == 0 or completed == request_count:
                    elapsed = max(time.time() - started, 0.001)
                    current_rps = completed / elapsed
                    http_429 = status_counts.get("429", 0)
                    live_placeholder.markdown(
                        f'''
### 🔴 Live Observation

| Metric | Current |
| :--- | :--- |
| Requests completed | **{completed} / {request_count}** |
| Elapsed | **{elapsed:.2f}s** |
| Current RPS | **{current_rps:.2f}** |
| HTTP 2xx | **{sum(v for k, v in status_counts.items() if k.startswith("2"))}** |
| HTTP 3xx | **{sum(v for k, v in status_counts.items() if k.startswith("3"))}** |
| HTTP 4xx | **{sum(v for k, v in status_counts.items() if k.startswith("4"))}** |
| HTTP 429 | **{http_429}** |
| HTTP 5xx | **{sum(v for k, v in status_counts.items() if k.startswith("5"))}** |
| Errors | **{status_counts.get("ERROR", 0)}** |

'''
                    )
        tasks = [asyncio.create_task(worker(i)) for i in range(1, request_count + 1)]
        await asyncio.gather(*tasks)
    results.sort(key=lambda x: x["request"])
    return results
def run_bounded_rate_test(url, request_count, concurrency, method, timeout, live_placeholder):
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(
        _async_rate_test(url, request_count, concurrency, method, timeout, live_placeholder)
    )
# ============================================================
# VERTICAL TOOL CARDS
# ============================================================
# ------------------------------------------------------------
# VULNERABILITY SCANNER
# ------------------------------------------------------------
with st.expander("🛡️ Vulnerability Scanner", expanded=True):
    st.caption("TCP port discovery, HTTP security inspection and TLS analysis.")
    if st.button("🚀 Start Security Scan", type="primary", use_container_width=True, key="start_security_scan"):
        if not target:
            st.warning("Enter a target first.")
        else:
            try:
                with st.spinner(f"Running {scan_type.lower()} on {target}..."):
                    start_time = time.time()
                    df_results = run_scan(target, scan_type)
                    elapsed = time.time() - start_time
                st.success(f"Security scan completed in {elapsed:.2f} seconds.")
                open_ports = int((df_results["Status"] == "Open").sum())
                critical = int((df_results["Severity"] == "Critical").sum())
                high = int((df_results["Severity"] == "High").sum())
                medium = int((df_results["Severity"] == "Medium").sum())
                low = int((df_results["Severity"] == "Low").sum())
                info = int((df_results["Severity"] == "Info").sum())
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Open Ports", open_ports)
                m2.metric("Critical", critical)
                m3.metric("High / Medium", high + medium)
                m4.metric("Total Findings", len(df_results))
                st.markdown("### Severity Summary")
                summary = pd.DataFrame(
                    {
                        "Severity": ["Critical", "High", "Medium", "Low", "Info"],
                        "Count": [critical, high, medium, low, info],
                    }
                )
                st.dataframe(summary, use_container_width=True, hide_index=True)
                st.markdown("### Detailed Findings")
                st.dataframe(
                    df_results,
                    use_container_width=True,
                    hide_index=True,
                    column_config={"CVSS": st.column_config.NumberColumn("CVSS Score", format="%.1f")},
                )
                hostname = normalize_target(target)
                if report_format == "CSV":
                    export_data = df_results.to_csv(index=False)
                    mime = "text/csv"
                    filename = f"scan_report_{hostname}.csv"
                else:
                    export_data = df_results.to_json(orient="records", indent=4)
                    mime = "application/json"
                    filename = f"scan_report_{hostname}.json"
                st.download_button(
                    "📥 Download Security Report",
                    data=export_data,
                    file_name=filename,
                    mime=mime,
                    use_container_width=True,
                    key="security_report_download",
                )
            except Exception as exc:
                st.error(f"Scanner error: {exc}")
# ------------------------------------------------------------
# WEB CRAWLER
# ------------------------------------------------------------
with st.expander("🕷️ Web Crawler", expanded=False):
    st.caption("Maps same-domain pages, links, metadata and keyword matches.")
    crawler_keywords = st.text_input("Keywords", placeholder="api, admin, login", key="crawler_keywords")
    crawler_depth = st.number_input("Crawl depth", min_value=0, max_value=5, value=2, step=1, key="crawler_depth")
    crawler_max_pages = st.number_input("Maximum pages", min_value=1, max_value=100, value=30, step=1, key="crawler_max_pages")
    if st.button("🕷️ Start Crawl", type="primary", use_container_width=True, key="run_crawler"):
        if not web_target:
            st.warning("Enter a target first.")
        else:
            try:
                keywords = [item.strip() for item in crawler_keywords.split(",") if item.strip()]
                with st.spinner("Mapping the application..."):
                    results = crawl_website(web_target, keywords, int(crawler_depth), int(crawler_max_pages))
                st.success(f"Crawl completed — {len(results)} pages observed.")
                if results:
                    pages = pd.DataFrame(
                        [
                            {
                                "URL": page.get("url", ""),
                                "Title": page.get("title", ""),
                                "Depth": page.get("depth", ""),
                                "Links": len(page.get("links", [])),
                                "Keyword Matches": len(page.get("matches", {})),
                            }
                            for page in results
                        ]
                    )
                    st.dataframe(pages, use_container_width=True, hide_index=True)
                    for index, page in enumerate(results, 1):
                        title = page.get("title") or page.get("url") or f"Page {index}"
                        with st.expander(f"{index}. {title}"):
                            st.write("**URL:**", page.get("url", ""))
                            st.write("**Depth:**", page.get("depth", 0))
                            if page.get("matches"):
                                st.write("**Keyword matches**")
                                st.json(page["matches"])
                            if page.get("links"):
                                st.write("**Discovered links**")
                                st.write(page["links"])
                    st.download_button(
                        "📥 Download Crawler Results",
                        data=json.dumps(results, indent=2, default=str),
                        file_name="web_crawler.json",
                        mime="application/json",
                        use_container_width=True,
                        key="crawler_download",
                    )
            except Exception as exc:
                st.error(f"Web Crawler error: {exc}")
# ------------------------------------------------------------
# HTTP SECURITY ANALYSIS
# ------------------------------------------------------------
with st.expander("🛡️ HTTP Security Analysis", expanded=False):
    st.caption("Passive analysis of security headers, cookies, CORS, redirects, API routes and authorization signals.")
    if st.button("🛡️ Analyze HTTP Security", type="primary", use_container_width=True, key="run_http_security"):
        if not web_target:
            st.warning("Enter a target first.")
        else:
            try:
                with st.spinner("Analyzing HTTP security behavior..."):
                    result = guardian_scan(web_target)
                findings = result.get("findings", [])
                st.success(f"HTTP security analysis completed — {len(findings)} observations.")
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Observations", len(findings))
                m2.metric("Security Headers", sum(1 for item in findings if item.get("category") == "security_header"))
                m3.metric("Cookies", sum(1 for item in findings if item.get("category") == "cookie"))
                m4.metric("API / Auth", sum(1 for item in findings if item.get("category") in ("api_route", "authorization")))
                if findings:
                    st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)
                else:
                    st.success("No observations requiring attention.")
                with st.expander("Technical Response Details"):
                    st.json(
                        {
                            "target": result.get("target"),
                            "final_url": result.get("final_url"),
                            "status_code": result.get("status_code"),
                            "response_ms": result.get("response_ms"),
                            "content_type": result.get("content_type"),
                            "https": result.get("https"),
                        }
                    )
                st.download_button(
                    "📥 Download HTTP Analysis",
                    data=json.dumps(result, indent=2, default=str),
                    file_name="http_security_analysis.json",
                    mime="application/json",
                    use_container_width=True,
                    key="http_security_download",
                )
            except Exception as exc:
                st.error(f"HTTP Security Analysis error: {exc}")
# ------------------------------------------------------------
# TECHNOLOGY DETECTION
# ------------------------------------------------------------
with st.expander("🔬 Technology Detection", expanded=False):
    st.caption("Detects frameworks, infrastructure, services, assets and publicly exposed version evidence.")
    if st.button("🔬 Detect Technologies", type="primary", use_container_width=True, key="run_technology_detection"):
        if not web_target:
            st.warning("Enter a target first.")
        else:
            try:
                with st.spinner("Fingerprinting technologies..."):
                    result = fingerprint(web_target)
                technologies = result.get("technologies", [])
                versions = result.get("versions", [])
                signals = result.get("security_signals", [])
                assets = result.get("assets", {})
                st.success("Technology detection completed.")
                s1, s2, s3, s4 = st.columns(4)
                s1.metric("Technologies", len(technologies))
                s2.metric("Version Evidence", len(versions))
                s3.metric("Security Signals", len(signals))
                s4.metric("Scripts", len(assets.get("scripts", [])))
                if technologies:
                    st.markdown("### Technologies")
                    st.dataframe(pd.DataFrame(technologies), use_container_width=True, hide_index=True)
                if versions:
                    st.markdown("### Version Evidence")
                    st.dataframe(pd.DataFrame(versions), use_container_width=True, hide_index=True)
                if signals:
                    st.markdown("### Security Signals")
                    st.dataframe(pd.DataFrame(signals), use_container_width=True, hide_index=True)
                if assets:
                    with st.expander("Observed Assets"):
                        st.json(assets)
                st.download_button(
                    "📥 Download Technology Report",
                    data=json.dumps(result, indent=2, default=str),
                    file_name="technology_detection.json",
                    mime="application/json",
                    use_container_width=True,
                    key="technology_download",
                )
            except Exception as exc:
                st.error(f"Technology Detection error: {exc}")
# ------------------------------------------------------------
# GITHUB AUTHENTICATION
# ------------------------------------------------------------
with st.expander("🔐 GitHub Authentication", expanded=False):
    st.caption("Provide a GitHub Personal Access Token to audit repositories accessible to your authenticated account.")
    github_token = st.text_input("GitHub Personal Access Token", type="password", placeholder="github_pat_••••••••••••", key="github_token_input")
    if github_token:
        st.success("GitHub token is available for this session.")
        st.caption("The token is not displayed in the interface or included in scan reports.")
    else:
        st.info("No GitHub token entered. Public repository search remains available.")
# ------------------------------------------------------------
# GITHUB REPOSITORY AUDIT
# ------------------------------------------------------------
with st.expander("🐙 GitHub Repository Audit", expanded=False):
    st.caption("Audits repositories accessible through the authenticated GitHub account.")
    github_audit_keywords = st.text_input("File / path patterns", value=".env", key="github_audit_keywords")
    github_audit_limit = st.number_input("Maximum repositories", min_value=1, max_value=100, value=30, step=1, key="github_audit_limit")
    if st.button("🐙 Run Repository Audit", type="primary", use_container_width=True, key="run_github_audit"):
        if not github_token:
            st.warning("Enter a GitHub Personal Access Token in the GitHub Authentication section first.")
        else:
            try:
                keywords = [item.strip() for item in github_audit_keywords.split(",") if item.strip()]
                with st.spinner("Auditing accessible GitHub repositories..."):
                    matches = github_audit(github_token, keywords, int(github_audit_limit))
                high = sum(1 for match in matches if match.get("severity") == "high")
                review = sum(1 for match in matches if match.get("severity") == "review")
                st.success(f"Repository audit completed — {len(matches)} matches.")
                a1, a2, a3 = st.columns(3)
                a1.metric("Matches", len(matches))
                a2.metric("High", high)
                a3.metric("Review", review)
                if matches:
                    st.dataframe(pd.DataFrame(matches), use_container_width=True, hide_index=True)
                else:
                    st.success("No matching files were returned.")
                st.download_button(
                    "📥 Download Repository Audit",
                    data=json.dumps(
                        {
                            "search": keywords,
                            "repositories_checked": int(github_audit_limit),
                            "matches": matches,
                        },
                        indent=2,
                        default=str,
                    ),
                    file_name="github_repository_audit.json",
                    mime="application/json",
                    use_container_width=True,
                    key="github_audit_download",
                )
            except Exception as exc:
                st.error(f"GitHub Repository Audit error: {exc}")


# ------------------------------------------------------------
# PUBLIC GITHUB SEARCH
# ------------------------------------------------------------

with st.expander("🔎 Public Repository Search", expanded=False):
    st.caption("Search and inspect public GitHub repositories without authentication.")

    scholar_query = st.text_input("Repository search query", value="language:Python", key="public_github_query")
    scholar_paths = st.text_input("File / path patterns", value="app", key="public_github_paths")
    scholar_limit = st.number_input("Maximum repositories", min_value=1, max_value=50, value=10, step=1, key="public_github_limit")

    if st.button("🔎 Search Public Repositories", type="primary", use_container_width=True, key="run_public_github_search"):
        if not scholar_query.strip():
            st.warning("Enter a repository search query.")
        else:
            try:
                keywords = [item.strip() for item in scholar_paths.split(",") if item.strip()]

                with st.spinner("Searching public GitHub repositories..."):
                    repositories, matches, stats = PATHWAYS["scholar"].run(scholar_query.strip(), keywords, int(scholar_limit), None)

                st.success(f"Public repository search completed — {len(matches)} file matches.")

                p1, p2, p3 = st.columns(3)
                p1.metric("Discovered", stats.get("discovered", len(repositories)))
                p2.metric("Inspected", stats.get("inspected", len(repositories)))
                p3.metric("File Matches", len(matches))

                if matches:
                    st.dataframe(pd.DataFrame(matches), use_container_width=True, hide_index=True)
                else:
                    st.info("No matching public paths were found.")

                st.download_button(
                    "📥 Download Public Search",
                    data=json.dumps(
                        {
                            "query": scholar_query.strip(),
                            "path_search": keywords,
                            "repositories": repositories,
                            "matches": matches,
                            "statistics": stats,
                        },
                        indent=2,
                        default=str,
                    ),
                    file_name="public_repository_search.json",
                    mime="application/json",
                    use_container_width=True,
                    key="public_github_download",
                )

            except Exception as exc:
                st.error(f"Public Repository Search error: {exc}")


# ------------------------------------------------------------
# RATE-LIMIT TESTING (UPGRADED UI & BACKEND)
# ------------------------------------------------------------

with st.expander("⏱️ Rate-Limit Testing", expanded=False):
    st.caption("High-throughput diagnostic testing using async I/O. Live response statistics are shown while the test runs.")

    rate_count = st.number_input(
        "Number of requests",
        min_value=10,
        max_value=10000,
        value=500,
        step=50,
        key="rate_request_count",
    )

    rate_concurrency = st.number_input(
        "Concurrency",
        min_value=1,
        max_value=500,
        value=50,
        step=5,
        key="rate_concurrency",
    )

    rate_method = st.selectbox("HTTP method", ["GET", "HEAD", "POST"], key="rate_method")

    rate_timeout = st.number_input(
        "Request timeout (seconds)",
        min_value=1,
        max_value=30,
        value=5,
        step=1,
        key="rate_timeout",
    )

    if st.button("⏱️ Start Rate-Limit Test", type="primary", use_container_width=True, key="start_rate_test"):
        if not web_target:
            st.warning("Enter a target first.")
        else:
            try:
                live_placeholder = st.empty()

                with st.spinner("Running high-speed diagnostic..."):
                    rate_results = run_bounded_rate_test(
                        web_target,
                        int(rate_count),
                        int(rate_concurrency),
                        rate_method,
                        int(rate_timeout),
                        live_placeholder,
                    )

                st.success("Rate-limit test completed.")

                statuses = {}
                latencies = []

                for item in rate_results:
                    status = str(item["status"])
                    statuses[status] = statuses.get(status, 0) + 1

                    if isinstance(item.get("latency_ms"), (int, float)):
                        latencies.append(item["latency_ms"])

                first_429 = next(
                    (item["request"] for item in rate_results if str(item["status"]) == "429"),
                    None,
                )

                if latencies:
                    sorted_latencies = sorted(latencies)
                    p50 = sorted_latencies[min(len(sorted_latencies) - 1, int(len(sorted_latencies) * 0.50))]
                    p95 = sorted_latencies[min(len(sorted_latencies) - 1, int(len(sorted_latencies) * 0.95))]

                    st.markdown("### Results")
                    r1, r2, r3, r4 = st.columns(4)
                    r1.metric("Requests", len(rate_results))
                    r2.metric("HTTP 429", statuses.get("429", 0))
                    r3.metric("p50 Latency", f"{p50:.1f} ms")
                    r4.metric("p95 Latency", f"{p95:.1f} ms")

                    if first_429 is not None:
                        st.info(f"First HTTP 429 observed at request #{first_429}.")

                st.markdown("### Response Distribution")
                distribution = pd.DataFrame([{"Status": status, "Count": count} for status, count in sorted(statuses.items())])
                st.dataframe(distribution, use_container_width=True, hide_index=True)

                st.markdown("### Request Results")
                st.dataframe(pd.DataFrame(rate_results), use_container_width=True, hide_index=True)

                st.download_button(
                    "📥 Download Rate-Limit Report",
                    data=json.dumps(
                        {
                            "target": web_target,
                            "request_count": int(rate_count),
                            "concurrency": int(rate_concurrency),
                            "method": rate_method,
                            "results": rate_results,
                        },
                        indent=2,
                        default=str,
                    ),
                    file_name="rate_limit_test.json",
                    mime="application/json",
                    use_container_width=True,
                    key="rate_limit_download",
                )

            except Exception as exc:
                st.error(f"Rate-limit test error: {exc}")
