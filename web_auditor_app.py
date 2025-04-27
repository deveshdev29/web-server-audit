import subprocess
import socket
import ssl
import requests
import streamlit as st
import os
import io
from docx import Document

if "docx_file" not in st.session_state:
    st.session_state.docx_file = None


# === Vulnerability mapping ===
nist_mappings = {
    "Apache/2.4.7": "CVE-2021-41773: Path traversal vulnerability in Apache HTTP Server 2.4.49 (fixed in later versions).",
    "X-Frame-Options header is not present": "Potential clickjacking vulnerability.",
    "X-Content-Type-Options header is not set": "Risk of MIME type confusion attacks.",
    "mod_negotiation is enabled": "May allow attackers to brute force filenames (CVE-2009-1195)."
}

# === Helper Functions ===
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return e.output.strip() or str(e)

def run_nmap(target):
    return run_command(f"nmap -sS -sV --script vuln {target}")

def run_nikto(target):
    return run_command(f"nikto -h {target} -Tuning 1234567890abcde -maxtime 600 -timeout 20")

def check_ssl(target):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((target, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return (f"Issuer: {cert.get('issuer')}\nValid from: {cert.get('notBefore')}\nValid until: {cert.get('notAfter')}")
    except Exception as e:
        return f"SSL check failed: {e}"

def check_http_headers(target):
    try:
        response = requests.get(f"https://{target}", timeout=10, verify=True)
        headers = response.headers
        report = ""
        for header in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
            report += f"{header}: {'Present' if header in headers else 'NOT present'}\n"
        return report
    except Exception as e:
        return f"Header check failed: {e}"

def analyze_findings(findings):
    recommendations = []
    for finding, recommendation in nist_mappings.items():
        if finding.lower() in findings.lower():
            recommendations.append(f"Issue: {finding}\nRecommendation: {recommendation}")
    return "\n\n".join(recommendations) if recommendations else "No critical vulnerabilities found."

def save_report(nmap_output, nikto_output, ssl_output, header_output, analysis):
    try:
        doc = Document()
        doc.add_heading('Web Server Security Audit Report', 0)

        sections = [
            ("Nmap Scan Results", nmap_output),
            ("Nikto Scan Results", nikto_output),
            ("SSL Certificate Information", ssl_output),
            ("HTTP Security Header Check", header_output),
            ("Analysis and Recommendations", analysis),
            ("Automated Suggestions", 
             "- Update outdated services.\n"
             "- Enable HTTP security headers.\n"
             "- Disable unnecessary modules.\n"
             "- Regularly monitor CVEs and patch promptly.\n"
             "- Use strong ciphers and review SSL configurations.\n"
             "- Periodically perform vulnerability scans and penetration tests.")
        ]

        for title, content in sections:
            doc.add_heading(title, level=1)
            doc.add_paragraph(content)

        buffer = io.BytesIO()
        doc.save(buffer)
        buffer.seek(0)
        return buffer

    except Exception as e:
        st.error(f"Report generation failed: {e}")
        print(f"[DEBUG] Report generation failed: {e}")
        return None


# === Streamlit UI ===
st.title("🔒 Web Server Security Auditor")

target = st.text_input("Enter target domain or IP (without https://):")

if st.button("Run Audit") and target:
    with st.spinner("Running Nmap..."):
        st.session_state.nmap_result = run_nmap(target)
    st.text_area("Nmap Output", st.session_state.nmap_result, height=200)

    with st.spinner("Running Nikto..."):
        st.session_state.nikto_result = run_nikto(target)
    st.text_area("Nikto Output", st.session_state.nikto_result, height=200)

    with st.spinner("Checking SSL Certificate..."):
        st.session_state.ssl_result = check_ssl(target)
    st.text_area("SSL Info", st.session_state.ssl_result, height=100)

    with st.spinner("Checking HTTP Security Headers..."):
        st.session_state.header_result = check_http_headers(target)
    st.text_area("HTTP Headers", st.session_state.header_result, height=150)

    with st.spinner("Analyzing Findings..."):
        st.session_state.analysis = analyze_findings(
            st.session_state.nmap_result +
            st.session_state.nikto_result +
            st.session_state.header_result
        )
    st.text_area("Analysis and Recommendations", st.session_state.analysis, height=200)

if (
    "nmap_result" in st.session_state and
    "nikto_result" in st.session_state and
    "ssl_result" in st.session_state and
    "header_result" in st.session_state and
    "analysis" in st.session_state
):
    if st.button("🛠️ Generate DOCX Report"):
        docx_file = save_report(
            st.session_state.nmap_result,
            st.session_state.nikto_result,
            st.session_state.ssl_result,
            st.session_state.header_result,
            st.session_state.analysis
        )
        if docx_file:
            st.download_button(
                label="📥 Download Audit Report",
                data=docx_file,
                file_name="audit_report.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            )
        else:
            st.error("The report could not be generated.")
