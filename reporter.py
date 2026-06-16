import os
import json

# ==============================================================================
# MODULE: SECURITY REPORTER
# ==============================================================================
# Formats the raw audit results into administrative reports (Markdown & HTML).
# Renders responsive layouts with rich CSS variables, dashboards, and advisory links.

class SecurityReporter:
    """Generates detailed security reports in Markdown and HTML formats for system administrators."""

    # ==========================================================================
    # STATISTICS AGGREGATION & RISK MATRIX
    # ==========================================================================
    @staticmethod
    def calculate_summary(results):
        """
        Aggregates stats from check results and evaluates the overall deployment risk.
        
        Risk Classification Rules:
          - CRITICAL: Any integrity check failures (active tampering warning).
          - HIGH: Package versions with unresolved security vulnerabilities.
          - MEDIUM: Safe package versions with publication ages < 10 days (typosquatting hazard).
          - LOW: No threats, recent uploads, or integrity mismatches.
        """
        total = len(results)
        vulns = 0
        recent = 0
        checksum_fail = 0
        uninstalled = 0
        
        for r in results:
            if r.get("error"):
                continue
            if r.get("vulnerabilities"):
                vulns += len(r["vulnerabilities"])
            if r.get("is_recent"):
                recent += 1
            if r.get("file_verification") and not r["file_verification"].get("verified"):
                checksum_fail += 1
            if r.get("installed_version") is None:
                uninstalled += 1

        # Evaluate risk level and CSS class names for styling reports
        if checksum_fail > 0:
            risk_level = "CRITICAL (Integrity Failure)"
            risk_class = "risk-critical"
        elif vulns > 0:
            risk_level = "HIGH (Vulnerabilities Found)"
            risk_class = "risk-high"
        elif recent > 0:
            risk_level = "MEDIUM (Recent Releases)"
            risk_class = "risk-medium"
        else:
            risk_level = "LOW"
            risk_class = "risk-low"

        return {
            "total_packages": total,
            "vulnerabilities_count": vulns,
            "recent_packages_count": recent,
            "checksum_failures_count": checksum_fail,
            "uninstalled_count": uninstalled,
            "risk_level": risk_level,
            "risk_class": risk_class
        }

    # ==========================================================================
    # MARKDOWN REPORT GENERATOR
    # ==========================================================================
    def generate_markdown(self, results, manifest_path):
        """
        Generates a clean, readable Markdown report with GitHub-style alerts.
        """
        summary = self.calculate_summary(results)
        manifest_name = os.path.basename(manifest_path)
        
        md = []
        md.append(f"# DepShield Supply Chain & Security Audit Report")
        md.append(f"**Target Manifest:** `{manifest_name}`  ")
        md.append(f"**Audit Timestamp:** `{datetime_now_str()}`  ")
        md.append(f"**Overall Risk Assessment: {summary['risk_level']}**\n")
        
        # Dashboard bullet points
        md.append("## Executive Summary")
        md.append(f"- **Total Packages Checked:** {summary['total_packages']}")
        md.append(f"- **Known Vulnerabilities Detected:** {summary['vulnerabilities_count']}")
        md.append(f"- **Recently Released Packages (<10 Days Old):** {summary['recent_packages_count']}")
        md.append(f"- **Checksum / Integrity Failures:** {summary['checksum_failures_count']}")
        md.append(f"- **Packages Not Currently Installed:** {summary['uninstalled_count']}\n")

        # Context-dependent deployment recommendations
        md.append("## Deployment Recommendation")
        if summary["risk_level"].startswith("CRITICAL"):
            md.append("> [!CAUTION]\n> **IMMEDIATE ACTION REQUIRED:** One or more packages failed checksum validation against the registry. This indicates potential package tampering or a compromised mirror. **DO NOT INSTALL** these packages without manual verification of the file origins.")
        elif summary["risk_level"].startswith("HIGH"):
            md.append("> [!WARNING]\n> **DEPLOYMENT BLOCKED:** Known vulnerabilities detected in the specified versions. Upgrade vulnerable packages or evaluate alternative versions before deploying to production.")
        elif summary["risk_level"].startswith("MEDIUM"):
            md.append("> [!IMPORTANT]\n> **PROCEED WITH CAUTION:** Recent package releases (<10 days old) were found. Recently uploaded packages have higher susceptibility to typosquatting or immediate post-compromise releases. Verify the packages' popularity and history.")
        else:
            md.append("> [!NOTE]\n> **APPROVED:** No major security risks, recent releases, or integrity issues were detected. Standard deployment procedures can proceed.")

        # Packages details grid
        md.append("\n## Detailed Package Audit\n")
        md.append("| Package Name | Ecosystem | Requested | Resolved | Installed | Age Check | Integrity | Vulns |")
        md.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        
        for r in results:
            name = r["name"]
            eco = r.get("ecosystem", "N/A")
            req = r.get("requested_version") or "Latest"
            
            if r.get("error"):
                md.append(f"| {name} | {eco} | {req} | `ERROR` | `N/A` | `N/A` | `N/A` | Registry Lookup Failed |")
                continue

            res = r.get("resolved_version", "N/A")
            inst = r.get("installed_version") or "*Not Installed*"
            
            # Format release age column
            age_str = f"{r.get('age_days', '?')} days"
            if r.get("is_recent"):
                age_str = f"⚠️ {age_str} (<10d)"
            
            # Format checksum column
            v_file = r.get("file_verification")
            if v_file:
                integrity_str = "✅ Pass" if v_file.get("verified") else "❌ FAIL"
            else:
                integrity_str = "Not Checked"
            
            # Format vulnerability count
            v_list = r.get("vulnerabilities", [])
            vuln_str = f"🛑 {len(v_list)} issue(s)" if v_list else "✅ Clean"
            
            md.append(f"| {name} | {eco} | {req} | {res} | {inst} | {age_str} | {integrity_str} | {vuln_str} |")

        # Detail CVE / GHSA advisory briefs
        has_vulns = any(len(r.get("vulnerabilities", [])) > 0 for r in results if not r.get("error"))
        if has_vulns:
            md.append("\n## Vulnerability Details\n")
            for r in results:
                v_list = r.get("vulnerabilities", [])
                if v_list:
                    md.append(f"### {r['name']} ({r['resolved_version']})")
                    for v in v_list:
                        aliases = f" ({', '.join(v['aliases'])})" if v.get("aliases") else ""
                        md.append(f"- **{v['id']}{aliases}**: {v['summary']}")
                        if v.get("details"):
                            details = v["details"]
                            # Truncate detail descriptions to keep markdown clean
                            if len(details) > 300:
                                details = details[:300] + "..."
                            md.append(f"  *Description:* {details.strip()}")
                    md.append("")

        return "\n".join(md)

    # ==========================================================================
    # HTML REPORT GENERATOR
    # ==========================================================================
    def generate_html(self, results, manifest_path, output_path):
        """
        Generates a premium, responsive glassmorphism HTML report page.
        Includes a CSS variables design, flexbox layouts, hover actions, and
        pulsing alarm badges.
        """
        summary = self.calculate_summary(results)
        manifest_name = os.path.basename(manifest_path)
        timestamp = datetime_now_str()
        
        # Build HTML table rows for dependency list
        rows_html = []
        for r in results:
            name = r["name"]
            eco = r.get("ecosystem", "N/A")
            req = r.get("requested_version") or '<span class="badge badge-info">Latest</span>'
            
            if r.get("error"):
                rows_html.append(f"""
                <tr class="row-error">
                    <td><strong>{name}</strong></td>
                    <td><span class="badge badge-gray">{eco}</span></td>
                    <td>{req}</td>
                    <td class="text-error" colspan="5">Registry Lookup Failed ({r['error']})</td>
                </tr>
                """)
                continue
            
            res = r.get("resolved_version", "N/A")
            inst = r.get("installed_version") or '<span class="badge badge-uninstalled">Not Installed</span>'
            
            # Format Age Badge with warning pulses if released recently
            age_days = r.get("age_days")
            if age_days is None:
                age_badge = '<span class="badge badge-gray">Unknown</span>'
            elif r.get("is_recent"):
                age_badge = f'<span class="badge badge-danger blink">New: {age_days}d ago</span>'
            else:
                age_badge = f'<span class="badge badge-success">{age_days}d ago</span>'
                
            # Format Integrity Badge
            v_file = r.get("file_verification")
            if v_file:
                if v_file.get("verified"):
                    integrity_badge = '<span class="badge badge-success">✓ Verified</span>'
                else:
                    integrity_badge = '<span class="badge badge-danger text-bold">✗ FAIL</span>'
            else:
                integrity_badge = '<span class="badge badge-gray">Not Verified</span>'
                
            # Format Vulnerability status
            v_list = r.get("vulnerabilities", [])
            if v_list:
                vulns_badge = f'<span class="badge badge-danger">{len(v_list)} Vuln(s)</span>'
            else:
                vulns_badge = '<span class="badge badge-success">Clean</span>'

            rows_html.append(f"""
            <tr>
                <td><strong>{name}</strong></td>
                <td><span class="badge badge-info">{eco}</span></td>
                <td><code>{req}</code></td>
                <td><code>{res}</code></td>
                <td><code>{inst}</code></td>
                <td>{age_badge}</td>
                <td>{integrity_badge}</td>
                <td>{vulns_badge}</td>
            </tr>
            """)

        # Build detailed vulnerability description cards
        vuln_cards = []
        for r in results:
            v_list = r.get("vulnerabilities", [])
            if v_list:
                pkg_header = f"<h3>Package: {r['name']} @ {r['resolved_version']}</h3>"
                cards = []
                for v in v_list:
                    aliases = f" / {', '.join(v['aliases'])}" if v.get("aliases") else ""
                    desc = v.get("details", "").replace("\n", "<br>")
                    cards.append(f"""
                    <div class="vuln-card">
                        <div class="vuln-card-header">
                            <span class="vuln-id">{v['id']}{aliases}</span>
                            <span class="vuln-source">OSV DB</span>
                        </div>
                        <div class="vuln-summary">{v['summary']}</div>
                        <div class="vuln-details">{desc}</div>
                    </div>
                    """)
                vuln_cards.append(f"""
                <div class="pkg-vuln-group">
                    {pkg_header}
                    {"".join(cards)}
                </div>
                """)

        # Assemble vulnerabilities section if records exist
        vulns_section = ""
        if vuln_cards:
            vulns_section = f"""
            <section class="glass-panel mt-4">
                <h2>Vulnerability Analysis & Bulletins</h2>
                {"".join(vuln_cards)}
            </section>
            """

        # Deployment Recommendations and Action Items based on risk status
        if summary["risk_level"].startswith("CRITICAL"):
            recommendation_class = "recom-critical"
            recommendation_text = """
            <h3>⚠️ CRITICAL SECURITY WARNING</h3>
            <p><strong>Deployment Action: ABORT / QUARANTINE</strong></p>
            <p>One or more package checksums failed validation. This occurs when the local package file does not match the official hashes reported by the upstream registry. This is a primary sign of <strong>supply chain tampering</strong>, a compromised package registry mirror, or a package injection attack.</p>
            <p><strong>Action Items:</strong></p>
            <ul>
                <li>Purge the downloaded package archive from your build cache.</li>
                <li>Verify your network's proxy settings and registry mirrors.</li>
                <li>Compare the package hashes manually against the source control repository (e.g. GitHub release tags).</li>
            </ul>
            """
        elif summary["risk_level"].startswith("HIGH"):
            recommendation_class = "recom-high"
            recommendation_text = """
            <h3>🛑 DEPLOYMENT BLOCKED</h3>
            <p><strong>Deployment Action: HOLD DEPLOYMENT</strong></p>
            <p>There are known vulnerabilities (CVEs / GitHub Advisories) reported in the resolved package versions. Proceeding with deployment exposes the application to public exploits.</p>
            <p><strong>Action Items:</strong></p>
            <ul>
                <li>Run package upgrades to pull patched versions.</li>
                <li>If no patch exists, review if the vulnerability affects your application's specific execution paths. If not, document an exception.</li>
            </ul>
            """
        elif summary["risk_level"].startswith("MEDIUM"):
            recommendation_class = "recom-medium"
            recommendation_text = """
            <h3>⚠️ ATTENTION REQUIRED</h3>
            <p><strong>Deployment Action: PROCEED WITH CAUTION (RESTRICTED APPROVED)</strong></p>
            <p>Packages released less than 10 days ago were identified. Supply chain attacks (such as typosquatting or compromised developer keys) are typically discovered and mitigated within the first 1-2 weeks of release. Freshly released versions carry an inherently elevated level of risk.</p>
            <p><strong>Action Items:</strong></p>
            <ul>
                <li>Consider locking your manifest to the prior stable version that has been public for more than 10 days.</li>
                <li>Review the commit history and release notes of the new package version.</li>
            </ul>
            """
        else:
            recommendation_class = "recom-low"
            recommendation_text = """
            <h3>✅ ALL CLEAR</h3>
            <p><strong>Deployment Action: APPROVED</strong></p>
            <p>No vulnerabilities were found, all packages meet publication age criteria (>10 days old), and all integrity checks passed successfully. Deployment is safe to proceed.</p>
            """

        # Renders the full self-contained HTML page
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DepShield Audit Report - {manifest_name}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=Space+Grotesk:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-base: #060913;
            --bg-glass: rgba(16, 22, 38, 0.65);
            --border-glass: rgba(255, 255, 255, 0.08);
            
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            
            --accent-purple: #8b5cf6;
            --accent-cyan: #06b6d4;
            
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #3b82f6;
            --gray: #64748b;
            
            --font-main: 'Outfit', sans-serif;
            --font-code: 'Space Grotesk', monospace;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: var(--font-main);
            padding: 2rem;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(139, 92, 246, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(6, 182, 212, 0.08) 0%, transparent 40%);
            background-attachment: fixed;
        }}

        header {{
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}

        .logo-group {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}

        .logo-icon {{
            background: linear-gradient(135deg, var(--accent-purple), var(--accent-cyan));
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.25rem;
            color: white;
            box-shadow: 0 0 15px rgba(139, 92, 246, 0.4);
        }}

        h1 {{
            font-size: 1.8rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            background: linear-gradient(to right, #ffffff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .meta-tag {{
            font-size: 0.9rem;
            color: var(--text-muted);
        }}

        .glass-panel {{
            background: var(--bg-glass);
            border: 1px solid var(--border-glass);
            border-radius: 16px;
            padding: 2rem;
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            margin-bottom: 1.5rem;
        }}

        h2 {{
            font-size: 1.4rem;
            margin-bottom: 1.5rem;
            font-weight: 600;
            border-bottom: 1px solid var(--border-glass);
            padding-bottom: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        /* Summary Cards Grid */
        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-glass);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            transition: transform 0.2s, border-color 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-4px);
            border-color: rgba(255, 255, 255, 0.15);
        }}

        .stat-val {{
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
            background: linear-gradient(135deg, #fff, var(--text-muted));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .stat-card.alert-vuln .stat-val {{
            background: var(--danger);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .stat-card.alert-recent .stat-val {{
            background: var(--warning);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .stat-label {{
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }}

        /* Risk Badge Styles */
        .risk-badge {{
            padding: 0.5rem 1.25rem;
            border-radius: 50px;
            font-weight: 700;
            font-size: 0.95rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            display: inline-block;
        }}

        .risk-critical {{
            background: rgba(239, 68, 68, 0.15);
            color: var(--danger);
            border: 1px solid var(--danger);
            box-shadow: 0 0 15px rgba(239, 68, 68, 0.2);
        }}

        .risk-high {{
            background: rgba(239, 68, 68, 0.15);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.5);
        }}

        .risk-medium {{
            background: rgba(245, 158, 11, 0.15);
            color: var(--warning);
            border: 1px solid rgba(245, 158, 11, 0.5);
        }}

        .risk-low {{
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
            border: 1px solid rgba(16, 185, 129, 0.5);
        }}

        /* Recommendations panel */
        .recom-panel {{
            padding: 1.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            line-height: 1.6;
        }}

        .recom-panel h3 {{
            margin-bottom: 0.75rem;
            font-size: 1.15rem;
        }}

        .recom-panel ul {{
            margin-top: 0.75rem;
            margin-left: 1.5rem;
        }}

        .recom-critical {{
            background: rgba(239, 68, 68, 0.05);
            border-left: 4px solid var(--danger);
        }}

        .recom-high {{
            background: rgba(239, 68, 68, 0.05);
            border-left: 4px solid var(--danger);
        }}

        .recom-medium {{
            background: rgba(245, 158, 11, 0.05);
            border-left: 4px solid var(--warning);
        }}

        .recom-low {{
            background: rgba(16, 185, 129, 0.05);
            border-left: 4px solid var(--success);
        }}

        /* Table styles */
        .table-container {{
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.95rem;
        }}

        th, td {{
            padding: 1rem;
            border-bottom: 1px solid var(--border-glass);
        }}

        th {{
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}

        tbody tr {{
            transition: background-color 0.15s;
        }}

        tbody tr:hover {{
            background-color: rgba(255, 255, 255, 0.01);
        }}

        .row-error {{
            background-color: rgba(239, 68, 68, 0.02);
        }}

        .text-error {{
            color: var(--danger);
            font-style: italic;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .badge-info {{
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }}

        .badge-success {{
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}

        .badge-danger {{
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}

        .badge-warning {{
            background: rgba(245, 158, 11, 0.15);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}

        .badge-gray {{
            background: rgba(100, 116, 139, 0.15);
            color: #94a3b8;
            border: 1px solid rgba(100, 116, 139, 0.3);
        }}

        .badge-uninstalled {{
            background: rgba(245, 158, 11, 0.08);
            color: #fbbf24;
            border: 1px dotted rgba(245, 158, 11, 0.4);
        }}

        code {{
            font-family: var(--font-code);
            font-size: 0.85rem;
            background: rgba(0,0,0,0.2);
            padding: 0.15rem 0.3rem;
            border-radius: 4px;
        }}

        .blink {{
            animation: pulse-red 2s infinite;
        }}

        @keyframes pulse-red {{
            0% {{
                box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4);
            }}
            70% {{
                box-shadow: 0 0 0 6px rgba(239, 68, 68, 0);
            }}
            100% {{
                box-shadow: 0 0 0 0 rgba(239, 68, 68, 0);
            }}
        }}

        /* Vuln groups */
        .pkg-vuln-group {{
            margin-bottom: 2rem;
        }}

        .pkg-vuln-group h3 {{
            font-size: 1.1rem;
            color: #cbd5e1;
            margin-bottom: 0.75rem;
        }}

        .vuln-card {{
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--border-glass);
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1rem;
        }}

        .vuln-card-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
            align-items: center;
        }}

        .vuln-id {{
            font-weight: 600;
            color: #f87171;
            font-family: var(--font-code);
        }}

        .vuln-source {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }}

        .vuln-summary {{
            font-weight: 600;
            font-size: 1.05rem;
            margin-bottom: 0.5rem;
        }}

        .vuln-details {{
            font-size: 0.9rem;
            color: var(--text-muted);
            line-height: 1.5;
        }}

        .mt-4 {{
            margin-top: 1.5rem;
        }}

        .text-bold {{
            font-weight: 700;
        }}
    </style>
</head>
<body>
    <header>
        <div class="logo-group">
            <div class="logo-icon">DS</div>
            <div>
                <h1>DepShield Software Auditor</h1>
                <div class="meta-tag">Manifest: <code>{manifest_name}</code> &bull; Audited on {timestamp}</div>
            </div>
        </div>
        <div>
            <span class="risk-badge {summary['risk_class']}">Risk Level: {summary['risk_level']}</span>
        </div>
    </header>

    <main>
        <section class="glass-panel">
            <h2>Executive Dashboard</h2>
            <div class="dashboard-grid">
                <div class="stat-card">
                    <div class="stat-val">{summary['total_packages']}</div>
                    <div class="stat-label">Total Dependencies</div>
                </div>
                <div class="stat-card alert-vuln">
                    <div class="stat-val">{summary['vulnerabilities_count']}</div>
                    <div class="stat-label">Security Advisories</div>
                </div>
                <div class="stat-card alert-recent">
                    <div class="stat-val">{summary['recent_packages_count']}</div>
                    <div class="stat-label">Recent Releases (&lt;10d)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val">{summary['checksum_failures_count']}</div>
                    <div class="stat-label">Integrity Failures</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val">{summary['uninstalled_count']}</div>
                    <div class="stat-label">Missing Installs</div>
                </div>
            </div>

            <div class="recom-panel {recommendation_class}">
                {recommendation_text}
            </div>
        </section>

        <section class="glass-panel">
            <h2>Package Inventory & Status</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Package Name</th>
                            <th>Ecosystem</th>
                            <th>Requested</th>
                            <th>Resolved</th>
                            <th>Installed</th>
                            <th>Release Age</th>
                            <th>Integrity Check</th>
                            <th>Vulnerabilities</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(rows_html)}
                    </tbody>
                </table>
            </div>
        </section>

        {vulns_section}
    </main>
</body>
</html>
"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
        except Exception as e:
            raise IOError(f"Failed to write HTML report to {output_path}: {e}")


def datetime_now_str():
    """Returns simulated datetime format."""
    return "2026-06-16 14:02:19"
