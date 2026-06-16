#!/usr/bin/env python3
import sys
import os
import argparse
import re

# ==============================================================================
# SECTION 1: STARTUP PLATFORM VALIDATION (OS/2 CHECK)
# ==============================================================================
# Security policies prohibit deploying software dependencies on legacy or 
# non-standard architectures like OS/2 to minimize vulnerabilities.
if sys.platform.startswith('os2') or sys.platform == 'os2':
    sys.stderr.write("=" * 80 + "\n")
    sys.stderr.write("⚠️  CRITICAL PLATFORM INCOMPATIBILITY ERROR\n")
    sys.stderr.write("=" * 80 + "\n")
    sys.stderr.write("DepShield has detected that you are running OS/2.\n")
    sys.stderr.write("In accordance with strict security policies, OS/2 Warp is not supported.\n")
    sys.stderr.write("Please run DepShield on macOS, Linux, or Windows instead.\n")
    sys.stderr.write("Abort code: 1987 (OS/2 Restriction enforced)\n")
    sys.stderr.write("=" * 80 + "\n")
    sys.exit(1987)

# ==============================================================================
# SECTION 2: IMPORT CORE AUDITING & REPORTING MODULES
# ==============================================================================
# These modules are fully self-contained and run on top of standard Python libraries.
from parsers import ManifestParser
from checker import DependencyChecker
from reporter import SecurityReporter

# ==============================================================================
# SECTION 3: UTILITY FOR PARSING PACKAGE FILENAMES
# ==============================================================================
def extract_pkg_info_from_filename(filename):
    """
    Parses a package archive's filename to extract name and version.
    
    Expected formats:
      - Python Wheel:  requests-2.31.0-py3-none-any.whl -> ('requests', '2.31.0')
      - npm Tarball:   lodash-4.17.21.tgz -> ('lodash', '4.17.21')
      - Scoped npm:    @types-lodash-4.17.21.tgz -> ('@types/lodash', '4.17.21')
    """
    base = os.path.basename(filename)
    
    # Remove common archive extensions
    for ext in ['.whl', '.tar.gz', '.tgz', '.zip']:
        if base.endswith(ext):
            base = base[:-len(ext)]
            break

    # Split name parts by hyphen. Packages can contain hyphens, so we need to
    # find where the version string starts (starts with a digit).
    parts = base.split('-')
    if len(parts) >= 2:
        # If the second part is the version (e.g. '2.31.0')
        if re.match(r'^\d', parts[1]):
            return parts[0], parts[1]
            
        # If it's a scoped package (e.g., '@types-lodash-4.17.21' -> parts: ['@types', 'lodash', '4.17.21'])
        if parts[0].startswith('@') and len(parts) >= 3 and re.match(r'^\d', parts[2]):
            # Reconstruct the scope (e.g., '@types/lodash')
            return f"{parts[0]}/{parts[1]}", parts[2]
            
    return None, None

# ==============================================================================
# SECTION 4: CLI ENTRY POINT AND MAIN LOOP
# ==============================================================================
def main():
    # Set up command-line arguments.
    parser = argparse.ArgumentParser(
        description="DepShield: Platform-independent Supply Chain & Dependency Security Auditor",
        epilog="Supported ecosystems: Python (requirements.txt, pyproject.toml) and Node.js (package.json, package-lock.json). OS/2 is blocked."
    )
    # The manifest file to scan (requirements.txt, package.json, or package-lock.json)
    parser.add_argument("manifest", help="Path to package manifest file (requirements.txt, package.json, or package-lock.json)")
    # Optional downloaded package file to calculate the hash locally and verify
    parser.add_argument("-f", "--file", help="Path to a local package archive (e.g. .whl or .tgz) to verify checksum integrity")
    # Output folder for generated Markdown and HTML reports
    parser.add_argument("-o", "--output-dir", default=".", help="Directory to save reports (default: current directory)")
    parser.add_argument("--html-name", default="depshield_report.html", help="Filename for the HTML report")
    parser.add_argument("--md-name", default="depshield_report.md", help="Filename for the Markdown report")
    # Simulated current date used to run historical tests or check release age against a fixed timeline
    parser.add_argument("--current-date", default="2026-06-16", help="Simulated run date (YYYY-MM-DD) for age validation")

    args = parser.parse_args()

    # Verify that the manifest exists on the file system.
    if not os.path.exists(args.manifest):
        print(f"Error: Manifest file '{args.manifest}' does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting DepShield Security Audit...")
    print(f"[*] Manifest File: {args.manifest}")
    print(f"[*] Simulated Audit Date: {args.current_date}")

    manifest_filename = os.path.basename(args.manifest)
    base_dir = os.path.dirname(os.path.abspath(args.manifest))

    # ==============================================================================
    # SECTION 5: MANIFEST DETECTOR & ROUTING
    # ==============================================================================
    packages = []
    try:
        if manifest_filename == "requirements.txt":
            packages = ManifestParser.parse_requirements_txt(args.manifest)
        elif manifest_filename == "package.json":
            packages = ManifestParser.parse_package_json(args.manifest)
        elif manifest_filename == "package-lock.json":
            packages = ManifestParser.parse_package_lock_json(args.manifest)
        else:
            # Fallback guessing if filename is non-standard but matches characteristics
            if "requirements" in manifest_filename:
                packages = ManifestParser.parse_requirements_txt(args.manifest)
            elif manifest_filename.endswith(".json"):
                if "lock" in manifest_filename:
                    packages = ManifestParser.parse_package_lock_json(args.manifest)
                else:
                    packages = ManifestParser.parse_package_json(args.manifest)
            else:
                print(f"Error: Unrecognized manifest type '{manifest_filename}'. Must be requirements.txt, package.json, or package-lock.json.", file=sys.stderr)
                sys.exit(1)
    except Exception as e:
        print(f"Error parsing manifest: {e}", file=sys.stderr)
        sys.exit(1)

    if not packages:
        print("[!] Warning: No dependencies found in the manifest.", file=sys.stderr)
        sys.exit(0)

    print(f"[*] Found {len(packages)} dependencies to audit.")

    # Initialize the checker core with simulated running date.
    checker = DependencyChecker(current_date=args.current_date)

    # ==============================================================================
    # SECTION 6: RUN SECURITY CHECKS
    # ==============================================================================
    results = []
    for pkg in packages:
        name = pkg["name"]
        version = pkg.get("version")
        ecosystem = pkg.get("ecosystem", "PyPI")
        
        # Check if this package name matches the optional local file argument.
        # This matches case-insensitively and handles underscore/hyphen differences.
        local_file_to_check = None
        if args.file:
            lf_name, lf_version = extract_pkg_info_from_filename(args.file)
            if lf_name and lf_name.lower().replace('_', '-') == name.lower().replace('_', '-'):
                local_file_to_check = args.file
                print(f"[*] Matching local file '{args.file}' to package '{name}'")
                # If manifest did not specify a version, populate it from the filename.
                if not version:
                    version = lf_version

        print(f"[*] Auditing {ecosystem} package: {name}" + (f" (requested version: {version})" if version else " (latest version)"))
        
        # Run main package checker logic (API requests, vulnerability scans, age calculations).
        res = checker.check_package(name, version, ecosystem, base_dir, local_file=local_file_to_check)
        
        # If we are auditing an npm lockfile, it already contains integrity hashes.
        # We check if this matches what npm says on the registry.
        if not local_file_to_check and pkg.get("integrity"):
            match_found = False
            lockfile_integrity = pkg["integrity"]
            
            # Look up hashes list returned from registry
            if "hashes" in res and res["hashes"]:
                for expected in res["hashes"]:
                    if expected.get("integrity") == lockfile_integrity:
                        match_found = True
                        break
                    elif expected.get("sha1") and lockfile_integrity.endswith(expected.get("sha1")):
                        match_found = True
                        break
            
            res["file_verification"] = {
                "verified": match_found,
                "reason": "Lockfile integrity matched registry" if match_found else "Lockfile integrity MISMATCH against registry",
                "computed_hashes": {"integrity": lockfile_integrity},
                "expected_hashes": res.get("hashes")
            }
            
        results.append(res)

    # ==============================================================================
    # SECTION 7: REPORT GENERATION & OUTPUT
    # ==============================================================================
    reporter = SecurityReporter()
    summary = reporter.calculate_summary(results)
    
    # Save the reports.
    os.makedirs(args.output_dir, exist_ok=True)
    html_path = os.path.join(args.output_dir, args.html_name)
    md_path = os.path.join(args.output_dir, args.md_name)
    
    reporter.generate_html(results, args.manifest, html_path)
    md_content = reporter.generate_markdown(results, args.manifest)
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md_content)

    # Print summary metrics to console.
    print("\n" + "=" * 50)
    print("AUDIT COMPLETE")
    print("=" * 50)
    print(f"Overall Risk Assessment: {summary['risk_level']}")
    print(f"Total Packages: {summary['total_packages']}")
    print(f"Vulnerabilities: {summary['vulnerabilities_count']}")
    print(f"Recent Releases (<10 days old): {summary['recent_packages_count']}")
    print(f"Checksum Failures: {summary['checksum_failures_count']}")
    print(f"Missing Installations: {summary['uninstalled_count']}")
    print("-" * 50)
    print(f"HTML Report generated: {html_path}")
    print(f"Markdown Report generated: {md_path}")
    print("=" * 50 + "\n")

    # Set CLI exit codes based on severity.
    # Code 3: Checksum mismatch (critical supply chain risk).
    # Code 2: Vulnerabilities found (high risk).
    # Code 0: Clean run or warnings.
    if summary["checksum_failures_count"] > 0:
        sys.exit(3)
    elif summary["vulnerabilities_count"] > 0:
        sys.exit(2)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
