import json
import re

# ==============================================================================
# MODULE: MANIFEST PARSER
# ==============================================================================
# Extracts package lists, target versions, and constraints from project manifests.

class ManifestParser:
    """Parser for package manifest files (pip requirements.txt, npm package.json/package-lock.json)."""

    # ==========================================================================
    # PYTHON REQUIREMENTS PARSER
    # ==========================================================================
    @staticmethod
    def parse_requirements_txt(file_path):
        """
        Parses a requirements.txt file and extracts pinned/unpinned packages.
        
        Returns a list of dictionaries:
          [{'name': 'requests', 'version': '2.31.0', 'raw_constraint': '...', 'ecosystem': 'PyPI'}]
        """
        packages = []
        # regex matches name followed by optional comparison operator and version string.
        # Group 1: Package name (allows alphanumeric, underscores, hyphens, brackets for extras)
        # Group 2: Comparison operator (==, >=, <=, etc.)
        # Group 3: Version string (allows digits, dots, hyphens, underscores)
        pattern = re.compile(r'^([a-zA-Z0-9_\-\[\]]+)(?:(==|>=|<=|>|<|~=)([a-zA-Z0-9\.\-\_]+))?')
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip blank lines, comments, or pip configuration flags (e.g. -r, -e, --index-url)
                    if not line or line.startswith('#') or line.startswith('-'):
                        continue
                    
                    # Strip any trailing inline comments (e.g., 'requests==2.31.0 # security patch')
                    if ' #' in line:
                        line = line.split(' #')[0].strip()

                    match = pattern.match(line)
                    if match:
                        name = match.group(1)
                        op = match.group(2)
                        version = match.group(3)
                        
                        # Remove extras from package name if present (e.g., requests[security] -> requests)
                        name = re.sub(r'\[.*\]', '', name)
                        
                        # We specifically track exact version matches ('==').
                        # For loose constraints, we set the version to None to trigger latest-release auditing.
                        packages.append({
                            "name": name,
                            "version": version if op == "==" else None,
                            "raw_constraint": line,
                            "ecosystem": "PyPI"
                        })
        except Exception as e:
            raise ValueError(f"Failed to parse requirements.txt: {e}")

        return packages

    # ==========================================================================
    # NODE.JS PACKAGE.JSON PARSER
    # ==========================================================================
    @staticmethod
    def parse_package_json(file_path):
        """
        Parses a package.json file to extract direct dependencies and devDependencies.
        
        Returns a list of dictionaries containing package names and clean version estimates.
        """
        packages = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Retrieve production and development dependencies
                deps = data.get("dependencies", {})
                dev_deps = data.get("devDependencies", {})
                
                all_deps = {}
                all_deps.update(deps)
                all_deps.update(dev_deps)

                for name, ver_range in all_deps.items():
                    # Clean up standard semver symbols (e.g. ^1.2.3 -> 1.2.3, ~4.17.0 -> 4.17.0)
                    # to obtain a base version we can query in the registry.
                    clean_version = re.sub(r'^[\^~>=<*]+', '', ver_range).strip()
                    # If it's a wildcard '*', we look up the latest release
                    if not clean_version or clean_version == '*':
                        clean_version = None

                    packages.append({
                        "name": name,
                        "version": clean_version,
                        "raw_constraint": ver_range,
                        "ecosystem": "npm"
                    })
        except Exception as e:
            raise ValueError(f"Failed to parse package.json: {e}")

        return packages

    # ==========================================================================
    # NODE.JS PACKAGE-LOCK.JSON PARSER
    # ==========================================================================
    @staticmethod
    def parse_package_lock_json(file_path):
        """
        Parses package-lock.json to extract exact resolved versions and integrity hashes.
        Supports both v1 lockfiles (recursive dependencies) and v2/v3 lockfiles (packages structure).
        """
        packages = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Lockfile formats v2 & v3 represent dependency structures under "packages"
                if "packages" in data:
                    for pkg_path, pkg_info in data["packages"].items():
                        if not pkg_path:  # Skip empty key representing the root package
                            continue
                        
                        # Extract the package name from path.
                        # E.g. 'node_modules/lodash' -> 'lodash'
                        # E.g. 'node_modules/a/node_modules/b' -> 'b'
                        parts = pkg_path.split("node_modules/")
                        name = parts[-1]
                        
                        version = pkg_info.get("version")
                        integrity = pkg_info.get("integrity")
                        resolved = pkg_info.get("resolved")
                        
                        if version:
                            packages.append({
                                "name": name,
                                "version": version,
                                "integrity": integrity,
                                "resolved": resolved,
                                "ecosystem": "npm"
                            })
                            
                # Lockfile format v1 represents dependencies under recursive "dependencies" blocks
                elif "dependencies" in data:
                    def parse_deps_v1(deps):
                        for name, info in deps.items():
                            version = info.get("version")
                            integrity = info.get("integrity")
                            resolved = info.get("resolved")
                            
                            if version:
                                packages.append({
                                    "name": name,
                                    "version": version,
                                    "integrity": integrity,
                                    "resolved": resolved,
                                    "ecosystem": "npm"
                                })
                            
                            # Recurse down nested dependency blocks
                            if "dependencies" in info:
                                parse_deps_v1(info["dependencies"])
                    
                    parse_deps_v1(data["dependencies"])
                    
        except Exception as e:
            raise ValueError(f"Failed to parse package-lock.json: {e}")

        return packages
