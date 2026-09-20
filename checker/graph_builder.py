"""
Graph Builder: Ingests package manifests and constructs enriched DependencyNode graphs.
"""

import os
import json
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from checker.models import DependencyNode
from checker.enrichment import EnrichmentClient
from parsers import ManifestParser


class GraphBuilder:
    """Ingests manifests, resolves dependencies, and builds enriched graphs."""

    def __init__(self, enrichment_client: Optional[EnrichmentClient] = None):
        self.enrichment_client = enrichment_client or EnrichmentClient()

    @staticmethod
    def parse_pipfile_lock(file_path: str) -> List[Dict[str, Any]]:
        """Parses a Pipfile.lock JSON file into package dictionaries."""
        packages = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            sections = [data.get('default', {}), data.get('develop', {})]
            seen = set()
            for sec in sections:
                for pkg_name, details in sec.items():
                    if pkg_name in seen:
                        continue
                    seen.add(pkg_name)
                    raw_ver = details.get('version', '')
                    ver_clean = re.sub(r'^[=~><!^]+', '', raw_ver).strip()
                    packages.append({
                        'name': pkg_name,
                        'version': ver_clean or None,
                        'raw_constraint': raw_ver,
                        'ecosystem': 'PyPI'
                    })
        except Exception:
            pass
        return packages

    def parse_manifest(self, file_path: str) -> Tuple[List[Dict[str, Any]], str]:
        """Auto-detects manifest type and extracts package descriptors."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Manifest file not found: {file_path}")

        fn = os.path.basename(file_path).lower()
        if fn == "requirements.txt" or "requirements" in fn:
            return ManifestParser.parse_requirements_txt(file_path), "PyPI"
        elif fn == "pipfile.lock":
            return self.parse_pipfile_lock(file_path), "PyPI"
        elif fn == "package.json":
            return ManifestParser.parse_package_json(file_path), "npm"
        elif fn == "package-lock.json":
            return ManifestParser.parse_package_lock_json(file_path), "npm"
        elif fn.endswith(".json"):
            if "lock" in fn:
                return ManifestParser.parse_package_lock_json(file_path), "npm"
            return ManifestParser.parse_package_json(file_path), "npm"
        else:
            # Fallback to requirements parser
            return ManifestParser.parse_requirements_txt(file_path), "PyPI"

    def build_from_manifest(self, file_path: str) -> List[DependencyNode]:
        """Ingests a manifest and returns enriched DependencyNode objects."""
        raw_pkgs, ecosystem = self.parse_manifest(file_path)
        nodes: List[DependencyNode] = []
        seen = set()

        for p in raw_pkgs:
            name = p.get("name")
            if not name or name in seen:
                continue
            seen.add(name)
            ver = p.get("version") or "latest"
            eco = p.get("ecosystem", ecosystem)
            nodes.append(DependencyNode(
                name=name,
                version=ver,
                ecosystem=eco
            ))

        # Enrich nodes with OSV vulnerabilities and registry release metadata
        enriched_nodes = self.enrichment_client.enrich_nodes(nodes)
        return enriched_nodes

    def build_from_packages(self, packages: List[Dict[str, Any]]) -> List[DependencyNode]:
        """Builds and enriches nodes from an explicit package list."""
        nodes: List[DependencyNode] = []
        seen = set()
        for p in packages:
            name = p.get("name")
            ver = p.get("version") or "latest"
            eco = p.get("ecosystem", "PyPI")
            key = f"{name}@{ver}"
            if key in seen:
                continue
            seen.add(key)
            nodes.append(DependencyNode(
                name=name,
                version=ver,
                ecosystem=eco
            ))
        return self.enrichment_client.enrich_nodes(nodes)
