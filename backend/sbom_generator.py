"""
Quantum Protocol v5.0 — SBOM Generator
Software Bill of Materials generator with CycloneDX/SPDX support.

Phase 8.9: SBOM (Software Bill of Materials) Generator
"""

import json
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
import xml.etree.ElementTree as ET


class SBOMFormat(Enum):
    CYCLONEDX_JSON = "cyclonedx-json"
    CYCLONEDX_XML = "cyclonedx-xml"
    SPDX_JSON = "spdx-json"
    SPDX_TAG_VALUE = "spdx-tag-value"


@dataclass
class Component:
    name: str
    version: str
    type: str  # library, framework, application, etc.
    purl: Optional[str] = None  # Package URL
    cpe: Optional[str] = None  # Common Platform Enumeration
    swid: Optional[str] = None  # Software ID
    licenses: List[str] = None
    copyright: Optional[str] = None
    supplier: Optional[str] = None
    hashes: Dict[str, str] = None  # alg -> hash
    vulnerabilities: List[Dict] = None


@dataclass
class SBOM:
    bom_format: str
    spec_version: str
    serial_number: str
    version: int
    timestamp: str
    components: List[Component]
    metadata: Dict
    dependencies: List[Dict] = None


class SBOMGenerator:
    """Generate SBOMs from dependency scans."""

    def __init__(self):
        self.spec_versions = {
            SBOMFormat.CYCLONEDX_JSON: "1.4",
            SBOMFormat.CYCLONEDX_XML: "1.4",
            SBOMFormat.SPDX_JSON: "2.3",
            SBOMFormat.SPDX_TAG_VALUE: "2.3"
        }

    def generate_from_dependencies(
        self,
        dependencies: List[Dict],
        format: SBOMFormat = SBOMFormat.CYCLONEDX_JSON,
        application_name: str = "Application",
        supplier_name: str = "Unknown"
    ) -> str:
        """Generate SBOM from a list of dependencies."""
        
        components = []
        for dep in dependencies:
            component = Component(
                name=dep.get("name", "Unknown"),
                version=dep.get("version", "Unknown"),
                type=dep.get("type", "library"),
                purl=dep.get("purl"),
                licenses=dep.get("licenses", []),
                vulnerabilities=dep.get("vulnerabilities", [])
            )
            components.append(component)
        
        if format == SBOMFormat.CYCLONEDX_JSON:
            return self._generate_cyclonedx_json(components, application_name, supplier_name)
        elif format == SBOMFormat.SPDX_JSON:
            return self._generate_spdx_json(components, application_name, supplier_name)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_cyclonedx_json(
        self,
        components: List[Component],
        application_name: str,
        supplier_name: str
    ) -> str:
        """Generate CycloneDX JSON format SBOM."""
        
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": self.spec_versions[SBOMFormat.CYCLONEDX_JSON],
            "serialNumber": f"urn:uuid:{self._generate_uuid()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "Quantum Protocol",
                        "name": "OWASP Scanner",
                        "version": "5.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": application_name,
                    "supplier": {"name": supplier_name}
                }
            },
            "components": []
        }
        
        for comp in components:
            comp_dict = {
                "type": comp.type,
                "name": comp.name,
                "version": comp.version,
            }
            
            if comp.purl:
                comp_dict["purl"] = comp.purl
            
            if comp.licenses:
                comp_dict["licenses"] = [{"license": {"name": lic}} for lic in comp.licenses]
            
            if comp.vulnerabilities:
                comp_dict["vulnerabilities"] = [
                    {
                        "id": vuln.get("cve", "Unknown"),
                        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vuln.get('cve', '')}"},
                        "ratings": [{"source": {"name": "NVD"}, "score": vuln.get("cvss", 0), "severity": vuln.get("severity", "unknown")}]
                    }
                    for vuln in comp.vulnerabilities
                ]
            
            bom["components"].append(comp_dict)
        
        return json.dumps(bom, indent=2)

    def _generate_spdx_json(
        self,
        components: List[Component],
        application_name: str,
        supplier_name: str
    ) -> str:
        """Generate SPDX JSON format SBOM."""
        
        spdx_id = f"SPDXRef-{self._generate_uuid()}"
        
        doc = {
            "spdxVersion": f"SPDX-{self.spec_versions[SBOMFormat.SPDX_JSON]}",
            "dataLicense": "CC0-1.0",
            "SPDXID": spdx_id,
            "name": application_name,
            "documentNamespace": f"https://quantum-protocol.io/sbom/{spdx_id}",
            "creationInfo": {
                "created": datetime.now(timezone.utc).isoformat(),
                "creators": [
                    f"Tool: Quantum Protocol-OWASP Scanner-5.0.0",
                    f"Organization: {supplier_name}"
                ]
            },
            "packages": []
        }
        
        # Add application package
        app_package = {
            "SPDXID": "SPDXRef-Application",
            "name": application_name,
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION"
        }
        doc["packages"].append(app_package)
        
        # Add dependencies as packages
        for i, comp in enumerate(components):
            package = {
                "SPDXID": f"SPDXRef-Package-{i}",
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": comp.purl or "NOASSERTION",
                "licenseConcluded": comp.licenses[0] if comp.licenses else "NOASSERTION",
                "licenseDeclared": comp.licenses[0] if comp.licenses else "NOASSERTION",
                "copyrightText": comp.copyright or "NOASSERTION",
                "externalRefs": []
            }
            
            if comp.purl:
                package["externalRefs"].append({
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl
                })
            
            doc["packages"].append(package)
        
        # Add relationships
        doc["relationships"] = [
            {
                "spdxElementId": spdx_id,
                "relatedSpdxElement": "SPDXRef-Application",
                "relationshipType": "DESCRIBES"
            }
        ]
        
        for i in range(len(components)):
            doc["relationships"].append({
                "spdxElementId": "SPDXRef-Application",
                "relatedSpdxElement": f"SPDXRef-Package-{i}",
                "relationshipType": "DEPENDS_ON"
            })
        
        return json.dumps(doc, indent=2)

    def _generate_uuid(self) -> str:
        """Generate a UUID for the SBOM."""
        import uuid
        return str(uuid.uuid4())

    def get_license_compliance_summary(self, components: List[Component]) -> Dict:
        """Analyze license compliance for components."""
        license_counts = {}
        restricted_licenses = ["GPL-3.0", "AGPL-3.0", "Proprietary"]
        warnings = []
        
        for comp in components:
            for lic in (comp.licenses or ["Unknown"]):
                license_counts[lic] = license_counts.get(lic, 0) + 1
                
                if lic in restricted_licenses:
                    warnings.append({
                        "component": comp.name,
                        "license": lic,
                        "warning": "Copyleft license may require source code disclosure"
                    })
        
        return {
            "license_distribution": license_counts,
            "total_components": len(components),
            "unique_licenses": len(license_counts),
            "warnings": warnings,
            "compliant": len(warnings) == 0
        }


# Singleton instance
sbom_generator = SBOMGenerator()
