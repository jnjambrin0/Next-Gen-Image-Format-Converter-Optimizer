#!/usr/bin/env python3
"""
Audit dependencies for telemetry and auto-update features.

This script checks all Python dependencies for:
1. Known telemetry/analytics packages
2. Auto-update mechanisms
3. Network-related functionality that could phone home
"""

import sys
import subprocess
import json
import importlib.metadata
from typing import Dict, List, Set, Optional
from pathlib import Path


# Known telemetry/analytics packages
TELEMETRY_PACKAGES = {
    "sentry-sdk",
    "sentry",
    "raven",
    "newrelic",
    "datadog",
    "elastic-apm",
    "opencensus",
    "opentelemetry-api",
    "opentelemetry-sdk",
    "google-analytics",
    "mixpanel",
    "segment",
    "analytics-python",
    "raygun4py",
    "rollbar",
    "bugsnag",
    "appdynamics",
    "honeycomb-beeline",
    "scout-apm",
    "instana",
    "pybrake",
    "aws-xray-sdk",
}

# Packages known to have auto-update features
AUTO_UPDATE_PACKAGES = {
    "pip",  # Can self-update
    "poetry",  # Can self-update
    "pipx",  # Can self-update
    "homebrew",  # Not Python but commonly used
}

# Packages that make network requests (potential concern)
NETWORK_PACKAGES = {
    "requests",  # OK if not used for telemetry
    "urllib3",  # OK if not used for telemetry
    "httpx",  # OK if not used for telemetry
    "aiohttp",  # OK if not used for telemetry
    "boto3",  # AWS SDK - OK if not initialized
    "google-cloud-*",  # Google Cloud SDK - OK if not initialized
    "azure-*",  # Azure SDK - OK if not initialized
}

# Packages that are safe/expected
SAFE_PACKAGES = {
    "pillow",  # Image processing
    "numpy",  # Numerical computing
    "fastapi",  # Web framework
    "uvicorn",  # ASGI server
    "pydantic",  # Data validation
    "pytest",  # Testing
    "black",  # Code formatting
    "mypy",  # Type checking
    "structlog",  # Logging (local only)
    "python-multipart",  # File uploads
    "sqlalchemy",  # Database ORM
    "alembic",  # Database migrations
}


class DependencyAuditor:
    """Audit Python dependencies for privacy concerns."""
    
    def __init__(self):
        self.findings = {
            "telemetry": [],
            "auto_update": [],
            "network": [],
            "unknown": [],
            "safe": []
        }
    
    def get_installed_packages(self) -> Dict[str, str]:
        """Get all installed packages with versions."""
        packages = {}
        try:
            # Use pip list in JSON format
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format=json"],
                capture_output=True,
                text=True,
                check=True
            )
            
            for pkg in json.loads(result.stdout):
                packages[pkg["name"].lower()] = pkg["version"]
        
        except Exception as e:
            print(f"Error getting package list: {e}")
        
        return packages
    
    def check_package_metadata(self, package_name: str) -> Optional[Dict]:
        """Check package metadata for concerning features."""
        try:
            metadata = importlib.metadata.metadata(package_name)
            
            concerns = []
            
            # Check home page for telemetry services
            home_page = metadata.get("Home-page", "").lower()
            for telemetry in ["sentry", "datadog", "newrelic", "analytics"]:
                if telemetry in home_page:
                    concerns.append(f"Homepage mentions {telemetry}")
            
            # Check description
            description = metadata.get("Summary", "").lower()
            for keyword in ["telemetry", "analytics", "monitoring", "tracking"]:
                if keyword in description:
                    concerns.append(f"Description mentions {keyword}")
            
            # Check for update-related keywords
            for keyword in ["auto-update", "self-update", "automatic update"]:
                if keyword in description:
                    concerns.append(f"May have {keyword} feature")
            
            if concerns:
                return {
                    "package": package_name,
                    "concerns": concerns,
                    "metadata": {
                        "home_page": metadata.get("Home-page", ""),
                        "summary": metadata.get("Summary", "")
                    }
                }
        
        except Exception:
            pass
        
        return None
    
    def audit_dependencies(self) -> None:
        """Perform dependency audit."""
        print("🔍 Auditing Python dependencies for privacy concerns...\n")
        
        packages = self.get_installed_packages()
        print(f"Found {len(packages)} installed packages\n")
        
        for package_name, version in packages.items():
            package_lower = package_name.lower()
            
            # Check against known lists
            if package_lower in TELEMETRY_PACKAGES:
                self.findings["telemetry"].append({
                    "package": package_name,
                    "version": version,
                    "concern": "Known telemetry/analytics package"
                })
            
            elif package_lower in AUTO_UPDATE_PACKAGES:
                self.findings["auto_update"].append({
                    "package": package_name,
                    "version": version,
                    "concern": "Has auto-update capability"
                })
            
            elif package_lower in SAFE_PACKAGES:
                self.findings["safe"].append(package_name)
            
            elif any(package_lower.startswith(net_pkg.replace("*", "")) 
                    for net_pkg in NETWORK_PACKAGES):
                # Check metadata for telemetry indicators
                metadata_concerns = self.check_package_metadata(package_name)
                if metadata_concerns:
                    self.findings["network"].append({
                        "package": package_name,
                        "version": version,
                        "concern": "Makes network requests",
                        "details": metadata_concerns["concerns"]
                    })
                else:
                    self.findings["safe"].append(package_name)
            
            else:
                # Unknown package - check metadata
                metadata_concerns = self.check_package_metadata(package_name)
                if metadata_concerns:
                    self.findings["unknown"].append({
                        "package": package_name,
                        "version": version,
                        "details": metadata_concerns["concerns"]
                    })
    
    def generate_report(self) -> str:
        """Generate audit report."""
        report = []
        
        # Telemetry packages (CRITICAL)
        if self.findings["telemetry"]:
            report.append("❌ CRITICAL: Telemetry/Analytics Packages Found")
            report.append("=" * 50)
            for pkg in self.findings["telemetry"]:
                report.append(f"  - {pkg['package']} v{pkg['version']}")
                report.append(f"    Concern: {pkg['concern']}")
            report.append("")
        
        # Auto-update packages (WARNING)
        if self.findings["auto_update"]:
            report.append("⚠️  WARNING: Auto-Update Capable Packages")
            report.append("=" * 50)
            for pkg in self.findings["auto_update"]:
                report.append(f"  - {pkg['package']} v{pkg['version']}")
                report.append(f"    Concern: {pkg['concern']}")
            report.append("")
        
        # Network packages (INFO)
        if self.findings["network"]:
            report.append("ℹ️  INFO: Network-Capable Packages")
            report.append("=" * 50)
            for pkg in self.findings["network"]:
                report.append(f"  - {pkg['package']} v{pkg['version']}")
                if "details" in pkg:
                    for detail in pkg["details"]:
                        report.append(f"    - {detail}")
            report.append("")
        
        # Unknown packages with concerns
        if self.findings["unknown"]:
            report.append("❓ Unknown Packages with Potential Concerns")
            report.append("=" * 50)
            for pkg in self.findings["unknown"]:
                report.append(f"  - {pkg['package']} v{pkg['version']}")
                if "details" in pkg:
                    for detail in pkg["details"]:
                        report.append(f"    - {detail}")
            report.append("")
        
        # Summary
        report.append("📊 Summary")
        report.append("=" * 50)
        report.append(f"  Total packages audited: {sum(len(v) if isinstance(v, list) else 0 for v in self.findings.values())}")
        report.append(f"  Telemetry packages: {len(self.findings['telemetry'])}")
        report.append(f"  Auto-update capable: {len(self.findings['auto_update'])}")
        report.append(f"  Network capable: {len(self.findings['network'])}")
        report.append(f"  Safe packages: {len(self.findings['safe'])}")
        
        # Recommendations
        if self.findings["telemetry"]:
            report.append("\n🚨 ACTION REQUIRED:")
            report.append("  Remove or disable telemetry packages:")
            for pkg in self.findings["telemetry"]:
                report.append(f"    pip uninstall {pkg['package']}")
        
        return "\n".join(report)
    
    def save_report(self, output_file: str = "dependency_audit.txt") -> None:
        """Save report to file."""
        report = self.generate_report()
        
        with open(output_file, "w") as f:
            f.write(report)
        
        print(f"\n📄 Report saved to: {output_file}")
    
    def get_exit_code(self) -> int:
        """Get exit code based on findings."""
        if self.findings["telemetry"]:
            return 1  # Critical - telemetry found
        elif self.findings["auto_update"]:
            return 2  # Warning - auto-update found
        else:
            return 0  # OK


def main():
    """Main entry point."""
    auditor = DependencyAuditor()
    auditor.audit_dependencies()
    
    # Print report
    print(auditor.generate_report())
    
    # Save report
    auditor.save_report()
    
    # Exit with appropriate code
    sys.exit(auditor.get_exit_code())


if __name__ == "__main__":
    main()