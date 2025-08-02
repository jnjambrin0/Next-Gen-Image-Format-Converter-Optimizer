"""
Enhanced network isolation verification for startup and runtime.
"""

import asyncio
import os
import socket
import subprocess
import sys
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
import structlog

from app.core.monitoring.network_check import NetworkIsolationChecker
from app.core.monitoring.security_events import SecurityEventTracker
from app.models.security_event import SecurityEventType, SecuritySeverity
from app.core.security.types import NetworkStatus, VerificationResult
from app.core.security.errors import (
    SecurityError,
    create_verification_error,
    create_network_error
)
from app.core.constants import NETWORK_CHECK_TIMEOUT
from app.core.security.metrics import SecurityMetricsCollector

logger = structlog.get_logger()


class NetworkStrictness(Enum):
    """Network verification strictness levels."""
    STANDARD = "standard"  # Basic checks only
    STRICT = "strict"      # + Active monitoring
    PARANOID = "paranoid"  # + Real-time enforcement


class NetworkVerifier(NetworkIsolationChecker):
    """
    Enhanced network isolation verifier with configurable strictness.
    Extends existing NetworkIsolationChecker with additional verification.
    """
    
    def __init__(
        self, 
        strictness: NetworkStrictness = NetworkStrictness.STANDARD,
        security_tracker: Optional[SecurityEventTracker] = None
    ):
        """
        Initialize network verifier.
        
        Args:
            strictness: Verification strictness level
            security_tracker: Optional security event tracker
        """
        super().__init__()
        self.strictness = strictness
        self.security_tracker = security_tracker
        self.metrics_collector = SecurityMetricsCollector()
        self._network_status: NetworkStatus = {
            "isolated": True,
            "verified": False,
            "strictness": strictness.value,
            "checks_passed": [],
            "checks_failed": [],
            "warnings": []
        }
    
    async def verify_network_isolation(self) -> Dict[str, Any]:
        """
        Perform comprehensive network isolation verification.
        
        Returns:
            Dict with isolation status and detailed findings
        """
        logger.info(f"Starting network isolation verification (strictness: {self.strictness.value})")
        
        # Start metrics collection
        self.metrics_collector.start_verification()
        
        # Start with basic checks from parent class
        basic_findings = self.check_network_isolation()
        self._network_status["warnings"].extend(basic_findings.get("warnings", []))
        
        # Check 1: Verify localhost-only binding
        localhost_check = self._verify_localhost_binding()
        if localhost_check["passed"]:
            self._network_status["checks_passed"].append("localhost_binding")
        else:
            self._network_status["checks_failed"].append("localhost_binding")
            self._network_status["isolated"] = False
            self._network_status["warnings"].extend(localhost_check.get("warnings", []))
        
        # Check 2: Verify no active connections
        if self.strictness in [NetworkStrictness.STRICT, NetworkStrictness.PARANOID]:
            connections_check = self._verify_no_active_connections()
            if connections_check["passed"]:
                self._network_status["checks_passed"].append("no_active_connections")
            else:
                self._network_status["checks_failed"].append("no_active_connections")
                self._network_status["isolated"] = False
                self._network_status["warnings"].extend(connections_check.get("warnings", []))
        
        # Check 3: Verify DNS blocking capability
        dns_check = await self._verify_dns_blocking()
        if dns_check["passed"]:
            self._network_status["checks_passed"].append("dns_blocking")
        else:
            self._network_status["checks_failed"].append("dns_blocking")
            if self.strictness == NetworkStrictness.PARANOID:
                self._network_status["isolated"] = False
            self._network_status["warnings"].extend(dns_check.get("warnings", []))
        
        # Check 4: Verify network interfaces
        if self.strictness == NetworkStrictness.PARANOID:
            interface_check = self._verify_network_interfaces()
            if interface_check["passed"]:
                self._network_status["checks_passed"].append("network_interfaces")
            else:
                self._network_status["checks_failed"].append("network_interfaces")
                self._network_status["warnings"].extend(interface_check.get("warnings", []))
        
        # Mark as verified
        self._network_status["verified"] = True
        
        # Record security event if not isolated
        if not self._network_status["isolated"] and self.security_tracker:
            await self.security_tracker.record_event({
                "event_type": SecurityEventType.VIOLATION,
                "severity": SecuritySeverity.WARNING,
                "details": {
                    "violation_type": "network_isolation_failed",
                    "checks_failed": self._network_status["checks_failed"],
                    "warning_count": len(self._network_status["warnings"])
                }
            })
        
        # End metrics collection
        self.metrics_collector.end_verification()
        
        # Record violations in metrics
        if not self._network_status["isolated"]:
            self.metrics_collector.record_violation()
        
        logger.info(
            "Network isolation verification complete",
            isolated=self._network_status["isolated"],
            checks_passed=len(self._network_status["checks_passed"]),
            checks_failed=len(self._network_status["checks_failed"])
        )
        
        return self._network_status
    
    def _verify_localhost_binding(self) -> VerificationResult:
        """
        Verify that all sockets are bound to localhost only.
        
        Returns:
            Dict with verification results
        """
        result: VerificationResult = {"passed": True, "warnings": []}
        
        try:
            # Check listening sockets using netstat or ss
            cmd = ["ss", "-tlnp"] if os.path.exists("/usr/bin/ss") else ["netstat", "-tlnp"]
            
            try:
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                
                # Parse output for non-localhost bindings
                for line in output.split('\n'):
                    if "LISTEN" in line or "tcp" in line:
                        # Look for 0.0.0.0 or :: bindings
                        if "0.0.0.0:" in line or ":::" in line or "*:" in line:
                            # Check if it's our process
                            if "python" in line or str(os.getpid()) in line:
                                result["passed"] = False
                                result["warnings"].append(
                                    "Application bound to all interfaces, should bind to localhost only"
                                )
                                break
            
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Command failed, try alternative check
                result["warnings"].append("Could not verify socket bindings (command failed)")
        
        except Exception as e:
            logger.warning(f"Error checking localhost binding: {e}")
            result["warnings"].append("Could not verify localhost binding")
        
        return result
    
    def _verify_no_active_connections(self) -> VerificationResult:
        """
        Verify no active outbound connections.
        
        Returns:
            Dict with verification results
        """
        result: VerificationResult = {"passed": True, "warnings": []}
        
        try:
            # Check active connections
            cmd = ["ss", "-tnp"] if os.path.exists("/usr/bin/ss") else ["netstat", "-tnp"]
            
            try:
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                
                # Look for established connections
                for line in output.split('\n'):
                    if "ESTABLISHED" in line or "ESTAB" in line:
                        # Check if it's our process and not localhost
                        if ("python" in line or str(os.getpid()) in line) and \
                           not ("127.0.0.1" in line or "::1" in line):
                            result["passed"] = False
                            result["warnings"].append("Active non-localhost connection detected")
                            break
            
            except (subprocess.CalledProcessError, FileNotFoundError):
                result["warnings"].append("Could not verify active connections (command failed)")
        
        except Exception as e:
            logger.warning(f"Error checking active connections: {e}")
            result["warnings"].append("Could not verify active connections")
        
        return result
    
    async def _verify_dns_blocking(self) -> VerificationResult:
        """
        Verify DNS resolution is blocked.
        
        Returns:
            Dict with verification results
        """
        result: VerificationResult = {"passed": True, "warnings": []}
        
        try:
            # Test DNS resolution blocking
            test_domains = ["example.com", "google.com", "8.8.8.8"]
            
            for domain in test_domains:
                try:
                    # This should fail if DNS is properly blocked
                    # Using asyncio for timeout handling
                    loop = asyncio.get_event_loop()
                    await asyncio.wait_for(
                        loop.run_in_executor(None, socket.getaddrinfo, domain, 80),
                        timeout=NETWORK_CHECK_TIMEOUT
                    )
                    # If we reach here, DNS resolution succeeded (not expected)
                    result["passed"] = False
                    result["warnings"].append(f"DNS resolution succeeded for {domain}")
                
                except asyncio.TimeoutError:
                    # Expected - DNS should be blocked or timeout
                    pass
                except socket.gaierror:
                    # Expected - DNS resolution failed
                    pass
        
        except Exception as e:
            logger.warning(f"Error testing DNS blocking: {e}")
            result["warnings"].append("Could not verify DNS blocking")
        
        return result
    
    def _verify_network_interfaces(self) -> VerificationResult:
        """
        Verify network interface configuration.
        
        Returns:
            Dict with verification results
        """
        result: VerificationResult = {"passed": True, "warnings": []}
        
        try:
            # Check network interfaces
            cmd = ["ip", "addr"] if os.path.exists("/usr/bin/ip") else ["ifconfig", "-a"]
            
            try:
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                
                # Look for non-loopback interfaces that are UP
                lines = output.split('\n')
                current_interface = None
                
                for line in lines:
                    # Detect interface names
                    if not line.startswith(' '):
                        if ':' in line:
                            current_interface = line.split(':')[0].strip()
                    
                    # Check if non-loopback interface is UP
                    if current_interface and current_interface not in ["lo", "lo0", "localhost"]:
                        if "UP" in line and "state UP" in line:
                            result["warnings"].append(
                                f"Non-loopback network interface {current_interface} is active"
                            )
            
            except (subprocess.CalledProcessError, FileNotFoundError):
                result["warnings"].append("Could not verify network interfaces (command failed)")
        
        except Exception as e:
            logger.warning(f"Error checking network interfaces: {e}")
            result["warnings"].append("Could not verify network interfaces")
        
        return result
    
    def get_network_status(self) -> NetworkStatus:
        """
        Get current network isolation status.
        
        Returns:
            Network status dictionary
        """
        return self._network_status.copy()
    
    def get_status_summary(self) -> str:
        """
        Get human-readable status summary.
        
        Returns:
            Status summary string
        """
        if not self._network_status["verified"]:
            return "Network isolation not yet verified"
        
        if self._network_status["isolated"]:
            return f"Network properly isolated ({self.strictness.value} mode)"
        else:
            failed_checks = ", ".join(self._network_status["checks_failed"])
            return f"Network isolation issues detected: {failed_checks}"
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get verification metrics.
        
        Returns:
            Dictionary containing verification metrics
        """
        metrics = self.metrics_collector.get_metrics()
        summary = self.metrics_collector.get_summary()
        
        return {
            "raw_metrics": metrics,
            "summary": summary,
            "network_status": self._network_status
        }


async def verify_network_at_startup(
    strictness: NetworkStrictness = NetworkStrictness.STANDARD,
    security_tracker: Optional[SecurityEventTracker] = None
) -> Dict[str, Any]:
    """
    Convenience function for startup network verification.
    
    Args:
        strictness: Verification strictness level
        security_tracker: Optional security event tracker
    
    Returns:
        Network isolation status
    """
    verifier = NetworkVerifier(strictness, security_tracker)
    return await verifier.verify_network_isolation()