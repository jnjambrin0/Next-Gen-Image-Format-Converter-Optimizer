"""
Security-related API endpoints including network status.
"""

from fastapi import APIRouter, Request, Depends, HTTPException
from typing import Dict, Any, Optional
from datetime import datetime

from app.core.security.network_verifier import NetworkVerifier, NetworkStrictness
from app.core.security.network_monitor import NetworkMonitor
from app.core.monitoring.security_events import SecurityEventTracker
from app.config import settings

router = APIRouter(prefix="/security", tags=["security"])


def get_network_verifier(request: Request) -> Optional[NetworkVerifier]:
    """Get network verifier from app state if available."""
    if hasattr(request.app.state, "network_verifier"):
        return request.app.state.network_verifier
    return None


def get_network_monitor(request: Request) -> Optional[NetworkMonitor]:
    """Get network monitor from app state if available."""
    if hasattr(request.app.state, "network_monitor"):
        return request.app.state.network_monitor
    return None


def get_security_tracker(request: Request) -> Optional[SecurityEventTracker]:
    """Get security event tracker from app state if available."""
    if hasattr(request.app.state, "security_tracker"):
        return request.app.state.security_tracker
    return None


@router.get("/network-status", response_model=Dict[str, Any])
async def get_network_status(
    request: Request,
    verifier: Optional[NetworkVerifier] = Depends(get_network_verifier),
    monitor: Optional[NetworkMonitor] = Depends(get_network_monitor)
) -> Dict[str, Any]:
    """
    Get detailed network isolation status.
    
    Returns comprehensive information about:
    - Network isolation verification results
    - Active monitoring status
    - Recent network violations
    - Configuration settings
    """
    response = {
        "timestamp": datetime.utcnow().isoformat(),
        "network_isolated": True,
        "verification_status": "unknown",
        "monitoring_active": False,
        "configuration": {
            "verification_enabled": settings.network_verification_enabled,
            "strictness": settings.network_verification_strictness,
            "monitoring_enabled": settings.network_monitoring_enabled,
            "terminate_on_violation": settings.terminate_on_network_violation
        }
    }
    
    # Get verification status from app state
    if hasattr(request.app.state, "network_status"):
        network_status = request.app.state.network_status
        response["network_isolated"] = network_status.get("isolated", True)
        response["verification_status"] = "verified" if network_status.get("verified", False) else "not_verified"
        response["verification_details"] = {
            "checks_passed": network_status.get("checks_passed", []),
            "checks_failed": network_status.get("checks_failed", []),
            "warnings": network_status.get("warnings", [])
        }
    
    # Get current verifier status if available
    if verifier:
        verifier_status = verifier.get_network_status()
        response["verifier_status"] = {
            "isolated": verifier_status.get("isolated", True),
            "verified": verifier_status.get("verified", False),
            "summary": verifier.get_status_summary()
        }
    
    # Get monitor status if available
    if monitor:
        monitor_stats = monitor.get_violation_stats()
        response["monitoring_active"] = monitor_stats.get("monitoring_active", False)
        response["monitor_status"] = {
            "active": monitor_stats.get("monitoring_active", False),
            "baseline_connections": monitor_stats.get("baseline_connections", 0),
            "total_violations": monitor_stats.get("total_violations", 0),
            "violations_by_pid": monitor_stats.get("violations_by_pid", {}),
            "terminate_enabled": monitor_stats.get("terminate_enabled", False)
        }
    
    return response


@router.get("/status", response_model=Dict[str, Any])
async def get_security_status(
    request: Request,
    tracker: Optional[SecurityEventTracker] = Depends(get_security_tracker)
) -> Dict[str, Any]:
    """
    Get overall security status including recent events.
    
    Returns:
        Security status with event summary and configuration
    """
    response = {
        "timestamp": datetime.utcnow().isoformat(),
        "security_enabled": True,
        "sandboxing_enabled": settings.enable_sandboxing,
        "sandbox_strictness": settings.sandbox_strictness,
        "network_isolation": {
            "enabled": settings.network_verification_enabled,
            "strictness": settings.network_verification_strictness,
            "monitoring": settings.network_monitoring_enabled
        }
    }
    
    # Get security event summary if tracker available
    if tracker:
        try:
            summary = tracker.get_event_summary(hours=24)
            response["event_summary"] = {
                "total_events_24h": summary.total_events,
                "events_by_type": summary.events_by_type,
                "events_by_severity": summary.events_by_severity,
                "recent_violations": len(summary.recent_violations)
            }
            
            # Get violation trends
            trends = tracker.get_violation_trends(days=7)
            response["violation_trends"] = {
                "period_days": trends["period_days"],
                "trend": trends["trend"],
                "daily_average": sum(d["total"] for d in trends["daily_violations"]) / len(trends["daily_violations"]) if trends["daily_violations"] else 0
            }
        except Exception as e:
            response["event_summary"] = {"error": "Failed to get event summary"}
    
    return response


@router.get("/events", response_model=Dict[str, Any])
async def get_security_events(
    request: Request,
    hours: int = 24,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    tracker: Optional[SecurityEventTracker] = Depends(get_security_tracker)
) -> Dict[str, Any]:
    """
    Get recent security events with optional filtering.
    
    Args:
        hours: Number of hours to look back (default: 24, max: 168)
        event_type: Filter by event type
        severity: Filter by severity level
    
    Returns:
        List of security events matching criteria
    """
    # Validate parameters
    if hours > 168:  # Max 7 days
        raise HTTPException(status_code=400, detail="Hours cannot exceed 168 (7 days)")
    
    if not tracker:
        return {
            "events": [],
            "message": "Security event tracking not available"
        }
    
    # Get event summary
    summary = tracker.get_event_summary(hours=hours)
    
    # Filter events if requested
    events = summary.recent_violations
    
    if event_type:
        events = [e for e in events if e.get("event_type") == event_type]
    
    if severity:
        events = [e for e in events if e.get("severity") == severity]
    
    return {
        "time_period_hours": hours,
        "total_events": len(events),
        "events": events,
        "filters": {
            "event_type": event_type,
            "severity": severity
        }
    }


@router.post("/verify-network", response_model=Dict[str, Any])
async def verify_network_isolation(
    request: Request,
    strictness: Optional[str] = None
) -> Dict[str, Any]:
    """
    Trigger manual network isolation verification.
    
    Args:
        strictness: Override strictness level (standard/strict/paranoid)
    
    Returns:
        Verification results
    """
    # Map strictness string to enum
    if strictness:
        strictness_map = {
            "standard": NetworkStrictness.STANDARD,
            "strict": NetworkStrictness.STRICT,
            "paranoid": NetworkStrictness.PARANOID
        }
        if strictness not in strictness_map:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid strictness level. Must be one of: {list(strictness_map.keys())}"
            )
        strictness_enum = strictness_map[strictness]
    else:
        strictness_enum = NetworkStrictness.STANDARD
    
    # Get security tracker if available
    tracker = get_security_tracker(request)
    
    # Perform verification
    from app.core.security.network_verifier import verify_network_at_startup
    result = await verify_network_at_startup(strictness_enum, tracker)
    
    # Update app state
    request.app.state.network_status = result
    
    return {
        "verification_completed": True,
        "result": result,
        "timestamp": datetime.utcnow().isoformat()
    }