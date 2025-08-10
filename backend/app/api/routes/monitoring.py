"""
API endpoints for privacy-focused monitoring and statistics.
"""

from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query

from app.config import settings
from app.core.monitoring.errors import ErrorReporter
from app.core.monitoring.security_events import SecurityEventTracker
from app.core.monitoring.stats import StatsCollector
from app.utils.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/monitoring", tags=["monitoring"])

import os

# Import for system info
import platform

# Ensure data directory exists
os.makedirs("./data", exist_ok=True)

# Global stats collector instance
stats_collector = StatsCollector(
    persist_to_db=settings.env == "production",
    db_path="./data/stats.db" if settings.env == "production" else None,
)

# Global error reporter instance
error_reporter = ErrorReporter(
    db_path="./data/errors.db"  # Always use file-based DB for now
)

# Global security event tracker instance
security_tracker = SecurityEventTracker(
    db_path="./data/security.db"  # Always use file-based DB for now
)


@router.get("/stats", response_model=Dict[str, Any])
async def get_aggregate_stats():
    """
    Get current aggregate statistics.

    Returns privacy-safe aggregate data only:
    - Total conversions and success rates
    - Format distribution
    - Size distribution
    - Average processing times

    No user data or file information is included.
    """
    try:
        stats = stats_collector.get_current_stats()
        return {
            "status": "success",
            "data": stats,
            "privacy_notice": "This data contains only aggregate statistics with no user information",
        }
    except Exception as e:
        logger.error("Failed to get statistics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@router.get("/stats/hourly", response_model=Dict[str, Any])
async def get_hourly_stats(
    hours: int = Query(
        default=24, ge=1, le=168, description="Number of hours to retrieve"
    )
):
    """
    Get hourly statistics for the specified period.

    Args:
        hours: Number of hours to retrieve (1-168, default 24)

    Returns:
        Hourly aggregate statistics
    """
    try:
        hourly_stats = stats_collector.get_hourly_stats(hours)
        return {
            "status": "success",
            "data": {"hours_requested": hours, "stats": hourly_stats},
        }
    except Exception as e:
        logger.error("Failed to get hourly statistics", error=str(e))
        raise HTTPException(
            status_code=500, detail="Failed to retrieve hourly statistics"
        )


@router.get("/stats/daily", response_model=Dict[str, Any])
async def get_daily_stats(
    days: int = Query(default=30, ge=1, le=90, description="Number of days to retrieve")
):
    """
    Get daily statistics for the specified period.

    Args:
        days: Number of days to retrieve (1-90, default 30)

    Returns:
        Daily aggregate statistics
    """
    try:
        daily_stats = stats_collector.get_daily_stats(days)
        return {
            "status": "success",
            "data": {"days_requested": days, "stats": daily_stats},
        }
    except Exception as e:
        logger.error("Failed to get daily statistics", error=str(e))
        raise HTTPException(
            status_code=500, detail="Failed to retrieve daily statistics"
        )


@router.get("/logging/config", response_model=Dict[str, Any])
async def get_logging_config():
    """
    Get current logging configuration.

    Returns:
        Current logging settings and privacy mode status
    """
    return {
        "status": "success",
        "data": {
            "log_level": settings.log_level,
            "anonymize_logs": settings.anonymize_logs,
            "logging_enabled": getattr(settings, "logging_enabled", True),
            "paranoia_mode": not getattr(settings, "logging_enabled", True),
            "retention_days": getattr(settings, "log_retention_days", 1),
            "privacy_features": {
                "strip_metadata_default": settings.strip_metadata_default,
                "anonymize_logs": settings.anonymize_logs,
                "retain_history_days": settings.retain_history_days,
            },
        },
    }


@router.put("/logging/paranoia", response_model=Dict[str, Any])
async def toggle_paranoia_mode(
    enable: bool = Query(description="Enable or disable paranoia mode"),
):
    """
    Toggle paranoia mode (disable all logging).

    Args:
        enable: True to enable paranoia mode (disable logging), False to disable paranoia mode

    Returns:
        Updated logging configuration
    """
    try:
        # Update settings (would need to be persisted in real implementation)
        settings.logging_enabled = not enable

        # Reconfigure logging
        from app.utils.logging import setup_logging

        setup_logging(
            log_level=settings.log_level, json_logs=True, enable_file_logging=not enable
        )

        logger.info(
            "Paranoia mode toggled",
            paranoia_mode_enabled=enable,
            logging_enabled=not enable,
        )

        return {
            "status": "success",
            "data": {
                "paranoia_mode": enable,
                "logging_enabled": not enable,
                "message": (
                    "Paranoia mode enabled - all file logging disabled"
                    if enable
                    else "Paranoia mode disabled - logging resumed"
                ),
            },
        }
    except Exception as e:
        logger.error("Failed to toggle paranoia mode", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to toggle paranoia mode")


@router.post("/stats/cleanup", response_model=Dict[str, Any])
async def cleanup_old_stats(
    hourly_retention: int = Query(
        default=168, ge=24, le=720, description="Hours to retain hourly stats"
    ),
    daily_retention: int = Query(
        default=90, ge=7, le=365, description="Days to retain daily stats"
    ),
):
    """
    Clean up old statistics.

    Args:
        hourly_retention: Hours to retain hourly stats (24-720, default 168)
        daily_retention: Days to retain daily stats (7-365, default 90)

    Returns:
        Cleanup status
    """
    try:
        await stats_collector.cleanup_old_stats(hourly_retention, daily_retention)
        return {
            "status": "success",
            "data": {
                "message": "Statistics cleanup completed",
                "hourly_retention": hourly_retention,
                "daily_retention": daily_retention,
            },
        }
    except Exception as e:
        logger.error("Failed to cleanup statistics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to cleanup statistics")


@router.get("/errors/report", response_model=Dict[str, Any])
async def get_error_report(
    hours: int = Query(
        default=24, ge=1, le=168, description="Number of hours to analyze"
    )
):
    """
    Get aggregate error report for the specified period.

    Args:
        hours: Number of hours to analyze (1-168, default 24)

    Returns:
        Privacy-safe error summary with:
        - Error counts by category
        - Error counts by type
        - Most frequent errors
        - No PII or sensitive information
    """
    try:
        summary = error_reporter.get_error_summary(hours=hours)
        return {"status": "success", "data": summary}
    except Exception as e:
        logger.error("Failed to get error report", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve error report")


@router.get("/errors/{error_id}", response_model=Dict[str, Any])
async def get_error_details(error_id: str):
    """
    Get details for a specific error.

    Args:
        error_id: Error ID to retrieve

    Returns:
        Sanitized error details
    """
    try:
        details = error_reporter.get_error_details(error_id)
        if not details:
            raise HTTPException(status_code=404, detail="Error not found")

        return {"status": "success", "data": details}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get error details", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve error details")


@router.post("/errors/cleanup", response_model=Dict[str, Any])
async def cleanup_old_errors(
    retention_days: int = Query(
        default=30, ge=1, le=90, description="Days to retain errors"
    )
):
    """
    Clean up old error reports.

    Args:
        retention_days: Days to retain error reports (1-90, default 30)

    Returns:
        Cleanup status
    """
    try:
        await error_reporter.cleanup_old_errors(retention_days=retention_days)
        return {
            "status": "success",
            "data": {
                "message": "Error cleanup completed",
                "retention_days": retention_days,
            },
        }
    except Exception as e:
        logger.error("Failed to cleanup errors", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to cleanup errors")


@router.get("/security/events", response_model=Dict[str, Any])
async def get_security_events(
    hours: int = Query(
        default=24, ge=1, le=168, description="Number of hours to analyze"
    )
):
    """
    Get summary of security events.

    Args:
        hours: Number of hours to analyze (1-168, default 24)

    Returns:
        Privacy-safe security event summary
    """
    try:
        summary = security_tracker.get_event_summary(hours=hours)
        return {"status": "success", "data": summary.dict()}
    except Exception as e:
        logger.error("Failed to get security events", error=str(e))
        raise HTTPException(
            status_code=500, detail="Failed to retrieve security events"
        )


@router.get("/security/violations/trends", response_model=Dict[str, Any])
async def get_violation_trends(
    days: int = Query(default=7, ge=1, le=30, description="Number of days to analyze")
):
    """
    Get security violation trends.

    Args:
        days: Number of days to analyze (1-30, default 7)

    Returns:
        Violation trend data
    """
    try:
        trends = security_tracker.get_violation_trends(days=days)
        return {"status": "success", "data": trends}
    except Exception as e:
        logger.error("Failed to get violation trends", error=str(e))
        raise HTTPException(
            status_code=500, detail="Failed to retrieve violation trends"
        )


@router.post("/security/cleanup", response_model=Dict[str, Any])
async def cleanup_security_events(
    retention_days: int = Query(
        default=90, ge=7, le=365, description="Days to retain events"
    )
):
    """
    Clean up old security events.

    Args:
        retention_days: Days to retain security events (7-365, default 90)

    Returns:
        Cleanup status
    """
    try:
        await security_tracker.cleanup_old_events(retention_days=retention_days)
        return {
            "status": "success",
            "data": {
                "message": "Security event cleanup completed",
                "retention_days": retention_days,
            },
        }
    except Exception as e:
        logger.error("Failed to cleanup security events", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to cleanup security events")


@router.get("/system/info", response_model=Dict[str, Any])
async def get_system_info():
    """
    Get system information including network isolation status.

    Returns:
        System information with:
        - Platform details
        - Resource usage
        - Network isolation status
        - Security configuration
    """
    try:
        # Get basic system info
        system_info = {
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
            },
            "resources": {"cpu_count": os.cpu_count(), "memory": {}},
        }

        # Get memory info if psutil available
        try:
            import psutil

            memory = psutil.virtual_memory()
            system_info["resources"]["memory"] = {
                "total_mb": memory.total // (1024 * 1024),
                "available_mb": memory.available // (1024 * 1024),
                "percent_used": memory.percent,
            }

            # Get CPU usage
            system_info["resources"]["cpu_percent"] = psutil.cpu_percent(interval=0.1)
        except ImportError:
            pass

        # Get network isolation status from app state

        # We need the request context to access app state
        # This is a limitation - we'll document it
        system_info["network_isolation"] = {
            "enabled": settings.network_verification_enabled,
            "strictness": settings.network_verification_strictness,
            "monitoring_enabled": settings.network_monitoring_enabled,
            "status": "Check /api/security/network-status for details",
        }

        # Security configuration
        system_info["security"] = {
            "sandboxing_enabled": settings.enable_sandboxing,
            "sandbox_strictness": settings.sandbox_strictness,
            "metadata_stripping_default": settings.strip_metadata_default,
            "rate_limit_per_minute": settings.rate_limit_per_minute,
        }

        # Application info
        system_info["application"] = {
            "name": settings.app_name,
            "environment": settings.env,
            "debug_mode": settings.debug,
            "api_port": settings.api_port,
            "api_host": settings.api_host,
        }

        return {
            "status": "success",
            "data": system_info,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error("Failed to get system info", error=str(e))
        raise HTTPException(
            status_code=500, detail="Failed to retrieve system information"
        )


@router.get("/logging/config", response_model=Dict[str, Any])
async def get_logging_config():
    """
    Get current logging configuration.

    Returns:
        Logging configuration including privacy settings
    """
    try:
        config = {
            "log_level": settings.log_level,
            "logging_enabled": settings.logging_enabled,
            "anonymize_logs": settings.anonymize_logs,
            "log_dir": settings.log_dir if settings.logging_enabled else None,
            "max_log_size_mb": settings.max_log_size_mb,
            "log_backup_count": settings.log_backup_count,
            "log_retention_hours": settings.log_retention_hours,
            "privacy_features": {
                "pii_filtering": True,
                "filename_masking": True,
                "ip_anonymization": True,
                "metadata_stripping": True,
            },
        }

        return {"status": "success", "data": config}

    except Exception as e:
        logger.error("Failed to get logging config", error=str(e))
        raise HTTPException(
            status_code=500, detail="Failed to retrieve logging configuration"
        )


# Export modules for use in other parts of the application
__all__ = ["router", "stats_collector", "error_reporter", "security_tracker"]
