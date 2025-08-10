"""Batch result compilation and management."""

import io
import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional

from app.core.batch.models import BatchItemStatus, BatchJob, BatchResult
from app.core.exceptions import ValidationError
from app.utils.logging import get_logger

logger = get_logger(__name__)


class BatchResultCollector:
    """Collects and manages results from batch processing."""

    def __init__(self):
        """Initialize the result collector."""
        self.logger = get_logger(__name__)

    def compile_results(
        self,
        job: BatchJob,
        successful_files: List[Dict[str, Any]],
        failed_files: List[Dict[str, Any]],
    ) -> BatchResult:
        """Compile batch processing results.

        Args:
            job: The batch job
            successful_files: List of successful file results
            failed_files: List of failed file results

        Returns:
            BatchResult object with compiled results
        """
        # Calculate total processing time
        total_processing_time = sum(
            f.get("processing_time", 0) for f in successful_files
        )

        # Create result object
        result = BatchResult(
            job_id=job.job_id,
            total_files=job.total_files,
            successful_files=successful_files,
            failed_files=failed_files,
            processing_time_seconds=total_processing_time,
            report_format="json",
        )

        self.logger.info(
            f"Compiled results for batch {job.job_id}: "
            f"{len(successful_files)} successful, {len(failed_files)} failed"
        )

        return result

    def generate_summary_report(
        self, job: BatchJob, result: BatchResult, format: str = "json"
    ) -> str:
        """Generate a summary report of batch processing.

        Args:
            job: The batch job
            result: The batch result
            format: Report format (json or csv)

        Returns:
            Report content as string
        """
        if format == "json":
            return self._generate_json_report(job, result)
        elif format == "csv":
            return self._generate_csv_report(job, result)
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def _generate_json_report(self, job: BatchJob, result: BatchResult) -> str:
        """Generate JSON format report."""
        report = {
            "job_id": job.job_id,
            "created_at": job.created_at.isoformat(),
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "total_files": job.total_files,
            "successful_files": len(result.successful_files),
            "failed_files": len(result.failed_files),
            "total_processing_time": result.processing_time_seconds,
            "average_processing_time": (
                result.processing_time_seconds / len(result.successful_files)
                if result.successful_files
                else 0
            ),
            "settings": job.settings,
            "files": [],
        }

        # Add file details
        for file_info in result.successful_files:
            report["files"].append(
                {
                    "index": file_info["index"],
                    "filename": file_info["filename"],
                    "status": "success",
                    "output_size": file_info.get("output_size", 0),
                    "processing_time": file_info.get("processing_time", 0),
                }
            )

        for file_info in result.failed_files:
            report["files"].append(
                {
                    "index": file_info["index"],
                    "filename": file_info["filename"],
                    "status": "failed",
                    "error": file_info.get("error", "Unknown error"),
                }
            )

        return json.dumps(report, indent=2)

    def _generate_csv_report(self, job: BatchJob, result: BatchResult) -> str:
        """Generate CSV format report."""
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(
            [
                "Index",
                "Filename",
                "Status",
                "Output Size (bytes)",
                "Processing Time (s)",
                "Error",
            ]
        )

        # Write successful files
        for file_info in result.successful_files:
            writer.writerow(
                [
                    file_info["index"],
                    file_info["filename"],
                    "success",
                    file_info.get("output_size", ""),
                    f"{file_info.get('processing_time', 0):.2f}",
                    "",
                ]
            )

        # Write failed files
        for file_info in result.failed_files:
            writer.writerow(
                [
                    file_info["index"],
                    file_info["filename"],
                    "failed",
                    "",
                    "",
                    file_info.get("error", "Unknown error"),
                ]
            )

        # Add summary at the end
        writer.writerow([])
        writer.writerow(["Summary"])
        writer.writerow(["Total Files", job.total_files])
        writer.writerow(["Successful", len(result.successful_files)])
        writer.writerow(["Failed", len(result.failed_files)])
        writer.writerow(
            ["Total Processing Time (s)", f"{result.processing_time_seconds:.2f}"]
        )

        return output.getvalue()

    def create_zip_archive(
        self,
        result: BatchResult,
        include_report: bool = True,
        output_format: str = "webp",
    ) -> bytes:
        """Create a ZIP archive of successful conversions.

        Args:
            result: The batch result containing file data
            include_report: Whether to include summary report

        Returns:
            ZIP file content as bytes
        """
        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            # Add successfully converted files
            for file_info in result.successful_files:
                if "output_data" in file_info:
                    # Generate output filename with proper extension
                    base_name = Path(file_info["filename"]).stem
                    # Map output format to extension
                    format_extensions = {
                        "webp": ".webp",
                        "avif": ".avif",
                        "jpeg": ".jpg",
                        "png": ".png",
                        "jxl": ".jxl",
                        "heif": ".heif",
                        "jpeg_optimized": "_optimized.jpg",
                        "png_optimized": "_optimized.png",
                        "webp2": ".wp2",
                        "jpeg2000": ".jp2",
                    }
                    ext = format_extensions.get(output_format, ".webp")
                    output_filename = f"{base_name}{ext}"

                    # Add file to ZIP
                    zip_file.writestr(output_filename, file_info["output_data"])

            # Add summary report if requested
            if include_report:
                # Create a simple job object for report generation
                # In production, you'd pass the actual job object
                from app.core.batch.models import BatchJob

                job = BatchJob(
                    job_id=result.job_id,
                    total_files=len(result.successful_files) + len(result.failed_files),
                    settings={},
                )

                # Add JSON report
                json_report = self._generate_json_report(job, result)
                zip_file.writestr("batch_summary.json", json_report)

                # Add CSV report
                csv_report = self._generate_csv_report(job, result)
                zip_file.writestr("batch_summary.csv", csv_report)

        zip_buffer.seek(0)
        return zip_buffer.read()

    def calculate_statistics(self, result: BatchResult) -> Dict[str, Any]:
        """Calculate batch processing statistics.

        Args:
            result: The batch result

        Returns:
            Dictionary of statistics
        """
        successful_count = len(result.successful_files)
        failed_count = len(result.failed_files)
        total_count = successful_count + failed_count

        # Calculate size statistics
        total_output_size = sum(
            f.get("output_size", 0) for f in result.successful_files
        )

        # Calculate time statistics
        processing_times = [
            f.get("processing_time", 0) for f in result.successful_files
        ]

        stats = {
            "total_files": total_count,
            "successful_files": successful_count,
            "failed_files": failed_count,
            "success_rate": (
                (successful_count / total_count * 100) if total_count > 0 else 0
            ),
            "total_output_size": total_output_size,
            "total_processing_time": result.processing_time_seconds,
            "average_processing_time": (
                sum(processing_times) / len(processing_times) if processing_times else 0
            ),
            "min_processing_time": min(processing_times) if processing_times else 0,
            "max_processing_time": max(processing_times) if processing_times else 0,
        }

        return stats
