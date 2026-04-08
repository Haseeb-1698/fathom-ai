"""
minio_client.py — MinIO S3-compatible object storage for Fathom.

Stores:
  - Uploaded malware samples (bucket: fathom-samples)
  - Generated analysis reports as JSON (bucket: fathom-reports)
  - CAPE report JSONs (bucket: fathom-cape)

All objects are keyed by SHA256 so they're deduplicated automatically.
Falls back gracefully if MinIO is unavailable — analysis still works.
"""

from __future__ import annotations

import io
import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ROOT_USER", "fathom")
MINIO_SECRET_KEY = os.environ.get("MINIO_ROOT_PASSWORD", "fathom2024")
MINIO_SECURE = os.environ.get("MINIO_SECURE", "false").lower() == "true"

BUCKET_SAMPLES = "fathom-samples"
BUCKET_REPORTS = "fathom-reports"
BUCKET_CAPE    = "fathom-cape"

_client = None


def _get_client():
    """Lazy-init MinIO client. Returns None if unavailable."""
    global _client
    if _client is not None:
        return _client
    try:
        from minio import Minio
        _client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        # Ensure buckets exist
        for bucket in (BUCKET_SAMPLES, BUCKET_REPORTS, BUCKET_CAPE):
            if not _client.bucket_exists(bucket):
                _client.make_bucket(bucket)
                logger.info("Created MinIO bucket: %s", bucket)
        logger.info("MinIO connected: %s", MINIO_ENDPOINT)
        return _client
    except ImportError:
        logger.warning("minio package not installed — file storage disabled")
        return None
    except Exception as e:
        logger.warning("MinIO unavailable (%s) — file storage disabled", e)
        return None


def store_sample(sha256: str, content: bytes, filename: str, content_type: str = "application/octet-stream") -> bool:
    """
    Store an uploaded sample file in MinIO.
    Key: {sha256}/{filename}
    Returns True on success, False on failure.
    """
    client = _get_client()
    if not client:
        return False
    try:
        key = f"{sha256}/{filename}"
        client.put_object(
            BUCKET_SAMPLES,
            key,
            io.BytesIO(content),
            length=len(content),
            content_type=content_type,
            metadata={"sha256": sha256, "original_name": filename},
        )
        logger.info("Stored sample %s (%d bytes) → minio://%s/%s", sha256[:16], len(content), BUCKET_SAMPLES, key)
        return True
    except Exception as e:
        logger.warning("MinIO store_sample failed for %s: %s", sha256[:16], e)
        return False


def store_cape_report(sha256: str, report: dict) -> bool:
    """Store a CAPE report JSON in MinIO for later retrieval."""
    client = _get_client()
    if not client:
        return False
    try:
        data = json.dumps(report, ensure_ascii=False).encode("utf-8")
        key = f"{sha256}/cape_report.json"
        client.put_object(
            BUCKET_CAPE,
            key,
            io.BytesIO(data),
            length=len(data),
            content_type="application/json",
            metadata={"sha256": sha256},
        )
        logger.info("Stored CAPE report %s → minio://%s/%s", sha256[:16], BUCKET_CAPE, key)
        return True
    except Exception as e:
        logger.warning("MinIO store_cape_report failed for %s: %s", sha256[:16], e)
        return False


def store_analysis_report(sha256: str, report_text: str, metadata: dict | None = None) -> bool:
    """Store a generated analysis report in MinIO."""
    client = _get_client()
    if not client:
        return False
    try:
        payload = {
            "sha256": sha256,
            "report": report_text,
            "metadata": metadata or {},
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        key = f"{sha256}/analysis_report.json"
        client.put_object(
            BUCKET_REPORTS,
            key,
            io.BytesIO(data),
            length=len(data),
            content_type="application/json",
            metadata={"sha256": sha256},
        )
        logger.info("Stored analysis report %s → minio://%s/%s", sha256[:16], BUCKET_REPORTS, key)
        return True
    except Exception as e:
        logger.warning("MinIO store_analysis_report failed for %s: %s", sha256[:16], e)
        return False


def get_sample_url(sha256: str, filename: str, expires_hours: int = 24) -> Optional[str]:
    """Generate a presigned URL for downloading a stored sample."""
    client = _get_client()
    if not client:
        return None
    try:
        from datetime import timedelta
        key = f"{sha256}/{filename}"
        url = client.presigned_get_object(
            BUCKET_SAMPLES, key,
            expires=timedelta(hours=expires_hours),
        )
        return url
    except Exception as e:
        logger.warning("MinIO presigned URL failed for %s: %s", sha256[:16], e)
        return None


def get_analysis_report(sha256: str) -> Optional[dict]:
    """Retrieve a stored analysis report from MinIO."""
    client = _get_client()
    if not client:
        return None
    try:
        key = f"{sha256}/analysis_report.json"
        response = client.get_object(BUCKET_REPORTS, key)
        data = json.loads(response.read().decode("utf-8"))
        response.close()
        return data
    except Exception as e:
        logger.debug("MinIO get_analysis_report miss for %s: %s", sha256[:16], e)
        return None


def sample_exists(sha256: str, filename: str) -> bool:
    """Check if a sample is already stored (deduplication)."""
    client = _get_client()
    if not client:
        return False
    try:
        client.stat_object(BUCKET_SAMPLES, f"{sha256}/{filename}")
        return True
    except Exception:
        return False
