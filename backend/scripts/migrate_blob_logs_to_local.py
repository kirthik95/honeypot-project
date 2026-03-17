import argparse
import os
import sys
from typing import Optional

try:
    from azure.storage.blob import BlobServiceClient  # type: ignore[import-not-found]
except Exception:
    BlobServiceClient = None


def _default_local_dir() -> str:
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(base_dir, "local_logs")


def _sanitize_filename(name: str) -> str:
    cleaned = []
    for ch in name.strip():
        if ch.isalnum() or ch in ("-", "_", "."):
            cleaned.append(ch)
        else:
            cleaned.append("_")
    safe = "".join(cleaned).strip("._")
    return safe[:180] if safe else "blob.json"


def _require_azure_sdk() -> None:
    if BlobServiceClient is None:
        print("[ERR] azure-storage-blob is not installed in this environment.")
        sys.exit(1)


def _connect(connection_string: str):
    _require_azure_sdk()
    return BlobServiceClient.from_connection_string(connection_string)


def _read_env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(name)
    if value is None or not str(value).strip():
        return default
    return str(value).strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download Azure Blob logs into local storage."
    )
    parser.add_argument(
        "--container",
        default=_read_env("AZURE_STORAGE_CONTAINER", "honeypot-logs"),
        help="Azure container name (default from AZURE_STORAGE_CONTAINER or honeypot-logs).",
    )
    parser.add_argument(
        "--local-dir",
        default=_read_env("LOCAL_LOG_DIR", _default_local_dir()),
        help="Local output directory (default from LOCAL_LOG_DIR or backend/local_logs).",
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="Optional blob name prefix to filter downloads.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max number of blobs to download (0 = no limit).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite files that already exist.",
    )
    args = parser.parse_args()

    connection_string = _read_env("AZURE_STORAGE_CONNECTION_STRING")
    if not connection_string:
        print("[ERR] AZURE_STORAGE_CONNECTION_STRING is not set.")
        return 1

    try:
        os.makedirs(args.local_dir, exist_ok=True)
    except Exception as exc:
        print(f"[ERR] Failed to create local dir: {exc}")
        return 1

    try:
        client = _connect(connection_string)
        container_client = client.get_container_client(args.container)
    except Exception as exc:
        print(f"[ERR] Failed to connect to Azure container: {exc}")
        return 1

    downloaded = 0
    skipped = 0
    errors = 0

    try:
        blobs = container_client.list_blobs(name_starts_with=args.prefix or None)
        for blob in blobs:
            if args.limit and downloaded >= args.limit:
                break
            blob_name = getattr(blob, "name", None) or "blob.json"
            safe_name = _sanitize_filename(blob_name)
            path = os.path.join(args.local_dir, safe_name)
            if os.path.exists(path) and not args.overwrite:
                skipped += 1
                continue
            try:
                blob_client = container_client.get_blob_client(blob_name)
                content = blob_client.download_blob().readall()
                with open(path, "wb") as handle:
                    handle.write(content)
                downloaded += 1
            except Exception as exc:
                print(f"[ERR] Failed to download {blob_name}: {exc}")
                errors += 1
    except Exception as exc:
        print(f"[ERR] Failed to list blobs: {exc}")
        return 1

    print(f"[OK] Downloaded: {downloaded}, skipped: {skipped}, errors: {errors}")
    return 0 if errors == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
