import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Type

BlobServiceClient: Optional[Any] = None
ResourceExistsError: Optional[Type[BaseException]] = None
try:
    from azure.storage.blob import BlobServiceClient  # type: ignore[import-not-found]
    from azure.core.exceptions import ResourceExistsError  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    pass


def _safe_name(value: str, default: str = "unknown") -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value.strip())
    return cleaned[:80] if cleaned else default


def _default_local_dir() -> str:
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(base_dir, "local_logs")


class BlobLogger:
    def __init__(self):
        self.container_name = os.getenv("AZURE_STORAGE_CONTAINER", "honeypot-logs")
        self.client = None
        self.fallback_logs: List[Dict[str, Any]] = []
        self.backend = os.getenv("LOG_STORAGE", "local").strip().lower() or "local"
        self.local_dir = os.getenv("LOCAL_LOG_DIR") or _default_local_dir()

        if self.backend in ("azure", "blob", "azure_blob"):
            if BlobServiceClient is None:
                print("[WARN] azure-storage-blob not available. Falling back to local logs.")
                self.backend = "local"
            else:
                connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
                if not connection_string:
                    print("[WARN] AZURE_STORAGE_CONNECTION_STRING not set. Falling back to local logs.")
                    self.backend = "local"
                else:
                    try:
                        client = BlobServiceClient.from_connection_string(connection_string)

                        # Create container if it doesn't exist.
                        try:
                            client.create_container(self.container_name)
                            print(f"[OK] Created blob container: {self.container_name}")
                        except Exception as e:
                            # ResourceExistsError is the only expected failure here.
                            if ResourceExistsError is not None and isinstance(e, ResourceExistsError):
                                print(f"[OK] Using existing blob container: {self.container_name}")
                            else:
                                raise

                        self.client = client
                        self.backend = "azure"
                    except Exception as e:
                        print(f"[ERR] Azure Blob init failed: {e}. Falling back to local logs.")
                        self.client = None
                        self.backend = "local"

        if self.backend in ("local", "file"):
            if self._ensure_local_dir():
                self.backend = "local"
                print(f"[OK] Local log storage: {self.local_dir}")
            else:
                self.backend = "memory"
                print("[WARN] Local log storage unavailable. Using in-memory logs.")
        elif self.backend not in ("azure", "memory"):
            self.backend = "local"
            if self._ensure_local_dir():
                print(f"[OK] Local log storage: {self.local_dir}")
            else:
                self.backend = "memory"
                print("[WARN] Local log storage unavailable. Using in-memory logs.")

    def _ensure_local_dir(self) -> bool:
        try:
            os.makedirs(self.local_dir, exist_ok=True)
            return True
        except Exception as e:
            print(f"[ERR] Failed to initialize local log directory: {e}")
            return False

    def _write_local(self, data: Dict[str, Any]) -> None:
        if not self._ensure_local_dir():
            self.fallback_logs.append(data)
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        session_id = _safe_name(str(data.get("session_id") or "unknown"))
        event_source = _safe_name(str(data.get("event_source") or "event"))
        filename = f"{event_source}_{timestamp}_{session_id}.json"
        path = os.path.join(self.local_dir, filename)
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
        except Exception as e:
            print(f"[ERR] Local logging failed: {e}. Falling back to in-memory logs.")
            self.fallback_logs.append(data)

    def log(self, data: Dict[str, Any]) -> None:
        """Log event data to local storage (or Azure if configured)."""
        if self.backend == "azure" and self.client is not None:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                session_id = _safe_name(str(data.get("session_id") or "unknown"))
                event_source = _safe_name(str(data.get("event_source") or "event"))
                blob_name = f"{event_source}_{timestamp}_{session_id}.json"

                blob_client = self.client.get_blob_client(container=self.container_name, blob=blob_name)
                json_data = json.dumps(data, indent=2)
                blob_client.upload_blob(json_data, overwrite=True)
                return
            except Exception as e:
                print(f"[ERR] Blob logging failed: {e}. Falling back to local logs.")
                self.backend = "local"

        if self.backend == "local":
            self._write_local(data)
            return

        self.fallback_logs.append(data)

    def get_all_logs(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Retrieve logs from local storage (or Azure if configured)."""
        if self.backend == "azure" and self.client is not None:
            try:
                container_client = self.client.get_container_client(self.container_name)
                blob_names = [b.name for b in container_client.list_blobs()]
                blob_names.sort(reverse=True)

                logs: List[Dict[str, Any]] = []
                for blob_name in blob_names[:limit]:
                    blob_client = self.client.get_blob_client(container=self.container_name, blob=blob_name)
                    content = blob_client.download_blob().readall()
                    try:
                        log_data = json.loads(content)
                    except Exception:
                        continue
                    if isinstance(log_data, dict):
                        logs.append(log_data)

                logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                return logs
            except Exception as e:
                print(f"[ERR] Failed to retrieve logs: {e}")
                return self.fallback_logs[-limit:]

        if self.backend == "local":
            try:
                if not os.path.isdir(self.local_dir):
                    return self.fallback_logs[-limit:]

                file_names = [name for name in os.listdir(self.local_dir) if name.endswith(".json")]
                file_names.sort(reverse=True)

                logs: List[Dict[str, Any]] = []
                for name in file_names[:limit]:
                    path = os.path.join(self.local_dir, name)
                    try:
                        with open(path, "r", encoding="utf-8") as handle:
                            content = handle.read()
                        log_data = json.loads(content)
                    except Exception:
                        continue
                    if isinstance(log_data, dict):
                        logs.append(log_data)

                logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                return logs
            except Exception as e:
                print(f"[ERR] Failed to retrieve local logs: {e}")
                return self.fallback_logs[-limit:]

        return self.fallback_logs[-limit:]

    def clear_all_logs(self) -> int:
        """Delete all logs in local storage (or Azure if configured)."""
        if self.backend == "azure" and self.client is not None:
            try:
                container_client = self.client.get_container_client(self.container_name)
                deleted = 0
                for blob in container_client.list_blobs():
                    try:
                        container_client.delete_blob(blob.name)
                        deleted += 1
                    except Exception:
                        continue
                return deleted
            except Exception as e:
                print(f"[ERR] Failed to clear logs: {e}")
                return 0

        if self.backend == "local":
            deleted = 0
            try:
                if os.path.isdir(self.local_dir):
                    for name in os.listdir(self.local_dir):
                        if not name.endswith(".json"):
                            continue
                        path = os.path.join(self.local_dir, name)
                        try:
                            os.remove(path)
                            deleted += 1
                        except Exception:
                            continue
            except Exception as e:
                print(f"[ERR] Failed to clear local logs: {e}")
                return 0
            finally:
                self.fallback_logs = []
            return deleted

        count = len(self.fallback_logs)
        self.fallback_logs = []
        return count
