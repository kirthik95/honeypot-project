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


class BlobLogger:
    def __init__(self):
        self.container_name = os.getenv("AZURE_STORAGE_CONTAINER", "honeypot-logs")
        self.client = None
        self.fallback_logs: List[Dict[str, Any]] = []

        if BlobServiceClient is None:
            print("[WARN] azure-storage-blob not available. Using fallback mode.")
            return
        assert BlobServiceClient is not None

        connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
        if not connection_string:
            print("[WARN] AZURE_STORAGE_CONNECTION_STRING not set. Using fallback mode.")
            return

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
        except Exception as e:
            print(f"[ERR] Azure Blob init failed: {e}. Using fallback mode.")
            self.client = None

    def log(self, data: Dict[str, Any]) -> None:
        """Log event data to Azure Blob Storage (or in-memory fallback)."""
        if self.client is None:
            self.fallback_logs.append(data)
            return

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            session_id = data.get("session_id", "unknown")
            blob_name = f"attack_{timestamp}_{session_id}.json"

            blob_client = self.client.get_blob_client(container=self.container_name, blob=blob_name)
            json_data = json.dumps(data, indent=2)
            blob_client.upload_blob(json_data, overwrite=True)
        except Exception as e:
            print(f"[ERR] Blob logging failed: {e}. Falling back to in-memory logs.")
            self.fallback_logs.append(data)

    def get_all_logs(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Retrieve logs from Azure Blob Storage (or in-memory fallback)."""
        if self.client is None:
            return self.fallback_logs[-limit:]

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

    def clear_all_logs(self) -> int:
        """Delete all logs in Azure (or clear in-memory fallback logs)."""
        if self.client is None:
            count = len(self.fallback_logs)
            self.fallback_logs = []
            return count

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
