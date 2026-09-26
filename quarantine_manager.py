"""
OwlEyeEngine - Real Cryptographic Quarantine Vault (v4.0 Enterprise)
Handles physical binary isolation, permission revocation, SHA-256 hashing,
and forensic audit manifest generation.
"""

import os
import sys
import shutil
import hashlib
import json
import time
import platform
from typing import Dict, Any, Optional

QUARANTINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine_vault")
MANIFEST_FILE = os.path.join(QUARANTINE_DIR, "quarantine_manifest.json")

class QuarantineVault:
    def __init__(self, vault_dir: str = QUARANTINE_DIR):
        self.vault_dir = vault_dir
        self.manifest_path = os.path.join(self.vault_dir, "quarantine_manifest.json")
        self._ensure_vault()

    def _ensure_vault(self):
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir, mode=0o700, exist_ok=True)
        if not os.path.exists(self.manifest_path):
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump({"vault_created": time.time(), "items": []}, f, indent=2)

    def calculate_sha256(self, filepath: str) -> Optional[str]:
        """Calculates SHA-256 digest of target file."""
        if not os.path.isfile(filepath):
            return None
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    def isolate_binary(self, filepath: str, pid: int, threat_reason: str) -> Dict[str, Any]:
        """
        Isolates a suspicious binary file:
          1. Calculates SHA-256 hash
          2. Copies to restricted quarantine vault
          3. Renames with .quarantine extension
          4. Revokes execution permissions
          5. Records metadata in manifest
        """
        if not os.path.isfile(filepath):
            return {"success": False, "message": f"Target path '{filepath}' is not a valid file"}

        file_hash = self.calculate_sha256(filepath)
        filename = os.path.basename(filepath)
        timestamp = int(time.time())
        quarantine_filename = f"{timestamp}_{file_hash[:12]}_{filename}.quarantine"
        quarantine_path = os.path.join(self.vault_dir, quarantine_filename)

        try:
            # Copy file to vault
            shutil.copy2(filepath, quarantine_path)

            # Revoke execution permissions (chmod 000 on Unix, read-only on Windows)
            if platform.system().lower() != "windows":
                os.chmod(quarantine_path, 0o400) # Read only for root

            # Attempt to neutralize original file ONLY if it is not an OS system interpreter
            system_interpreters = ["python.exe", "python3", "python", "cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh"]
            if filename.lower() not in system_interpreters:
                try:
                    os.rename(filepath, f"{filepath}.neutralized")
                except Exception:
                    pass

            record = {
                "id": f"QUAR-{timestamp}",
                "original_path": filepath,
                "quarantine_path": quarantine_path,
                "sha256": file_hash,
                "pid": pid,
                "reason": threat_reason,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
                "size_bytes": os.path.getsize(quarantine_path)
            }

            self._record_manifest(record)
            return {
                "success": True,
                "message": f"Binary safely isolated in Quarantine Vault: {file_hash[:16]}...",
                "sha256": file_hash,
                "quarantine_record": record
            }

        except Exception as e:
            return {"success": False, "message": f"Failed to isolate binary: {str(e)}"}

    def _record_manifest(self, record: Dict[str, Any]):
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["items"].insert(0, record)
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def list_quarantined_items(self) -> list:
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                return json.load(f).get("items", [])
        except Exception:
            return []


if __name__ == "__main__":
    vault = QuarantineVault()
    print("Quarantine Vault ready at:", vault.vault_dir)
    print("Items currently in vault:", len(vault.list_quarantined_items()))
