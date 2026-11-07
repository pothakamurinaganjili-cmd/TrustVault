import json
import hmac
import hashlib
import os
from pathlib import Path


def create_signature(last_event_id, last_event_hash, key):
    data = {
        "last_event_id": last_event_id,
        "last_event_hash": last_event_hash
    }

    canonical = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    )

    return hmac.new(
        key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def write_checkpoint(file_path, last_event_id, last_event_hash, key):
    data = {
        "last_event_id": last_event_id,
        "last_event_hash": last_event_hash
    }

    data["signature"] = create_signature(
        last_event_id,
        last_event_hash,
        key
    )

    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = Path(str(path) + ".tmp")

    temp_path.write_text(
        json.dumps(data, indent=4),
        encoding="utf-8"
    )

    os.replace(temp_path, path)


def read_checkpoint(file_path, key):
    path = Path(file_path)

    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))

        expected_signature = create_signature(
            data["last_event_id"],
            data["last_event_hash"],
            key
        )

        if not hmac.compare_digest(
            expected_signature,
            data["signature"]
        ):
            return None

        return data

    except (OSError, ValueError, KeyError, TypeError):
        return None