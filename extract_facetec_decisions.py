from __future__ import annotations

import re
from collections import defaultdict


def extract_ascii_strings(data: bytes, minlen: int = 4) -> list[str]:
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
            continue
        if len(cur) >= minlen:
            out.append(cur.decode("ascii", "ignore"))
        cur.clear()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "ignore"))
    return out


def dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for s in items:
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def main() -> None:
    so_path = "libkagsf6n35nmdmj4aav5sk6moq3.so"
    with open(so_path, "rb") as f:
        data = f.read()

    uniq = dedupe_preserve_order(extract_ascii_strings(data, 4))

    categories: dict[str, list[str]] = {
        "DECISION_ROOT_JSON_KEYS": [
            "faceScanSecurityChecks",
            "replayCheckSucceeded",
            "sessionTokenCheckSucceeded",
            "auditTrailVerificationCheckSucceeded",
            "frontAuditTrailVerificationCheckSucceeded",
            "backAuditTrailVerificationCheckSucceeded",
            "faceScanLivenessCheckSucceeded",
        ],
        "SERVER_ENDPOINTS_DOMAINS": [
            "api.facetec.com",
            "/liveness-3d",
            "/FaceTecScan",
            "/enrollment-3d",
            "/match-3d",
            "/match-3d-2d",
            "/match-3d-2d-idscan",
            "/match-3d-2d-profile-pic",
        ],
        "QUALITY_GATES_UI": [
            "No Glare",
            "Extreme Lighting",
            "Ideal Pose",
            "BAD_POSE",
            "MOVE_CLOSER",
            "FRAME_YOUR_FACE",
            "GET_READY",
            "ZOOM",
            "OVERZOOM",
            "UNZOOM",
            "FACE_SCAN_ZOOMED",
            "FACE_SCAN_UNZOOMED",
        ],
        "LIVENESS_ERRORS_STATUS": [
            "LIVENESS",
            "Liveness",
            "livenessResult",
            "LIVENESS_FAILED",
            "process failed",
            "RESULT_SCREEN_SHOWN",
            "USER_CANCELLED",
            "LOCKOUT",
            "incompatible",
        ],
        "ANTI_REPLAY_LOOP_AUDIT": [
            "LOOP_DETECTION",
            "replay",
            "Audit trail",
            "audit trail",
            "audit",
            "SESSION",
            "session token",
            "SESSION_ID",
            "USER SESSION REPORT",
        ],
        "SENSOR_MOTION_POSE": [
            "yaw",
            "pitch",
            "roll",
            "pose",
            "Motion",
            "MotionEvent",
            "gyroscope",
            "accelerometer",
            "IMU",
            "inertial",
        ],
    }

    hits: dict[str, list[str]] = defaultdict(list)
    for s in uniq:
        s_low = s.lower()
        for cat, needles in categories.items():
            for n in needles:
                if n.lower() in s_low:
                    hits[cat].append(s)
                    break

    token_patterns: list[tuple[str, str]] = [
        (r"\bFACE_(?:SCAN|CAPTURE)_[A-Z0-9_]+\b", "FACE_ENUMS"),
        (r"\bLIVENESS_[A-Z0-9_]+\b", "LIVENESS_ENUMS"),
        (r"\bFACETEC_[A-Z0-9_]+\b", "FACETEC_ENUMS"),
    ]
    compiled = [(re.compile(rx), cat) for rx, cat in token_patterns]
    for s in uniq:
        for rx, cat in compiled:
            if rx.search(s):
                hits[cat].append(s)

    # De-dupe within categories
    for cat, lst in list(hits.items()):
        hits[cat] = dedupe_preserve_order(lst)

    out_path = "facetec_so_decision_report.txt"
    with open(out_path, "w", encoding="utf-8") as out:
        out.write(f"File: {so_path}\n")
        out.write(f"Total unique ASCII strings: {len(uniq)}\n\n")
        for cat in sorted(hits.keys()):
            out.write(f"## {cat}\n")
            for line in hits[cat]:
                out.write(line + "\n")
            out.write("\n")

    print(out_path)
    print("categories:", ", ".join(sorted(hits.keys())))


if __name__ == "__main__":
    main()

