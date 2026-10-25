"""Decode GitHub Contents JSON without treating transport wrapping as authority.

Only CR/LF wrapping is removed. The decoded bytes must match their Git blob ID;
this is byte integrity, never a signature, candidate receipt or publication grant.
"""
import base64
import hashlib
import json
import re

MAX_FILE_BYTES = 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}\Z")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate GitHub file JSON key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("nonfinite GitHub file JSON value")


def decode_json_file(source, expected_path):
    if (type(source) is not dict or type(expected_path) is not str
            or not expected_path or source.get("path") != expected_path
            or source.get("encoding") != "base64"
            or type(source.get("sha")) is not str
            or not SHA.fullmatch(source["sha"])
            or type(source.get("content")) is not str
            or not 0 < len(source["content"]) <= 2 * MAX_FILE_BYTES):
        raise ValueError("invalid GitHub Contents file identity")
    compact = source["content"].replace("\r", "").replace("\n", "")
    raw = base64.b64decode(compact, validate=True)
    if (not 0 < len(raw) <= MAX_FILE_BYTES
            or base64.b64encode(raw).decode("ascii") != compact):
        raise ValueError("invalid GitHub Contents base64 bytes")
    if "size" in source and (type(source["size"]) is not int
                              or source["size"] != len(raw)):
        raise ValueError("GitHub Contents file size mismatch")
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    if blob != source["sha"]:
        raise ValueError("GitHub Contents Git blob digest mismatch")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                       parse_constant=_constant)
    if type(value) is not dict:
        raise ValueError("GitHub Contents JSON object required")
    return value
