from __future__ import annotations

import csv
import json
import re
import zipfile
from pathlib import Path
from typing import Any

from openpyxl import load_workbook

from backend.schemas.common import AssetCreate

MAX_IMPORT_ROWS = 100_000
MAX_COLUMNS = 128
ASSET_COLUMNS = {
    "id",
    "name",
    "kind",
    "classification",
    "owner",
    "environment",
    "criticality",
    "compliance",
    "waf",
}
SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(filename: str) -> str:
    name = Path(filename.replace("\\", "/")).name
    result = SAFE_FILENAME.sub("_", name).strip("._")[:180]
    if not result or result in {".", ".."}:
        raise ValueError("Filename is invalid")
    return result


def load_rows(path: Path):
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or len(reader.fieldnames) > MAX_COLUMNS:
                raise ValueError("CSV must contain a header and no more than 128 columns")
            for index, row in enumerate(reader, start=2):
                if index > MAX_IMPORT_ROWS + 1:
                    raise ValueError("Import exceeds the 100,000 row limit")
                yield index, row
        return
    if path.suffix.lower() == ".xlsx":
        with zipfile.ZipFile(path) as archive:
            total_uncompressed = sum(info.file_size for info in archive.infolist())
            if total_uncompressed > 100 * 1024 * 1024:
                raise ValueError("Workbook expands beyond the 100 MB processing limit")
        workbook = load_workbook(path, read_only=True, data_only=True)
        try:
            sheet = workbook.active
            header = next(sheet.iter_rows(min_row=1, max_row=1, values_only=True), None)
            if not header or len(header) > MAX_COLUMNS:
                raise ValueError("Workbook must contain a header and no more than 128 columns")
            names = [str(item).strip() if item is not None else "" for item in header]
            if not any(names):
                raise ValueError("Workbook header is empty")
            for index, values in enumerate(sheet.iter_rows(min_row=2, values_only=True), start=2):
                if index > MAX_IMPORT_ROWS + 1:
                    raise ValueError("Import exceeds the 100,000 row limit")
                yield (
                    index,
                    {name: value for name, value in zip(names, values, strict=False) if name},
                )
        finally:
            workbook.close()
        return
    raise ValueError("Only CSV and XLSX files are supported")


def inspect_headers(path: Path) -> list[str]:
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            headers = next(csv.reader(stream), [])
    else:
        with zipfile.ZipFile(path) as archive:
            if sum(info.file_size for info in archive.infolist()) > 100 * 1024 * 1024:
                raise ValueError("Workbook expands beyond the 100 MB processing limit")
        workbook = load_workbook(path, read_only=True, data_only=True)
        try:
            headers = next(workbook.active.iter_rows(min_row=1, max_row=1, values_only=True), [])
        finally:
            workbook.close()
        headers = [str(item).strip() if item is not None else "" for item in headers]
    if not headers or len(headers) > MAX_COLUMNS or len(set(headers)) != len(headers):
        raise ValueError("File must contain unique column headers (maximum 128)")
    return headers


def parse_asset_row(row: dict[str, Any], mapping: dict[str, str]) -> AssetCreate:
    mapped = {target: row.get(source) for target, source in mapping.items()}
    if "id" in mapped and mapped["id"] is not None:
        mapped["id"] = str(mapped["id"]).strip()
    if "name" in mapped and mapped["name"] is not None:
        mapped["name"] = str(mapped["name"]).strip()
    if "compliance" in mapped:
        value = mapped["compliance"]
        mapped["compliance"] = None if value is None or value == "" else int(float(str(value)))
    for key in ("kind", "classification", "owner", "environment", "criticality", "waf"):
        if mapped.get(key) is not None:
            mapped[key] = str(mapped[key]).strip()
    return AssetCreate.model_validate(mapped)


def validate_mapping(mapping_text: str) -> dict[str, str]:
    mapping = json.loads(mapping_text or "{}")
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("Provide a target-to-source column mapping")
    if set(mapping) - ASSET_COLUMNS or not {"id", "name", "kind"}.issubset(mapping):
        raise ValueError("Mapping must include id, name and kind, with supported asset fields only")
    if not all(
        isinstance(target, str) and isinstance(source, str) and source.strip()
        for target, source in mapping.items()
    ):
        raise ValueError("Column mappings must contain non-empty header names")
    return {key: value.strip() for key, value in mapping.items()}
