#!/usr/bin/env python3

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Dict, List

RAW_PATH = Path(__file__).resolve().parents[1] / "data" / "linkedin_industry_codes_v2_2023-07-04.txt"
JSON_OUT = Path(__file__).resolve().parents[1] / "data" / "industry_codes_v2.json"
CSV_OUT = Path(__file__).resolve().parents[1] / "data" / "industry_codes_v2.csv"

ENTRY_START_RE = re.compile(r"^(?P<id>\d{1,5})\t(?P<label>[^\t]+)\t(?P<hierarchy>[^\t]+)\t(?P<desc>.*)$")
HEADER_LINE_RE = re.compile(r"^Industry ID\s+Label\s+Hierarchy\s+Description$")


def normalize_whitespace(text: str) -> str:
	text = text.replace("\xa0", " ")
	text = re.sub(r"\s*>\s*>\s*", " > ", text)
	lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
	return "\n".join([line for line in lines if line])


def parse_raw_text(lines: List[str]) -> List[Dict[str, str]]:
	records: List[Dict[str, str]] = []
	current: Dict[str, str] = {}

	def flush_current():
		if current:
			current["hierarchy"] = normalize_whitespace(current.get("hierarchy", ""))
			desc = current.get("description", "")
			desc = normalize_whitespace(desc)
			current["description"] = desc
			records.append({
				"industryId": int(current["industryId"]),
				"label": current["label"].strip(),
				"hierarchy": current["hierarchy"].strip(),
				"description": current["description"].strip(),
			})

	for raw_line in lines:
		line = raw_line.rstrip("\n")
		if not line.strip():
			continue
		if HEADER_LINE_RE.match(line):
			continue
		m = ENTRY_START_RE.match(line)
		if m:
			flush_current()
			current = {
				"industryId": m.group("id"),
				"label": m.group("label"),
				"hierarchy": m.group("hierarchy"),
				"description": m.group("desc").strip(),
			}
			continue
		if current:
			current["description"] = (current.get("description", "") + "\n" + line).strip()
			continue

	flush_current()
	return records


def write_json(records: List[Dict[str, str]], path: Path) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	with path.open("w", encoding="utf-8") as f:
		json.dump(records, f, ensure_ascii=False, indent=2)


def write_csv(records: List[Dict[str, str]], path: Path) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	with path.open("w", encoding="utf-8", newline="") as f:
		writer = csv.writer(f)
		writer.writerow(["industryId", "label", "hierarchy", "description"])
		for r in records:
			writer.writerow([r["industryId"], r["label"], r["hierarchy"], r["description"]])


def search(records: List[Dict[str, str]], query: str) -> List[Dict[str, str]]:
	q = query.lower()
	return [r for r in records if q in str(r["industryId"]).lower() or q in r["label"].lower() or q in r["hierarchy"].lower() or q in r["description"].lower()]


def main():
	parser = argparse.ArgumentParser(description="Parse LinkedIn Industry Codes V2 raw text to JSON/CSV and optional search")
	parser.add_argument("--raw", type=Path, default=RAW_PATH, help="Path to raw text file")
	parser.add_argument("--json_out", type=Path, default=JSON_OUT, help="Output JSON path")
	parser.add_argument("--csv_out", type=Path, default=CSV_OUT, help="Output CSV path")
	parser.add_argument("--search", type=str, default="", help="Search term or industry id")
	args = parser.parse_args()

	with args.raw.open("r", encoding="utf-8") as f:
		lines = f.readlines()

	records = parse_raw_text(lines)
	records.sort(key=lambda r: r["industryId"])

	write_json(records, args.json_out)
	write_csv(records, args.csv_out)

	if args.search:
		results = search(records, args.search)
		print(f"Found {len(results)} match(es) for '{args.search}':")
		for r in results:
			print(f"- {r['industryId']} | {r['label']} | {r['hierarchy']}")
	else:
		print(f"Parsed {len(records)} industries. JSON: {args.json_out} CSV: {args.csv_out}")


if __name__ == "__main__":
	main()