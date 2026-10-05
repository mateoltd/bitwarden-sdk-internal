#!/usr/bin/env python3
"""Require a calibrated reduction diagnostic and normal probe completion."""
import argparse
from pathlib import Path
import re
import xml.etree.ElementTree as ET


def validate(implementation, representative, reduction, status, xml, output):
    if xml.tag != "valgrindoutput" or xml.findtext("protocoltool") != "memcheck":
        raise ValueError("Unexpected detector output")
    states = xml.findall("status")
    if xml.find("fatal_signal") is not None or not states or states[-1].findtext("state") != "FINISHED":
        raise ValueError("Detector did not complete normally")
    errors = xml.findall("error")
    expected_status = 77 if implementation == "original" else 0
    if status != expected_status or bool(errors) != (implementation == "original"):
        raise ValueError("Uncalibrated original or failing candidate")
    for error in errors:
        frames = error.findall("stack/frame")
        # Original registry 0.7.5 correction mask, not arbitrary undefined data.
        if error.findtext("kind") != "UninitCondition" or not any(
            frame.findtext("file") == "src/uint/ref_type/div.rs"
            # Speed optimization attributes the same borrow-dependent branch
            # to the final subtraction, size optimization to the masked add-back.
            and frame.findtext("line") in {"324", "335"}
            for frame in frames
        ) or not any(frame.findtext("file") == "main.rs" for frame in frames):
            raise ValueError("Unrelated detector error cannot calibrate the property")
    count = sum(int(pair.findtext("count")) for pair in xml.findall("errorcounts/pair"))
    pattern = re.escape(f"{implementation} {representative} {reduction}: ") + r"([0-9]+) property errors\n"
    completed = re.fullmatch(pattern, output)
    if completed is None or int(completed[1]) != count or (implementation == "original" and count == 0):
        raise ValueError("Missing arithmetic completion or incoherent detector count")
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("implementation", choices=("original", "candidate"))
    parser.add_argument("representative", choices=("zero", "high"))
    parser.add_argument("reduction", choices=("rem", "rem-vartime"))
    parser.add_argument("status", type=int)
    parser.add_argument("xml", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    count = validate(args.implementation, args.representative, args.reduction, args.status,
                     ET.parse(args.xml).getroot(), args.output.read_text())
    print(f"Validated {args.implementation} {args.representative} {args.reduction}: {count} errors")
