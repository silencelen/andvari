#!/usr/bin/env python3
"""Prints the UI tests' summary as a table.

usage: summarize.py <uitest-summary.json> [--markdown]

The file is written by the tests themselves (AndvariUITests/Support/Recorder.swift): a list of
{"test", "status", "message", "seconds", "screenshots"}. Exit status 1 when it is missing or empty.
"""
import json
import sys


def main():
    path = sys.argv[1]
    markdown = "--markdown" in sys.argv[2:]
    try:
        with open(path, encoding="utf-8") as handle:
            entries = json.load(handle)
    except (OSError, ValueError) as error:
        print("No summary: %s" % error)
        return 1
    if not entries:
        print("No summary: no test finished.")
        return 1
    counts = {}
    for entry in entries:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    totals = ", ".join("%d %s" % (counts[key], key) for key in sorted(counts))
    if markdown:
        print("### iOS UI tests: %s\n" % totals)
        print("| Test | Status | Seconds | Screenshots | Message |")
        print("|---|---|---|---|---|")
        for entry in entries:
            message = (entry.get("message") or "").replace("\n", "<br>").replace("|", "\\|")
            print("| %s | %s | %.0f | %d | %s |" % (entry["test"], entry["status"], entry.get("seconds", 0), len(entry.get("screenshots", [])), message))
    else:
        print(totals)
        width = max(len(entry["test"]) for entry in entries)
        for entry in entries:
            print("%-8s %-*s %4.0fs %2d shots" % (entry["status"], width, entry["test"], entry.get("seconds", 0), len(entry.get("screenshots", []))))
            for line in (entry.get("message") or "").splitlines():
                print("         %s" % line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
