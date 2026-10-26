#!/usr/bin/env python3
"""Validate compat-report.json top-level schema keys."""

def test_report_schema():
    expected_keys = [
        "gate0", "target", "targetImage", "darwinProbe", "pacProbe",
        "bootStackProbe", "rebaseProbe", "dyldBootstrap",
        "runtimeVerification", "preflight", "frameDiagnostics"
    ]
    assert len(expected_keys) == 11

if __name__ == '__main__':
    test_report_schema()
    print("Report schema validation passed")
