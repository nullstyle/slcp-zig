#!/usr/bin/env python3
"""Require native SLCPRUN1 outcomes and compare representable cases with WASM ABI v1."""

import argparse
import json
from pathlib import Path
import selectors
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ERROR_CODES = {"OutOfMemory": 1, "EngineFailed": 4, "EffectBudgetExceeded": 7}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def wasm_memory_limits(data):
    require(data[:8] == b"\x00asm\x01\x00\x00\x00", "not a WASM v1 module")

    def uleb(at):
        result = 0
        for shift in range(0, 35, 7):
            require(at < len(data), "truncated WASM integer")
            byte = data[at]
            at += 1
            result |= (byte & 127) << shift
            if byte < 128:
                return result, at
        raise ValueError("oversized WASM integer")

    offset = 8
    while offset < len(data):
        kind = data[offset]
        size, start = uleb(offset + 1)
        require(start + size <= len(data), "truncated WASM section")
        if kind == 5:
            count, at = uleb(start)
            require(count == 1, "expected one defined WASM memory")
            flags, at = uleb(at)
            minimum, at = uleb(at)
            require(flags == 1, "expected bounded unshared WASM32 memory")
            maximum, at = uleb(at)
            require(at == start + size, "unexpected WASM memory entries")
            return minimum * 65536, maximum * 65536
        offset = start + size
    raise ValueError("missing WASM memory definition")


class Host:
    def __init__(self, node, script, wasm):
        self.child = subprocess.Popen([node, str(script), str(wasm)], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=None, text=True)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.child.stdout, selectors.EVENT_READ)
        self.next_id = 0

    def call(self, command, **fields):
        self.next_id += 1
        self.child.stdin.write(json.dumps({"id": self.next_id, "cmd": command, **fields}) + "\n")
        self.child.stdin.flush()
        require(self.selector.select(timeout=30), "WASM runner response timed out")
        line = self.child.stdout.readline(64 * 1024 * 1024)
        require(line.endswith("\n"), "WASM runner died or exceeded receipt bound")
        value = json.loads(line)
        require(value.get("id") == self.next_id and value.get("ok") is True,
                "WASM runner refusal: " + str(value))
        return value

    def close(self):
        try:
            if self.child.poll() is None:
                self.child.stdin.write('{"cmd":"quit"}\n')
                self.child.stdin.flush()
                self.child.wait(timeout=5)
        finally:
            if self.child.poll() is None:
                self.child.kill()
                self.child.wait()
            self.selector.close()
            self.child.stdin.close()
            self.child.stdout.close()


def native_receipts(runner, fixture_path, fixture):
    result = subprocess.run([str(runner), str(fixture_path)], stdout=subprocess.PIPE,
                            stderr=None, timeout=60, check=True)
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    require(lines, "native runner produced no receipt")
    summary = lines[-1]
    require(summary.get("format") == "SLCPRUN1" and summary.get("result") == "PASS",
            "native runner did not complete fixture")
    require(summary.get("cases") == len(fixture["cases"]) and summary.get("inputs", 0) > 0,
            "native runner completed no cases/inputs")
    cases = {}
    for line in lines[:-1]:
        require(line.get("format") == "SLCPRUN1", "wrong native receipt format")
        name = line["case"]
        item = cases.setdefault(name, {"metadata": None, "steps": []})
        if "outcome" in line:
            require(line["index"] == len(item["steps"]), "native input order mismatch")
            item["steps"].append(line["outcome"])
        else:
            require(item["metadata"] is None, "duplicate native case metadata")
            item["metadata"] = line
    require(set(cases) == {case["name"] for case in fixture["cases"]}, "native case inventory mismatch")
    require(sum(len(item["steps"]) for item in cases.values()) == summary["inputs"], "native input total mismatch")
    return cases


def run(runner, wasm, fixture_path, node, host_script):
    fixture = json.loads(fixture_path.read_text())
    require(fixture.get("format") == "SLCPRUN1" and fixture.get("cases"), "invalid/empty SLCPRUN1 fixture")
    receipts = native_receipts(runner, fixture_path, fixture)
    initial, maximum = wasm_memory_limits(wasm.read_bytes())
    require((initial, maximum) == (4 * 1024 * 1024, 64 * 1024 * 1024), "WASM memory profile differs")
    compared = inputs = fatal_inputs = partial_effects = sticky_inputs = budget_cases = 0
    unsupported = []
    driver_isolation = False
    host = Host(node, host_script, wasm)
    try:
        abi = host.call("abi")
        require((abi["version"], abi["min"], abi["max"]) == (1, 1, 1), "WASM ABI version differs")
        for case in fixture["cases"]:
            name = case["name"]
            native = receipts[name]
            metadata = native["metadata"]
            require(metadata is not None, "missing native case metadata")
            if "init_error" in metadata:
                require(metadata["init_error"] == case.get("init_error") and not case["steps"],
                        "initialization failure differs")
                unsupported.append({"case": name, "reason": "native initialization rejected explicit profile", "init_error": metadata["init_error"]})
                continue
            config = metadata.get("v1_config")
            if config is None:
                require(any(value == 0 for value in metadata["limits"].values()), "unexplained WASM incompatibility")
                unsupported.append({"case": name, "reason": "WASM ABI v1 cannot express explicit zero limits"})
                continue
            driver = metadata["driver"]
            require(driver == case.get("driver", "default"), "native driver profile differs")
            handle = host.call("new", config=config, driver=driver)["handle"]
            previously_failed = False
            try:
                require(len(native["steps"]) == len(case["steps"]), "native step inventory differs")
                for expected, actual in zip(case["steps"], native["steps"]):
                    pushed = host.call("push", handle=handle, input=expected["input"])
                    want_error = actual["push_error"]
                    require(pushed["pushed"] == (0 if want_error else 1), name + ": push outcome differs")
                    if want_error:
                        require(want_error in ERROR_CODES and pushed.get("errCode") == ERROR_CODES[want_error],
                                name + ": typed refusal differs")
                    effects = host.call("drain", handle=handle)["effects"]
                    observable_set = set(actual["observable_effects"])
                    normative = [frame for frame in effects if frame not in observable_set]
                    observable = [frame for frame in effects if frame in observable_set]
                    require(normative == actual["effects"], name + ": normative partial/effect bytes differ")
                    require(observable == actual["observable_effects"], name + ": observable effects differ")
                    require(actual["disposition"] == ("discard" if want_error or actual["failed"] else "apply"),
                            name + ": native effect disposition differs")
                    if actual["failed"]:
                        fatal_inputs += 1
                        partial_effects += len(normative)
                        require(pushed["pushed"] == 0, name + ": failed native engine accepted by WASM")
                    if previously_failed:
                        sticky_inputs += 1
                        require(actual["failed"] and want_error == "EngineFailed" and not effects,
                                name + ": sticky failure progressed")
                    previously_failed = actual["failed"]
                    inputs += 1
                budget_cases += int(any(isinstance(value, int) and value > 0 for value in case.get("limits", {}).values()))
                compared += 1
            finally:
                host.call("free", handle=handle)
        # Keep both profiles live: a fault in one handle must not leak into
        # the ordinary default driver used by an independent handle.
        ordinary = next(case for case in fixture["cases"]
                        if case.get("driver", "default") == "default" and not case.get("limits") and case["steps"])
        faulty = next(case for case in fixture["cases"] if case.get("driver") == "combine_fault")
        normal_handle = host.call("new", config=receipts[ordinary["name"]]["metadata"]["v1_config"])["handle"]
        fault_handle = host.call("new", config=receipts[faulty["name"]]["metadata"]["v1_config"], driver="combine_fault")["handle"]
        try:
            require(host.call("push", handle=fault_handle, input=faulty["steps"][0]["input"])["pushed"] == 0,
                    "fault driver did not fail its own handle")
            require(host.call("push", handle=normal_handle, input=ordinary["steps"][0]["input"])["pushed"] == 1,
                    "fault driver leaked into ordinary handle")
            frames = host.call("drain", handle=normal_handle)["effects"]
            outcome = receipts[ordinary["name"]]["steps"][0]
            require([frame for frame in frames if frame not in set(outcome["observable_effects"])] == outcome["effects"],
                    "ordinary handle effects changed after independent driver fault")
            driver_isolation = True
        finally:
            host.call("free", handle=fault_handle)
            host.call("free", handle=normal_handle)
    finally:
        host.close()
    require(compared > 0 and inputs > 0 and fatal_inputs > 0 and sticky_inputs > 0 and budget_cases > 0,
            "fixture did not exercise cross-target success/budget/fatal/sticky paths")
    require(partial_effects > 0, "fixture did not exercise retained partial effects after fatal push")
    require(unsupported, "fixture did not expose explicit-zero incompatibility")
    return {"format": "SLCPRUN1-CROSS-TARGET", "result": "PASS", "compared_cases": compared,
            "inputs": inputs, "fatal_inputs": fatal_inputs, "partial_effects": partial_effects,
            "sticky_inputs": sticky_inputs, "logical_budget_cases": budget_cases,
            "driver_handle_isolation": driver_isolation,
            "unsupported_wasm1": unsupported,
            "memory_profile": {"wasm_initial": initial, "wasm_maximum": maximum,
                               "effect_logical_payload_budget": 16 * 1024 * 1024,
                               "native_serialized_receipt_bound": 64 * 1024 * 1024}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, default=ROOT / "zig-out/bin/slcp-conformance-runner")
    parser.add_argument("--wasm", type=Path, default=ROOT / "zig-out/bin/slcp_core.wasm")
    parser.add_argument("--fixture", type=Path, default=ROOT / "vectors/runner/SLCPRUN1.json")
    parser.add_argument("--host", type=Path, default=ROOT / "tests/wasm/host.mjs")
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    try:
        receipt = run(args.runner.resolve(), args.wasm.resolve(), args.fixture.resolve(), args.node, args.host.resolve())
        print(json.dumps(receipt, sort_keys=True))
    except (ValueError, KeyError, StopIteration, OSError, subprocess.SubprocessError) as error:
        print("runner-conformance: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
