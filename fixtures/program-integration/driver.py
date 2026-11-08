#!/usr/bin/env python3
"""Final business combinations against the original H and independent A/B/C."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import time
import tomllib

sys.path.insert(0, "/fixture/ci/scripts")
import ci_progress
import mod_manifest
import runtime_cases

INPUTS = Path("/inputs")
BINARY = INPUTS / "host/bin/codex"
WORK = Path("/work")
PROFILE = Path("/profile")
EVIDENCE = Path("/evidence")
PACKAGES = {"a": "g02a/turn-budget", "b": "g02b/review-before-send", "c": "g03/tool-concurrency"}
OWNERS = {"a": "org.example.turn-budget", "b": "org.example.review-before-send", "c": "org.example.tool-concurrency"}
REPORTS = ("program-runtime-integration.json",)


def module(relative):
    path = Path("/fixture/fixtures") / relative
    spec = importlib.util.spec_from_file_location("cm_program_" + path.parent.name.replace("-", "_"), path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def setup(selected, limit=16):
    budget = module("turn-budget/driver.py")
    for relative in (("m02/lifecycle-audit/normal", "m02/example-tool/normal") if selected else ()):
        budget.cm(PROFILE, EVIDENCE / "management", "install", INPUTS / "mods" / relative)
    for owner in selected:
        budget.cm(PROFILE, EVIDENCE / "management", "install", INPUTS / "mods" / PACKAGES[owner])
    if "a" in selected:
        mod_manifest.write_toml(PROFILE / "cm-runtime.toml", {"format_version": 2, "enabled": [],
            "mods": {OWNERS["a"]: {"policy": budget.policy(limit)}}})
        budget.cm(PROFILE, EVIDENCE / "management", "lock")


def payloads():
    return {key: mod_manifest.sha(INPUTS / "mods" / relative / "payload.so") for key, relative in PACKAGES.items()}


@contextmanager
def terminal(name, selected, provider=None, *, leaves=False, code_mode=False):
    review = module("review-before-send/driver.py")
    directory = EVIDENCE / name
    leaf_dir = directory / "leaves"
    settings = {"tool_concurrency": 1} if "c" in selected else {}
    if leaves:
        settings.update(model_catalog_json="/fixture/concurrency-models.json", features={"code_mode": code_mode},
            mcp_servers={"g03": {"command": "/usr/bin/python3",
                "args": ["-B", "/fixture/fixtures/tool-concurrency/driver.py", "mcp", str(leaf_dir)],
                "startup_timeout_sec": 30, "tool_timeout_sec": 90}})
    instance = review.Terminal("program", name, PROFILE, reviewed="b" in selected, provider=provider,
        settings=settings, directory=directory)
    try:
        if leaves:
            leaf_dir.mkdir()
        yield instance
    except BaseException:
        instance.close(False)
        raise
    else:
        instance.close(True)
        assert not instance.provider.errors, instance.provider.errors


def submit(instance, token, selected, *, paste=False):
    text = "CM_M02_" + token
    budget = module("turn-budget/driver.py")
    before_requests, before_admissions = len(instance.provider.requests), len(budget.admissions(instance.directory))
    if "b" in selected:
        if paste:
            instance.send("\x1b[200~" + text + "\x1b[201~")
            instance.review()
            instance.send(b"\r\t\r")
            instance.quiet()
            instance.send(b"\x1b")
            instance.send(b"\x03")
            instance.review(text[:-1] + "x")
        else:
            instance.review(text)
        assert len(instance.provider.requests) == before_requests
        assert len(budget.admissions(instance.directory)) == before_admissions
        instance.send("y")
    else:
        instance.send(text)
        instance.wait(lambda: instance.managed.tui_text_visible(instance.output, text), "input rendered")
        time.sleep(0.2)
        instance.send(b"\r")


def settled(instance, token, expected="M02 complete "):
    instance.wait(lambda: instance.managed.tui_text_visible(instance.output, expected + token), "actual business reply")
    instance.wait_turns()


def invariants(instance, selected):
    rows = instance.native()
    ready = [row["detail"] for row in rows if row["event"] == "ready"]
    assert len(ready) == 1 and instance.identity["executable_sha256"] == mod_manifest.sha(BINARY)
    expected = {OWNERS[key] for key in selected}
    loaded = {row["detail"]["mod"] for row in rows if row["event"] == "init-complete"}
    assert expected <= loaded and (set(OWNERS.values()) & loaded) == expected, (expected, loaded)
    if not selected:
        assert not loaded and ready[0]["mod_count"] == 0
    budget = module("turn-budget/driver.py")
    admissions = budget.admissions(instance.directory)
    thread = next((row["detail"]["thread"] for row in rows if row["event"] == "runtime-scope-open"
        and row["detail"]["thread"] and not row["detail"]["turn"]), None)
    # Auxiliary title requests have their own thread and retain their raw admissions below.
    turns = {row["turn"] for row in admissions if row["thread"] == thread}
    charges = {turn: budget.charged(budget.admissions(instance.directory, turn)) for turn in turns}
    charges = {turn: values for turn, values in charges.items() if values}
    assert bool(admissions) == ("a" in selected)
    if "a" in selected:
        assert thread and charges and all(values == list(range(1, len(values) + 1)) for values in charges.values())
    assert bool(instance.reviews()) == ("b" in selected)
    return {"loaded": sorted(loaded), "ready": ready[0], "budget_charges": charges,
        "business_thread": thread, "budget_admissions": admissions,
        "review_ids": [row["detail"] for row in instance.reviews()], "identity": instance.identity}


def business(name, selected, *, mutate=None):
    sdk = module("runtime-sdk/driver.py")
    with terminal(name, selected, sdk.Provider(tool=bool(selected))) as instance:
        token = "program-" + name
        submit(instance, token, selected)
        settled(instance, token)
        value = invariants(instance, selected)
        if mutate:
            mutate()
            # A running process keeps its loaded set while the next process uses the new generation.
            submit(instance, token + "-live", selected)
            settled(instance, token + "-live")
            assert invariants(instance, selected)["ready"] == value["ready"]
        value["requests"] = list(instance.provider.requests)
    value["shutdown"] = mod_manifest.read(instance.directory / "result.json")
    return value


def leaf_audit(rows, *, cancelled=False):
    running, acquired, released, peak = set(), [], [], 0
    for row in rows:
        detail = row["detail"]
        if row["event"] == "tool-concurrency-acquired":
            assert detail["call_id"] not in running
            running.add(detail["call_id"])
            acquired.append(detail)
            peak = max(peak, len(running))
            assert peak <= 1, "More than one actual leaf admitted"
        elif row["event"] == "tool-concurrency-released":
            assert detail["call_id"] in running, "Duplicate or foreign release"
            running.remove(detail["call_id"])
            released.append(detail)
    assert not running and acquired and len(acquired) == len(released)
    orchestration = {row["detail"]["call_id"] for row in rows
        if row["event"] == "tool-concurrency-role" and row["detail"]["role"] == "orchestration"}
    assert not orchestration & {row["call_id"] for row in acquired}
    return {"peak": peak, "acquired": acquired, "released": released, "orchestration": sorted(orchestration),
        "cancelled": cancelled}


def leaves(name, selected, *, code_mode=False, cancel=None, exec_tools=False):
    concurrency = module("tool-concurrency/driver.py")
    provider = concurrency.Provider(cells=2 if code_mode else 3, code_mode=code_mode,
        exec_barriers=EVIDENCE / name / "leaves" if exec_tools else None)
    with terminal(name, selected, provider, leaves=True, code_mode=code_mode) as instance:
        token = "program-" + name
        submit(instance, token, selected)
        entered = EVIDENCE / name / "leaves"
        instance.wait(lambda: len(list(entered.glob("*.entered"))) == 1 and
            sum(row["event"] == "tool-concurrency-wait" for row in instance.native()) > 1,
            "one running leaf and a separately queued leaf")
        if code_mode:
            instance.wait(lambda: any(row["event"] == "tool-concurrency-role" and
                row["detail"]["role"] == "orchestration" and row["detail"]["tool"].endswith("wait")
                for row in instance.native()), "Code Mode wait reached without holding a leaf permit")
        before = instance.native()
        if cancel:
            active = [row["detail"] for row in before if row["event"] == "tool-concurrency-acquired"]
            assert len(active) == 1
            cancelled_turn = active[0]["turn"]
            queued = {row["detail"]["call_id"] for row in before if row["event"] == "tool-concurrency-wait"
                and row["detail"]["turn"] == cancelled_turn} - {row["call_id"] for row in active}
            assert queued, "Cancellation did not exercise an actual queued leaf"
            assert len(list(entered.glob("*.entered"))) == 1
            instance.send(b"\x1b")
            instance.wait(lambda: any(row["event"] == "runtime-scope-closed" and
                row["detail"]["turn"] == cancelled_turn for row in instance.native()), "UI interrupt closed the cancelled turn")
            # Release only after turn cancellation is observed; queued work must never enter.
            (entered / "release").touch()
            for label in ("A", "B"):
                (entered / (label + ".release")).touch()
            assert len(list(entered.glob("*.entered"))) == 1
            provider.release.set()
            provider.exec_barriers = None
            submit(instance, token + "-recovery", selected)
            settled(instance, token + "-recovery", "G03 complete ")
        else:
            (entered / "release").touch()
            for label in ("A", "B"):
                (entered / (label + ".release")).touch()
            settled(instance, token, "G03 complete ")
        value = invariants(instance, selected)
        value["leaf_audit"] = leaf_audit(instance.native(), cancelled=bool(cancel))
        if not cancel:
            count = 2 if exec_tools else 4 if code_mode else 3
            assert len(value["leaf_audit"]["acquired"]) == count
            assert len(list(entered.glob("*.entered"))) == count
        else:
            first = [row for row in value["leaf_audit"]["acquired"] if row["turn"] == cancelled_turn]
            assert len(first) == 1 and not queued & {row["call_id"] for row in first}
            assert any(row["turn"] != cancelled_turn for row in value["leaf_audit"]["acquired"]), "Recovery reused a closed turn"
            value["cancel_boundary"] = {"case": cancel, "classification": "scope_closed_after_UI_interrupt",
                "turn": cancelled_turn, "running": active, "queued_never_admitted": sorted(queued)}
        value["requests"] = list(provider.requests)
    value["shutdown"] = mod_manifest.read(instance.directory / "result.json")
    return value


def case_empty():
    command = [str(BINARY), "cm", "--home", str(PROFILE), "launch", "--", "--version"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    mod_manifest.write(EVIDENCE / "empty-initialize.json", {"command": command,
        "return_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert module("managed-package/driver.py").state(PROFILE)[1]["installed"] == {}
    return business("empty", "")


def case_a():
    setup("a", 2)
    return budget_boundary("a", "a")


def case_b():
    setup("b")
    return business("b", "b")


def case_c():
    setup("c")
    return leaves("c", "c", code_mode=True)


def case_abc_input():
    setup("abc")
    sdk = module("runtime-sdk/driver.py")
    with terminal("abc-input", "abc", sdk.Provider(tool=True)) as instance:
        submit(instance, "program-abc-input", "abc", paste=True)
        settled(instance, "program-abc-inpux")
        value = invariants(instance, "abc")
        assert len(value["review_ids"]) == 2
        requests = [row for row in instance.provider.requests if row["purpose"] == "business"]
        assert len(requests) == 2 and all("CM_M02_program-abc-inpux" in sdk.text_values(row["input"]) for row in requests)
        assert list(value["budget_charges"].values()) == [[1, 2]]
        value["requests"] = requests
    return value


def budget_boundary(name, selected):
    budget = module("turn-budget/driver.py")
    provider = budget.Provider(desired=3, retry=True)
    with terminal(name, selected, provider) as instance:
        submit(instance, "program-" + name, selected)
        instance.wait(lambda: any(row["detail"].get("error", {}).get("code") == "sampling_budget_exhausted"
            for row in budget.admissions(instance.directory)), "budget terminal after two logical samples")
        instance.wait_turns()
        value = invariants(instance, selected)
        assert list(value["budget_charges"].values()) == [[1, 2]]
        requests = budget.business_requests(provider)
        assert [row["status"] for row in requests] == [503, 200, 200], requests
        provider.desired, provider.retry = 1, False
        submit(instance, "program-" + name + "-next", selected)
        settled(instance, "program-" + name + "-next", "Budget complete ")
        final = invariants(instance, selected)
        assert sorted(final["budget_charges"].values()) == [[1], [1, 2]]
        value["next_turn"] = final
        value["requests"] = list(provider.requests)
    return value


def case_abc_budget():
    setup("abc", 2)
    return budget_boundary("abc-budget", "abc")


def case_abc_tool_leaves():
    setup("abc")
    return {"exec": leaves("abc-direct", "abc", exec_tools=True), "nested": leaves("abc-nested", "abc", code_mode=True)}


def case_abc_cancel_queued():
    setup("abc")
    return leaves("abc-cancel-queued", "abc", cancel="queued")


def case_abc_cancel_running():
    setup("abc")
    return leaves("abc-cancel-running", "abc", code_mode=True, cancel="running")


def case_abc_provider_error():
    setup("abc")
    budget = module("turn-budget/driver.py")
    provider = budget.Provider(desired=1, failure_status=400)
    with terminal("abc-provider-error", "abc", provider) as instance:
        submit(instance, "program-provider-error", "abc")
        instance.wait(lambda: instance.managed.tui_text_visible(instance.output, "controlled transport retry"), "actual provider error")
        instance.wait_turns()
        requests = budget.business_requests(provider)
        assert [row["status"] for row in requests] == [400]
        value = invariants(instance, "abc")
        assert list(value["budget_charges"].values()) == [[1]]
        value["actual_error_and_recovery"] = requests
        provider.failure_status = None
        submit(instance, "program-provider-recovered", "abc")
        settled(instance, "program-provider-recovered", "Budget complete ")
    return {"same_process": value, "new_process": business("provider-restart", "abc")}


def case_wrong_backend():
    setup("abc")
    seams = module("sdk-seams/driver.py")
    directory = EVIDENCE / "wrong-backend"
    directory.mkdir()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.setblocking(False)
    endpoint = "ws://127.0.0.1:" + str(listener.getsockname()[1])
    try:
        value = seams.command(PROFILE, ["cm", "--home", PROFILE, "launch", "--", "--remote", endpoint,
            "--tool-concurrency", "1"], directory, good=False)
        assert not select.select([listener], [], [], 0)[0], "Unsupported backend contacted before rejection"
    finally:
        listener.close()
    assert "remote backends are unsupported" in value["stderr"].lower(), value
    failures = [row["detail"] for row in value["native"] if row["event"] == "startup-failed"]
    assert len(failures) == 1 and failures[0]["code"] == "backend" and failures[0]["already_native_executed"] is False
    assert not any(row["event"] == "ready" for row in value["native"])
    value["backend_contacted"] = False
    value["already_native_executed"] = any(row["event"] == "init-start" for row in value["native"])
    return value


def case_exclusive_conflict():
    setup("abc")
    budget = module("turn-budget/driver.py")
    negative = WORK / "negative-profile"
    shutil.copytree(INPUTS / "mods/g02a/turn-budget", negative / "mods/original")
    shutil.copytree(INPUTS / "mods/g02a/turn-budget", negative / "mods/duplicate")
    path = negative / "mods/duplicate/mod.toml"
    fields = tomllib.loads(path.read_text())
    fields["id"] = "org.example.duplicate-budget"
    mod_manifest.write_toml(path, fields)
    mod_manifest.selection(negative, [OWNERS["a"], fields["id"]])
    result = budget.cm(negative, EVIDENCE / "negative", "plan", success=False)
    assert result["code"] == "exclusive_conflict" and result["already_native_executed"] is False
    return {"rejection": result, "positive": business("conflict-positive", "abc")}


def changed_set(name, action, owners, expected):
    setup("abc")
    budget = module("turn-budget/driver.py")
    managed = module("managed-package/driver.py")
    before = managed.state(PROFILE)
    retained = PROFILE / "user-data/keep.json"
    mod_manifest.write(retained, {"owner": "program-user", "value": name})
    marker = retained.read_bytes()
    official = {path.relative_to(INPUTS / "official").as_posix(): mod_manifest.sha(path)
        for path in sorted((INPUTS / "official").rglob("*")) if path.is_file()}
    original = payloads()
    frozen_payloads = set(original.values()) | {mod_manifest.sha(INPUTS / "mods/m02" / owner / "normal/payload.so")
        for owner in ("lifecycle-audit", "example-tool")}
    preserved_state = []
    def change():
        state_before = managed.protected_inventory(PROFILE / "state") if (PROFILE / "state").exists() else []
        for owner in owners:
            budget.cm(PROFILE, EVIDENCE / "management", action, OWNERS[owner])
        if not expected:
            for owner in ("lifecycle-audit", "example-tool"):
                budget.cm(PROFILE, EVIDENCE / "management", "disable", owner)
        assert managed.state(PROFILE) != before
        assert retained.read_bytes() == marker
        state_after = managed.protected_inventory(PROFILE / "state") if (PROFILE / "state").exists() else []
        assert state_after == state_before, "Management changed retained Mod state"
        preserved_state.extend(state_after)
        current = managed.state(PROFILE)[1]
        assert set(current["enabled"]) == {OWNERS[key] for key in expected} | (
            {"lifecycle-audit", "example-tool"} if expected else set())
        installed = {mod_manifest.sha(path) for path in (PROFILE / "store/objects").rglob("payload.so")}
        assert installed <= frozen_payloads and {original[key] for key in expected} <= installed
    live = business(name + "-live", "abc", mutate=change)
    restarted = business(name + "-restart", expected)
    after = managed.state(PROFILE)
    assert retained.read_bytes() == marker and payloads() == original
    assert {path.relative_to(INPUTS / "official").as_posix(): mod_manifest.sha(path)
        for path in sorted((INPUTS / "official").rglob("*")) if path.is_file()} == official
    return {"live": live, "restart": restarted, "before_generation": json.loads(before[0]),
        "after_generation": json.loads(after[0]), "payload_sha256": original, "preserved_user_data": True,
        "preserved_state_inventory": preserved_state,
        "mod_owned_state": "A/B/C declare no persistent file-state schema; M04 ownership remains separately qualified",
        "official_sha256": official}


def case_disable_b():
    return changed_set("disable-b", "disable", "b", "ac")


def case_disable_all():
    return changed_set("disable-all", "disable", "abc", "")


def case_remove_a():
    return changed_set("remove-a", "remove", "a", "bc")


def case_remove_b():
    return changed_set("remove-b", "remove", "b", "ac")


def case_remove_c():
    return changed_set("remove-c", "remove", "c", "ab")


def case_reenable_abc():
    setup("abc")
    budget = module("turn-budget/driver.py")
    original = payloads()
    for owner in "abc":
        budget.cm(PROFILE, EVIDENCE / "management", "disable", OWNERS[owner])
    for owner in ("lifecycle-audit", "example-tool"):
        budget.cm(PROFILE, EVIDENCE / "management", "disable", owner)
    disabled = business("reenable-disabled", "")
    for owner in "abc":
        budget.cm(PROFILE, EVIDENCE / "management", "enable", OWNERS[owner])
    for owner in ("lifecycle-audit", "example-tool"):
        budget.cm(PROFILE, EVIDENCE / "management", "enable", owner)
    assert payloads() == original
    return {"disabled": disabled, "reenabled": leaves("reenable-abc", "abc", code_mode=True)}


@ci_progress.case()
def matrix(case):
    global PROFILE
    runtime_cases.enter(globals(), "program", case)
    # Reuse the audited plug-and-play TUI namespace, with an independent home per case.
    PROFILE = Path("/profile/review/plug-and-play") / ("program-" + case)
    for directory in (WORK, PROFILE, EVIDENCE):
        directory.mkdir(parents=True)
    before = payloads()
    host = mod_manifest.sha(BINARY)
    scope = mod_manifest.read(Path("/fixture/ci/program/cases.json"))["cases"][case]
    value = globals()[runtime_cases.function(case, "program")]()
    assert payloads() == before and mod_manifest.sha(BINARY) == host
    runtime_cases.finish("program", case, [{case: {"status": "pass", "host_sha256": host,
        "payload_sha256": before, "scope": scope, "result": value}}], REPORTS)


if __name__ == "__main__":
    assert len(sys.argv) == 3 and sys.argv[1] == "matrix"
    matrix(sys.argv[2])
