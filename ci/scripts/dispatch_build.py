#!/usr/bin/env python3
"""Trusted CM dispatcher. Executes only in Actions; never runs requested source."""
import json
import base64
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from record_run import require_hosted_linux

API_VERSION = "2026-03-10"
TARGET = "x86_64-unknown-linux-gnu"


def api(path, payload=None):
    token = os.environ.get("CM_BUILD_FANOUT_TOKEN")
    if not token:
        raise RuntimeError("CM_BUILD_FANOUT_TOKEN with access to the fixed builder is required")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
               "Authorization": "Bearer " + token, "User-Agent": "CM-build-dispatcher"}
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request("https://api.github.com/" + path, data=data, headers=headers,
                                     method="POST" if payload is not None else "GET")
    # Never automatically retry a mutation whose outcome may be unknown.
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response)


def get_run(path):
    for attempt in range(4):
        try:
            return api(path)
        except urllib.error.HTTPError as exc:
            if exc.code not in {404, 429, 500, 502, 503, 504} or attempt == 3:
                raise
            time.sleep(2 ** attempt)


def write(root, name, data):
    (root / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    require_hosted_linux()
    root = Path(os.environ["GITHUB_WORKSPACE"])
    out = Path(os.environ["CM_DISPATCH_EVIDENCE_DIR"])
    out.mkdir(parents=True, exist_ok=True)
    source = os.environ["GITHUB_REPOSITORY"]
    default_branch = os.environ["CM_SOURCE_DEFAULT_BRANCH"]
    write(out, "dispatch-context.json", {"schema_version": 1, "source_repository": source,
        "control_workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "job": os.environ.get("GITHUB_JOB"), "target": TARGET,
        "worker_repository": "DSLZL/CM-build-linux-x64"})
    if os.environ.get("GITHUB_EVENT_NAME") not in {"push", "workflow_dispatch"} or os.environ.get("GITHUB_REF") != "refs/heads/" + default_branch:
        raise RuntimeError("Cross-repository dispatch is limited to the trusted CM default-branch workflow")
    control_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if control_sha != os.environ.get("GITHUB_WORKFLOW_SHA"):
        raise RuntimeError("Dispatcher source must be its exact trusted workflow revision")
    cfg = json.loads((root / ".github/cm-build-routing.json").read_text(encoding="utf-8"))
    if cfg.get("schema_version") != 1 or cfg.get("configured") is not True:
        raise RuntimeError("Author CI blocked: reviewed fixed-repository routing is not enabled; no local build fallback")
    worker = cfg.get("builder_repository", "")
    if cfg.get("source_repository") != source or cfg.get("target") != TARGET or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", worker) or "REPLACE" in worker or worker == source:
        raise RuntimeError("Invalid fixed Linux x64 builder routing")
    if cfg.get("builder_workflow") != "build.yml":
        raise RuntimeError("The reviewed worker entry point must be build.yml")
    worker_info = api("repos/" + worker)
    if worker_info.get("full_name") != worker or cfg.get("builder_ref") != worker_info.get("default_branch"):
        raise RuntimeError("Worker routing must use the actual fixed worker default branch")
    worker_branch = cfg["builder_ref"]
    source_sha = os.environ.get("CM_REQUESTED_SOURCE_SHA") or control_sha
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise RuntimeError("Requested source must be an exact 40-hex CM commit")
    epoch = os.environ.get("CM_REQUESTED_CACHE_EPOCH") or "v1"
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", epoch):
        raise RuntimeError("Invalid cache epoch")
    worker_sha = api("repos/" + worker + "/commits/" + urllib.parse.quote(worker_branch, safe=""))["sha"]
    request_id = "cm-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"] + "-" + uuid.uuid4().hex
    kind = os.environ.get("CM_REQUESTED_BUILD_KIND") or "qualification"
    origin = os.environ.get("CM_REQUESTED_HOST_ORIGIN") or ""
    if kind not in ("qualification", "mod-only") or (kind == "qualification" and origin) or (kind == "mod-only" and not origin):
        raise RuntimeError("Select qualification or provide the exact qualification origin for mod-only")
    request = {"ref": worker_branch, "inputs": {"source_sha": source_sha, "request_id": request_id, "cache_epoch": epoch,
        "build_kind": kind, "host_origin": origin}}
    write(out, "dispatch-request.json", {"source_repository": source, "source_sha": source_sha,
          "control_sha": control_sha, "worker_repository": worker, "observed_worker_sha": worker_sha,
          "request_id": request_id, "target": TARGET, "request": request})
    response = api("repos/" + worker + "/actions/workflows/build.yml/dispatches", request)
    run_id = response.get("workflow_run_id")
    run_url = "https://github.com/" + worker + "/actions/runs/" + str(run_id)
    if type(run_id) is not int or run_id <= 0 or response.get("html_url") != run_url:
        raise RuntimeError("No exact child run ID returned; inspect this request, do not redispatch automatically")
    write(out, "dispatch-response.json", response)
    print("CM worker run:", run_url, flush=True)
    run_path = "repos/" + worker + "/actions/runs/" + str(run_id)
    deadline = time.monotonic() + 6600
    while True:
        run = get_run(run_path)
        if run.get("id") != run_id or run.get("html_url") != run_url or run.get("repository", {}).get("full_name") != worker or run.get("event") != "workflow_dispatch" or run.get("path") != ".github/workflows/build.yml":
            raise RuntimeError("Child run identity differs from the fixed worker workflow")
        if run.get("head_sha") != worker_sha or run.get("head_branch") != worker_branch:
            raise RuntimeError("Worker revision changed during dispatch; this run is not accepted")
        if run.get("display_title") != "CM Linux x64 / " + request_id:
            raise RuntimeError("Child run request ID binding does not match")
        write(out, "child-run.json", run)
        if run.get("status") == "completed":
            if run.get("conclusion") != "success":
                raise RuntimeError("Exact child run completed with " + str(run.get("conclusion")) + ": " + run_url)
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Timed out observing the exact child run; no replacement run was started: " + run_url)
        time.sleep(15)
    records = []
    page = 1
    while True:
        batch = api(run_path + "/artifacts?per_page=100&page=" + str(page))["artifacts"]
        records.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    receipt_name = "cm-build-receipt-" + request_id + "-" + str(run["run_attempt"])
    artifact_name = "cm-linux-x64-task-artifacts-" + request_id + "-" + str(run["run_attempt"])
    def exact(name):
        found = [a for a in records if a.get("name") == name and a.get("expired") is False]
        if len(found) != 1:
            raise RuntimeError("Missing or ambiguous exact child artifact: " + name)
        return found[0]
    receipt_record = exact(receipt_name)
    source_config = api("repos/" + source + "/contents/.github/cm-ci.json?ref=" + source_sha)
    consumer_required = json.loads(base64.b64decode(source_config["content"]))["task_id"] in ("CM-P04", "CM-M01", "CM-M02", "CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B")
    consumer_artifact = exact("cm-linux-x64-consumer-artifacts-" + request_id + "-" + str(run["run_attempt"])) if consumer_required else None
    jobs = get_run(run_path + "/attempts/" + str(run["run_attempt"]) + "/jobs?per_page=100")["jobs"]
    producer_jobs = [job for job in jobs if job["name"] in ("build-read / linux-x64", "build-write / linux-x64") and job["conclusion"] == "success"]
    if len(producer_jobs) != 1:
        raise RuntimeError("An exact successful producer job is required")
    if consumer_required:
        consumer_jobs = [job for job in jobs if job["name"] == "runtime-consumer"]
        if len(consumer_jobs) != 1 or consumer_jobs[0]["conclusion"] != "success":
            raise RuntimeError("P04 consumer was missing, skipped or failed")
    receipt_dir = out / "worker-receipt"
    env = dict(os.environ)
    env["GH_TOKEN"] = os.environ["CM_BUILD_FANOUT_TOKEN"]
    subprocess.run(["gh", "run", "download", str(run_id), "--repo", worker, "--name", receipt_name,
                    "--dir", str(receipt_dir)], check=True, env=env)
    receipt = json.loads((receipt_dir / "worker-receipt.json").read_text(encoding="utf-8"))
    ci = receipt["ci"]
    production = ci.get("production_origin")
    if production:
        from retry import verify_production_origin
        original = verify_production_origin(production, worker=worker, fetch=api)
        for repository, previous, current in ((source, production["source_sha"], source_sha),
                                               (worker, production["workflow_sha"], worker_sha)):
            if api("repos/" + repository + "/compare/" + previous + "..." + current)["status"] not in ("ahead", "identical"):
                raise RuntimeError("Reused producer is not an ancestor of the requested source/workflow")
        artifact = original["product_artifact"]
        artifact_name = artifact["name"]
        input_artifact = original["input_artifact"]
    else:
        artifact = exact(artifact_name)
        input_artifact = exact("cm-linux-x64-runtime-inputs-" + request_id + "-" + str(run["run_attempt"])) if consumer_required else None
    expected = {"repository": worker, "source_repository": source, "source_sha": source_sha, "head_sha": source_sha,
                "workflow_sha": worker_sha, "execution_role": "platform_builder", "cache_repository": worker,
                "request_id": request_id, "target": TARGET, "run_id": run_id, "run_url": run_url,
                "run_attempt": run["run_attempt"], "artifact_id": artifact["id"], "artifact_name": artifact_name,
                "job": producer_jobs[0]["name"], "job_id": producer_jobs[0]["id"], "job_conclusion": "success", "build_kind": kind}
    if any(ci.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Worker receipt does not match the requested source and exact GitHub run/artifact")
    digest = str(artifact.get("digest", "")).removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or ci.get("artifact_sha256") != digest:
        raise RuntimeError("Actual upload digest and remote artifact digest differ")
    if consumer_required:
        consumer = receipt.get("consumer") or {}
        expected_consumer = {"execution_role": "runtime_consumer", "cache_mode": "none", "job": "runtime-consumer",
            "job_conclusion": "success", "producer_job_id": producer_jobs[0]["id"],
            "job_id": consumer_jobs[0]["id"], "artifact_id": consumer_artifact["id"], "artifact_name": consumer_artifact["name"],
            "artifact_sha256": str(consumer_artifact["digest"]).removeprefix("sha256:"), "source_sha": source_sha,
            "workflow_sha": worker_sha, "run_id": run_id, "run_attempt": run["run_attempt"], "request_id": request_id}
        if any(consumer.get(key) != value for key, value in expected_consumer.items()):
            raise RuntimeError("Consumer receipt differs from exact source/workflow/run/job/artifact")
        expected_input = {"artifact_id": input_artifact["id"], "artifact_name": input_artifact["name"],
                          "artifact_sha256": str(input_artifact["digest"]).removeprefix("sha256:")}
        if not re.fullmatch(r"[0-9a-f]{64}", expected_input["artifact_sha256"]) or consumer.get("input_artifact") != expected_input:
            raise RuntimeError("Consumer receipt does not bind its exact producer input artifact")
        if production:
            from worker_policy import artifact_binding
            if consumer.get("production_origin") != production:
                raise RuntimeError("Consumer receipt has a different original producer")
            validation = consumer.get("validation_artifact") or {}
            artifact_binding(exact("cm-linux-x64-validation-inputs-" + request_id + "-" + str(run["run_attempt"])),
                validation["artifact_id"], "cm-linux-x64-validation-inputs-" + request_id + "-" + str(run["run_attempt"]),
                validation["artifact_sha256"], run_id)
    ci["conclusion"] = run["conclusion"]
    if kind == "qualification" and consumer_required:
        origin = {"run_id": run_id, "run_attempt": run["run_attempt"], "source_sha": source_sha,
            "workflow_sha": worker_sha, "request_id": request_id}
        for prefix, record in (("input", input_artifact), ("consumer", consumer_artifact), ("receipt", receipt_record)):
            origin[prefix + "_artifact_id"] = record["id"]
            origin[prefix + "_artifact_sha256"] = record["digest"].removeprefix("sha256:")
        write(out, "host-origin.json", origin)
    write(out, "verified-worker-result.json", {"schema_version": 1, "implementation_commit": source_sha,
          "ci": ci, "artifact": artifact, "consumer_artifact": consumer_artifact, "input_artifact": input_artifact,
          "consumer": receipt.get("consumer"),
          "jobs": jobs, "receipt_artifact": receipt_record,
          "parent_run_url": "https://github.com/" + source + "/actions/runs/" + os.environ["GITHUB_RUN_ID"],
          "note": "CI provenance only. Review actual acceptance evidence before treating a task as complete."})
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        stream.write("### Verified Linux x64 worker result\n\n- Source: `" + source + "@" + source_sha + "`\n- Worker: [" + worker + "](" + run_url + ")\n- Artifact SHA-256: `" + digest + "`\n")


def self_check():
    """Exercise blocked dispatch paths with a transport that cannot send requests."""
    import tempfile
    from unittest.mock import patch
    results = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / ".github").mkdir()
        base = {"schema_version": 1, "configured": True, "source_repository": "DSLZL/CM",
            "builder_repository": "DSLZL/CM-build-linux-x64", "builder_ref": "main",
            "builder_workflow": "build.yml", "target": TARGET}
        for name in ("routing-disabled", "missing-token", "wrong-source", "ci-unavailable"):
            cfg = {**base}
            if name == "routing-disabled":
                cfg["configured"] = False
            if name == "wrong-source":
                cfg["source_repository"] = "untrusted/source"
            (root / ".github/cm-build-routing.json").write_text(json.dumps(cfg))
            env = {"GITHUB_WORKSPACE": str(root), "CM_DISPATCH_EVIDENCE_DIR": str(root / "out"),
                "GITHUB_REPOSITORY": "DSLZL/CM", "CM_SOURCE_DEFAULT_BRANCH": "main",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                "GITHUB_WORKFLOW_SHA": "a" * 40}
            if name != "missing-token":
                env["CM_BUILD_FANOUT_TOKEN"] = "controlled-fixture-unused"
            with patch.dict(os.environ, env, clear=True), patch(__name__ + ".require_hosted_linux"), \
                patch("subprocess.check_output", return_value="a" * 40), \
                patch("urllib.request.urlopen", side_effect=urllib.error.URLError("controlled unavailable")) as transport:
                try:
                    main()
                except (RuntimeError, urllib.error.URLError):
                    pass
                else:
                    raise AssertionError("Blocked author CI dispatched a child build")
                assert all(call.args[0].get_method() == "GET" for call in transport.call_args_list)
                assert transport.call_count == int(name == "ci-unavailable")
                context = json.loads((root / "out/dispatch-context.json").read_text())
                assert context["control_workflow_sha"] == "a" * 40 and context["source_repository"] == "DSLZL/CM"
                assert context["target"] == TARGET and "controlled-fixture-unused" not in json.dumps(context)
                results.append({"case": name, "status": "pass", "simulated_transport": True,
                    "actual_network_requests": 0, "mutation_requests": 0, "local_build_calls": 0})
    return results


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, KeyError, IndexError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CM dispatch blocked/failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
