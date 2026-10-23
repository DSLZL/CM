#!/usr/bin/env python3
"""Trusted CM dispatcher. Executes only in Actions; never runs requested source."""
import json
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
    if os.environ.get("GITHUB_EVENT_NAME") not in {"push", "workflow_dispatch"} or os.environ.get("GITHUB_REF") != "refs/heads/" + default_branch:
        raise RuntimeError("Cross-repository dispatch is limited to the trusted CM default-branch workflow")
    control_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if control_sha != os.environ.get("GITHUB_WORKFLOW_SHA"):
        raise RuntimeError("Dispatcher source must be its exact trusted workflow revision")
    cfg = json.loads((root / ".github/cm-build-routing.json").read_text(encoding="utf-8"))
    if cfg.get("schema_version") != 1 or cfg.get("configured") is not True:
        raise RuntimeError("CM-000 must configure the actual source and builder repositories")
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
    request = {"ref": worker_branch, "inputs": {"source_sha": source_sha, "request_id": request_id, "cache_epoch": epoch}}
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
    artifact = exact(artifact_name)
    receipt_dir = out / "worker-receipt"
    env = dict(os.environ)
    env["GH_TOKEN"] = os.environ["CM_BUILD_FANOUT_TOKEN"]
    subprocess.run(["gh", "run", "download", str(run_id), "--repo", worker, "--name", receipt_name,
                    "--dir", str(receipt_dir)], check=True, env=env)
    receipt = json.loads((receipt_dir / "worker-receipt.json").read_text(encoding="utf-8"))
    ci = receipt["ci"]
    expected = {"repository": worker, "source_repository": source, "source_sha": source_sha, "head_sha": source_sha,
                "workflow_sha": worker_sha, "execution_role": "platform_builder", "cache_repository": worker,
                "request_id": request_id, "target": TARGET, "run_id": run_id, "run_url": run_url,
                "run_attempt": run["run_attempt"], "artifact_id": artifact["id"], "artifact_name": artifact_name}
    if any(ci.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Worker receipt does not match the requested source and exact GitHub run/artifact")
    digest = str(artifact.get("digest", "")).removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or ci.get("artifact_sha256") != digest:
        raise RuntimeError("Actual upload digest and remote artifact digest differ")
    ci["conclusion"] = run["conclusion"]
    write(out, "verified-worker-result.json", {"schema_version": 1, "implementation_commit": source_sha,
          "ci": ci, "artifact": artifact, "receipt_artifact": receipt_record,
          "parent_run_url": "https://github.com/" + source + "/actions/runs/" + os.environ["GITHUB_RUN_ID"],
          "note": "CI provenance only. Review actual acceptance evidence before treating a task as complete."})
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        stream.write("### Verified Linux x64 worker result\n\n- Source: `" + source + "@" + source_sha + "`\n- Worker: [" + worker + "](" + run_url + ")\n- Artifact SHA-256: `" + digest + "`\n")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, KeyError, IndexError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CM dispatch blocked/failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
