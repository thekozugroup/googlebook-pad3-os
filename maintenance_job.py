#!/usr/bin/env python3
"""Plan/execute one pinned offline native job on a trusted runner; never publish.

External schema 1: source_commit, profile, stage (assemble/package), recipe pin,
output reference. Package also needs plan/tools/review/handoff, key/certificate,
feed_key/feed_public_key and apksigner/aapt2 pins. Every pin is {path, sha256};
path references use input:relative, tool:relative, work:relative, output:relative.
Recipe/plan/tools templates use the same pins; tools.scratch must be work:.
Review pins the portable plan bytes. Only paths and that plan digest are rebound
in private runtime copies. Assemble emits a portable, externally pinned handoff.
Only the reviewed R5 profile and sequences 5 through 8 are supported.
Git cleanliness covers Git-visible files; execution requires an isolated trusted
runner without unreviewed ignored executables or bytecode caches.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

from maintenance_workspace import local_path, require, task_root

ROOT = Path(__file__).resolve().parent
COMMON = {"schema", "source_commit", "profile", "stage", "recipe", "output"}
PACKAGE = {"plan", "tools", "review", "handoff", "key", "certificate", "feed_key", "feed_public_key", "apksigner", "aapt2"}
PARTITIONS = ("system", "system_ext", "product")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4 * 1024**2, "invalid external JSON input")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def source_bound(commit):
    """Bind Git-visible state; runner isolation remains an external prerequisite."""
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", commit), "require an exact source commit")
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"], capture_output=True, text=True, check=True)
    state = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=normal"], capture_output=True, text=True, check=True)
    require(head.stdout.strip() == commit and not state.stdout.strip(), "source commit differs or checkout is dirty")


def reference(value, roots):
    require(isinstance(value, str) and ":" in value, "require a root-relative reference")
    name, relative = value.split(":", 1)
    require(name in roots and relative and "\\" not in relative, "unknown reference root")
    parts = PurePosixPath(relative)
    require(not parts.is_absolute() and str(parts) == relative and ".." not in parts.parts, "unsafe relative reference")
    path = roots[name] / relative
    require(path == path.resolve() and path.is_relative_to(roots[name]), "reference escapes its physical root")
    return path


def pin(entry, roots, pins):
    require(isinstance(entry, dict) and set(entry) == {"path", "sha256"}, "require a file pin")
    require(isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), "invalid input digest")
    path = reference(entry["path"], roots)
    require(path.is_file() and not path.is_symlink()
            and pins.get(path, entry["sha256"]) == entry["sha256"], "conflicting external input pins")
    require(path in pins or digest(path) == entry["sha256"], "external input pin mismatch")
    pins[path] = entry["sha256"]
    return path


def materialize(value, roots, pins):
    if isinstance(value, dict):
        if set(value) == {"path", "sha256"}:
            return {"path": str(pin(value, roots, pins)), "sha256": value["sha256"]}
        return {key: materialize(item, roots, pins) for key, item in value.items()}
    if isinstance(value, list):
        return [materialize(item, roots, pins) for item in value]
    return value


def reviewed_recipe(recipe, profile):
    from native_install import r5_userspace
    require(profile == r5_userspace.LINEAGE and recipe.get("schema") == 2
            and type(recipe.get("sequence")) is int and 5 <= recipe["sequence"] <= 8,
            "unreviewed profile or sequence; source adaptation requires review")
    r5_userspace.validate_lineage(recipe)


def reviewed_product(sha256, sequence):
    from native_install import product_cleanup
    products = {5: product_cleanup.R5_TARGET_SHA, 6: product_cleanup.R5_DIAGNOSTICS_TARGET_SHA,
                7: product_cleanup.R5_METRICS_TARGET_SHA, 8: product_cleanup.R5_PHOTOS_TARGET_SHA}
    require(sha256 == products[sequence], "unreviewed Product hash requires review")


def prepare(job_path, job_sha256, roots):
    roots = {name: local_path(path) for name, path in roots.items()}
    require(set(roots) == {"input", "tool", "work", "output"}, "four explicit roots required")
    project = local_path(ROOT)
    require(all(p.is_dir() and not p.is_relative_to(project) and not project.is_relative_to(p)
                for p in roots.values()), "roots must be existing external local directories")
    owner = task_root(roots["work"], project)
    require(task_root(roots["output"], project) == owner and roots["output"].is_relative_to(roots["work"]),
            "output root must be within the owned work root")
    job_path = local_path(job_path)
    require(not job_path.is_relative_to(project) and digest(job_path) == job_sha256, "external job pin mismatch")
    job = read_json(job_path)
    require(isinstance(job, dict) and job.get("stage") in {"assemble", "package"}, "unsupported offline job stage")
    require(set(job) == COMMON | (PACKAGE if job["stage"] == "package" else set())
            and type(job["schema"]) is int and job["schema"] == 1,
            "unexpected job fields")
    source_bound(job["source_commit"])
    pins = {job_path: job_sha256}
    files = {name: pin(job[name], roots, pins) for name in ("recipe", *sorted(PACKAGE)) if name in job}
    configs = {name: materialize(read_json(files[name]), roots, pins)
               for name in ("recipe", "plan", "tools", "review") if name in files}
    recipe = configs["recipe"]
    reviewed_recipe(recipe, job["profile"])
    output = reference(job["output"], roots)
    require(output != roots["output"] and output.is_relative_to(roots["output"])
            and not output.exists() and output.parent.is_dir(), "output must be a new child of output root")
    if job["stage"] == "package":
        plan, tools, review = (configs[name] for name in ("plan", "tools", "review"))
        require(tools.get("scratch") == "work:.", "tools scratch must use the work root")
        tools["scratch"] = str(roots["work"])
        require(review.get("plan_sha256") == job["plan"]["sha256"], "review does not bind the portable plan")
        handoff = read_json(files["handoff"])
        require(handoff.get("schema") == 1 and handoff.get("status") == "assembled_unbooted"
                and handoff.get("source_commit") == job["source_commit"] and handoff.get("profile") == job["profile"]
                and handoff.get("sequence") == recipe["sequence"] == plan.get("sequence")
                and handoff.get("recipe_sha256") == job["recipe"]["sha256"], "handoff source or recipe mismatch")
        require(handoff.get("images") == {name: plan["images"][name]["sha256"] for name in PARTITIONS}, "handoff image mismatch")
        reviewed_product(plan["images"]["product"]["sha256"], recipe["sequence"])
        require(all(files[name].name == name for name in ("apksigner", "aapt2")), "require the named APK verification tools")
        for name in ("key", "feed_key"):
            require(files[name].stat().st_mode & 0o077 == 0, "private signer permissions are too broad")
    return dict(job=job, roots=roots, pins=pins, files=files, configs=configs, output=output)


def private_json(path, value):
    with open(path, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def summary(prepared, status):
    job = prepared["job"]
    result = dict(status=status, stage=job["stage"], source_commit=job["source_commit"], profile=job["profile"],
                  sequence=prepared["configs"]["recipe"]["sequence"], runtime_verified=False, source_isolation_required=True)
    if status == "plan_ready":
        result.update(nested_manifests_validated=False,
                      execution_validation="existing_native_builder_validators")
    return result


def package_manifest(prepared, paths, scratch):
    """Bind the exact native builder output and authenticate its local OTA parts."""
    import build_native_rom as native
    from native_install.payload import openssl, public_key, verify_digest

    output = prepared["output"]
    require(output.is_dir() and output == output.resolve(), "package output is missing or unsafe")
    files = {path.name: path for path in output.iterdir()}
    metadata = {"stable.json", "stable.json.sig", "feed-verification-key.der", "native-public-key.pem", "validation.json"}
    require(metadata <= files.keys() and len(files) <= len(metadata) + 16
            and all(path.is_file() and not path.is_symlink() for path in files.values()), "unexpected package output inventory")
    require(all(0 < files[name].stat().st_size <= 4 * 1024**2 for name in metadata), "invalid package metadata size")
    feed = files["stable.json"].read_bytes()
    signature = files["stable.json.sig"].read_bytes()
    expected_key = prepared["files"]["feed_public_key"]
    require(files["feed-verification-key.der"].read_bytes() == expected_key.read_bytes(), "package feed key mismatch")
    require(files["native-public-key.pem"].read_bytes() == public_key(prepared["files"]["certificate"]), "package payload key mismatch")
    public = openssl("pkey", "-pubin", "-inform", "DER", "-in", expected_key, "-pubout")
    verify_digest(hashlib.sha256(feed).digest(), signature, public, scratch)
    descriptors = json.loads(feed)
    require(native.json_bytes(descriptors) == feed and isinstance(descriptors, list) and len(descriptors) == 1,
            "unexpected signed feed structure")
    descriptor, plan = descriptors[0], prepared["configs"]["plan"]
    require(descriptor["schema"] == 1 and descriptor["device"] == "erhai" and descriptor["channel"] == "stable"
            and descriptor["sequence"] == plan["sequence"] and descriptor["version"] == plan["version"]
            and descriptor["published_at"] == plan["timestamp"] and descriptor["expires_at"] == plan["expires_utc"]
            and descriptor["pre_build_fingerprints"] == plan["pre_build_fingerprints"]
            and descriptor["source_slot"] == "_" + plan["source_slot"]
            and descriptor["base_profile"] == "erhai-crdroid-20261025", "signed feed does not match the package plan")
    ota = descriptor["ota"]
    require(set(ota) == {"size", "sha256", "parts"} and type(ota["size"]) is int and 0 < ota["size"] <= 16 * 1024**3
            and isinstance(ota["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", ota["sha256"])
            and isinstance(ota["parts"], list) and 0 < len(ota["parts"]) <= 16, "invalid signed OTA description")
    count = (ota["size"] + native.RELEASE_PART_BYTES - 1) // native.RELEASE_PART_BYTES
    require(len(ota["parts"]) == count, "signed OTA part count mismatch")
    names = ["GoogleBook-erhai-native.zip" + (f".part{i + 1:03d}" if count > 1 else "") for i in range(count)]
    require(set(files) == metadata | set(names), "package has missing or extra release assets")
    prefix = f"https://github.com/{native.repo_name(plan['repository'])}/releases/download/{plan['release_tag']}/"
    manifest = {name: {"bytes": files[name].stat().st_size, "sha256": digest(files[name])} for name in sorted(metadata)}
    require(manifest["stable.json"]["sha256"] == hashlib.sha256(feed).hexdigest()
            and manifest["stable.json.sig"]["sha256"] == hashlib.sha256(signature).hexdigest(), "signed feed changed during verification")
    joined = hashlib.sha256()
    total = 0
    for name, part in zip(names, ota["parts"]):
        require(set(part) == {"url", "size", "sha256"} and part["url"] == prefix + name
                and type(part["size"]) is int and part["size"] == min(native.RELEASE_PART_BYTES, ota["size"] - total),
                "signed OTA part layout mismatch")
        require(files[name].stat().st_size == part["size"], "local OTA part size differs from signed feed")
        sha, size = hashlib.sha256(), 0
        with files[name].open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                sha.update(chunk)
                joined.update(chunk)
                size += len(chunk)
        require(size == part["size"] and sha.hexdigest() == part["sha256"], "local OTA part differs from signed feed")
        manifest[name] = {"bytes": size, "sha256": sha.hexdigest()}
        total += size
    require(total == ota["size"] and joined.hexdigest() == ota["sha256"], "joined OTA differs from signed feed")
    validation = read_json(files["validation.json"])
    require(validation.get("status") in {"OFFLINE_NATIVE_OTA_CANDIDATE_UNAPPLIED", "OFFLINE_NATIVE_CANDIDATE_UNBOOTED"}
            and validation.get("execution_approved") is False
            and validation.get("parent_plan_sha256") == digest(paths["plan"])
            and validation.get("parent_review_sha256") == digest(paths["review"])
            and validation.get("images_sha256") == {name: pin["sha256"] for name, pin in plan["images"].items()},
            "package validation does not bind the runtime plan")
    require(set(files) == {path.name for path in output.iterdir()}, "package output changed during verification")
    return manifest


def execute(prepared, *, trusted_runner=False):
    require(trusted_runner, "execution requires an explicitly trusted runner")
    job, roots = prepared["job"], prepared["roots"]
    source_bound(job["source_commit"])
    require(all(path == path.resolve() and path.is_file() and not path.is_symlink()
                and digest(path) == sha for path, sha in prepared["pins"].items()), "inputs changed after planning")
    task_root(roots["work"], ROOT)
    task_root(roots["output"], ROOT)
    require(not prepared["output"].exists(), "output appeared after planning")
    run = Path(tempfile.mkdtemp(prefix="native-job-", dir=roots["work"]))
    run.chmod(0o700)
    paths = {name: run / (name + ".json") for name in prepared["configs"]}
    try:
        for name, config in prepared["configs"].items():
            if name == "review":
                config = dict(config, plan_sha256=digest(paths["plan"]))
            private_json(paths[name], config)
        command = [sys.executable, "-B"]
        if job["stage"] == "assemble":
            command += [str(ROOT / "build_native_userspace.py"), "--recipe", str(paths["recipe"]),
                        "--output", str(prepared["output"]), "--scratch", str(roots["work"])]
        else:
            command += [str(ROOT / "build_native_rom.py"), "build"]
            for name in ("plan", "tools", "review", "key", "certificate", "feed_key", "feed_public_key", "apksigner", "aapt2"):
                flag = "feed-public-key" if name == "feed_public_key" else name.replace("_", "-")
                command += ["--" + flag, str(paths[name] if name in paths else prepared["files"][name])]
            command += ["--output", str(prepared["output"])]
        environment = dict(os.environ, TMPDIR=str(run), PYTHONDONTWRITEBYTECODE="1")
        for name in ("PYTHONPATH", "PYTHONHOME"):
            environment.pop(name, None)
        with open(run / "builder.log", "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as log:
            result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
        require(result.returncode == 0, "offline builder failed; inspect private task logs")
        source_bound(job["source_commit"])
        require(all(path == path.resolve() and not path.is_symlink() and digest(path) == sha
                    for path, sha in prepared["pins"].items()), "inputs changed during execution")
        result = summary(prepared, "assembled_unbooted" if job["stage"] == "assemble" else "packaged_unbooted")
        result.update(schema=1, recipe_sha256=job["recipe"]["sha256"])
        if job["stage"] == "assemble":
            report = read_json(prepared["output"] / "userspace-build.json")
            require(report.get("recipe_sha256") == digest(paths["recipe"])
                    and report.get("status") == "NATIVE_USERSPACE_ASSEMBLED_UNBOOTED", "builder report mismatch")
            result["images"] = {name: digest(prepared["output"] / (name + ".img")) for name in PARTITIONS}
            require(all(report["images"][name]["sha256"] == sha for name, sha in result["images"].items()), "built image receipt mismatch")
            reviewed_product(result["images"]["product"], result["sequence"])
        else:
            result["plan_sha256"] = job["plan"]["sha256"]
            result["files"] = package_manifest(prepared, paths, run)
            result["feed_signature_verified"] = True
        private_json(run / "handoff.json", result)
        return dict(summary(prepared, result["status"]), handoff="work:" + str(run.relative_to(roots["work"]) / "handoff.json"))
    finally:
        # Logs and handoff stay private; runtime configs expose local signer paths.
        for path in paths.values():
            path.unlink(missing_ok=True)


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError("invalid job arguments")
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=["plan", "execute"])
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--job-sha256", required=True)
    for name in ("input", "tool", "work", "output"):
        parser.add_argument("--" + name + "-root", type=Path, required=True)
    parser.add_argument("--trusted-runner", action="store_true")
    try:
        args = parser.parse_args(argv)
        require(args.command != "execute" or args.trusted_runner, "trusted runner required")
        roots = {name: getattr(args, name + "_root") for name in ("input", "tool", "work", "output")}
        prepared = prepare(args.job, args.job_sha256, roots)
        result = execute(prepared, trusted_runner=args.trusted_runner) if args.command == "execute" else summary(prepared, "plan_ready")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        print(json.dumps({"status": "blocked", "reason": "job validation or execution failed; inspect private task evidence"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
