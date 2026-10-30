import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
from unittest import mock

import maintenance_job as job
import maintenance_workspace as workspace
import build_native_rom as native
from native_install import payload
from native_install import product_cleanup, r5_userspace


class JobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="job-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "source"
        self.project.mkdir()
        for name in ("CLEANOS_MARKER", "LINUX_MARKER"):
            patch = mock.patch.object(workspace, name, ".fixture-" + name.lower())
            patch.start()
            self.addCleanup(patch.stop)
        for patch in (mock.patch.object(workspace.platform, "system", return_value="Linux"), mock.patch.object(job, "ROOT", self.project)):
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(job, "source_bound")
        self.bound = patch.start()
        self.addCleanup(patch.stop)
        self.roots = {name: self.base / name for name in ("input", "tool")}
        for path in self.roots.values():
            path.mkdir()
        self.roots["work"] = workspace.init_linux(self.base, self.project)
        self.roots["output"] = self.roots["work"] / "outputs"
        self.roots["output"].mkdir()
        self.image = self.put("base.img", b"reviewed source")
        patch = mock.patch.dict(r5_userspace.IMAGE_SHAS, {name: self.image["sha256"] for name in job.PARTITIONS})
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(r5_userspace, "GRAFT_SHA", self.image["sha256"])
        patch.start()
        self.addCleanup(patch.stop)
        self.recipe = dict(schema=2, lineage=r5_userspace.LINEAGE, sequence=5,
                           images={name: dict(self.image) for name in job.PARTITIONS}, files={"tablet_graft_source": dict(self.image)})
        self.config = dict(schema=1, source_commit="a" * 40, profile=r5_userspace.LINEAGE, stage="assemble",
                           recipe=self.put_json("recipe.json", self.recipe), output="output:userspace")

    def put(self, name, data, root="input"):
        path = self.roots[root] / name
        path.write_bytes(data)
        path.chmod(0o600)
        return dict(path=root + ":" + name, sha256=job.digest(path))

    def put_json(self, name, value):
        return self.put(name, json.dumps(value, sort_keys=True).encode())

    def prepare(self):
        pin = self.put_json("job.json", self.config)
        return job.prepare(self.roots["input"] / "job.json", pin["sha256"], self.roots)

    def package(self):
        self.target = self.put("target.img", b"assembled image")
        patch = mock.patch.object(product_cleanup, "R5_TARGET_SHA", self.target["sha256"])
        patch.start()
        self.addCleanup(patch.stop)
        self.plan = dict(sequence=5, images={name: dict(self.target) for name in job.PARTITIONS},
                         repository=native.PUBLIC_REPO, release_tag="fixture", version="fixture", timestamp=1,
                         expires_utc=2, pre_build_fingerprints=["fixture"], source_slot="b")
        plan = self.put_json("plan.json", self.plan)
        handoff = dict(schema=1, status="assembled_unbooted", source_commit=self.config["source_commit"],
                       profile=self.config["profile"], sequence=5, recipe_sha256=self.config["recipe"]["sha256"],
                       images={name: self.target["sha256"] for name in job.PARTITIONS})
        self.config.update(stage="package", output="output:package", plan=plan,
                           tools=self.put_json("tools.json", dict(scratch="work:.")),
                           review=self.put_json("review.json", dict(plan_sha256=plan["sha256"])),
                           handoff=self.put_json("handoff.json", handoff))
        for name in ("key", "certificate", "feed_key", "feed_public_key"):
            self.config[name] = self.put(name, b"external private fixture")
        for name in ("apksigner", "aapt2"):
            self.config[name] = self.put(name, b"verified tool fixture", root="tool")

    def write_package(self, prepared, paths, public=b"public fixture"):
        output = prepared["output"]
        output.mkdir()
        archive = b"candidate archive"
        chunks = [archive[i:i + native.RELEASE_PART_BYTES] for i in range(0, len(archive), native.RELEASE_PART_BYTES)]
        plan = prepared["configs"]["plan"]
        prefix = f"https://github.com/{plan['repository']}/releases/download/{plan['release_tag']}/"
        parts = []
        for i, chunk in enumerate(chunks):
            name = "GoogleBook-erhai-native.zip" + (f".part{i + 1:03d}" if len(chunks) > 1 else "")
            (output / name).write_bytes(chunk)
            parts.append(dict(url=prefix + name, size=len(chunk), sha256=hashlib.sha256(chunk).hexdigest()))
        feed = dict(schema=1, device="erhai", channel="stable", sequence=plan["sequence"], version=plan["version"],
                    published_at=plan["timestamp"], expires_at=plan["expires_utc"], base_profile="erhai-crdroid-20261025",
                    pre_build_fingerprints=plan["pre_build_fingerprints"], source_slot="_" + plan["source_slot"],
                    ota=dict(size=len(archive), sha256=hashlib.sha256(archive).hexdigest(), parts=parts), payload={})
        (output / "stable.json").write_bytes(native.json_bytes([feed]))
        (output / "stable.json.sig").write_bytes(b"fixture signature")
        (output / "feed-verification-key.der").write_bytes(prepared["files"]["feed_public_key"].read_bytes())
        (output / "native-public-key.pem").write_bytes(public)
        (output / "validation.json").write_bytes(native.json_bytes(dict(
            status="OFFLINE_NATIVE_OTA_CANDIDATE_UNAPPLIED", execution_approved=False,
            parent_plan_sha256=job.digest(paths["plan"]), parent_review_sha256=job.digest(paths["review"]),
            images_sha256={name: pin["sha256"] for name, pin in plan["images"].items()})))

    def package_fixture(self):
        self.package()
        prepared = self.prepare()
        runtime = self.roots["work"] / "package-verification"
        runtime.mkdir()
        paths = {name: runtime / (name + ".json") for name in ("plan", "review")}
        for name, path in paths.items():
            job.private_json(path, prepared["configs"][name])
        self.write_package(prepared, paths)
        return prepared, paths, runtime

    def verify_package(self, prepared, paths, runtime):
        with mock.patch.object(payload, "openssl", return_value=b"public fixture"), mock.patch.object(payload, "verify_digest"):
            return job.package_manifest(prepared, paths, runtime)

    def test_plan_is_read_only_and_resolves_pins_to_physical_roots(self):
        before = set(self.roots["work"].rglob("*"))
        prepared = self.prepare()
        self.assertEqual(set(self.roots["work"].rglob("*")), before)
        self.assertEqual(prepared["configs"]["recipe"]["images"]["system"]["path"], str(self.roots["input"] / "base.img"))
        self.assertEqual(job.summary(prepared, "plan_ready")["status"], "plan_ready")
        self.assertFalse(job.summary(prepared, "plan_ready")["nested_manifests_validated"])
        self.assertEqual(job.summary(prepared, "plan_ready")["execution_validation"], "existing_native_builder_validators")
        self.assertTrue(job.summary(prepared, "plan_ready")["source_isolation_required"])
        self.bound.assert_called_with("a" * 40)

    def test_unknown_stage_or_extra_argv_field_is_rejected(self):
        for changes in (dict(stage="publish"), dict(argv=["adb", "shell"]), dict(schema=2)):
            original = dict(self.config)
            self.config.update(changes)
            with self.assertRaises(ValueError):
                self.prepare()
            self.config = original

    def test_new_profile_sequence_and_donor_are_rejected(self):
        for change in (dict(sequence=9), dict(schema=1), dict(lineage="unreviewed")):
            recipe = dict(self.recipe, **change)
            self.config["recipe"] = self.put_json("recipe.json", recipe)
            with self.assertRaises(ValueError):
                self.prepare()
        recipe = dict(self.recipe, images={name: self.put("other.img", b"new donor") for name in job.PARTITIONS})
        self.config["recipe"] = self.put_json("recipe.json", recipe)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_reference_escape_symlink_and_absolute_paths_are_rejected(self):
        alias = self.roots["input"] / "alias.img"
        alias.symlink_to(self.roots["input"] / "base.img")
        for reference in ("input:../base.img", "input:/base.img", "input:alias.img", "input:a//b", "unknown:base.img"):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                job.reference(reference, self.roots)

    def test_pins_and_trusted_runner_are_rechecked_before_execution(self):
        prepared = self.prepare()
        with mock.patch.object(job.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                job.execute(prepared)
            (self.roots["input"] / "base.img").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                job.execute(prepared, trusted_runner=True)
            run.assert_not_called()

    def test_assemble_uses_only_builtin_builder_and_emits_private_handoff(self):
        prepared = self.prepare()
        def builder(command, **kwargs):
            self.assertEqual(command[1:3], ["-B", str(self.project / "build_native_userspace.py")])
            self.assertNotIn("adb", command)
            self.assertEqual(kwargs["cwd"], self.project)
            output = prepared["output"]
            output.mkdir()
            for name in job.PARTITIONS:
                (output / (name + ".img")).write_bytes(b"candidate")
            recipe = Path(command[command.index("--recipe") + 1])
            report = dict(status="NATIVE_USERSPACE_ASSEMBLED_UNBOOTED", recipe_sha256=job.digest(recipe),
                          images={name: dict(sha256=job.digest(output / (name + ".img"))) for name in job.PARTITIONS})
            (output / "userspace-build.json").write_text(json.dumps(report))
            kwargs["stdout"].write("private builder evidence\n")
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(job.subprocess, "run", side_effect=builder), mock.patch.object(
                product_cleanup, "R5_TARGET_SHA", hashlib.sha256(b"candidate").hexdigest()):
            result = job.execute(prepared, trusted_runner=True)
        handoff = job.reference(result["handoff"], self.roots)
        self.assertEqual(job.read_json(handoff)["recipe_sha256"], self.config["recipe"]["sha256"])
        self.assertEqual(handoff.stat().st_mode & 0o777, 0o600)
        self.assertEqual((handoff.parent / "builder.log").stat().st_mode & 0o777, 0o600)
        self.assertEqual({p.name for p in handoff.parent.iterdir()}, {"handoff.json", "builder.log"})
        self.assertNotIn(str(self.base), json.dumps(result))

    def test_builder_failure_keeps_private_log_and_removes_runtime_configs(self):
        prepared = self.prepare()
        with mock.patch.object(job.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaises(ValueError):
                job.execute(prepared, trusted_runner=True)
        runs = list(self.roots["work"].glob("native-job-*"))
        self.assertEqual(len(runs), 1)
        self.assertEqual({p.name for p in runs[0].iterdir()}, {"builder.log"})

    def test_assembly_cannot_issue_handoff_for_an_unknown_product(self):
        prepared = self.prepare()
        def builder(command, **kwargs):
            output = prepared["output"]
            output.mkdir()
            for name in job.PARTITIONS:
                (output / (name + ".img")).write_bytes(b"unknown Product")
            recipe = Path(command[command.index("--recipe") + 1])
            (output / "userspace-build.json").write_text(json.dumps(dict(
                status="NATIVE_USERSPACE_ASSEMBLED_UNBOOTED", recipe_sha256=job.digest(recipe),
                images={name: dict(sha256=job.digest(output / (name + ".img"))) for name in job.PARTITIONS})))
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(job.subprocess, "run", side_effect=builder), self.assertRaisesRegex(ValueError, "Product"):
            job.execute(prepared, trusted_runner=True)
        self.assertFalse(list(self.roots["work"].glob("native-job-*/handoff.json")))

    def test_package_requires_exact_review_and_handoff_and_closed_product(self):
        self.package()
        self.prepare()
        original = dict(self.config)
        for field, value in (("review", dict(plan_sha256="0" * 64)),
                             ("handoff", dict(schema=1, status="assembled_unbooted", source_commit="b" * 40))):
            self.config[field] = self.put_json(field + "-bad.json", value)
            with self.assertRaises(ValueError):
                self.prepare()
            self.config = dict(original)
        with mock.patch.object(product_cleanup, "R5_TARGET_SHA", "0" * 64):
            with self.assertRaisesRegex(ValueError, "Product"):
                self.prepare()

    def test_package_rebinds_only_runtime_review_and_uses_fixed_flags(self):
        self.package()
        prepared = self.prepare()
        portable_review = (self.roots["input"] / "review.json").read_bytes()
        def builder(command, **kwargs):
            self.assertEqual(command[1:4], ["-B", str(self.project / "build_native_rom.py"), "build"])
            plan = Path(command[command.index("--plan") + 1])
            review = Path(command[command.index("--review") + 1])
            self.assertEqual(job.read_json(review)["plan_sha256"], job.digest(plan))
            self.assertIn("--feed-public-key", command)
            self.assertIn("--feed-key", command)
            self.assertNotIn("--recipe", command)
            self.write_package(prepared, {"plan": plan, "review": review})
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(job.subprocess, "run", side_effect=builder), mock.patch.object(
                payload, "openssl", return_value=b"public fixture"), mock.patch.object(payload, "verify_digest") as verify:
            result = job.execute(prepared, trusted_runner=True)
            self.assertEqual(result["status"], "packaged_unbooted")
            verify.assert_called_once()
        handoff = job.read_json(job.reference(result["handoff"], self.roots))
        self.assertTrue(handoff["feed_signature_verified"])
        self.assertEqual(handoff["files"], {path.name: dict(bytes=path.stat().st_size, sha256=job.digest(path))
                                             for path in prepared["output"].iterdir()})
        self.assertEqual((self.roots["input"] / "review.json").read_bytes(), portable_review)

    def test_package_manifest_binds_every_unsplit_output(self):
        prepared, paths, runtime = self.package_fixture()
        result = self.verify_package(prepared, paths, runtime)
        self.assertEqual(len(result), 6)
        self.assertEqual(result, {path.name: dict(bytes=path.stat().st_size, sha256=job.digest(path))
                                  for path in prepared["output"].iterdir()})

    def test_split_parts_and_joined_hash_are_both_verified(self):
        with mock.patch.object(native, "RELEASE_PART_BYTES", 4):
            prepared, paths, runtime = self.package_fixture()
            result = self.verify_package(prepared, paths, runtime)
            self.assertEqual(len(result), 10)
            self.assertNotIn("GoogleBook-erhai-native.zip", result)
            feed_path = prepared["output"] / "stable.json"
            feed = job.read_json(feed_path)
            feed[0]["ota"]["sha256"] = "0" * 64
            feed_path.write_bytes(native.json_bytes(feed))
            with self.assertRaisesRegex(ValueError, "joined OTA"):
                self.verify_package(prepared, paths, runtime)

    def test_missing_extra_directory_and_symlink_assets_are_rejected(self):
        prepared, paths, runtime = self.package_fixture()
        output = prepared["output"]
        original = (output / "stable.json.sig").read_bytes()
        (output / "stable.json.sig").unlink()
        with self.assertRaises(ValueError):
            self.verify_package(prepared, paths, runtime)
        (output / "stable.json.sig").write_bytes(original)
        for name in ("extra.zip", "GoogleBook-erhai-native.zip.part001"):
            extra = output / name
            extra.write_bytes(b"unexpected")
            with self.assertRaises(ValueError):
                self.verify_package(prepared, paths, runtime)
            extra.unlink()
        directory = output / "logs"
        directory.mkdir()
        with self.assertRaises(ValueError):
            self.verify_package(prepared, paths, runtime)
        directory.rmdir()
        (output / "stable.json.sig").unlink()
        (output / "stable.json.sig").symlink_to(prepared["files"]["feed_public_key"])
        with self.assertRaises(ValueError):
            self.verify_package(prepared, paths, runtime)

    def test_local_part_bytes_and_signed_layout_must_match(self):
        prepared, paths, runtime = self.package_fixture()
        output = prepared["output"]
        archive = output / "GoogleBook-erhai-native.zip"
        original = archive.read_bytes()
        for data in (b"x" * len(original), original[:-1]):
            archive.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "local OTA"):
                self.verify_package(prepared, paths, runtime)
        archive.write_bytes(original)
        feed_path = output / "stable.json"
        original_feed = feed_path.read_bytes()
        for field, value in (("url", "https://example.invalid/not-a-release"), ("size", len(original) + 1), ("sha256", "0" * 64)):
            feed = json.loads(original_feed)
            feed[0]["ota"]["parts"][0][field] = value
            feed_path.write_bytes(native.json_bytes(feed))
            with self.assertRaises(ValueError):
                self.verify_package(prepared, paths, runtime)

    def test_package_keys_and_validation_bind_the_pinned_inputs(self):
        prepared, paths, runtime = self.package_fixture()
        output = prepared["output"]
        for name in ("feed-verification-key.der", "native-public-key.pem"):
            path = output / name
            original = path.read_bytes()
            path.write_bytes(b"substituted key")
            with self.assertRaisesRegex(ValueError, "key mismatch"):
                self.verify_package(prepared, paths, runtime)
            path.write_bytes(original)
        validation = job.read_json(output / "validation.json")
        validation["parent_plan_sha256"] = "0" * 64
        (output / "validation.json").write_bytes(native.json_bytes(validation))
        with self.assertRaisesRegex(ValueError, "runtime plan"):
            self.verify_package(prepared, paths, runtime)

    def test_failed_package_verification_never_issues_handoff(self):
        self.package()
        prepared = self.prepare()
        with mock.patch.object(job.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaises(ValueError):
                job.execute(prepared, trusted_runner=True)
        self.assertFalse(list(self.roots["work"].glob("native-job-*/handoff.json")))

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for feed signature test")
    def test_real_feed_signature_rejects_tampering(self):
        prepared, paths, runtime = self.package_fixture()
        key, cert = runtime / "ephemeral.key", runtime / "ephemeral.pem"
        payload.openssl("genrsa", "-out", key, "2048")
        payload.openssl("req", "-new", "-x509", "-key", key, "-days", "1", "-subj", "/CN=Offline fixture", "-out", cert)
        public = payload.openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
        prepared["files"]["feed_public_key"].write_bytes(public)
        prepared["files"]["certificate"] = cert
        output = prepared["output"]
        (output / "feed-verification-key.der").write_bytes(public)
        (output / "native-public-key.pem").write_bytes(payload.public_key(cert))
        feed = (output / "stable.json").read_bytes()
        (output / "stable.json.sig").write_bytes(payload.sign_digest(hashlib.sha256(feed).digest(), key))
        self.assertEqual(len(job.package_manifest(prepared, paths, runtime)), 6)
        (output / "stable.json").write_bytes(feed.replace(b'"fixture"', b'"changed"'))
        with self.assertRaises(ValueError):
            job.package_manifest(prepared, paths, runtime)
        self.assertFalse((runtime / "verification.signature").exists())
        self.assertFalse((runtime / "verification.public.pem").exists())

    def test_group_readable_signer_and_different_task_outputs_are_rejected(self):
        self.package()
        (self.roots["input"] / "key").chmod(0o644)
        with self.assertRaises(ValueError):
            self.prepare()
        other = workspace.init_linux(self.base, self.project)
        self.roots["output"] = other
        with self.assertRaises(ValueError):
            self.prepare()

    def test_raw_errors_arguments_and_configs_are_never_printed(self):
        secret = "PRIVATE-FIXTURE-DO-NOT-PRINT"
        output = io.StringIO()
        with contextlib.redirect_stdout(output), mock.patch.object(job, "prepare", side_effect=OSError(secret)):
            self.assertEqual(job.main(["plan", "--job", secret, "--job-sha256", "x",
                                      *[v for name, path in self.roots.items() for v in ("--" + name + "-root", str(path))]]), 1)
            self.assertEqual(job.main(["plan", "--unknown-" + secret]), 1)
        self.assertNotIn(secret, output.getvalue())

    def test_duplicate_json_fields_and_source_commit_drift_are_rejected(self):
        path = self.roots["input"] / "duplicate.json"
        path.write_text('{"schema":1,"schema":2}')
        with self.assertRaises(ValueError):
            job.read_json(path)
        self.bound.side_effect = ValueError("source changed")
        with self.assertRaises(ValueError):
            self.prepare()


class SourceBindingTests(unittest.TestCase):
    def test_source_binding_requires_exact_commit_and_clean_tree(self):
        commit = "a" * 40
        for head, state in (("b" * 40, ""), (commit, " M changed.py"), (commit, "?? injected.py")):
            with mock.patch.object(job.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0, head, ""), subprocess.CompletedProcess([], 0, state, "")]):
                with self.assertRaises(ValueError):
                    job.source_bound(commit)
        with mock.patch.object(job.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0, commit, ""), subprocess.CompletedProcess([], 0, "", "")]):
            job.source_bound(commit)
        with self.assertRaises(ValueError):
            job.source_bound("main")


if __name__ == "__main__":
    unittest.main()
