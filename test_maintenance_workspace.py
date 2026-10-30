import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import maintenance_workspace as workspace


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="workspace-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "source"
        self.project.mkdir()
        # Separate fixture markers from the real host task owning test outputs.
        for name, value in (("CLEANOS_MARKER", ".fixture-cleanos.json"), ("LINUX_MARKER", ".fixture-linux.json")):
            patch = mock.patch.object(workspace, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(workspace.platform, "system", return_value="Linux")
        self.host = patch.start()
        self.addCleanup(patch.stop)
        self.root = workspace.init_linux(self.base, self.project)

    def change_marker(self, **changes):
        marker = self.root / workspace.LINUX_MARKER
        value = json.loads(marker.read_text())
        value.update(changes)
        marker.write_text(json.dumps(value))

    def test_linux_init_is_private_and_validates_child_without_creating_it(self):
        child = self.root / "new-output"
        self.assertEqual(workspace.task_root(child, self.project), self.root)
        self.assertFalse(child.exists())
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / workspace.LINUX_MARKER).stat().st_mode), 0o600)
        with self.assertRaises(ValueError):
            workspace.task_root(child, self.project, root_only=True)

    def test_foreign_project_finished_or_uid_is_rejected(self):
        marker = self.root / workspace.LINUX_MARKER
        original = marker.read_text()
        for changes in ({"owner": os.getuid() + 1}, {"finished": True}, {"finished": 0}, {"project": str(self.base)}, {"id": "other"}):
            with self.subTest(changes=changes):
                marker.write_text(original)
                self.change_marker(**changes)
                with self.assertRaises(ValueError):
                    workspace.task_root(self.root, self.project)

    def test_missing_nested_and_symlink_markers_are_rejected(self):
        child = self.root / "nested"
        child.mkdir()
        marker = child / workspace.LINUX_MARKER
        marker.write_text("{}")
        with self.assertRaises(ValueError):
            workspace.task_root(child, self.project)
        marker.unlink()
        original = self.root / workspace.LINUX_MARKER
        saved = self.root / "saved.json"
        original.rename(saved)
        with self.assertRaises(ValueError):
            workspace.task_root(self.root, self.project)
        original.symlink_to(saved)
        with self.assertRaises(ValueError):
            workspace.task_root(self.root, self.project)

    def test_symlink_and_cloud_paths_are_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for path in (alias, self.base / "Documents" / "out", self.base / "OneDrive - example" / "out"):
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                workspace.task_root(path, self.project)

    def test_unowned_and_source_scratch_cannot_be_initialized(self):
        for parent in (self.project, self.root):
            with self.assertRaises(ValueError):
                workspace.init_linux(parent, self.project)

    def test_public_linux_marker_permissions_are_rejected(self):
        (self.root / workspace.LINUX_MARKER).chmod(0o644)
        with self.assertRaises(ValueError):
            workspace.task_root(self.root, self.project)

    def test_mac_requires_cleanos_and_still_checks_backup_exclusion(self):
        self.host.return_value = "Darwin"
        with self.assertRaises(ValueError):
            workspace.task_root(self.root, self.project)
        with self.assertRaises(ValueError):
            workspace.init_linux(self.base, self.project)
        (self.root / workspace.LINUX_MARKER).rename(self.root / workspace.CLEANOS_MARKER)
        with mock.patch.object(workspace, "CLEANOS_ROOT", self.base), mock.patch.object(workspace.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "[Excluded]", "")
            self.assertEqual(workspace.task_root(self.root, self.project, root_only=True, backup_excluded=True), self.root)
            self.assertEqual(run.call_args.args[0][:2], ["tmutil", "isexcluded"])
            run.return_value.stdout = "[Included]"
            with self.assertRaises(ValueError):
                workspace.task_root(self.root, self.project, backup_excluded=True)

    def test_delegating_builders_accept_linux_owner_and_preserve_output_checks(self):
        import build_native_rom as native
        import patch_taskmanager as patcher
        output = self.root / "candidate.img"
        with mock.patch.object(native, "ROOT", self.project), mock.patch.object(patcher, "ROOT", self.project):
            self.assertEqual(native.scratch_output(output), output)
            self.assertEqual(patcher.verify_scratch(self.root), self.root)
            output.write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                native.scratch_output(output)
            self.assertEqual(output.read_bytes(), b"preserve")
            with self.assertRaises(ValueError):
                patcher.verify_scratch(self.base)

    def test_erofs_delegates_ownership_before_any_rewrite(self):
        import erofs_sanitize as erofs
        image = self.base / "source.img"
        image.write_bytes(b"fixture")
        with mock.patch.object(erofs, "__file__", str(self.project / "erofs_sanitize.py")), mock.patch.object(
                erofs, "task_root", wraps=workspace.task_root) as guard:
            with self.assertRaisesRegex(ValueError, "removals"):
                erofs.rewrite(image, self.root / "output.img", [], self.root)
            guard.assert_called_once_with(self.root, self.project)
        self.assertFalse((self.root / "output.img").exists())


if __name__ == "__main__":
    unittest.main()
