import argparse
import importlib.util
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("config_build", Path(__file__).resolve().parents[1] / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class BuildBoundaryTest(unittest.TestCase):
    def test_unknown_base_is_rejected_before_outputs_or_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "wrong.apk"
            base.write_bytes(b"unsupported input")
            args = argparse.Namespace(gms_base=base, scratch=root / "output", java_home=root / "absent",
                                      android_jar=root / "absent", d8=root / "absent")
            with patch.object(build, "task_root") as owner:
                with self.assertRaisesRegex(ValueError, "unsupported GMS base SHA-256"):
                    build.build(args)
                owner.assert_not_called()
            self.assertFalse(args.scratch.exists())

    def test_unsafe_output_paths_are_rejected(self):
        for path in (Path("relative"), Path("/tmp/CloudStorage/config-output")):
            with self.assertRaises(ValueError):
                build.local_path(path)

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, output = root / "input.apk", root / "output"
            base.write_bytes(b"test fixture")
            output.mkdir()
            sentinel = output / "unique-source"
            sentinel.write_text("preserve")
            args = argparse.Namespace(gms_base=base, scratch=output, java_home=root / "absent",
                                      android_jar=root / "absent", d8=root / "absent")
            with patch.object(build, "digest", return_value=build.GMS_SHA):
                with self.assertRaisesRegex(ValueError, "must not exist"):
                    build.build(args)
            self.assertEqual(sentinel.read_text(), "preserve")


class EnsureRegressionTest(unittest.TestCase):
    source = (build.COMPONENT / "NativeConfigRepair.java").read_text()

    def test_actual_scope_query_rejects_conflicting_rows_and_preserves_other_scope(self):
        # Run the helper's actual aggregate SQL with SQLite storage types, not a second implementation.
        match = re.search(r'db.rawQuery\("(SELECT count\(\*\),coalesce[^"\n]+)"\+flagPlaceholders\(\)\+"\)"', self.source)
        self.assertIsNotNone(match)
        for flags in (("45788784", "45726908", "45794909", "45805241"), ("45742359", "45784133")):
            n = len(flags)
            query = match[1] + ",".join("?" for _ in flags) + ")"
            with sqlite3.connect(":memory:") as db:
                db.execute("CREATE TABLE flag_overrides(config_package_id,account_id,active,name,type,value,source)")
                unrelated = [("other", 0, 1, flags[0], 2, 0, 0),
                             ("profile", 7, 1, flags[0], 2, 0, 0),
                             ("profile", 0, 1, "*", 2, 1, 0),
                             ("profile", 0, 1, "unrelated", 2, 0, 1),
                             ("profile", 0, 0, flags[0], 2, 0, 0)]
                db.executemany("INSERT INTO flag_overrides VALUES(?,?,?,?,?,?,?)", unrelated)
                args = ("profile", *flags)
                self.assertEqual(db.execute(query, args).fetchone(), (0, 0, 0))
                rows = [("profile", 0, 1, flag, 2, 1, 0) for flag in flags]
                db.executemany("INSERT INTO flag_overrides VALUES(?,?,?,?,?,?,?)", rows)
                before = list(db.execute("SELECT * FROM flag_overrides"))
                for _ in range(3):
                    self.assertEqual(db.execute(query, args).fetchone(), (n, n, n))
                self.assertEqual(list(db.execute("SELECT * FROM flag_overrides")), before)
                for column, value, original in (("value", "1", 1), ("value", "true", 1), ("value", 0, 1),
                                                ("value", 1.0, 1), ("value", None, 1), ("source", 1, 0), ("type", 1, 2)):
                    with self.subTest(flags=n, column=column, value=value):
                        db.execute(f"UPDATE flag_overrides SET {column}=? WHERE config_package_id='profile' AND account_id=0 AND active=1 AND name=?", (value, flags[0]))
                        self.assertEqual(db.execute(query, args).fetchone(), (n, n-1, n))
                        db.execute(f"UPDATE flag_overrides SET {column}=? WHERE config_package_id='profile' AND account_id=0 AND active=1 AND name=?", (original, flags[0]))
                db.execute("INSERT INTO flag_overrides VALUES(?,?,?,?,?,?,?)", rows[0])
                self.assertEqual(db.execute(query, args).fetchone(), (n+1, n+1, n))
                db.execute("DELETE FROM flag_overrides WHERE config_package_id='profile' AND account_id=0 AND active=1 AND name=?", (flags[0],))
                self.assertEqual(db.execute(query, args).fetchone(), (n-1, n-1, n-1))
                for row in unrelated:
                    self.assertIn(row, list(db.execute("SELECT * FROM flag_overrides")))

    def test_commit_marker_follows_successful_transaction_close(self):
        run = self.source[self.source.index("    void run("):]
        commit = run.index('qo.getMethod("e").invoke(tx)')
        close = run.index('finally{qo.getMethod("close").invoke(tx);}')
        marker = run.index('System.out.println("NATIVE_PROFILE_STAGE_COMMITTED')
        self.assertLess(commit, close)
        self.assertLess(close, marker)
        self.assertLess(marker, run.index('Object read='))

    def test_ensure_rechecks_scoped_rows_and_effective_state_before_writer(self):
        read = self.source[self.source.index('Object read='):]
        self.assertLess(read.index('stagingRequired(db,id,mode)'), read.index('effective(loader,qo,read,expected)'))
        self.assertLess(read.index('effective(loader,qo,read,expected)'), read.index('Object writer='))

    def test_app_process_main_keeps_explicit_exit_status(self):
        main = self.source[self.source.index('    public static void main('):self.source.index('    String registeredConfig(')]
        self.assertIn('repair.run(identity[0],identity[1],args[3]);System.exit(0);', main)
        self.assertIn('System.err.println("NATIVE_CONFIG_REPAIR_ERROR "+e.getClass().getName());System.exit(1);', main)


if __name__ == "__main__":
    unittest.main()
