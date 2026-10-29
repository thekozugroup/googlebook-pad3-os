import hashlib
import json
import os
import re
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from pen_policy import (FILENAMES, HASH_FILENAME, MEMBERSHIPS, PACKAGE, SELECTOR, certificate_hex,
                        native_pen_module, prepare_pen_policy, signer_contexts)

ROOT = Path(__file__).resolve().parent
CERT_PATH = ROOT / "profiles/pad3-components/certificate.der"
CERT_SHA256 = "3625a00c6244e94e3150604c4903800c3928e958e77a5b2d2814be1864f82eb4"
MAC = b'<?xml version="1.0" encoding="iso-8859-1"?><!-- preserve -->\n<policy>\n</policy>\n'
SEAPP = b'# keep this comment\nuser=_app isPrivApp=true domain=priv_app type=app_data_file'


class CertificateValidation(unittest.TestCase):
    def test_malformed_certificate_rejected(self):
        for value in [None, 1, b"", b"\x30\x00", "", "abc", "zz", "aa bb", b"not a certificate", b"x" * 16385]:
            with self.subTest(value=repr(value)[:40]), self.assertRaises(ValueError):
                certificate_hex(value)

    def test_policy_source_drift_rejected(self):
        with self.assertRaisesRegex(ValueError, "native system_ext policy changed"):
            native_pen_module(b"(type pen_app)\n")

    def test_fresh_owned_scratch_required(self):
        with self.assertRaisesRegex(ValueError, "fresh local task"):
            prepare_pen_policy({}, b"", b"", "unused", ROOT / "reports")


@unittest.skipUnless(CERT_PATH.is_file() and shutil.which("openssl"), "public component certificate/OpenSSL unavailable")
class SignerContexts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert = CERT_PATH.read_bytes()
        if hashlib.sha256(cls.cert).hexdigest() != CERT_SHA256:
            raise AssertionError("public component test certificate changed")

    def test_der_and_hex_have_identical_mapping(self):
        signature = certificate_hex(self.cert)
        self.assertEqual(bytes.fromhex(signature), self.cert)
        self.assertEqual(certificate_hex(signature.upper()), signature)
        self.assertEqual(signer_contexts(MAC, SEAPP, self.cert), signer_contexts(MAC, SEAPP, signature.upper()))

    def test_trailing_data_truncation_and_pem_rejected(self):
        for cert in [self.cert + b"\x00", self.cert[:-1], self.cert + self.cert, b"-----BEGIN CERTIFICATE-----\n"]:
            with self.subTest(length=len(cert)), self.assertRaises(ValueError):
                certificate_hex(cert)

    def test_exact_package_selector_and_preserved_donor_bytes(self):
        mac, seapp = signer_contexts(MAC, SEAPP, self.cert)
        root = ET.fromstring(mac)
        self.assertEqual(len(root), 1)
        signer = root[0]
        self.assertEqual(signer.attrib, {"signature": self.cert.hex()})
        self.assertEqual(signer[0].attrib, {"name": PACKAGE})
        self.assertEqual(signer[0][0].attrib, {"value": "pad3_pen"})
        self.assertEqual(len(signer), 1)
        self.assertEqual(len(signer[0]), 1)
        self.assertFalse(signer.findall("seinfo"))
        self.assertTrue(seapp.startswith(SEAPP))
        self.assertEqual(seapp[len(SEAPP):], b"\n" + SELECTOR)
        before, after = MAC.split(b"</policy>")
        self.assertTrue(mac.startswith(before))
        self.assertTrue(mac.endswith(b"</policy>" + after))
        self.assertNotIn(b"seinfo=platform", seapp)
        self.assertNotIn(b"user=system", seapp)

    def test_existing_other_signer_and_package_preserved(self):
        existing = b'<signer signature="abcd"><package name="other.app"><seinfo value="other"/></package></signer>'
        original = MAC.replace(b"</policy>", existing + b"</policy>")
        mac, _ = signer_contexts(original, SEAPP, self.cert)
        self.assertIn(existing, mac)
        self.assertEqual(len(ET.fromstring(mac)), 2)

    def test_duplicate_or_conflicting_mac_entries_rejected_across_partitions(self):
        entries = [f'<signer signature="{self.cert.hex().upper()}"><seinfo value="platform"/></signer>',
                   f'<signer signature="{self.cert.hex()}"><package name="other.app"><seinfo value="other"/></package></signer>',
                   '<signer signature="abcd"><package name="org.lineageos.pen"><seinfo value="other"/></package></signer>',
                   '<signer signature="abcd"><package name="other.app"><seinfo value="pad3_pen"/></package></signer>']
        for entry in entries:
            conflict = ("<policy>" + entry + "</policy>").encode()
            for extra in [False, True]:
                with self.subTest(entry=entry[:60], other_partition=extra), self.assertRaisesRegex(ValueError, "duplicate or conflicting"):
                    signer_contexts(MAC if extra else conflict, SEAPP, self.cert,
                                    other_mac_permissions=(conflict,) if extra else ())

    def test_duplicate_selector_rejected_across_partitions(self):
        conflicts = [SELECTOR, b'name=org.lineageos.pen seinfo=platform domain=other\n',
                     b'name=org.lineageos.* domain=other\n', b'seinfo=pad3_pen domain=other\n', b'domain=pen_app\n']
        for conflict in conflicts:
            with self.subTest(conflict=conflict), self.assertRaisesRegex(ValueError, "pen seapp selector"):
                signer_contexts(MAC, SEAPP, self.cert, other_seapp_contexts=(conflict,))

    def test_second_application_is_rejected(self):
        mac, seapp = signer_contexts(MAC, SEAPP, self.cert)
        with self.assertRaisesRegex(ValueError, "duplicate or conflicting"):
            signer_contexts(mac, seapp, self.cert)

    def test_malformed_xml_or_ambiguous_closing_tag_rejected(self):
        for data in [b"<policy>", b"<other/>", b"<policy/>", b"<!DOCTYPE policy><policy></policy>",
                     b"<policy><!-- </policy> --></policy>"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                signer_contexts(data, SEAPP, self.cert)


class NativePenModule(unittest.TestCase):
    def test_narrow_native_extraction_and_private_attribute_remap(self):
        native = ("\n".join("(typeattributeset " + name + " (unrelated pen_app))" for name in MEMBERSHIPS) + "\n"
                  "(type pen_app)\n(roletype object_r pen_app)\n(type pen_app_userfaultfd)\n"
                  "(allow pen_app self (netlink_kobject_uevent_socket (read create bind setopt)))\n"
                  "(allow vendor_hal_oplus_touch pen_app (memfd_file (read write getattr map)))\n"
                  "(typeattribute base_typeattr_1346)\n"
                  "(typeattributeset base_typeattr_1346 (and (domain) (not (pen_app))))\n"
                  "(neverallow base_typeattr_1347 base_typeattr_1346 (file (write)))\n"
                  "(allow unrelated self (file (write)))\n").encode()
        with patch("pen_policy.NATIVE_CIL_SHA256", hashlib.sha256(native).hexdigest()):
            module = native_pen_module(native)
        for name in MEMBERSHIPS:
            self.assertIn(f"(typeattributeset {name} (pen_app))".encode(), module)
        self.assertNotIn(b"unrelated", module)
        self.assertNotIn(b"base_typeattr_", module)
        self.assertIn(b"(neverallow pad3_pen_native_1347 pad3_pen_native_1346", module)
        self.assertIn(b"(allow vendor_hal_oplus_touch pen_app", module)
        self.assertNotIn(b"(permissive", module)


@unittest.skipUnless(os.environ.get("PEN_POLICY_COMPILER") and os.environ.get("PEN_POLICY_TEST_WORK") and
                     os.environ.get("PEN_POLICY_NATIVE_CIL") and CERT_PATH.is_file(),
                     "set PEN_POLICY_COMPILER, PEN_POLICY_TEST_WORK and PEN_POLICY_NATIVE_CIL for real cached-image validation")
class CachedPolicyCompile(unittest.TestCase):
    def test_baseline_failure_never_stages_candidate(self):
        with tempfile.TemporaryDirectory(dir=os.environ["PEN_POLICY_TEST_WORK"]) as temporary:
            work = Path(temporary) / "failed-baseline"
            with patch("build_dsu_diagnostic.compile_policy", side_effect=ValueError("current-base policy regression")), \
                    patch("pen_policy.check") as candidate_check:
                with self.assertRaisesRegex(ValueError, "current-base policy regression"):
                    prepare_pen_policy(dict.fromkeys(("system", "system_ext", "product"), Path("unused")),
                                       Path(os.environ["PEN_POLICY_NATIVE_CIL"]).read_bytes(), CERT_PATH.read_bytes(),
                                       Path(os.environ["PEN_POLICY_COMPILER"]), work)
            candidate_check.assert_not_called()
            self.assertFalse((work / "candidate-inputs").exists())

    def test_strict_failure_keeps_separate_report_and_preserves_base(self):
        def baseline(images, compiler, root, output):
            for part in ("system", "system_ext", "product"):
                (root / part).mkdir(parents=True)
            for name, data in zip(FILENAMES, (b"(type original)\n", MAC, SEAPP)):
                (root / "system_ext" / name).write_bytes(data)
            return {"strict_neverallow_pass": True, "compiled_sha256": "baseline"}

        with tempfile.TemporaryDirectory(dir=os.environ["PEN_POLICY_TEST_WORK"]) as temporary:
            work = Path(temporary) / "failed-strict"
            with patch("build_dsu_diagnostic.compile_policy", side_effect=baseline), \
                    patch("pen_policy.check", return_value={"strict_neverallow_pass": False,
                                                           "strict_neverallow_failures": 1}):
                with self.assertRaisesRegex(ValueError, "fails strict policy"):
                    prepare_pen_policy(dict.fromkeys(("system", "system_ext", "product"), Path("unused")),
                                       Path(os.environ["PEN_POLICY_NATIVE_CIL"]).read_bytes(), CERT_PATH.read_bytes(),
                                       Path(os.environ["PEN_POLICY_COMPILER"]), work)
            report = json.loads((work / "pen-policy-report.json").read_text())
            self.assertEqual(report["baseline"]["compiled_sha256"], "baseline")
            self.assertFalse(report["candidate"]["strict_neverallow_pass"])
            self.assertEqual((work / "baseline-inputs/system_ext/system_ext_sepolicy.cil").read_bytes(), b"(type original)\n")

    def test_actual_baseline_and_augmented_strict_compile(self):
        cache = Path("build-inputs/donor-images")
        images = {name: cache / (name + "_a.img") for name in ("system", "system_ext", "product")}
        if not all(p.is_file() for p in images.values()):
            self.skipTest("pinned donor images unavailable")
        work = Path(os.environ["PEN_POLICY_TEST_WORK"]) / "validated-candidate"
        result = prepare_pen_policy(images, Path(os.environ["PEN_POLICY_NATIVE_CIL"]).read_bytes(),
                                    CERT_PATH.read_bytes(), Path(os.environ["PEN_POLICY_COMPILER"]), work)
        profile = json.loads((ROOT / "profiles/erhai-crdroid-20261025/profile.json").read_text())
        self.assertEqual(result["baseline"]["compiled_sha256"], profile["compiled_policy_sha256"])
        self.assertTrue(result["baseline"]["strict_neverallow_pass"])
        self.assertTrue(result["candidate"]["strict_neverallow_pass"])
        self.assertEqual(result["candidate"]["strict_neverallow_failures"], 0)
        self.assertNotEqual(result["candidate"]["compiled_sha256"], result["baseline"]["compiled_sha256"])
        self.assertEqual(result["candidate"]["compiled_sha256"], result["candidate"]["strict_compiled_sha256"])
        self.assertEqual(result["certificate_sha256"], CERT_SHA256)
        changed = set()
        for base in (work / "baseline-inputs").rglob("*"):
            if base.is_file():
                relative = base.relative_to(work / "baseline-inputs")
                candidate = work / "candidate-inputs" / relative
                if candidate.read_bytes() != base.read_bytes():
                    changed.add(str(relative))
        self.assertEqual(changed, {"system_ext/" + name for name in (*FILENAMES, HASH_FILENAME)})
        original = (work / "baseline-inputs/system_ext/system_ext_sepolicy.cil").read_bytes()
        augmented = (work / "candidate-inputs/system_ext/system_ext_sepolicy.cil").read_bytes()
        self.assertTrue(augmented.startswith(original))
        addition = augmented[len(original):]
        mapping = (work / "candidate-inputs/system_ext/mapping/202604.cil").read_bytes()
        digest_path = work / "candidate-inputs/system_ext" / HASH_FILENAME
        self.assertEqual(digest_path.read_bytes(), (hashlib.sha256(augmented + mapping).hexdigest() + "\n").encode())
        self.assertNotEqual(digest_path.read_bytes(), (work / "baseline-inputs/system_ext" / HASH_FILENAME).read_bytes())
        self.assertEqual(len(re.findall(rb"^\(type pen_app\)$", addition, re.M)), 1)
        self.assertIn(b"(typeattributeset vendor_hal_oplus_touch_client (pen_app))", addition)
        self.assertNotIn(b"(allow priv_app ", addition)
        self.assertNotIn(b"(permissive", addition)
        self.assertTrue(result["baseline_files_preserved"])


if __name__ == "__main__":
    unittest.main()
