import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import tempfile

spec = importlib.util.spec_from_file_location("compat", Path(__file__).resolve().parents[1] / "verify-linux-compat.py")
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)

VERSIONS = "Version definition section Name: GLIBC_99.0\nVersion needs section '.gnu.version_r'\nName: GLIBC_2.2.5 Flags: none\nName: GLIBC_2.17 Flags: none"
DYNAMIC = "(NEEDED) Shared library: [libc.so.6]\n(NEEDED) Shared library: [libgcc_s.so.1]"
HEADERS = "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]"


class AbiTests(unittest.TestCase):
    def test_accept_217_and_ignore_definition_not_requirement(self):
        self.assertEqual(compat.parse_abi(VERSIONS, DYNAMIC, HEADERS)["neededLibraries"], ["libc.so.6", "libgcc_s.so.1"])

    def test_accept_patch_zero_without_false_alarm(self):
        compat.parse_abi(VERSIONS.replace("2.17", "2.17.0"), DYNAMIC, HEADERS)

    def test_reject_newer_or_private_abi(self):
        for label in ["2.18", "2.34", "PRIVATE", "ABI_DT_RELR", "2.17.1"]:
            with self.subTest(label=label), self.assertRaises(ValueError):
                compat.parse_abi(VERSIONS.replace("2.17", label), DYNAMIC, HEADERS)

    def test_reject_missing_version_needs(self):
        with self.assertRaises(ValueError):
            compat.parse_abi("Version definition section Name: GLIBC_2.17", DYNAMIC, HEADERS)

    def test_reject_missing_glibc(self):
        with self.assertRaises(ValueError):
            compat.parse_abi("Version needs section Name: GCC_3.0", DYNAMIC, HEADERS)

    def test_reject_extra_library(self):
        with self.assertRaises(ValueError):
            compat.parse_abi(VERSIONS, DYNAMIC + "\n(NEEDED) Shared library: [libssl.so.3]", HEADERS)

    def test_reject_static_binary_or_wrong_loader(self):
        for dynamic, headers in [("", HEADERS), (DYNAMIC, HEADERS.replace("/lib64/", "/lib/"))]:
            with self.subTest(dynamic=dynamic, headers=headers), self.assertRaises(ValueError):
                compat.parse_abi(VERSIONS, dynamic, headers)

    def test_reject_relr(self):
        for tag in ["RELR", "RELRSZ", "RELRENT"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                compat.parse_abi(VERSIONS, DYNAMIC + f"\n({tag}) 0x123", HEADERS)


class RpcTests(unittest.TestCase):
    def replies(self):
        return [{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18"}}, {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": str(i)} for i in range(25)]}}, {"jsonrpc": "2.0", "id": 3, "result": {"isError": False}}, {"jsonrpc": "2.0", "id": 4, "result": {"content": [{"type": "text", "text": json.dumps({"text": compat.SENTINEL})}]}}]

    def encode(self, replies):
        return "\n".join(map(json.dumps, replies))

    def test_exact_roundtrip(self):
        compat.validate_rpc(self.encode(self.replies()))

    def test_reject_missing_response(self):
        with self.assertRaises(ValueError):
            compat.validate_rpc(self.encode(self.replies()[:-1]))

    def test_reject_error_or_changed_content(self):
        for kind in ["error", "content", "tools", "duplicates"]:
            data = self.replies()
            if kind == "error":
                data[2]["result"]["isError"] = True
            elif kind == "content":
                data[3]["result"]["content"][0]["text"] = '{"text":"wrong"}'
            elif kind == "tools":
                data[1]["result"]["tools"].pop()
            else:
                data[1]["result"]["tools"][0] = data[1]["result"]["tools"][1]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                compat.validate_rpc(self.encode(data))


class ReceiptTests(unittest.TestCase):
    def test_failed_verification_replaces_old_pass_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "ferroc"
            binary.write_bytes(b"not an ELF")
            report = Path(directory) / "report.json"
            report.write_text('{"passed":true}', encoding="utf-8")
            argv = ["verify-linux-compat.py", "--binary", str(binary), "--report", str(report)]
            with patch("sys.argv", argv), self.assertRaises(ValueError):
                compat.main()
            self.assertIs(json.loads(report.read_text(encoding="utf-8"))["passed"], False)

    def test_missing_docker_cannot_produce_pass_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "ferroc"
            binary.write_bytes(b"fixture")
            report = Path(directory) / "report.json"
            argv = ["verify-linux-compat.py", "--binary", str(binary), "--report", str(report)]
            with patch("sys.argv", argv), patch.object(compat, "verify", side_effect=FileNotFoundError("docker")), self.assertRaises(FileNotFoundError):
                compat.main()
            self.assertIs(json.loads(report.read_text(encoding="utf-8"))["passed"], False)


if __name__ == "__main__":
    unittest.main()
