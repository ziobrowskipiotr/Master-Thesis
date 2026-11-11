"""Regression tests for bugs which could invert the thesis conclusions."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_evaluation.py"
SPEC = importlib.util.spec_from_file_location("benchmark_evaluation_under_test", MODULE_PATH)
evaluation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluation)


class ClassifierTests(unittest.TestCase):
    def run_result(self, executable, returncode, stderr, stdout=""):
        process = SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)
        with patch.object(evaluation.subprocess, "run", return_value=process):
            return evaluation.evaluate_single_run(executable, 1)

    def test_startup_mte_token_is_not_detection(self):
        result = self.run_result(
            "parser_P1_mte_sync", 0,
            "[SECURITY_INIT] MTE Sync (SEGV_MTESERR)\n[EXPLOIT_SUCCESS] P1\n",
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["effect_occurred"])
        self.assertFalse(result["detected"])
        self.assertFalse(result["prevented"])

    def test_p5_fault_is_not_overwritten_with_expected_bypass(self):
        result = self.run_result(
            "parser_P5_mte_sync", 139,
            "[ATTACK_TRIGGER] P5\n[SECURITY_INIT] MTE Synchronous Mode\n"
            "[SECURITY_TRAP] Kod bledu (si_code): SEGV_MTESERR (9)\n"
            "[!] PC: 0x000000001234abcd\n",
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["detected"])
        self.assertTrue(result["prevented"])
        self.assertEqual(result["mechanism"], "MTE Sync Tag Fault")
        self.assertEqual(result["pc"], "0x000000001234abcd")

    def test_effect_and_later_canary_detection_are_both_retained(self):
        result = self.run_result(
            "parser_P2_canary", -6,
            "[ATTACK_TRIGGER] P2\n[EXPLOIT_SUCCESS] P2\n*** stack smashing detected ***\n",
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["detected"])
        self.assertTrue(result["effect_occurred"])
        self.assertFalse(result["prevented"])
        self.assertEqual(result["mechanism"], "Stack Canary")

    def test_async_mte_detection_and_effect_are_independent(self):
        result = self.run_result(
            "parser_P1_mte_async", -11,
            "[ATTACK_TRIGGER] P1\n[EXPLOIT_SUCCESS] P1\n"
            "[SECURITY_TRAP] Kod bledu (si_code): SEGV_MTEAERR (8)\n",
        )
        self.assertTrue(result["detected"])
        self.assertTrue(result["effect_occurred"])
        self.assertFalse(result["prevented"])

    def test_regular_crash_after_effect_is_not_labeled_as_detection(self):
        result = self.run_result(
            "parser_P1_mte_sync", -11,
            "[ATTACK_TRIGGER] P1\n[EXPLOIT_SUCCESS] P1\n[SECURITY_TRAP] SEGV_MAPERR\n",
        )
        self.assertTrue(result["valid"])
        self.assertFalse(result["detected"])
        self.assertIsNone(result["mechanism"])

    def test_unattributed_control_flow_crashes_are_not_security_proof(self):
        for executable in ("disp_D1_pac", "disp_D4_bti", "disp_D2_bypass_cfi"):
            with self.subTest(executable=executable):
                result = self.run_result(
                    executable, -4,
                    "[ATTACK_TRIGGER] D\n[SECURITY_TRAP] SIGILL [Illegal opcode / BTI Branch Fault / PAC FPAC Trap]\n",
                )
                self.assertFalse(result["valid"])
                self.assertFalse(result["detected"])
                self.assertEqual(result["invalid_reason"], "unattributed_crash")

    def test_explicit_validated_trap_preserves_bypass_observation(self):
        result = self.run_result(
            "disp_D2_bypass_cfi", -4,
            "[ATTACK_TRIGGER] D2\n[SECURITY_TRAP] mechanism=CFI site=validated\n",
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["detected"])
        self.assertEqual(result["mechanism"], "CFI")

    def test_sanitizer_report_identifies_access_not_generic_segv(self):
        overflow = self.run_result(
            "parser_P1_asan", 1,
            "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n",
        )
        self.assertTrue(overflow["valid"])
        self.assertTrue(overflow["detected"])
        segv = self.run_result(
            "disp_D1_asan", 1,
            "==123==ERROR: AddressSanitizer: SEGV on unknown address 0x1\n",
        )
        self.assertFalse(segv["valid"])
        self.assertFalse(segv["detected"])

    def test_concrete_hwasan_and_scudo_reports(self):
        for executable, stderr, detector in (
            ("parser_P1_hwasan", "ERROR: HWAddressSanitizer: tag-mismatch on address 0xff\n", "HWAddressSanitizer: tag-mismatch"),
            ("kv_M2_hwasan", "ERROR: HWAddressSanitizer: invalid-free on address 0xff\n", "HWAddressSanitizer: invalid-free"),
            ("kv_M2_scudo", "[ATTACK_TRIGGER] M2\nScudo ERROR: invalid chunk state when deallocating address 0xff\n", "Scudo: invalid chunk state"),
        ):
            with self.subTest(executable=executable):
                result = self.run_result(executable, 134, stderr)
                self.assertTrue(result["valid"])
                self.assertEqual(result["mechanism"], detector)

    def test_glibc_baseline_double_free_is_a_real_detection(self):
        for diagnostic in (
            "free(): double free detected in tcache 2",
            "double free or corruption (fasttop)",
            "malloc(): corrupted top size",
        ):
            with self.subTest(diagnostic=diagnostic):
                result = self.run_result(
                    "kv_M2_base", -6, "[ATTACK_TRIGGER] M2\n" + diagnostic + "\n"
                )
                self.assertTrue(result["valid"])
                self.assertTrue(result["detected"])
                self.assertFalse(result["effect_occurred"])
                self.assertEqual(result["mechanism"], "glibc allocator")
                self.assertTrue(result["prevented"])

    def test_glibc_diagnosis_needs_trigger_and_failure(self):
        for returncode, stderr in (
            (-6, "free(): double free detected in tcache 2\n"),
            (0, "[ATTACK_TRIGGER] M2\nfree(): double free detected in tcache 2\n"),
        ):
            result = self.run_result("kv_M2_base", returncode, stderr)
            self.assertFalse(result["valid"])
            self.assertFalse(result["detected"])

    def test_init_and_resource_failures_are_invalid(self):
        messages = (
            "[SECURITY_INIT_ERROR] mprotect(PROT_MTE) failed\n",
            "[!] OSTRZEŻENIE: Tryb MTE nie został włączony przez jądro!\n",
            "[!] OSTRZEŻENIE: mprotect(PROT_MTE) dla stosu zwróciło błąd: 22\n",
            "[!] OSTRZEŻENIE: prctl(PR_SET_TAGGED_ADDR_CTRL) dla Scudo zwróciło błąd: 22\n",
            "ERROR: AddressSanitizer: allocator is out of memory trying to allocate\n",
            "FATAL: HWAddressSanitizer runtime could not initialize\n",
        )
        for message in messages:
            with self.subTest(message=message):
                result = self.run_result("parser_P1_mte_sync", 1, message)
                self.assertFalse(result["valid"])
                self.assertFalse(result["detected"])
                self.assertEqual(result["status"], "BŁĄD ŚRODOWISKA")

    def test_clean_exit_without_attack_evidence_is_invalid(self):
        for stderr in ("", "[ATTACK_TRIGGER] D1\n"):
            result = self.run_result("disp_D1_base", 0, stderr)
            self.assertFalse(result["valid"])
            self.assertFalse(result["detected"])

    def test_missing_executable_and_timeout_keep_output(self):
        with patch.object(evaluation.subprocess, "run", side_effect=FileNotFoundError("missing executable")):
            result = evaluation.evaluate_single_run("missing", 1)
        self.assertFalse(result["valid"])
        self.assertEqual(result["invalid_reason"], "FileNotFoundError")
        timeout = subprocess.TimeoutExpired(["binary"], 1, output=b"partial stdout", stderr=b"partial stderr")
        with patch.object(evaluation.subprocess, "run", side_effect=timeout):
            result = evaluation.evaluate_single_run("hanging", 1, timeout=1)
        self.assertFalse(result["valid"])
        self.assertEqual(result["invalid_reason"], "timeout")
        self.assertEqual(result["stdout"], "partial stdout")
        self.assertEqual(result["stderr"], "partial stderr")


class AggregateTests(unittest.TestCase):
    def test_invalid_runs_do_not_enter_denominator_and_raw_logs_survive(self):
        observed = [
            evaluation._classify("", "[SECURITY_INIT_ERROR] failed", 78),
            evaluation._classify("", "[ATTACK_TRIGGER] P1\nERROR: AddressSanitizer: heap-buffer-overflow\n", 1),
            evaluation._classify("", "[ATTACK_TRIGGER] P1\n[EXPLOIT_SUCCESS] P1\n", 0),
        ]
        for result in observed:
            result["command"] = ["build/parser_P1_asan", "input.bin"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build").mkdir()
            (root / "build" / "parser_P1_asan").write_bytes(b"test binary")
            with patch.object(evaluation, "evaluate_single_run", side_effect=observed):
                summary = evaluation.run_efficacy_test("parser_P1_asan", 1, trials=3,
                    log_dir=root, build_dir=root / "build", run_id="experiment-a")
            self.assertEqual(summary["Liczba_Prob"], 2)
            self.assertEqual(summary["Proby_Niewazne"], 1)
            self.assertEqual(summary["Skutecznosc_Procent"], 50.0)
            self.assertEqual(summary["Skutki_Proby"], 1)
            self.assertEqual(summary["Prewencja_Potwierdzona_Proby"], 1)
            records = [json.loads(line) for line in (root / "benchmark_trials_log.jsonl").read_text().splitlines()]
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0]["stderr"], "[SECURITY_INIT_ERROR] failed")
            self.assertEqual(records[0]["run_id"], "experiment-a")
            self.assertEqual(len(records[0]["binary_sha256"]), 64)
            self.assertEqual(records[1]["command"], ["build/parser_P1_asan", "input.bin"])
            with patch.object(evaluation, "evaluate_single_run", return_value=observed[2]):
                evaluation.run_efficacy_test("parser_P1_asan", 1, trials=1, log_dir=root, run_id="experiment-b")
            appended = [json.loads(line) for line in (root / "benchmark_trials_log.jsonl").read_text().splitlines()]
            self.assertEqual(len(appended), 4)
            self.assertEqual(appended[-1]["run_id"], "experiment-b")

    def test_all_invalid_is_na_instead_of_zero_percent(self):
        result = evaluation._classify("", "[SECURITY_INIT_ERROR] failed", 78)
        result["command"] = ["build/parser_P1_mte_sync", "1"]
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(evaluation, "evaluate_single_run", return_value=result):
                summary = evaluation.run_efficacy_test("parser_P1_mte_sync", 1, trials=3, log_dir=temporary)
        self.assertEqual(summary["Liczba_Prob"], 0)
        self.assertEqual(summary["Proby_Niewazne"], 3)
        self.assertIsNone(summary["Skutecznosc_Procent"])
        self.assertIsNone(summary["Zablokowano"])


if __name__ == "__main__":
    unittest.main()
