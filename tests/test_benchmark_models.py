import math
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from benchmark_models import aggregate_costs, compute_costs, sensitivity_analysis


def measurement(application, mechanism, runtime, memory, text=100):
    return {
        "Grupa": application,
        "Wariant": f"test_0_{mechanism}",
        "Mediana czasu (s)": runtime,
        "Mediana RAM (KB)": memory,
        "Rozmiar .text (B)": text,
    }


class CostModelTests(unittest.TestCase):
    def test_default_sensitivity_matches_main_cost_with_covarying_measurements(self):
        rows = [
            measurement("A", "base", 1, 1),
            measurement("A", "asan", 1, 1),
            measurement("B", "base", 1, 1),
            measurement("B", "asan", 3, 3),
        ]
        costs = compute_costs(rows)
        average = aggregate_costs(costs)[0]
        sensitivity = sensitivity_analysis(costs, [{"Mechanizm": "asan", "S_sys_prod (%)": 80}])
        default = next(row for row in sensitivity if row["Waga_CPU"] == 0.75)
        self.assertEqual(average["C_cloud"], 2.75)
        self.assertEqual(default["C_cloud"], average["C_cloud"])
        self.assertEqual(default["PPS_Kwadratowy"], (0.8 ** 2) / 2.75 * 100)

    def test_measured_speedup_is_not_clamped(self):
        rows = [measurement("A", "base", 2, 2), measurement("A", "asan", 1, 1)]
        cost = compute_costs(rows)[0]
        self.assertEqual(cost["r_T"], 0.5)
        self.assertEqual(cost["r_M"], 0.5)
        self.assertEqual(cost["C_cloud"], 0.4375)
        self.assertLess(cost["Omega_cloud_pct"], 0)

    def test_missing_or_invalid_baseline_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Brak wariantu base"):
            compute_costs([measurement("A", "asan", 1, 1)])
        for field in ("Mediana czasu (s)", "Mediana RAM (KB)"):
            for value in (None, 0, -1, math.nan, math.inf):
                with self.subTest(field=field, value=value):
                    base = measurement("A", "base", 1, 1)
                    base[field] = value
                    with self.assertRaises(ValueError):
                        compute_costs([base, measurement("A", "asan", 1, 1)])

    def test_invalid_security_measurement_is_rejected(self):
        for value in (None, 0, -1, math.nan, math.inf):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    compute_costs([measurement("A", "base", 1, 1), measurement("A", "asan", value, 1)])

    def test_duplicate_application_cannot_receive_double_weight(self):
        rows = [measurement("A", "base", 1, 1), measurement("A", "asan", 1, 1)]
        with self.assertRaises(ValueError):
            compute_costs(rows + [measurement("A", "asan", 2, 2)])
        costs = compute_costs(rows)
        with self.assertRaises(ValueError):
            aggregate_costs(costs + costs)

    def test_different_application_sets_remain_explicit(self):
        rows = [
            measurement("B", "base", 1, 1), measurement("B", "asan", 1, 1),
            measurement("A", "base", 1, 1), measurement("A", "asan", 1, 1),
            measurement("A", "pac", 1, 1),
        ]
        aggregated = {row["Mechanizm"]: row for row in aggregate_costs(compute_costs(rows))}
        self.assertEqual(aggregated["asan"]["application_set"], "A;B")
        self.assertEqual(aggregated["asan"]["application_count"], 2)
        self.assertEqual(aggregated["pac"]["application_set"], "A")
        self.assertEqual(aggregated["pac"]["application_count"], 1)

    def test_unknown_variant_cannot_become_baseline(self):
        row = measurement("A", "mistyped", 1, 1)
        with self.assertRaisesRegex(ValueError, "Nieznany mechanizm"):
            compute_costs([row])

    def test_missing_code_size_does_not_create_fake_size(self):
        rows = [measurement("A", "base", 1, 1, text=0), measurement("A", "asan", 2, 2, text=None)]
        costs = compute_costs(rows)
        self.assertIsNone(costs[0]["r_S"])
        self.assertIsNone(aggregate_costs(costs)[0]["r_S"])

    def test_incomplete_score_is_not_replaced_with_zero(self):
        costs = compute_costs([measurement("A", "base", 1, 1), measurement("A", "asan", 2, 2)])
        for score in (None, math.nan):
            with self.subTest(score=score):
                self.assertEqual(sensitivity_analysis(costs, [{"Mechanizm": "asan", "S_sys_prod (%)": score}]), [])

    def test_explicit_diagnostic_score_column_is_supported(self):
        costs = compute_costs([measurement("A", "base", 1, 1), measurement("A", "asan", 2, 2)])
        scores = [{"Mechanizm": "asan", "Detekcja_testowane_scenariusze (%)": 50}]
        sensitivity = sensitivity_analysis(
            costs, scores,
            score_field="Detekcja_testowane_scenariusze (%)",
        )
        default = next(row for row in sensitivity if row["Waga_CPU"] == 0.75)
        self.assertEqual(default["C_cloud"], 2.5)
        self.assertEqual(default["PPS_Liniowy"], 20)
        self.assertEqual(default["PPS_Kwadratowy"], 10)

    def test_invalid_weights_are_rejected(self):
        for value in (-0.1, 1.1, math.nan, math.inf, None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    compute_costs([], cpu_weight=value)
        with self.assertRaises(ValueError):
            sensitivity_analysis([], [], [("invalid", 0.75, 0.50)])


if __name__ == "__main__":
    unittest.main()
