import csv
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('runner_under_test', SCRIPTS/'run_benchmarks.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def test_ci_is_undefined_without_valid_trials(self):
        self.assertEqual(runner.wilson_score_interval(0, 0), (None, None))

    def test_cost_scores_do_not_fill_missing_scenarios_with_zero(self):
        rows = [{'Mechanizm':'asan','Atak':'P1','Liczba_Prob':2,'Wykryte_Proby':2}]
        result = runner.make_scores(rows, [], {'P1':'Spatial', 'P2':'Spatial'})[0]
        self.assertEqual(result['Detekcja_testowane_scenariusze (%)'], 100)
        self.assertEqual(result['Pokrycie_pakietu (%)'], 50)
        self.assertIsNone(result['S_sys_prod (%)'])
        self.assertIsNone(result['PPS_System (pkt)'])

    def test_performance_requires_timing_and_rss(self):
        process = SimpleNamespace(returncode=0, stdout='Czas_wykonania_ns:42\n', stderr='')
        with patch.object(runner.subprocess, 'run', return_value=process):
            self.assertTrue(runner.run_performance_test('disp_D0_base', 1)['Error'])
        process.stderr='Maximum resident set size (kbytes): 1024\n'
        with patch.object(runner.subprocess, 'run', return_value=process):
            observed=runner.run_performance_test('disp_D0_base', 1)
        self.assertFalse(observed['Error'])
        self.assertEqual(observed['Czas Wewnętrzny (s)'],42/1e9)

    def test_incomplete_measurements_are_explicit(self):
        rows=[{'Grupa':'Parser','Wariant':'parser_P0_base','Czas Wewnętrzny (s)':1,
               'Czas Przetwarzania (s)':1,'Czas Alokacji (s)':0,
               'Czas Sprzatania (s)':0,'RAM (KB)':100}]
        summary=runner.performance_summary(rows,[],expected_runs=2)
        self.assertFalse(summary[0]['Kompletne'])
        self.assertEqual(summary[0]['Udane_Pomiary'],1)

    def test_plots_only_never_rewrites_metadata_or_reads_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            metadata=root/'benchmark_environment.json'
            metadata.write_text('{"schema_version":2,"run_id":"original"}',encoding='utf-8')
            before=metadata.read_bytes()
            with patch.object(runner,'ROOT',root), patch.object(runner,'plot_results') as plotting, patch.object(runner.subprocess,'run',side_effect=AssertionError('no subprocess in plots-only')):
                self.assertEqual(runner.main(['--plots-only','--output-dir',str(root)]),0)
            self.assertEqual(metadata.read_bytes(),before)
            plotting.assert_called_once()

    def test_efficacy_pipeline_keeps_invalid_trials_and_full_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            (root/'data').mkdir()
            (root/'data/checksums.sha256').write_text('# test manifest\n')
            (root/'build').mkdir()
            for name in ('parser_P1_base','parser_P1_asan'):
                (root/'build'/name).write_bytes(b'test-binary')
            output=root/'out'
            def process(command, **kwargs):
                exe=Path(command[0]).name
                if exe=='parser_P1_asan':
                    return SimpleNamespace(returncode=1,stdout='',stderr='ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n')
                if exe=='parser_P1_base':
                    return SimpleNamespace(returncode=78,stdout='',stderr='[SECURITY_INIT_ERROR] mocked failure\n')
                return SimpleNamespace(returncode=0,stdout='test tool version\n',stderr='')
            config=({}, {'P1':(['parser_P1_base','parser_P1_asan'],1)}, {'P1':'Spatial'})
            with patch.object(runner,'ROOT',root), patch.object(runner,'workloads',return_value=config), patch.object(runner,'plot_results'), patch.object(runner.subprocess,'run',side_effect=process):
                code=runner.main(['--profile','smoke','--efficacy-only','--skip-build','--output-dir',str(output)])
            self.assertEqual(code,3)
            with (output/'benchmark_efficacy_data.csv').open() as stream:
                rows={row['Wariant']:row for row in csv.DictReader(stream)}
            self.assertEqual(rows['parser_P1_base']['Skutecznosc_Procent'],'')
            self.assertEqual(rows['parser_P1_base']['Liczba_Prob'],'0')
            self.assertEqual(float(rows['parser_P1_asan']['Skutecznosc_Procent']),100)
            records=[json.loads(line) for line in (output/'benchmark_trials_log.jsonl').read_text().splitlines()]
            self.assertEqual(len(records),2)
            self.assertIn('heap-buffer-overflow',records[1]['stderr'])
            self.assertTrue(records[1]['binary_sha256'])


if __name__=='__main__':
    unittest.main()
