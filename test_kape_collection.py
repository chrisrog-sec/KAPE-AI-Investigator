import tempfile, unittest, json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from kape_collection import (KapeError, find_kape_executable, discover_targets,
    categorise_targets, build_command, run_collection, run_wizard, sha256_file)

class KapeCollectionTests(unittest.TestCase):
    def fixture(self):
        td=tempfile.TemporaryDirectory(); root=Path(td.name)
        exe=root/'kape.exe'; exe.write_bytes(b'mock exe')
        t=root/'Targets'; t.mkdir()
        files=[]
        for n in ['Windows_EventLogs.tkape','Windows_Prefetch.tkape','Registry_Hives.tkape','NTFS_MFT.tkape','Network_Firewall.tkape']:
            p=t/n; p.write_text('mock target definition',encoding='utf-8'); files.append(p)
        return td,root,exe,files
    def test_discover_and_categories(self):
        td,root,exe,files=self.fixture(); self.addCleanup(td.cleanup)
        self.assertEqual(len(discover_targets(exe)),5)
        grouped=categorise_targets(files)
        self.assertTrue(grouped['eventlogs']); self.assertTrue(grouped['execution'])
        self.assertTrue(grouped['registry']); self.assertTrue(grouped['filesystem']); self.assertTrue(grouped['network'])
    def test_reject_wrong_executable(self):
        td,root,exe,files=self.fixture(); self.addCleanup(td.cleanup)
        with self.assertRaises(KapeError): find_kape_executable(root/'gkape.exe')
    def test_requires_confirmation_before_runner(self):
        td,root,exe,files=self.fixture(); self.addCleanup(td.cleanup)
        runner=Mock()
        with self.assertRaises(KapeError): run_collection(exe,'C:\\',root/'out',files,confirmed=False,runner=runner)
        runner.assert_not_called()
    def test_mocked_run_logs_and_hashes(self):
        td,root,exe,files=self.fixture(); self.addCleanup(td.cleanup)
        dest=root/'out'
        def fake(argv, **kwargs):
            self.assertFalse(kwargs.get('shell',True))
            self.assertIn('--target',argv)
            self.assertNotIn('--module',argv)
            dest.mkdir(exist_ok=True,parents=True)
            (dest/'collected.evtx').write_bytes(b'synthetic output')
            return SimpleNamespace(returncode=0,stdout='mock success',stderr='')
        result=run_collection(exe,'C:\\',dest,files,confirmed=True,runner=fake)
        self.assertTrue((result['log_dir']/'collection_command.json').is_file())
        self.assertTrue((result['log_dir']/'collection_result.json').is_file())
        self.assertTrue((result['log_dir']/'sha256_manifest.json').is_file())
        manifest=json.loads((result['log_dir']/'sha256_manifest.json').read_text())
        row=next(x for x in manifest['files'] if x['path']=='collected.evtx')
        self.assertEqual(row['sha256'],sha256_file(dest/'collected.evtx'))

    def test_wizard_back_navigation_allows_source_correction(self):
        td,root,exe,files=self.fixture(); self.addCleanup(td.cleanup)
        # Five category selections, then source/destination. BACK at confirmation
        # returns to destination; BACK there returns to source for correction.
        answers=iter([str(exe), '1', '1', '1', '1', '1', 'D:\\',
                      str(root/'out'), 'BACK', 'BACK', 'C:\\',
                      str(root/'out'), 'CANCEL'])
        output=[]
        runner=Mock()
        result=run_wizard(root, input_fn=lambda prompt: next(answers),
                          output_fn=output.append, runner=runner)
        self.assertIsNone(result)
        preview='\n'.join(output)
        self.assertIn(f'Source: C:\\', preview)
        self.assertIn('Collection cancelled. No KAPE process was started.', preview)
        runner.assert_not_called()


    def test_admin_privilege_error_is_not_reported_as_success(self):
        td,root,exe,files=self.fixture(); self.addCleanup(td.cleanup)
        def fake(argv, **kwargs):
            return SimpleNamespace(returncode=0, stdout='Administrator privileges not found! Exiting!!\n', stderr='')
        with self.assertRaisesRegex(KapeError, 'administrator privileges are missing'):
            run_collection(exe,'C:\\',root/'out',files,confirmed=True,runner=fake)

    def test_reject_target_outside_install(self):
        td,root,exe,files=self.fixture(); self.addCleanup(td.cleanup)
        outsider=root/'outside.tkape'; outsider.write_text('x')
        with self.assertRaises(KapeError): build_command(exe,'C:\\',root/'out',[outsider])

if __name__=='__main__': unittest.main()
