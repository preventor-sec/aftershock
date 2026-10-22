import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

spec=importlib.util.spec_from_file_location('collector',Path(__file__).parents[1]/'tools'/'collect_evidence.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class CollectorTest(unittest.TestCase):
    def args(self,**kw):
        d=dict(container=None,name='test-host',environment='local',target='https://example.com');d.update(kw);return SimpleNamespace(**d)
    def test_installed_observations_are_labeled(self):
        with patch.object(c.shutil,'which',side_effect=lambda x:'/bin/'+x),patch.object(c,'run',side_effect=['PHP 8.3.36 (cli)','v24.22.1','nginx version: nginx/1.30.6']):
            b=c.collect(self.args())
        self.assertEqual(len(b['components']),3)
        self.assertTrue(all(x['evidenceType']=='installed-binary' for x in b['components']))
        self.assertTrue(all('unverified' in x['source'] for x in b['components']))
    def test_missing_runtime_does_not_fabricate_evidence(self):
        with patch.object(c.shutil,'which',return_value=None),self.assertRaises(ValueError):c.collect(self.args())
    def test_container_argument_injection_rejected(self):
        with patch.object(c.shutil,'which',return_value='/bin/docker'),self.assertRaises(ValueError):c.collect(self.args(container=['--privileged']))
    def test_commands_use_argument_arrays(self):
        with patch.object(c.shutil,'which',return_value='/bin/docker'),patch.object(c,'run',side_effect=['sha256:123','PHP 8.3.36 (cli)','','']) as run:
            b=c.collect(self.args(container=['api']))
        self.assertEqual(run.call_args_list[1].args[0],['/bin/docker','exec','api','php','-v'])
        self.assertEqual(b['components'][0]['revision'],'sha256:123')
if __name__=='__main__':unittest.main()
