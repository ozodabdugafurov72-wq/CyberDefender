"""Pure negative identity fixtures: no processes spawned or terminated."""
import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tests.support.owned_lifecycle import validate
class IdentityTests(unittest.TestCase):
    def setUp(self):self.expected=dict(pid=42,created='fixture-time',parent=1,session=2,executable='fixture-helper',run='run-a',alive=True)
    def test_match(self):validate(self.expected,self.expected,'run-a')
    def test_wrong_run(self):
        with self.assertRaises(PermissionError):validate(self.expected,self.expected,'run-b')
    def test_exited(self):
        current=dict(self.expected,alive=False)
        with self.assertRaises(PermissionError):validate(self.expected,current,'run-a')
def negative(field,value):
    def test(self):
        current=dict(self.expected);current[field]=value
        with self.assertRaises(PermissionError):validate(self.expected,current,'run-a')
    return test
for field,value in dict(pid=43,created='reused-pid-time',parent=3,session=4,executable='unrelated').items():setattr(IdentityTests,'test_wrong_'+field,negative(field,value))
if __name__=='__main__':unittest.main(verbosity=2)
