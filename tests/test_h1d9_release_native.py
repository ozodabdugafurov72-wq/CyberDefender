"""Reuse the existing native lifecycle tests with only the selected release path."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('h1d9_release_contract',ROOT/'tests/test_h1d_native_live.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.BINARY=ROOT/'native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe'

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(module))
    raise SystemExit(not result.wasSuccessful())
