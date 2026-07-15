import os
import sys

# Add project root to sys.path to ensure correct imports during pytest runs
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Suppress the anti-tamper engine during all test runs
os.environ["CHRONOS_DISABLE_ANTI_TAMPER"] = "true"
