"""
vul_packages
============
Modular package vulnerability scanner and local OSV database engine.
"""

from pathlib import Path

__version__ = "1.0.0"
DB_PATH = Path(__file__).parent / "vulnerabilities.db"
ZIPS_DIR = Path(__file__).parent / "zips"

