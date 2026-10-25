from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from publish_generated import guarded_inputs


class PublicationGuardTests(unittest.TestCase):
    def test_each_output_protects_its_generator_and_inputs(self):
        cases = {
            "Trackers/Trackers.txt": {
                "scripts/build_trackers.py", "data/sources/TrackersList_URLs.txt",
                ".github/workflows/merge-trackers.yml",
            },
            "Surge/Icon.json": {
                "scripts/build_icon_json.py", "Surge/Icon/",
                ".github/workflows/merge-surge-icons.yml",
            },
            "Surge/Module/StartUpAds.sgmodule": {
                "Surge/Module/.generator/build.py",
                "Surge/Module/runtime/body-rewrite.js",
                ".github/workflows/update-moyu-startup.yml",
            },
            "Surge/Module/Adblock4limbo.sgmodule": {
                "Surge/Module/.generator/update-adblock4limbo.py",
                ".github/workflows/update-adblock4limbo.yml",
            },
            "data/reports/china_download_manifest.json": {
                "scripts/build_china_domain.py", "data/sources/ChinaDomainList_URLs.txt",
            },
            "data/reports/ad_download_manifest.json": {
                "scripts/build_ad_sets.py", "data/sources/AdBlockList_URLs.txt",
            },
        }
        for output, expected in cases.items():
            with self.subTest(output=output):
                self.assertTrue(expected.issubset(set(guarded_inputs([output]))))


if __name__ == "__main__":
    unittest.main()
