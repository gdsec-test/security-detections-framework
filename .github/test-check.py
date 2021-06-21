#!/usr/bin/envpython3

"""\
Programmatically check if the json has test or exception to it
"""

import json
import os
import sys


def test_check():
    """\
    Consolidate
    """
    file_count = 0
    test_passed = 0

    # Change paths as required
    for subdir, _, files in os.walk("../alerts/templates"):
        for filename in files:
            file_count += 1
            filepath = subdir + os.sep + filename
            if filepath.endswith("json"):
                with open(filepath, "r") as file:
                    inside_dict = json.load(file)

                if "test" in inside_dict.keys():
                    if (inside_dict["test"]["archive"] != '') or (inside_dict["test"]["exception"] != ''):
                        test_passed += 1
                        continue
                    else:
                        print(filepath + " file doesnt have tests or exceptions")
                        continue

                else:
                    print(filepath + " file doesn't have tests")
                    continue

    if files == test_passed:
        return True
    else:
        return False


if __name__ == "__main__":
    if test_check() is False:
        sys.exit(1)
