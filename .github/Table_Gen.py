#!/usr/bin/envpython3

"""\
Programmatically check if json given validates against the schema
"""

import json
import os
import sys

from jsonschema import validate
from jsonschema.exceptions import ValidationError

def get_schema():
    with open('alerts/templates/metadata-schema.json', 'r') as file:
        schema = json.load(file)
    return schema


def validate_json(json_data):
    execute_api_schema = get_schema()

    try:
        validate(instance=json_data, schema=execute_api_schema)
    except ValidationError as err:
        print(err)
        return False

    return True


def test_check():
    file_count = 0
    test_passed = 0

    # Change paths as required - currently runs for all folders withing detections
    for subdir, _, files in os.walk("alerts/detections"):
        if subdir == "templates":
            continue
        for filename in files:
            filepath = os.path.join(subdir, filename)
            if filepath.endswith(".json"):
                file_count += 1
                with open(filepath, "r") as file:
                    json_data = json.load(file)

                if validate_json(json_data):
                    test_passed += 1
                    continue
                else:
                    print(filepath + " file doesn't validate the specified schema")
                    continue

    if file_count == test_passed:
        return True
    else:
        return False


if __name__ == "__main__":
    if test_check() is False:
        print("Check \"alerts/templates\" for schema and a successful validation")
        sys.exit(1)
    else:
        print("All tests/ exceptions passed!!")
