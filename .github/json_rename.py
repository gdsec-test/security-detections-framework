import json
import os

folder_path = "/Users/twhipple1/Downloads/rules-export"
files = os.listdir(folder_path)

for file in files:
    if file.startswith('alert'):
        with open(f"{folder_path}/{file}", "r") as f:
            json_file = json.load(f)
        str = json_file["name"].split(".")[0] + ".json"
        filename = result = str.replace("/", "-")
        os.rename(f"{folder_path}/{file}", f"{folder_path}/{filename}")
