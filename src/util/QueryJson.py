import json
import re
import os


def queryFile(file_path, filter_path, filter_key=None, filter_val=None):
    back = []
    data = json.load(open(file_path))
    if filter_path == [""]:
        return [data]
    for key in filter_path:
        data = data.get(key)
        if not data:
            return
    if type(data) == list:
        for row in data:
            if filter_val:
                if row[filter_key] == filter_val:
                    back.append(row)
            else:
                back.append(row)
    else:
        back.append({"value": data})
    return back


def query(path_pattern, filter):
    if "=" in filter:
        filter_path, filter_val = filter.split("=")
        filter_path = filter_path.split(".")
        filter_key = filter_path.pop()
        filter_val = int(filter_val)
    else:
        filter_path = filter
        filter_path = filter_path.split(".")
        filter_key = None
        filter_val = None
    if "/*/" in path_pattern:
        root_dir, file_pattern = path_pattern.replace("\\", "/").split("/*/")
    else:
        root_dir, file_pattern = re.match(
            "(.*)/(.*?)$", path_pattern.replace("\\", "/")
        ).groups()
    for root, dirs, files in os.walk(root_dir, topdown=False):
        root = root.replace("\\", "/")
        inner_path = root.replace(root_dir, "").strip("/")
        for file_name in files:
            if file_pattern != file_name:
                continue
            try:
                res = queryFile(
                    root + "/" + file_name, filter_path, filter_key, filter_val
                )
                if not res:
                    continue
            except Exception:
                continue
            for row in res:
                row["inner_path"] = inner_path
                yield row


if __name__ == "__main__":
    for row in list(
        query(
            "../../data/12Hw8rTgzrNo4DSh2AkqwPRqDyTticwJyH/data/users/*/data.json",
            "",
        )
    ):
        print(row)
