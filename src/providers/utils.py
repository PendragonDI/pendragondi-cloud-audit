from typing import List, Dict

def finalize_status(files: List[Dict], hash_map: Dict[str, List[str]]):
    path_to_status = {}
    for hash_val, paths in hash_map.items():
        if len(paths) > 1:
            for p in paths:
                path_to_status[p] = "duplicate"
    for f in files:
        if f["path"] in path_to_status:
            f["status"].append(path_to_status[f["path"]])
        f["status"] = ",".join(f["status"]) or "active"
