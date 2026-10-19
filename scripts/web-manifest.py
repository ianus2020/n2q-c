#!/usr/bin/env python3
"""Record the exact public glue/WASM pair produced by the locked build."""
import hashlib
import json
from pathlib import Path
import re
root=Path(__file__).resolve().parents[1]/"impl/n2q-c-wasm/web/pkg"
def entry(name):
    data=(root/name).read_bytes()
    if not 0<len(data)<=4194304:
        raise ValueError("asset size outside loader limits")
    return {"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
js=(root/"n2q_c_wasm.js").read_text()
# The verified Blob module is deliberately self-contained; no relative imports.
if re.search(r'^\s*import\s|\bfrom\s+[\'"]\.|\bimport\s*\(',js,re.M):
    raise ValueError("generated JS needs a loader review for new module imports")
manifest={"version":1,"js":entry("n2q_c_wasm.js"),"wasm":entry("n2q_c_wasm_bg.wasm")}
(root/"build-manifest.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
print("JS/WASM build manifest recorded")
