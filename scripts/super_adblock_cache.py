from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request

def sha(data):
    return hashlib.sha256(data).hexdigest()

def private_root():
    value=os.getenv("SUPER_ADBLOCK_PRIVATE_CACHE")
    if not value or os.getenv("GITHUB_ACTIONS")=="true":
        return None
    root=Path(value).expanduser()
    if not root.is_absolute():
        raise ValueError("Cache must be an absolute private path")
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if root.is_symlink() or root.stat().st_uid!=os.getuid() or stat.S_IMODE(root.stat().st_mode)&0o077:
        raise ValueError("Cache directory is not private")
    return root

def atomic(path,data):
    fd,name=tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(data)
        os.replace(name,path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def fetch(endpoint,opener,validate_endpoint,validate_bytes,max_bytes,timeout):
    root=private_root()
    key=sha(endpoint.encode())
    cached=None
    headers={"User-Agent":"Net-Link-SuperAdBlock/1.0","Accept":"text/plain,*/*"}
    if root:
        try:
            meta=json.loads((root/(key+".json")).read_bytes())
            if meta["endpoint"]!=endpoint or not isinstance(meta["etag"],str) or not meta["etag"] or len(meta["etag"])>1024 or any(ord(c)<32 for c in meta["etag"]):
                raise ValueError("Invalid ETag")
            raw=(root/(key+".bin")).read_bytes()
            if len(raw)>max_bytes or sha(raw)!=meta["sha256"]:
                raise ValueError("Cache integrity")
            validate_bytes(raw)
            cached=raw
            headers["If-None-Match"]=meta["etag"]
        except (OSError,ValueError,KeyError,TypeError):
            pass
    try:
        with opener.open(Request(endpoint,headers=headers),timeout=timeout) as response:
            if response.status!=200:
                raise ValueError("Unexpected HTTP status")
            validate_endpoint(response.geturl())
            raw=response.read(max_bytes+1)
            if len(raw)>max_bytes:
                raise ValueError("Oversize response")
            validate_bytes(raw)
            etag=response.headers.get("ETag")
    except HTTPError as exc:
        if exc.code!=304 or cached is None:
            raise
        validate_endpoint(exc.geturl())
        return cached,"revalidated-cache"
    if root and etag and len(etag)<=1024 and not any(ord(c)<32 for c in etag):
        atomic(root/(key+".bin"),raw)
        atomic(root/(key+".json"),json.dumps({"endpoint":endpoint,"etag":etag,"sha256":sha(raw)},sort_keys=True).encode())
    return raw,"network"
