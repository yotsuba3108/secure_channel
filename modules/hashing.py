import hashlib, hmac, os, time, statistics

def bit_diff(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

# 1. Test vectors
print("SHA256 abc:", hashlib.sha256(b"abc").hexdigest())
print("SHA1 abc  :", hashlib.sha1(b"abc").hexdigest())
print("MD5 abc   :", hashlib.md5(b"abc").hexdigest())
print("SHA256 abd:", hashlib.sha256(b"abd").hexdigest())
print("SHA1 abd  :", hashlib.sha1(b"abd").hexdigest())
print("MD5 abd   :", hashlib.md5(b"abd").hexdigest())
for n in ("sha256","sha1","md5"):
    a=hashlib.new(n,b"abc").digest(); b=hashlib.new(n,b"abd").digest()
    print(n,"diff bits",bit_diff(a,b),"/",len(a)*8)

# 2. HMAC
msg=b"The quick brown fox jumps over the lazy dog"
t=hmac.new(b"key",msg,hashlib.sha256).hexdigest()
print("HMAC:",t)
print("cmp ok:",hmac.compare_digest(t,"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"))
wrong=hmac.new(b"kex",msg,hashlib.sha256).hexdigest()
print("HMAC wrong key:",wrong, hmac.compare_digest(t,wrong))
t2=hmac.new(b"key",msg+b".",hashlib.sha256).hexdigest()
print("HMAC msg changed:",t2)

# 3. avalanche statistics: flip 1 bit, 1000 random 64-byte messages
import random
random.seed(1)
for n in ("sha256","sha1","md5"):
    ds=[]
    for _ in range(1000):
        m=bytearray(random.randbytes(64))
        h1=hashlib.new(n,bytes(m)).digest()
        i=random.randrange(64*8); m[i//8]^=1<<(i%8)
        h2=hashlib.new(n,bytes(m)).digest()
        ds.append(bit_diff(h1,h2))
    print(n,"mean",round(statistics.mean(ds),2),"stdev",round(statistics.pstdev(ds),2),"min",min(ds),"max",max(ds))

# 4. timing 10MB
data=os.urandom(10*1024*1024)
for n in ("sha256","sha1","md5"):
    ts=[]
    for _ in range(20):
        s=time.perf_counter(); hashlib.new(n,data).hexdigest(); ts.append((time.perf_counter()-s)*1000)
    print(n,"mean ms",round(statistics.mean(ts),2),"std",round(statistics.pstdev(ts),2),"MB/s",round(10/(statistics.mean(ts)/1000),0))






"""
hash_module.py - Phan B.2.2: Ham bam, HMAC va hieu ung thac.
Dung nhu mot Flask Blueprint de ghep vao app.py chung cua nhom:

    from hash_module import hash_bp
    app.register_blueprint(hash_bp)

Chay rieng de thu:  python hash_module.py  ->  http://127.0.0.1:5001/hash
"""
import hashlib
import hmac
import os
import statistics
import time

from flask import Blueprint, Flask, jsonify, request

hash_bp = Blueprint("hash_bp", __name__)

ALGOS = {
    "sha256": {"bits": 256, "secure": True},
    "sha1":   {"bits": 160, "secure": False},
    "md5":    {"bits": 128, "secure": False},
}
WARN = {
    "sha1": "SHA-1 da bi tim ra va cham (SHAttered, 2017) - khong dung cho bao mat.",
    "md5":  "MD5 da bi pha vo (va cham tim duoc trong vai giay) - khong dung cho bao mat.",
}


# ---------- ham tien ich ----------
def bit_diff(a: bytes, b: bytes) -> int:
    """So bit khac nhau giua hai chuoi byte cung do dai (khoang cach Hamming)."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def digest_all(data: bytes) -> dict:
    out = {}
    for name in ALGOS:
        out[name] = {
            "hex": hashlib.new(name, data).hexdigest(),
            "bits": ALGOS[name]["bits"],
            "warning": WARN.get(name),
        }
    return out


def get_input_bytes() -> bytes:
    """Lay du lieu tu file tai len (neu co) hoac tu truong 'text'."""
    f = request.files.get("file")
    if f:
        return f.read()
    if request.is_json:
        return (request.get_json(silent=True) or {}).get("text", "").encode("utf-8")
    return request.form.get("text", "").encode("utf-8")


def flip_one_char(text: str, pos: int) -> str:
    """Sua dung 1 ky tu tai vi tri pos (tang ma ky tu len 1)."""
    n = ord(text[pos]) + 1
    if 0xD800 <= n <= 0xDFFF or n > 0x10FFFF:   # tranh vung surrogate / ngoai Unicode
        n = ord(text[pos]) - 1
    return text[:pos] + chr(n) + text[pos + 1:]


# ---------- API ----------
@hash_bp.post("/api/hash")
def api_hash():
    data = get_input_bytes()
    return jsonify({"length_bytes": len(data), "hashes": digest_all(data)})


@hash_bp.post("/api/avalanche")
def api_avalanche():
    body = request.get_json(silent=True) or {}
    text = body.get("text", "")
    if not text:
        return jsonify({"error": "Hay nhap van ban khong rong."}), 400
    pos = int(body.get("position", len(text) - 1))
    if not 0 <= pos < len(text):
        return jsonify({"error": "Vi tri ky tu ngoai pham vi."}), 400
    text2 = flip_one_char(text, pos)
    res = {}
    for name, info in ALGOS.items():
        h1 = hashlib.new(name, text.encode()).digest()
        h2 = hashlib.new(name, text2.encode()).digest()
        d = bit_diff(h1, h2)
        res[name] = {
            "hash1": h1.hex(), "hash2": h2.hex(),
            "diff_bits": d, "total_bits": info["bits"],
            "ratio": round(d / info["bits"], 4),
        }
    return jsonify({"original": text, "modified": text2, "position": pos, "result": res})


@hash_bp.post("/api/hmac")
def api_hmac():
    body = request.get_json(silent=True) or {}
    key = body.get("key", "").encode()
    msg = body.get("message", "").encode()
    tag = hmac.new(key, msg, hashlib.sha256).hexdigest()
    out = {"tag": tag}
    given = body.get("tag")
    if given is not None:
        # so sanh hang thoi gian, chong tan cong do thoi gian (timing attack)
        ok = hmac.compare_digest(tag.encode(), given.strip().lower().encode())
        out["verify"] = {
            "valid": ok,
            "message": "The hop le" if ok else "The khong hop le (sai khoa hoac thong diep bi sua)",
        }
    return jsonify(out)


@hash_bp.post("/api/hash-benchmark")
def api_benchmark():
    """Do thoi gian bam 1 file >= 10 MB cho tung ham bam (lap 'repeat' lan)."""
    f = request.files.get("file")
    data = f.read() if f else os.urandom(10 * 1024 * 1024)
    repeat = max(1, min(int(request.form.get("repeat", 20)), 100))
    if len(data) < 10 * 1024 * 1024:
        return jsonify({"error": "Can file >= 10 MB (bo trong de tu sinh 10 MB ngau nhien)."}), 400
    size_mb = len(data) / (1024 * 1024)
    res = {}
    for name in ALGOS:
        ts = []
        for _ in range(repeat):
            t0 = time.perf_counter()
            hashlib.new(name, data).digest()
            ts.append((time.perf_counter() - t0) * 1000)
        mean = statistics.mean(ts)
        res[name] = {
            "mean_ms": round(mean, 2),
            "stdev_ms": round(statistics.pstdev(ts), 2),
            "throughput_mb_s": round(size_mb / (mean / 1000), 1),
        }
    return jsonify({"size_mb": round(size_mb, 2), "repeat": repeat, "result": res})


# ---------- giao dien don gian ----------
PAGE = """<!doctype html><html lang="vi"><meta charset="utf-8"><title>Ham bam &amp; HMAC</title>
<style>body{font-family:sans-serif;max-width:900px;margin:20px auto}textarea,input{width:100%;box-sizing:border-box}
pre{background:#f4f4f4;padding:8px;overflow:auto}.warn{color:#b00020}section{border:1px solid #ccc;padding:10px;margin:12px 0}</style>
<h2>B.2.2 - Ham bam, HMAC, hieu ung thac</h2>
<section><h3>1. Bam van ban / file</h3>
<textarea id="t" rows="3">abc</textarea><input type="file" id="f">
<button onclick="doHash()">Tinh SHA-256 / SHA-1 / MD5</button><pre id="o1"></pre></section>
<section><h3>2. Hieu ung thac (sua 1 ky tu)</h3>
<input id="pos" placeholder="vi tri ky tu (de trong = ky tu cuoi)">
<button onclick="doAv()">Sua 1 ky tu va so sanh</button><pre id="o2"></pre></section>
<section><h3>3. HMAC-SHA256</h3>
<input id="k" value="key"><input id="m" value="The quick brown fox jumps over the lazy dog">
<input id="tg" placeholder="the can kiem tra (tuy chon)">
<button onclick="doH()">Tinh / kiem tra</button><pre id="o3"></pre></section>
<section><h3>4. Do thoi gian bam (file &gt;= 10 MB)</h3>
<input type="file" id="bf"><button onclick="doB()">Do (20 lan)</button><pre id="o4"></pre></section>
<script>
const j=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json());
async function doHash(){const fd=new FormData();const f=document.getElementById('f').files[0];
 if(f)fd.append('file',f);else fd.append('text',document.getElementById('t').value);
 const r=await fetch('/api/hash',{method:'POST',body:fd}).then(r=>r.json());
 o1.textContent=Object.entries(r.hashes).map(([n,v])=>n.toUpperCase()+': '+v.hex+(v.warning?'\\n  ! '+v.warning:'')).join('\\n');}
async function doAv(){const t=document.getElementById('t').value;const p=document.getElementById('pos').value;
 const b={text:t};if(p!=='')b.position=+p;const r=await j('/api/avalanche',b);
 o2.textContent=r.error||('Goc: '+r.original+'  ->  Sua: '+r.modified+'\\n'+Object.entries(r.result).map(([n,v])=>n.toUpperCase()+': khac '+v.diff_bits+'/'+v.total_bits+' bit ('+(v.ratio*100).toFixed(1)+'%)').join('\\n'));}
async function doH(){const r=await j('/api/hmac',{key:k.value,message:m.value,tag:tg.value||undefined});
 o3.textContent='Tag: '+r.tag+(r.verify?'\\n'+r.verify.message:'');}
async function doB(){const fd=new FormData();const f=document.getElementById('bf').files[0];if(f)fd.append('file',f);
 const r=await fetch('/api/hash-benchmark',{method:'POST',body:fd}).then(r=>r.json());
 o4.textContent=r.error||('File '+r.size_mb+' MB, '+r.repeat+' lan\\n'+Object.entries(r.result).map(([n,v])=>n.toUpperCase()+': '+v.mean_ms+' ms (+-'+v.stdev_ms+'), '+v.throughput_mb_s+' MB/s').join('\\n'));}
</script></html>"""


@hash_bp.get("/hash")
def page():
    return PAGE


if __name__ == "__main__":
    app = Flask(__name__)
    app.register_blueprint(hash_bp)
    app.run(port=5001, debug=True)
