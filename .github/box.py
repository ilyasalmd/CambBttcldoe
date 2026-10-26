"""Seal or open a folder with AES-256-GCM.

  python box.py seal DIR OUT.bin AAD     # tar.gz DIR, encrypt to OUT.bin
  python box.py open IN.bin DIR AAD      # decrypt IN.bin, unpack into DIR

The key is base64 in the environment variable BOX_KEY (32 bytes). AAD binds a box to its job, so a box from one
job cannot be swapped into another. Needs the `cryptography` package. Prints nothing on success.
"""
import base64
import io
import os
import sys
import tarfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"BX1"


def key():
    k = base64.b64decode(os.environ.get("BOX_KEY", ""))
    if len(k) != 32:
        sys.exit("BOX_KEY missing or not 32 bytes")
    return AESGCM(k)


def seal(src, out, aad):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(src, arcname=".")
    nonce = os.urandom(12)
    with open(out, "wb") as f:
        f.write(MAGIC + nonce + key().encrypt(nonce, buf.getvalue(), aad.encode()))


def open_(src, dest, aad):
    blob = open(src, "rb").read()
    if blob[:3] != MAGIC:
        sys.exit("not a box")
    data = key().decrypt(blob[3:15], blob[15:], aad.encode())
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        tar.extractall(dest, filter="data")


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] not in ("seal", "open"):
        sys.exit(__doc__)
    (seal if sys.argv[1] == "seal" else open_)(*sys.argv[2:])
