#!/usr/bin/env python3
"""Runs the component from Python, with no bindings beyond what the runtime provides."""
import copy
import sys

from wasmtime import Engine, Store
from wasmtime.component import Component, Linker

API = "medcrypto:crypto/api@0.2.0"
FHE = "medcrypto:crypto/fhe-ops@0.2.0"


class Medcrypto:
    def __init__(self, path):
        engine = Engine()
        self.store = Store(engine)
        self.instance = Linker(engine).instantiate(self.store, Component.from_file(engine, path))
        self.api = self.instance.get_export_index(self.store, API)
        self.fhe = self.instance.get_export_index(self.store, FHE)

    def call(self, name, *args):
        return self.call_in(self.api, name, *args)

    def fhe_call(self, name, *args):
        return self.call_in(self.fhe, name, *args)

    def call_in(self, interface, name, *args):
        index = self.instance.get_export_index(self.store, name, interface)
        func = self.instance.get_func(self.store, index)
        result = func(self.store, *args)
        func.post_return(self.store)
        return result


def h(text):
    return bytes.fromhex(text)


def show(value):
    return bytes(value).hex()


def error_name(call):
    # This runtime returns the error case of a result as the enum's name.
    result = call()
    return result if isinstance(result, str) else "no error"


def main(path):
    m = Medcrypto(path)
    key, nonce = bytes(32), bytes(12)
    print("sha256", show(m.call("sha256", b"abc")))
    print("hkdf", show(m.call("hkdf", b"\x0b" * 22, h("000102030405060708090a0b0c"), h("f0f1f2f3f4f5f6f7f8f9"), 42)))
    sealed = bytes(m.call("seal", key, nonce, b"", bytes(16)))
    print("seal", sealed.hex())
    print("open", show(m.call("open", key, nonce, b"", sealed)))
    tampered = bytes([sealed[0] ^ 1]) + sealed[1:]
    print("open-tampered", error_name(lambda: m.call("open", key, nonce, b"", tampered)))
    print("seal-short-key", error_name(lambda: m.call("seal", bytes(31), nonce, b"", b"")))
    pair = m.call("keypair-from-seed", h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
    public, secret = bytes(getattr(pair, "public-key")), bytes(getattr(pair, "secret-key"))
    print("public-key", public.hex())
    signature = bytes(m.call("sign", secret, b""))
    print("signature", signature.hex())
    lower = lambda b: str(b).lower()
    print("verify", lower(m.call("verify", public, b"", signature)))
    print("verify-wrong-message", lower(m.call("verify", public, b"x", signature)))
    print("merkle-root", show(m.call("merkle-root", [b"", h("00"), h("10")])))
    print("audit-link", show(m.call("audit-link", b"ab", b"c")))
    print("constant-time-equal", lower(m.call("constant-time-equal", b"a", b"a")), lower(m.call("constant-time-equal", b"a", b"b")))

    rounded = lambda values: " ".join("%.3f" % v for v in values)
    pair = m.fhe_call("keygen", bytes([1]) * 32)
    fhe_public, fhe_secret = bytes(getattr(pair, "public-key")), bytes(getattr(pair, "secret-key"))
    print("fhe-public-key", show(m.call("sha256", fhe_public)))
    a = m.fhe_call("encrypt-vector", fhe_public, [120.5, 80.0, 5.75], bytes([2]) * 32)
    b = m.fhe_call("encrypt-vector", fhe_public, [10.0, 20.0, 0.25], bytes([3]) * 32)
    print("fhe-decrypt", rounded(m.fhe_call("decrypt-vector", fhe_secret, a)))
    print("fhe-add", rounded(m.fhe_call("decrypt-vector", fhe_secret, m.fhe_call("homomorphic-add", a, b))))
    print("fhe-scalar-mul", rounded(m.fhe_call("decrypt-vector", fhe_secret, m.fhe_call("homomorphic-scalar-mul", a, 2.0))))
    print("fhe-scalar-half", rounded(m.fhe_call("decrypt-vector", fhe_secret, m.fhe_call("homomorphic-scalar-mul", a, 0.5))))
    print("fhe-bad-entropy", error_name(lambda: m.fhe_call("keygen", bytes(32))))
    garbage = copy.copy(a)
    setattr(garbage, "data", b"\x01\x02\x03")
    print("fhe-garbage", error_name(lambda: m.fhe_call("homomorphic-scalar-mul", garbage, 2.0)))


if __name__ == "__main__":
    main(sys.argv[1])
