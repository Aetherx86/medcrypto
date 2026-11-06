#!/usr/bin/env python3
"""Runs the component from Python, with no bindings beyond what the runtime provides."""
import sys

from wasmtime import Engine, Store
from wasmtime.component import Component, Linker

INTERFACE = "medcrypto:crypto/api@0.1.0"


class Medcrypto:
    def __init__(self, path):
        engine = Engine()
        self.store = Store(engine)
        self.instance = Linker(engine).instantiate(self.store, Component.from_file(engine, path))
        self.interface = self.instance.get_export_index(self.store, INTERFACE)

    def call(self, name, *args):
        index = self.instance.get_export_index(self.store, name, self.interface)
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


if __name__ == "__main__":
    main(sys.argv[1])
