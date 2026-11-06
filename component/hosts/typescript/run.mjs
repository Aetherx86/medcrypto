// Runs the component from JavaScript, through the module that jco generates from it.
import { api } from "./generated/medcrypto.js";

const h = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const show = (bytes) => Buffer.from(bytes).toString("hex");
const text = (s) => new TextEncoder().encode(s);

// A result's error case arrives as an exception, and its payload is the enum's name.
function errorName(call) {
  try {
    call();
    return "no error";
  } catch (e) {
    return String(e.payload ?? e);
  }
}

const key = new Uint8Array(32);
const nonce = new Uint8Array(12);
const none = new Uint8Array(0);

console.log("sha256", show(api.sha256(text("abc"))));
console.log("hkdf", show(api.hkdf(new Uint8Array(22).fill(0x0b), h("000102030405060708090a0b0c"), h("f0f1f2f3f4f5f6f7f8f9"), 42)));
const sealed = api.seal(key, nonce, none, new Uint8Array(16));
console.log("seal", show(sealed));
console.log("open", show(api.open(key, nonce, none, sealed)));
const tampered = Uint8Array.from(sealed);
tampered[0] ^= 1;
console.log("open-tampered", errorName(() => api.open(key, nonce, none, tampered)));
console.log("seal-short-key", errorName(() => api.seal(new Uint8Array(31), nonce, none, none)));
const pair = api.keypairFromSeed(h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
console.log("public-key", show(pair.publicKey));
const signature = api.sign(pair.secretKey, none);
console.log("signature", show(signature));
console.log("verify", api.verify(pair.publicKey, none, signature));
console.log("verify-wrong-message", api.verify(pair.publicKey, text("x"), signature));
console.log("merkle-root", show(api.merkleRoot([none, h("00"), h("10")])));
console.log("audit-link", show(api.auditLink(text("ab"), text("c"))));
console.log("constant-time-equal", api.constantTimeEqual(text("a"), text("a")), api.constantTimeEqual(text("a"), text("b")));
