// Runs the component from JavaScript, through the module that jco generates from it.
import { api, fheOps, bfvOps, pqSignatures } from "./generated/medcrypto.js";

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

const rounded = (values) => Array.from(values, (v) => v.toFixed(3)).join(" ");
const fhe = fheOps.keygen(new Uint8Array(32).fill(1));
console.log("fhe-public-key", show(api.sha256(fhe.publicKey)));
const a = fheOps.encryptVector(fhe.publicKey, Float64Array.of(120.5, 80.0, 5.75), new Uint8Array(32).fill(2));
const b = fheOps.encryptVector(fhe.publicKey, Float64Array.of(10.0, 20.0, 0.25), new Uint8Array(32).fill(3));
console.log("fhe-decrypt", rounded(fheOps.decryptVector(fhe.secretKey, a)));
console.log("fhe-add", rounded(fheOps.decryptVector(fhe.secretKey, fheOps.homomorphicAdd(a, b))));
console.log("fhe-scalar-mul", rounded(fheOps.decryptVector(fhe.secretKey, fheOps.homomorphicScalarMul(a, 2.0))));
console.log("fhe-scalar-half", rounded(fheOps.decryptVector(fhe.secretKey, fheOps.homomorphicScalarMul(a, 0.5))));
console.log("fhe-bad-entropy", errorName(() => fheOps.keygen(new Uint8Array(32))));
console.log("fhe-garbage", errorName(() => fheOps.homomorphicScalarMul({ ...a, data: Uint8Array.of(1, 2, 3) }, 2.0)));

const integers = (values) => Array.from(values, (v) => v.toString()).join(" ");
const filled = (byte) => new Uint8Array(32).fill(byte);
const bfvPair = bfvOps.keygen(filled(4));
console.log("bfv-public-key", show(api.sha256(bfvPair.publicKey)));
const relin = bfvOps.relinKeygen(bfvPair.secretKey, filled(5));
const x = bfvOps.encrypt(bfvPair.publicKey, 20, BigInt64Array.of(1000n, -2000n, 3n), filled(6));
const y = bfvOps.encrypt(bfvPair.publicKey, 20, BigInt64Array.of(5n, 60n, -7n), filled(7));
console.log("bfv-ciphertext", show(api.sha256(x.data)));
console.log("bfv-decrypt", integers(bfvOps.decrypt(bfvPair.secretKey, x)));
console.log("bfv-add", integers(bfvOps.decrypt(bfvPair.secretKey, bfvOps.add(x, y))));
const product = bfvOps.multiply(x, y, relin);
console.log("bfv-multiply", integers(bfvOps.decrypt(bfvPair.secretKey, product)));
console.log("bfv-budget-left", bfvOps.noiseBudget(bfvPair.secretKey, product) > 1.0);
console.log("bfv-bad-entropy", errorName(() => bfvOps.keygen(new Uint8Array(32))));

const seed = filled(8);
const hybrid = pqSignatures.publicKeyFromSeed(seed);
console.log("pq-public-key", show(api.sha256(hybrid.ed25519)), show(api.sha256(hybrid.mlDsa65)));
const hybridSignature = pqSignatures.sign(seed, text("ctx"), text("message"), filled(9));
console.log("pq-signature", show(api.sha256(hybridSignature.ed25519)), show(api.sha256(hybridSignature.mlDsa65)));
console.log("pq-verify", pqSignatures.verify(hybrid, text("ctx"), text("message"), hybridSignature));
console.log("pq-verify-wrong-message", pqSignatures.verify(hybrid, text("ctx"), text("other"), hybridSignature));
console.log("pq-verify-stripped", pqSignatures.verify(hybrid, text("ctx"), text("message"), { ...hybridSignature, mlDsa65: none }));
console.log("pq-weak-seed", errorName(() => pqSignatures.publicKeyFromSeed(new Uint8Array(32))));
