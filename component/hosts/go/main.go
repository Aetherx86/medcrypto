// Runs the same component from Go.
//
// Go has no mature component runtime yet, so this host does by hand what one would do. It takes the core
// module out of the component file, and calls it using the Canonical ABI, the fixed convention by
// which a component's lists and results are laid out in memory. That works without any imports to
// supply, because this component has none.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const prefix = "medcrypto:crypto/api@0.1.0#"

var errorNames = []string{"bad-length", "authentication-failed", "bad-output-length", "weak-seed"}

// coreModule finds the core module, which is section 1 of a component.
func coreModule(component []byte) ([]byte, error) {
	if len(component) < 8 || string(component[:4]) != "\x00asm" {
		return nil, fmt.Errorf("not a WebAssembly binary")
	}
	for at := 8; at < len(component); {
		id := component[at]
		size, n := binary.Uvarint(component[at+1:])
		if n <= 0 || size > uint64(len(component)) {
			return nil, fmt.Errorf("bad section size")
		}
		body := at + 1 + n
		if body+int(size) > len(component) {
			return nil, fmt.Errorf("truncated section")
		}
		if id == 1 {
			return component[body : body+int(size)], nil
		}
		at = body + int(size)
	}
	return nil, fmt.Errorf("no core module")
}

type host struct {
	ctx context.Context
	mod api.Module
}

func (h *host) call(name string, args ...uint64) uint64 {
	f := h.mod.ExportedFunction(prefix + name)
	if f == nil {
		panic("no export " + name)
	}
	out, err := f.Call(h.ctx, args...)
	if err != nil {
		panic(err)
	}
	if len(out) == 0 {
		return 0
	}
	return out[0]
}

func (h *host) alloc(size, align uint64) uint64 {
	out, err := h.mod.ExportedFunction("cabi_realloc").Call(h.ctx, 0, 0, align, size)
	if err != nil {
		panic(err)
	}
	return out[0]
}

// list copies bytes into the module's memory, and gives the pointer and length a list is passed as.
func (h *host) list(data []byte) (uint64, uint64) {
	if len(data) == 0 {
		return 1, 0
	}
	p := h.alloc(uint64(len(data)), 1)
	if !h.mod.Memory().Write(uint32(p), data) {
		panic("write out of range")
	}
	return p, uint64(len(data))
}

func (h *host) u32(at uint64) uint32 {
	v, ok := h.mod.Memory().ReadUint32Le(uint32(at))
	if !ok {
		panic("read out of range")
	}
	return v
}

func (h *host) bytesAt(at uint64) []byte {
	p, n := h.u32(at), h.u32(at+4)
	data, ok := h.mod.Memory().Read(p, n)
	if !ok {
		panic("read out of range")
	}
	return append([]byte(nil), data...)
}

// A `result` is a tag at the start, and then at offset 4 either the value or the error enum.
func (h *host) result(ret uint64) ([]byte, string) {
	tag, _ := h.mod.Memory().ReadByte(uint32(ret))
	if tag == 0 {
		return h.bytesAt(ret + 4), ""
	}
	code, _ := h.mod.Memory().ReadByte(uint32(ret + 4))
	return nil, errorNames[code]
}

func decode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	ctx := context.Background()
	component, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	core, err := coreModule(component)
	if err != nil {
		panic(err)
	}
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)
	mod, err := runtime.InstantiateWithConfig(ctx, core, wazero.NewModuleConfig().WithStartFunctions())
	if err != nil {
		panic(err)
	}
	h := &host{ctx, mod}

	hexOf := func(name string, args ...uint64) string {
		return hex.EncodeToString(h.bytesAt(h.call(name, args...)))
	}
	two := func(a, b []byte) []uint64 {
		p, n := h.list(a)
		q, m := h.list(b)
		return []uint64{p, n, q, m}
	}
	four := func(a, b, c, d []byte) []uint64 {
		return append(two(a, b), two(c, d)...)
	}
	mustOk := func(data []byte, e string) []byte {
		if e != "" {
			panic(e)
		}
		return data
	}
	boolean := func(v uint64) string {
		if v != 0 {
			return "true"
		}
		return "false"
	}

	p, n := h.list([]byte("abc"))
	fmt.Println("sha256", hexOf("sha256", p, n))

	ikm := make([]byte, 22)
	for i := range ikm {
		ikm[i] = 0x0b
	}
	args := append(two(ikm, decode("000102030405060708090a0b0c")), 0, 0)
	q, m := h.list(decode("f0f1f2f3f4f5f6f7f8f9"))
	args[4], args[5] = q, m
	args = append(args, 42)
	fmt.Println("hkdf", hex.EncodeToString(mustOk(h.result(h.call("hkdf", args...)))))

	key, nonce := make([]byte, 32), make([]byte, 12)
	sealed := mustOk(h.result(h.call("seal", four(key, nonce, nil, make([]byte, 16))...)))
	fmt.Println("seal", hex.EncodeToString(sealed))
	fmt.Println("open", hex.EncodeToString(mustOk(h.result(h.call("open", four(key, nonce, nil, sealed)...)))))

	tampered := append([]byte(nil), sealed...)
	tampered[0] ^= 1
	_, e := h.result(h.call("open", four(key, nonce, nil, tampered)...))
	fmt.Println("open-tampered", e)
	_, e = h.result(h.call("seal", four(make([]byte, 31), nonce, nil, nil)...))
	fmt.Println("seal-short-key", e)

	p, n = h.list(decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	ret := h.call("keypair-from-seed", p, n)
	if tag, _ := mod.Memory().ReadByte(uint32(ret)); tag != 0 {
		panic("keypair failed")
	}
	// The record's two lists follow the tag in order.
	public, secret := h.bytesAt(ret+4), h.bytesAt(ret+12)
	fmt.Println("public-key", hex.EncodeToString(public))
	signature := mustOk(h.result(h.call("sign", two(secret, nil)...)))
	fmt.Println("signature", hex.EncodeToString(signature))

	verify := func(message []byte) uint64 {
		a := two(public, message)
		r, s := h.list(signature)
		return h.call("verify", append(a, r, s)...)
	}
	fmt.Println("verify", boolean(verify(nil)))
	fmt.Println("verify-wrong-message", boolean(verify([]byte("x"))))

	// A list of lists is an array of pointer and length pairs.
	leaves := [][]byte{nil, decode("00"), decode("10")}
	array := h.alloc(uint64(len(leaves))*8, 4)
	for i, leaf := range leaves {
		lp, ln := h.list(leaf)
		mod.Memory().WriteUint32Le(uint32(array)+uint32(i)*8, uint32(lp))
		mod.Memory().WriteUint32Le(uint32(array)+uint32(i)*8+4, uint32(ln))
	}
	fmt.Println("merkle-root", hexOf("merkle-root", array, uint64(len(leaves))))

	fmt.Println("audit-link", hexOf("audit-link", two([]byte("ab"), []byte("c"))...))
	fmt.Println("constant-time-equal",
		boolean(h.call("constant-time-equal", two([]byte("a"), []byte("a"))...)),
		boolean(h.call("constant-time-equal", two([]byte("a"), []byte("b"))...)))
}
