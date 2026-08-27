// slcp_core.wasm host runner for the M4 differential harness (design §7,
// §13.5). Instantiates the FROZEN WASM ABI (src/wasm/slcp_host_abi.zig),
// supplies the three `slcp_driver` imports (§7.3) with the DEFAULT driver
// semantics (§8.4), and speaks a line protocol on stdin/stdout so
// `tests/wasm/differential_test.zig` can drive the real wasm side by side
// with the native engine.
//
// WHY A SCRIPTING RUNTIME, AND WHY THIS ONE
// -----------------------------------------
// The ABI is not zero-import: `combine_candidates` re-enters `slcp_alloc`
// while the engine is mid-transition (§7.3). A host that supplies those
// imports needs a real WebAssembly embedding, and wasmtime's CLI cannot
// provide host imports written in Zig-land without the C API + a build-time
// C dependency. Node and Deno both embed V8's WebAssembly natively.
// This file is authored as plain ESM using ONLY `node:fs` and `process`, so
// it runs unchanged under BOTH:
//     node tests/wasm/host.mjs zig-out/bin/slcp_core.wasm
//     deno run --allow-read tests/wasm/host.mjs zig-out/bin/slcp_core.wasm
// The Zig test spawns `node` (no permission flags, and `node` is the
// runtime already assumed by the repo tooling); Deno is the drop-in second
// opinion when the wasm is suspected of runtime-specific behavior.
//
// LINE PROTOCOL (newline-delimited JSON, one request per line, one response
// per line, strictly request/response ordered — never pipelined)
// ------------------------------------------------------------------------
// Requests carry an `id` echoed verbatim in the response. All byte payloads
// are lowercase hex strings. Every response has `ok: true|false`; a false
// response carries `err` (human text) and, when it came from the ABI's
// sticky error, `errCode` (slcp_host_abi.ErrorCode ordinal) and `errMsg`.
//
//   {"id":1,"cmd":"abi"}
//     -> {"id":1,"ok":true,"version":1,"min":1,"max":1,
//         "flagsLo":5,"flagsHi":0}
//   {"id":2,"cmd":"version"}
//     -> {"id":2,"ok":true,"version":"slcp-core 0.17.0-dev..."}
//   {"id":3,"cmd":"new","config":"<EngineConfig frame hex>"}
//     -> {"id":3,"ok":true,"handle":1} | {"ok":false,"errCode":5,...}
//   {"id":4,"cmd":"push","handle":1,"input":"<Input frame hex>"}
//     -> {"id":4,"ok":true,"pushed":1}
//        {"id":4,"ok":true,"pushed":0,"errCode":3,"errMsg":"..."}
//        (`pushed:0` is a TYPED refusal, not a harness failure — the native
//         side's pushInput error is expected to agree with it.)
//   {"id":5,"cmd":"counts","handle":1}
//     -> {"id":5,"ok":true,"count":3,"bytes":412}
//   {"id":6,"cmd":"drain","handle":1}
//     -> {"id":6,"ok":true,"effects":["<Effect frame hex>",...]}
//        (pop_effect/pop_commit until the queue is empty; each BORROWED
//         frame is copied out before the commit that frees it, §7.2.)
//   {"id":7,"cmd":"free","handle":1}          -> {"id":7,"ok":true}
//   {"id":8,"cmd":"qsetHash","qset":"<QuorumSet frame hex>"}
//     -> {"id":8,"ok":true,"hash":"<32-byte hex>"}
//   {"id":9,"cmd":"lint","qset":"<QuorumSet frame hex>"}
//     -> {"id":9,"ok":true,"frame":"<LintDiagnostics frame hex>"}
//   {"id":10,"cmd":"stats"}
//     -> {"id":10,"ok":true,"validate":91,"combine":4,"extract":0}
//        (cumulative slcp_driver import call counts — the non-vacuity gate:
//         a differential run that never entered combine_candidates has not
//         actually exercised the §7.3 re-entrant path.)
//   {"id":11,"cmd":"quit"}                    -> (exit 0, no response)
//
// Responses are bounded by the reader buffer on the Zig side (4 MiB); a
// `drain` whose effects exceed that is a harness limit, not an ABI limit.
//
// DRIVER IMPORTS (§7.3) — default driver semantics (§8.4)
// ------------------------------------------------------
//   validate_value      -> 2 (valid) iff len > 0, else 0 (invalid)
//   combine_candidates  -> lexicographic max of the ValueList frame's
//                          elements; empty list is a FAULT (nonzero), which
//                          is what native `defaultCombine` does with
//                          `error.DriverFault`
//   extract_valid_value -> 0 (none), matching `Driver.default()`'s null
//                          vtable slot: nomination.extractValid maps both a
//                          null slot and a `none` answer to `null`.
//
// CAPNP LAYOUT PARSED HERE (ValueList only — schema/host.capnp:52,
// `struct ValueList { values @0 :List(Data); }`)
// ------------------------------------------------------------------------
// A framed message (MessageBuilder.toBytes): u32 LE (segmentCount - 1),
// then segmentCount u32 LE word-sizes, padded to an 8-byte boundary, then
// the segments. Only single-segment frames are accepted (what
// MessageBuilder emits for this struct); far pointers throw, which surfaces
// as a driver fault rather than a silently wrong combine.
// Word 0 of segment 0 is the root STRUCT pointer:
//   lo&3 == 0, offset = signext30(lo>>>2) words past the pointer's own word,
//   dataWords = hi&0xffff, ptrWords = (hi>>>16)&0xffff.
// `values` is pointer #0 of that struct: a LIST pointer
//   (lo&3 == 1, elemSize = hi&7 == 6 -> pointer list, count = hi>>>3).
// Each element is itself a LIST pointer with elemSize 2 (bytes), count =
// byte length. A null pointer decodes as an empty Data.

import { readFileSync, writeSync } from "node:fs";

const WASM_PATH = process.argv[2] ?? "zig-out/bin/slcp_core.wasm";

// ---------------------------------------------------------------------------
// Memory views (re-created per access: the wasm memory can grow under us)
// ---------------------------------------------------------------------------

let wasm = null; // exports
let memory = null;

const u8 = () => new Uint8Array(memory.buffer);
const dv = () => new DataView(memory.buffer);

/// 16-byte scratch page for the ABI's out-params (out_ptr_ptr/out_len_ptr
/// pairs and slcp_error_take's 3-u32 out block). Allocated once.
let scratch = 0;

function copyIn(bytes) {
  const p = wasm.slcp_alloc(bytes.length);
  if (p === 0) throw new Error("slcp_alloc returned 0");
  if (bytes.length > 0) u8().set(bytes, p);
  return p;
}

function copyOut(ptr, len) {
  return u8().slice(ptr, ptr + len);
}

function readOutPair() {
  const d = dv();
  return [d.getUint32(scratch, true), d.getUint32(scratch + 4, true)];
}

/// Take the sticky error atomically (§7.2) and decode its STATIC text.
function takeError() {
  wasm.slcp_error_take(scratch);
  const d = dv();
  const code = d.getUint32(scratch, true);
  const ptr = d.getUint32(scratch + 4, true);
  const len = d.getUint32(scratch + 8, true);
  const msg = len === 0 ? "" : new TextDecoder().decode(copyOut(ptr, len));
  return { errCode: code, errMsg: msg };
}

// ---------------------------------------------------------------------------
// Minimal capnp reader — ValueList (see the layout note in the file header)
// ---------------------------------------------------------------------------

function signExt30(x) {
  return x >= 0x20000000 ? x - 0x40000000 : x;
}

class Seg {
  constructor(frame) {
    this.frame = frame;
    this.d = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    const segCount = this.d.getUint32(0, true) + 1;
    if (segCount !== 1) {
      throw new Error(`ValueList frame has ${segCount} segments; reader handles 1`);
    }
    this.words = this.d.getUint32(4, true);
    let base = 4 + 4 * segCount;
    if (base % 8 !== 0) base += 4;
    this.base = base;
  }

  /// Read the raw pointer words at segment word index `w`.
  ptr(w) {
    if (w < 0 || w >= this.words) throw new Error(`pointer word ${w} out of segment`);
    const off = this.base + w * 8;
    return { lo: this.d.getUint32(off, true), hi: this.d.getUint32(off + 4, true) };
  }

  bytesAt(word, len) {
    const start = this.base + word * 8;
    return this.frame.slice(start, start + len);
  }
}

/// Decode the `values` list of a framed ValueList into an array of
/// Uint8Array. Throws on anything the layout note does not cover.
function readValueList(ptr, len) {
  const seg = new Seg(u8().subarray(ptr, ptr + len));

  const root = seg.ptr(0);
  if (root.lo === 0 && root.hi === 0) return [];
  if ((root.lo & 3) === 2) throw new Error("far pointer at root; reader handles single-segment frames only");
  if ((root.lo & 3) !== 0) throw new Error("root is not a struct pointer");
  const structStart = 1 + signExt30(root.lo >>> 2);
  const dataWords = root.hi & 0xffff;
  const ptrWords = (root.hi >>> 16) & 0xffff;
  if (ptrWords < 1) return []; // `values` absent => empty list

  const listWord = structStart + dataWords;
  const lp = seg.ptr(listWord);
  if (lp.lo === 0 && lp.hi === 0) return [];
  if ((lp.lo & 3) === 2) throw new Error("far pointer at ValueList.values");
  if ((lp.lo & 3) !== 1) throw new Error("ValueList.values is not a list pointer");
  const elemSize = lp.hi & 7;
  if (elemSize !== 6) throw new Error(`ValueList.values elemSize ${elemSize}, expected 6 (pointer list)`);
  const count = lp.hi >>> 3;
  const listStart = listWord + 1 + signExt30(lp.lo >>> 2);

  const out = [];
  for (let i = 0; i < count; i += 1) {
    const w = listStart + i;
    const ep = seg.ptr(w);
    if (ep.lo === 0 && ep.hi === 0) {
      out.push(new Uint8Array(0));
      continue;
    }
    if ((ep.lo & 3) === 2) throw new Error("far pointer at ValueList element");
    if ((ep.lo & 3) !== 1) throw new Error("ValueList element is not a list pointer");
    const esize = ep.hi & 7;
    if (esize !== 2) throw new Error(`ValueList element elemSize ${esize}, expected 2 (bytes)`);
    const ecount = ep.hi >>> 3;
    out.push(seg.bytesAt(w + 1 + signExt30(ep.lo >>> 2), ecount));
  }
  return out;
}

/// std.mem.order over bytes: element-wise, then by length.
function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

// ---------------------------------------------------------------------------
// slcp_driver imports (§7.3)
// ---------------------------------------------------------------------------

function driverFault(what, e) {
  process.stderr.write(`slcp_driver.${what}: ${e && e.stack ? e.stack : e}\n`);
}

const stats = { validate: 0, combine: 0, extract: 0 };

const slcp_driver = {
  // 0 invalid | 1 maybeValid | 2 valid | 3+ fault
  validate_value(_slotLo, _slotHi, _ptr, len, _isNomination) {
    stats.validate += 1;
    return len > 0 ? 2 : 0;
  },

  // 0 = ok; the result is written into an slcp_alloc'd buffer that the
  // engine copies and frees.
  combine_candidates(_slotLo, _slotHi, listPtr, listLen, outPtrPtr, outLenPtr) {
    stats.combine += 1;
    try {
      const values = readValueList(listPtr, listLen);
      if (values.length === 0) return 1; // native defaultCombine: error.DriverFault
      let best = values[0];
      for (let i = 1; i < values.length; i += 1) {
        if (cmpBytes(values[i], best) > 0) best = values[i];
      }
      const p = wasm.slcp_alloc(best.length);
      if (p === 0) return 2;
      u8().set(best, p);
      const d = dv();
      d.setUint32(outPtrPtr, p, true);
      d.setUint32(outLenPtr, best.length, true);
      return 0;
    } catch (e) {
      driverFault("combine_candidates", e);
      return 3;
    }
  },

  // 0 none | 1 some | other = fault. The default driver has no extractor.
  extract_valid_value(_slotLo, _slotHi, _ptr, _len, _outPtrPtr, _outLenPtr) {
    stats.extract += 1;
    return 0;
  },
};

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

function toHex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 1) s += HEX[bytes[i]];
  return s;
}

function fromHex(s) {
  if (typeof s !== "string" || s.length % 2 !== 0) throw new Error("bad hex payload");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

function handle(req) {
  switch (req.cmd) {
    case "abi":
      return {
        ok: true,
        version: wasm.slcp_abi_version(),
        min: wasm.slcp_abi_min_version(),
        max: wasm.slcp_abi_max_version(),
        flagsLo: wasm.slcp_feature_flags_lo(),
        flagsHi: wasm.slcp_feature_flags_hi(),
      };

    case "version": {
      wasm.slcp_version_string(scratch, scratch + 4);
      const [p, l] = readOutPair();
      if (p === 0) return { ok: false, err: "slcp_version_string returned null" };
      const s = new TextDecoder().decode(copyOut(p, l));
      wasm.slcp_buf_free(p, l); // OWNED
      return { ok: true, version: s };
    }

    case "new": {
      const cfg = fromHex(req.config);
      const p = copyIn(cfg);
      const h = wasm.slcp_engine_new(p, cfg.length);
      wasm.slcp_free(p, cfg.length);
      if (h === 0) return { ok: false, err: "slcp_engine_new returned 0", ...takeError() };
      return { ok: true, handle: h };
    }

    case "push": {
      const bytes = fromHex(req.input);
      const p = copyIn(bytes);
      const rc = wasm.slcp_engine_push_input(req.handle, p, bytes.length);
      wasm.slcp_free(p, bytes.length);
      if (rc === 0) return { ok: true, pushed: 0, ...takeError() };
      return { ok: true, pushed: 1 };
    }

    case "counts":
      return {
        ok: true,
        count: wasm.slcp_engine_effect_count(req.handle),
        bytes: wasm.slcp_engine_effect_bytes(req.handle),
      };

    case "drain": {
      const effects = [];
      for (;;) {
        const has = wasm.slcp_engine_pop_effect(req.handle, scratch, scratch + 4);
        if (has === 0) {
          const code = wasm.slcp_last_error_code();
          if (code !== 0) return { ok: false, err: "pop_effect failed", ...takeError() };
          break;
        }
        const [p, l] = readOutPair();
        effects.push(toHex(copyOut(p, l))); // BORROWED — copy before commit
        wasm.slcp_engine_pop_commit(req.handle);
      }
      return { ok: true, effects };
    }

    case "free":
      wasm.slcp_engine_free(req.handle);
      return { ok: true };

    case "qsetHash": {
      const q = fromHex(req.qset);
      const p = copyIn(q);
      const out = wasm.slcp_alloc(32);
      const rc = wasm.slcp_qset_hash(p, q.length, out);
      const res = rc === 0
        ? { ok: false, err: "slcp_qset_hash failed", ...takeError() }
        : { ok: true, hash: toHex(copyOut(out, 32)) };
      wasm.slcp_free(out, 32);
      wasm.slcp_free(p, q.length);
      return res;
    }

    case "lint": {
      const q = fromHex(req.qset);
      const p = copyIn(q);
      const rc = wasm.slcp_lint_qset(p, q.length, scratch, scratch + 4);
      wasm.slcp_free(p, q.length);
      if (rc === 0) return { ok: false, err: "slcp_lint_qset failed", ...takeError() };
      const [op, ol] = readOutPair();
      const frame = toHex(copyOut(op, ol));
      wasm.slcp_buf_free(op, ol); // OWNED
      return { ok: true, frame };
    }

    case "stats":
      return { ok: true, ...stats };

    default:
      return { ok: false, err: `unknown cmd ${JSON.stringify(req.cmd)}` };
  }
}

// ---------------------------------------------------------------------------
// stdin/stdout pump
// ---------------------------------------------------------------------------

const enc = new TextEncoder();

function writeLine(obj) {
  const bytes = enc.encode(JSON.stringify(obj) + "\n");
  let off = 0;
  while (off < bytes.length) {
    try {
      off += writeSync(1, bytes, off, bytes.length - off);
    } catch (e) {
      if (e.code === "EAGAIN") continue; // non-blocking pipe: spin
      throw e;
    }
  }
}

function main() {
  const module = new WebAssembly.Module(readFileSync(WASM_PATH));
  const instance = new WebAssembly.Instance(module, { slcp_driver });
  wasm = instance.exports;
  memory = wasm.memory;
  scratch = wasm.slcp_alloc(16);
  if (scratch === 0) throw new Error("scratch allocation failed");

  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buf += chunk;
    for (;;) {
      const nl = buf.indexOf("\n");
      if (nl < 0) break;
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (line.trim().length === 0) continue;

      let req;
      try {
        req = JSON.parse(line);
      } catch (e) {
        writeLine({ id: null, ok: false, err: `bad request json: ${e.message}` });
        continue;
      }
      if (req.cmd === "quit") process.exit(0);
      let res;
      try {
        res = handle(req);
      } catch (e) {
        res = { ok: false, err: `${e && e.stack ? e.stack : e}` };
      }
      res.id = req.id ?? null;
      writeLine(res);
    }
  });
  process.stdin.on("end", () => process.exit(0));
}

main();
