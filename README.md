# covenants.diy

An interactive research and development environment for designing, analyzing, and evaluating Bitcoin covenant constructions and covenant-based protocols. It provides a visual interface for constructing Bitcoin Script programs, inspecting their execution, and experimenting with emerging covenant proposals and techniques.

**<https://covenants.diy>**

Signet and regtest only. A place to design and to learn, not to move money.

## What it knows

- OP_CHECKTEMPLATEVERIFY (BIP 119)
- OP_CHECKSIGFROMSTACK (BIP 348)
- OP_CAT (BIP 347)
- ANYPREVOUT (BIP 118)
- OP_TEMPLATEHASH (BIP 446)
- OP_INTERNALKEY (BIP 349)
- OP_PAIRCOMMIT (BIP 442)

Choose which are active in the header and every
script is marked enforced, degraded, or inert against that choice.

Nine worked examples ship with it: a vault, congestion control,
delegation, an oracle payout, rebindable state both ways, a merkle proof,
a covenant using only OP_CAT, and a recursive covenant.

## Build

```sh
cd web
npm install
npm run wasm   # compiles the Rust crates to wasm
npm run dev
```

`npm test` runs the browser suites, `cargo test` the Rust ones.

## Layout

| | |
|---|---|
| `crates/core` | template hashes, sighashes, taproot assembly, rulesets |
| `crates/interp` | a fork of rust-bitcoin-scriptexec (CC0) carrying the proposed opcodes |
| `crates/wasm` | browser bindings |
| `web` | the editor |
| `web/functions` | the endpoints a shared graph is stored in and read back from |

Every hash and signature is computed in the browser. The endpoints move
opaque payloads and never open one beyond checking that it is a graph.

## Sharing

File > Export > Permalink stores the graph and copies a short link to it,
`covenants.diy/g/<id>`. The id is the first ten characters of the
base64url SHA-256 of the payload, so the same graph always gets the same
link and is stored once.

## Licence

MIT, except `crates/interp`. That one is a fork of rust-bitcoin-scriptexec
and stays under the CC0-1.0 dedication it came with.
