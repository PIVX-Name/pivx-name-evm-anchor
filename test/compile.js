const solc = require("solc"), fs = require("fs");
const sources = {};
for (const f of ["PiNSAnchor.sol", "MockPiNSAnchor.sol"]) sources[f] = { content: fs.readFileSync("../" + f, "utf8") };
// Test-only verifiers, so the real anchor (not the mock) can be driven through a rules change
sources["TestVerifiers.sol"] = { content: fs.readFileSync("TestVerifiers.sol", "utf8") };
const out = JSON.parse(solc.compile(JSON.stringify({
  language: "Solidity", sources,
  // evmVersion is pinned, not left to solc's shifting default (solc defaults to the
  // newest fork it knows), so the committed .bin is deterministic across solc builds. "shanghai"
  // is the exact floor the bytecode needs: it emits PUSH0 and no later opcode, so the
  // artifact runs on BSC and any other Shanghai-or-newer chain. The compiled runtime is
  // byte-identical whether this says shanghai, cancun, prague or osaka.
  settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "shanghai", outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } }
})));
for (const e of out.errors || []) console.log(e.severity.toUpperCase() + ": " + e.formattedMessage.split("\n")[0]);
if ((out.errors||[]).some(e => e.severity === "error")) process.exit(1);
fs.writeFileSync("artifacts.json", JSON.stringify(out.contracts));
console.log("COMPILED OK");
