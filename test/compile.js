const solc = require("solc"), fs = require("fs");
const sources = {};
for (const f of ["PiNSAnchor.sol", "MockPiNSAnchor.sol"]) sources[f] = { content: fs.readFileSync("../" + f, "utf8") };
// Test-only verifiers, so the real anchor (not the mock) can be driven through a rules change
sources["TestVerifiers.sol"] = { content: fs.readFileSync("TestVerifiers.sol", "utf8") };
const out = JSON.parse(solc.compile(JSON.stringify({
  language: "Solidity", sources,
  settings: { optimizer: { enabled: true, runs: 200 }, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } }
})));
for (const e of out.errors || []) console.log(e.severity.toUpperCase() + ": " + e.formattedMessage.split("\n")[0]);
if ((out.errors||[]).some(e => e.severity === "error")) process.exit(1);
fs.writeFileSync("artifacts.json", JSON.stringify(out.contracts));
console.log("COMPILED OK");
