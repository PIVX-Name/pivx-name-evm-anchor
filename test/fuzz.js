// Randomised state-machine check for PiNSAnchor, via MockPiNSAnchor.
//
// test.js walks through scenarios someone thought of. This drives a seeded random
// sequence of commits (honest and malformed), rollbacks, rules changes and sequencer
// rotations against a deliberately simple reference model - an array of roots - and
// after every step compares everything a client can observe: the current root, the tip,
// the height, the epoch, and the validity of every root ever seen. A disagreement prints
// the seed and step, so the failing sequence can be replayed exactly.
const ganache = require("ganache");
const { ethers } = require("ethers");
const ART = require("./artifacts.json");
const A = ART["MockPiNSAnchor.sol"].MockPiNSAnchor;
const ACCEPT_ALL = ART["TestVerifiers.sol"].AcceptAllVerifier;

const GAS = { gasLimit: 900000 };
const ZERO = "0x" + "00".repeat(32);
const LOCK = 7 * 24 * 3600;
const BIRTHDAY = 1000;
const R = (n) => "0x" + n.toString(16).padStart(64, "0");
const VK = (n) => "0x" + ("cd" + n.toString(16).padStart(4, "0")).padEnd(64, "0");
const pv = (a, b, h) => ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "uint32"], [a, b, h]);

// mulberry32: small, seedable, good enough to pick operations
const rng = (seed) => () => {
  seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

// Sends a transaction and reports whether it succeeded. Only a revert counts as failure;
// anything else is a broken harness and is rethrown.
const attempt = async (p) => {
  try { const r = await (await p).wait(); return r.status === 1; }
  catch (e) { if (e.code === "CALL_EXCEPTION") return false; throw e; }
};

async function run(seed, steps) {
  const rand = rng(seed);
  const pick = (arr) => arr[Math.floor(rand() * arr.length)];
  const provider = new ethers.BrowserProvider(ganache.provider({ logging: { quiet: true } }));
  const [owner, seqA, seqB, stranger] = await Promise.all([0, 1, 2, 3].map((i) => provider.getSigner(i)));
  const v = await new ethers.ContractFactory(ACCEPT_ALL.abi, "0x" + ACCEPT_ALL.evm.bytecode.object, owner).deploy();
  await v.waitForDeployment();
  const verifier = await v.getAddress();
  const c = await new ethers.ContractFactory(A.abi, "0x" + A.evm.bytecode.object, owner)
    .deploy(verifier, VK(0), BIRTHDAY, seqA.address, LOCK);
  await c.waitForDeployment();

  // --- the model ---
  const m = {
    chain: [{ root: ZERO, height: BIRTHDAY }], // index = position; genesis at 0
    epoch: 1,
    vkey: VK(0),
    seq: seqA,
  };
  const seen = new Set([ZERO]);
  let nextRoot = 1, nextVk = 1;
  const tip = () => m.chain[m.chain.length - 1];
  const validIn = (root) => m.chain.some((e) => e.root === root);
  const stats = { commit: 0, commitRejected: 0, rollback: 0, rollbackRejected: 0, rules: 0, rotate: 0 };

  const fail = (step, what) => { throw new Error("seed " + seed + ", step " + step + ": " + what); };

  const compare = async (step, fAll) => {
    const st = await c.anchoredState();
    if (st.root !== tip().root) fail(step, "root " + st.root + " != model " + tip().root);
    if (Number(st.blockHeight) !== tip().height) fail(step, "height " + st.blockHeight + " != model " + tip().height);
    if (Number(st.currentEpoch) !== m.epoch) fail(step, "epoch " + st.currentEpoch + " != model " + m.epoch);
    if (Number(await c.tipIndex()) !== m.chain.length - 1) fail(step, "tipIndex disagrees with the model");
    if (await c.currentRoot() !== tip().root) fail(step, "currentRoot() disagrees with anchoredState()");
    if (!fAll) return;
    for (const root of seen) {
      const fModel = validIn(root);
      if (await c.isRootValid(root) !== fModel) fail(step, "isRootValid(" + root + ") != model " + fModel);
      const [fValid, nHeight] = await c.verifyRootValidity(root);
      const nExpected = fModel ? m.chain.find((e) => e.root === root).height : 0;
      if (fValid !== fModel || Number(nHeight) !== nExpected) fail(step, "verifyRootValidity(" + root + ") disagrees");
    }
    // one never-seen root, which must never read as valid
    if (await c.isRootValid(R(0xdead0000 + step))) fail(step, "an unknown root reads as valid");
  };

  for (let step = 0; step < steps; step++) {
    const roll = rand();
    const S = c.connect(m.seq);

    if (roll < 0.55) {
      // --- commit: mostly honest, sometimes each kind of malformed batch ---
      const kind = rand();
      let oldRoot = tip().root, newRoot, height = tip().height + 1 + Math.floor(rand() * 3);
      if (kind < 0.65) { newRoot = R(nextRoot++); }
      else if (kind < 0.72) { newRoot = pick([...seen]); }                 // re-anchor attempt
      else if (kind < 0.78) { oldRoot = R(0xbad00000 + step); newRoot = R(nextRoot++); } // wrong parent
      else if (kind < 0.84) { newRoot = R(nextRoot++); height = tip().height - Math.floor(rand() * 2); } // stale height
      else if (kind < 0.88) { newRoot = ZERO; }
      else { newRoot = R(nextRoot++); }                                     // honest, from a stranger below
      const signer = kind >= 0.88 && rand() < 0.5 ? stranger : m.seq;
      const fExpect = signer !== stranger && oldRoot === tip().root && newRoot !== ZERO &&
        !validIn(newRoot) && height > tip().height;
      const fGot = await attempt(c.connect(signer).commitBatch("0x", pv(oldRoot, newRoot, height), GAS));
      if (fGot !== fExpect) fail(step, "commit " + newRoot + " expected " + fExpect + ", got " + fGot);
      if (fGot) { m.chain.push({ root: newRoot, height }); seen.add(newRoot); stats.commit++; }
      else stats.commitRejected++;
    } else if (roll < 0.75) {
      // --- rollback, to a valid or deliberately invalid target ---
      const target = rand() < 0.8 ? pick(m.chain).root : pick([...seen]);
      const fExpect = target !== ZERO && target !== tip().root && validIn(target);
      if (!(await attempt(c.pause(GAS)))) fail(step, "pause failed");
      const fProposed = await attempt(S.proposeRootRollback(target, GAS));
      if (fProposed !== fExpect) fail(step, "rollback proposal to " + target + " expected " + fExpect);
      if (fProposed) {
        if (!(await attempt(c.approveRootRollback(target, GAS)))) fail(step, "approved rollback failed");
        m.chain.length = m.chain.findIndex((e) => e.root === target) + 1;
        m.epoch++;
        stats.rollback++;
      } else stats.rollbackRejected++;
      if (!(await attempt(c.unpause(GAS)))) fail(step, "unpause failed");
    } else if (roll < 0.85) {
      // --- a full rules change, sometimes cancelled ---
      const vk = VK(nextVk++);
      if (!(await attempt(S.proposeRulesChange(vk, verifier, GAS)))) fail(step, "rules proposal failed");
      if (!(await attempt(c.approveRulesChange(vk, verifier, GAS)))) fail(step, "rules approval failed");
      if (rand() < 0.3) {
        if (!(await attempt(c.revertRulesChange(GAS)))) fail(step, "rules revert failed");
      } else {
        if (await attempt(c.connect(stranger).activateRulesChange(GAS))) fail(step, "activated before the timelock");
        await provider.send("evm_increaseTime", [LOCK]);
        await provider.send("evm_mine", []);
        if (!(await attempt(c.connect(stranger).activateRulesChange(GAS)))) fail(step, "activation failed");
        m.vkey = vk; m.epoch++; stats.rules++;
      }
      if (await c.programVkey() !== m.vkey) fail(step, "programVkey disagrees with the model");
    } else {
      // --- rotate the sequencer, with a proposal left pending that must not survive ---
      const vk = VK(nextVk++);
      await attempt(S.proposeRulesChange(vk, verifier, GAS));
      const next = m.seq === seqA ? seqB : seqA;
      if (!(await attempt(c.updateSequencer(next.address, GAS)))) fail(step, "rotation failed");
      if (await c.pendingRulesVkey() !== ZERO) fail(step, "rotation left a proposal pending");
      m.seq = next; stats.rotate++;
    }

    await compare(step, step % 10 === 9 || step === steps - 1);
  }
  return stats;
}

(async () => {
  const seeds = (process.env.FUZZ_SEEDS || "1,2,3").split(",").map(Number);
  const steps = Number(process.env.FUZZ_STEPS || 250);
  for (const seed of seeds) {
    try {
      const stats = await run(seed, steps);
      console.log("  PASS  seed " + seed + ", " + steps + " steps " + JSON.stringify(stats));
    } catch (e) {
      console.log("  FAIL  " + e.message);
      process.exit(1);
    }
  }
})();
