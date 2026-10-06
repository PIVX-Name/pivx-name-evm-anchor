// State-machine tests for PiNSAnchor, via MockPiNSAnchor so the SP1 verifier is bypassed
// and the contract's own logic is what is under test.
//
// Every state-changing call passes an explicit gasLimit: ganache's eth_estimateGas
// evaluates against stale state once a prior estimate has reverted, which produces
// spurious failures. With a fixed limit, reverts surface as receipt status 0 instead.
const ganache = require("ganache");
const { ethers } = require("ethers");
const ART = require("./artifacts.json");
const A = ART["MockPiNSAnchor.sol"].MockPiNSAnchor;
const REAL = ART["PiNSAnchor.sol"].PiNSAnchor;
const EXPECTING = ART["TestVerifiers.sol"].ExpectingVerifier;
const ACCEPT_ALL = ART["TestVerifiers.sol"].AcceptAllVerifier;

const GAS = { gasLimit: 900000 };
const ZERO = "0x" + "00".repeat(32);
const R = (n) => "0x" + n.toString(16).padStart(64, "0");
const VK = (n) => "0x" + ("ab" + n.toString(16).padStart(2, "0")).padEnd(64, "0");
const LOCK = 7 * 24 * 3600; // MIN_RULES_TIMELOCK
const MAX_LOCK = 90 * 24 * 3600; // MAX_RULES_TIMELOCK
const pv = (a, b, h) => ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "uint32"], [a, b, h]);

let pass = 0, fail = 0;
const check = async (name, fn) => {
  try { await fn(); console.log("  PASS  " + name); pass++; }
  catch (e) { console.log("  FAIL  " + name + "\n        " + String(e.message).slice(0, 140)); fail++; }
};
const ok = async (p) => { const r = await (await p).wait(); if (r.status !== 1) throw new Error("tx reverted"); };

// Set once the chain is up; `reverts` replays against it to learn why a call failed.
let PROVIDER = null;
const ERRORS = new ethers.Interface([...A.abi, ...ART["TestVerifiers.sol"].ExpectingVerifier.abi]);

// Asserts that a transaction reverted - and, given `errName`, that it reverted with that
// custom error. Only a revert counts: any other failure (a bad argument, a dropped
// connection) is rethrown rather than mistaken for the contract refusing. The reason is
// recovered by replaying the same call against the state just before the transaction,
// since a mined receipt does not carry revert data. Without the name, a check can pass
// because some other guard happened to fire first.
const reverts = async (p, errName) => {
  const tx = await p;
  let receipt;
  try { receipt = await tx.wait(); }
  catch (e) { if (e.code !== "CALL_EXCEPTION") throw e; receipt = e.receipt; }
  if (!receipt || receipt.status !== 0) throw new Error("expected a revert, but it succeeded");
  if (!errName) return;
  try {
    await PROVIDER.call({ to: tx.to, from: tx.from, data: tx.data, blockTag: receipt.blockNumber - 1 });
  } catch (e) {
    const data = e.data ?? e.info?.error?.data;
    let name = null;
    try { name = data ? ERRORS.parseError(data)?.name : null; } catch { /* not one of ours */ }
    if (name === errName) return;
    throw new Error("reverted with " + (name ?? data ?? e.shortMessage) + ", expected " + errName);
  }
  throw new Error("the replayed call did not revert");
};
// `reverts` cannot take a deployment: `factory.deploy()` resolves to a contract, which has
// no `.wait()`, and the TypeError from calling it was caught as if it were the revert - so
// every constructor check passed whatever the constructor did. This waits for the
// deployment itself.
const deployReverts = async (p) => {
  try { await (await p).waitForDeployment(); }
  catch { return; }
  throw new Error("expected the deployment to revert, but it succeeded");
};

(async () => {
  const provider = new ethers.BrowserProvider(ganache.provider({ logging: { quiet: true } }));
  PROVIDER = provider;
  const [owner, seq, stranger, seq2] = [
    await provider.getSigner(0), await provider.getSigner(1),
    await provider.getSigner(2), await provider.getSigner(3),
  ];
  const factory = new ethers.ContractFactory(A.abi, "0x" + A.evm.bytecode.object, owner);
  const acceptAllFactory = new ethers.ContractFactory(ACCEPT_ALL.abi, "0x" + ACCEPT_ALL.evm.bytecode.object, owner);
  // Verifiers must have code now, so the mock gets real (if permissive) ones to point at
  const deployVerifier = async () => { const v = await acceptAllFactory.deploy(); await v.waitForDeployment(); return v.getAddress(); };
  const V1 = await deployVerifier();
  const V2 = await deployVerifier();
  const WALLET = "0x000000000000000000000000000000000000dEaD"; // an address with no code
  // Genesis is always the empty tree; the shared contract below commits R(1) at height
  // 100 as its first batch, so the tests that follow start from a committed root.
  const deploy = (sequencer) => factory.deploy(V1, VK(1), 99, sequencer, LOCK);
  // Moves the chain's clock forward, for the rules-change timelock
  const travel = async (secs) => {
    await provider.send("evm_increaseTime", [secs]);
    await provider.send("evm_mine", []);
  };

  await check("constructor rejects sequencer == deployer", () => deployReverts(deploy(owner.address)));
  await check("constructor rejects zero sequencer", () => deployReverts(deploy(ethers.ZeroAddress)));
  await check("constructor rejects a verifier with no code",
    () => deployReverts(factory.deploy(WALLET, VK(1), 99, seq.address, LOCK)));
  await check("constructor rejects a zero program key",
    () => deployReverts(factory.deploy(V1, ZERO, 99, seq.address, LOCK)));
  await check("constructor rejects a rules timelock shorter than the minimum",
    () => deployReverts(factory.deploy(V1, VK(1), 99, seq.address, LOCK - 1)));
  await check("constructor rejects a rules timelock longer than the maximum",
    () => deployReverts(factory.deploy(V1, VK(1), 99, seq.address, MAX_LOCK + 1)));
  await check("constructor accepts the minimum and the maximum rules timelock", async () => {
    for (const nLock of [LOCK, MAX_LOCK]) {
      const g = await factory.deploy(V1, VK(1), 99, seq.address, nLock);
      await g.waitForDeployment();
      if (Number(await g.rulesTimelock()) !== nLock) throw new Error("timelock not stored");
    }
  });
  await check("the mock refuses to deploy outside a test chain", async () => {
    // a second chain claiming BSC mainnet's id
    const bsc = new ethers.BrowserProvider(ganache.provider({ chain: { chainId: 56 }, logging: { quiet: true } }));
    const deployer = await bsc.getSigner(0);
    const v = await new ethers.ContractFactory(ACCEPT_ALL.abi, "0x" + ACCEPT_ALL.evm.bytecode.object, deployer).deploy();
    await v.waitForDeployment();
    const mockOnBsc = new ethers.ContractFactory(A.abi, "0x" + A.evm.bytecode.object, deployer);
    await deployReverts(mockOnBsc.deploy(await v.getAddress(), VK(1), 99, (await bsc.getSigner(1)).address, LOCK));
  });

  // --- anchoring from an empty registry (M7) ---
  // The compact SMT folds an empty tree to bytes32(0), so deploying at the registrar
  // wallet's birthday means genesis IS the zero root. It must be accepted there, and
  // rejected everywhere else.
  await check("deploys with the empty-tree root as genesis", async () => {
    const g = await factory.deploy(V1, VK(1), 3424542, seq.address, LOCK);
    await g.waitForDeployment();
    if (await g.currentRoot() !== ZERO) throw new Error("genesis root not stored");
    if (Number(await g.currentBlockHeight()) !== 3424542) throw new Error("birthday height not stored");
    if (!(await g.isRootValid(ZERO))) throw new Error("empty tree not recorded as a valid state");
    const st = await g.anchoredState();
    if (st.root !== ZERO || Number(st.blockHeight) !== 3424542 || Number(st.currentEpoch) !== 1)
      throw new Error("anchoredState does not describe the empty genesis");
  });
  await check("the first batch builds on the empty tree", async () => {
    const g = await factory.deploy(V1, VK(1), 3424542, seq.address, LOCK);
    await g.waitForDeployment();
    const G = g.connect(seq);
    await ok(G.commitBatch("0x", pv(ZERO, R(2), 3424543), GAS));
    if (await g.currentRoot() !== R(2)) throw new Error("first batch did not land");
    if (Number(await g.currentBlockHeight()) !== 3424543) throw new Error("height did not advance");
  });
  await check("a batch still cannot commit the empty root", async () => {
    const g = await factory.deploy(V1, VK(1), 3424542, seq.address, LOCK);
    await g.waitForDeployment();
    await reverts(g.connect(seq).commitBatch("0x", pv(ZERO, ZERO, 3424543), GAS), "InvalidRoot");
  });
  await check("rollback to the empty tree is still refused", async () => {
    const g = await factory.deploy(V1, VK(1), 3424542, seq.address, LOCK);
    await g.waitForDeployment();
    await ok(g.connect(seq).commitBatch("0x", pv(ZERO, R(2), 3424543), GAS));
    await reverts(g.connect(seq).proposeRootRollback(ZERO, GAS), "InvalidRoot");
  });

  const c = await deploy(seq.address); await c.waitForDeployment();
  const S = c.connect(seq), X = c.connect(stranger);
  await ok(S.commitBatch("0x", pv(ZERO, R(1), 100), GAS));

  // Sends a transaction and returns the decoded args of every `name` event it emitted, so
  // a test can assert on what the log actually says rather than only on resulting state.
  const logs = async (p) => {
    const r = await (await p).wait();
    if (r.status !== 1) throw new Error("tx reverted");
    const parsed = [];
    for (const log of r.logs) {
      try { const l = c.interface.parseLog(log); if (l) parsed.push(l); } catch { /* not one of ours */ }
    }
    return parsed;
  };
  const events = async (p, name) => (await logs(p)).filter((l) => l.name === name).map((l) => l.args);

  await check("rejects publicValues of the wrong length", () => reverts(S.commitBatch("0x", "0x1234", GAS), "InvalidPublicValues"));
  await check("rejects a wrong oldRoot", () => reverts(S.commitBatch("0x", pv(R(99), R(2), 101), GAS), "InvalidOldRoot"));
  await check("rejects a non-increasing block height", () => reverts(S.commitBatch("0x", pv(R(1), R(2), 100), GAS), "InvalidBlockHeight"));
  await check("rejects a zero newRoot", () => reverts(S.commitBatch("0x", pv(R(1), ZERO, 101), GAS), "InvalidRoot"));
  await check("rejects a stranger", () => reverts(X.commitBatch("0x", pv(R(1), R(2), 101), GAS), "NotSequencer"));
  await check("accepts a valid batch and advances state", async () => {
    await ok(S.commitBatch("0x", pv(R(1), R(2), 101), GAS));
    if (await c.currentRoot() !== R(2)) throw new Error("root not updated");
    if (Number(await c.currentBlockHeight()) !== 101) throw new Error("height not updated");
    if (!(await c.isRootValid(R(2)))) throw new Error("root not recorded");
    if (!(await c.isRootValid(R(1)))) throw new Error("earlier root lost from history");
    if (!(await c.isRootValid(ZERO))) throw new Error("genesis lost from history");
  });
  // Every operation raises a nonce, so an honest batch never reproduces an earlier state.
  // One that did would hold two indexes in the chain, and its record could name only one.
  await check("rejects a batch that leaves the root unchanged", () => reverts(S.commitBatch("0x", pv(R(2), R(2), 102), GAS), "InvalidRoot"));
  await check("rejects a batch that returns to an earlier anchored root", () => reverts(S.commitBatch("0x", pv(R(2), R(1), 102), GAS), "InvalidRoot"));
  await check("pause blocks commitBatch", async () => {
    await ok(c.pause(GAS));
    await reverts(S.commitBatch("0x", pv(R(2), R(3), 102), GAS), "EnforcedPause");
    await ok(c.unpause(GAS));
  });

  // --- timelocked rules change (M1) ---
  //
  // Verifier and program key change together, and only after the timelock: a client
  // pins `epoch`, so a new program reaches it only once it has been updated.
  const VERIFIER2 = V2;
  await check("starts at epoch 1", async () => {
    if (Number(await c.epoch()) !== 1) throw new Error("wrong initial epoch");
    const st = await c.anchoredState();
    if (st.root !== R(2) || Number(st.blockHeight) !== 101 || Number(st.currentEpoch) !== 1)
      throw new Error("anchoredState does not match the stored state");
  });
  await check("owner cannot propose a rules change (strict sequencer)", () => reverts(c.proposeRulesChange(VK(2), V2, GAS), "NotSequencer"));
  await check("stranger cannot propose a rules change", () => reverts(X.proposeRulesChange(VK(2), V2, GAS), "NotSequencer"));
  await check("approving with no pending proposal reverts", () => reverts(c.approveRulesChange(VK(2), V2, GAS), "NoPendingProposal"));
  await check("activating with nothing scheduled reverts", () => reverts(X.activateRulesChange(GAS), "NotScheduled"));
  await check("a proposal that changes nothing is refused", () => reverts(S.proposeRulesChange(VK(1), V1, GAS), "NoChange"));
  await check("a verifier with no code is refused", () => reverts(S.proposeRulesChange(VK(2), WALLET, GAS), "InvalidAddress"));
  await check("approval schedules the change instead of applying it", async () => {
    await ok(S.proposeRulesChange(VK(2), VERIFIER2, GAS));
    if (await c.pendingRulesVkey() !== VK(2)) throw new Error("proposal not stored");
    if (await c.pendingRulesVerifier() !== VERIFIER2) throw new Error("verifier not stored");
    const ev = await events(c.approveRulesChange(VK(2), VERIFIER2, GAS), "RulesChangeScheduled");
    if (ev.length !== 1 || ev[0].approver !== owner.address) throw new Error("schedule not announced with its approver");
    if (await c.programVkey() !== VK(1)) throw new Error("vkey changed before the timelock");
    if (await c.sp1Verifier() !== V1) throw new Error("verifier changed before the timelock");
    if (Number(await c.epoch()) !== 1) throw new Error("epoch moved before the timelock");
  });
  await check("cannot activate before the timelock has passed", async () => {
    await travel(LOCK - 120);
    await reverts(X.activateRulesChange(GAS), "TimelockActive");
  });
  await check("a scheduled change cannot be replaced by a new proposal", () => reverts(S.proposeRulesChange(VK(9), V1, GAS), "ChangeAlreadyScheduled"));
  await check("anyone activates it after the timelock, and the epoch advances", async () => {
    await travel(240);
    const all = await logs(X.activateRulesChange(GAS));
    const ev = all.filter((l) => l.name === "RulesChanged").map((l) => l.args);
    const ep = all.filter((l) => l.name === "EpochAdvanced").map((l) => l.args);
    if (await c.programVkey() !== VK(2)) throw new Error("vkey not applied");
    if (await c.sp1Verifier() !== VERIFIER2) throw new Error("verifier not applied");
    if (Number(await c.epoch()) !== 2) throw new Error("epoch not advanced");
    if (Number((await c.anchoredState()).currentEpoch) !== 2) throw new Error("anchoredState missed the new epoch");
    if (ev.length !== 1) throw new Error("change not announced");
    if (ep.length !== 1 || Number(ep[0].newEpoch) !== 2) throw new Error("epoch not announced");
    if (ev[0].oldVkey !== VK(1) || ev[0].oldVerifier !== V1) throw new Error("event lost the old rules");
    if (ev[0].activatedBy !== stranger.address) throw new Error("event does not name the activator");
    if (await c.pendingRulesVkey() !== ZERO || Number(await c.rulesChangeActivatesAt()) !== 0)
      throw new Error("pending change not cleared");
  });
  await check("sequencer cannot approve its own proposal", async () => {
    await ok(S.proposeRulesChange(VK(3), VERIFIER2, GAS));
    await reverts(S.approveRulesChange(VK(3), VERIFIER2, GAS), "Unauthorized");
  });
  await check("approving a key other than the one proposed reverts (TOCTOU guard)",
    () => reverts(c.approveRulesChange(VK(9), VERIFIER2, GAS), "ProposalMismatch"));
  await check("approving a verifier other than the one proposed reverts (TOCTOU guard)",
    () => reverts(c.approveRulesChange(VK(3), V1, GAS), "ProposalMismatch"));
  await check("owner can reject a proposal without changing the rules", async () => {
    await ok(c.revertRulesChange(GAS));
    if (await c.pendingRulesVkey() !== ZERO) throw new Error("pending not cleared");
    if (await c.programVkey() !== VK(2)) throw new Error("vkey changed on reject");
    if (Number(await c.epoch()) !== 2) throw new Error("epoch changed on reject");
  });
  await check("owner can cancel a change while its timelock runs", async () => {
    await ok(S.proposeRulesChange(VK(3), VERIFIER2, GAS));
    await ok(c.approveRulesChange(VK(3), VERIFIER2, GAS));
    const ev = await events(c.revertRulesChange(GAS), "RulesChangeReverted");
    if (ev.length !== 1 || ev[0].rejectedVkey !== VK(3)) throw new Error("cancellation not announced");
    await travel(LOCK + 1);
    await reverts(X.activateRulesChange(GAS), "NotScheduled");
    if (Number(await c.epoch()) !== 2) throw new Error("cancelled change took effect");
  });
  // The attack the version exists for: change the rules, use them, change them back. The
  // keys read the same afterwards; the version does not.
  await check("changing the rules and changing them back is two epochs, not zero", async () => {
    await ok(S.proposeRulesChange(VK(1), V1, GAS));
    await ok(c.approveRulesChange(VK(1), V1, GAS));
    await travel(LOCK);
    await ok(X.activateRulesChange(GAS));
    if (await c.programVkey() !== VK(1) || await c.sp1Verifier() !== V1) throw new Error("rules not restored");
    if (Number(await c.epoch()) !== 3) throw new Error("a reversal must not restore the old epoch");
  });
  await check("there is no single-step way to replace the verifier", async () => {
    if (c.interface.getFunction("updateVerifier") !== null) throw new Error("updateVerifier still exists");
  });

  // --- two-step rollback (M2) ---
  await check("cannot propose a rollback to an unknown root", () => reverts(S.proposeRootRollback(R(1234), GAS), "UnknownRoot"));
  await check("cannot propose a rollback to the current root", () => reverts(S.proposeRootRollback(R(2), GAS), "InvalidRoot"));
  await check("rollback approval requires pause", async () => {
    await ok(S.proposeRootRollback(R(1), GAS));
    await reverts(c.approveRootRollback(R(1), GAS), "ExpectedPause");
  });
  await check("rollback restores the earlier root and height, and advances the epoch", async () => {
    const nBefore = Number(await c.epoch());
    await ok(c.pause(GAS));
    const ep = await events(c.approveRootRollback(R(1), GAS), "EpochAdvanced");
    if (await c.currentRoot() !== R(1)) throw new Error("root not rolled back");
    if (Number(await c.currentBlockHeight()) !== 100) throw new Error("height not rolled back");
    // a rollback re-points names without their owners' signatures: pinned clients must stop
    if (Number(await c.epoch()) !== nBefore + 1) throw new Error("rollback did not advance the epoch");
    if (ep.length !== 1 || Number(ep[0].newEpoch) !== nBefore + 1) throw new Error("epoch not announced");
    await ok(c.unpause(GAS));
  });
  await check("the chain continues from the rolled-back state", async () => {
    await ok(S.commitBatch("0x", pv(R(1), R(5), 101), GAS));
    if (await c.currentRoot() !== R(5)) throw new Error("cannot build on the rolled-back root");
  });
  await check("rollback recovers a batch committed with a near-max uint32 height (H3)", async () => {
    await ok(S.commitBatch("0x", pv(R(5), R(6), 4294967290), GAS));
    await reverts(S.commitBatch("0x", pv(R(6), R(7), 4294967290), GAS), "InvalidBlockHeight"); // no height left
    await ok(c.pause(GAS));
    await ok(S.proposeRootRollback(R(5), GAS));
    await ok(c.approveRootRollback(R(5), GAS));
    await ok(c.unpause(GAS));
    await ok(S.commitBatch("0x", pv(R(5), R(8), 102), GAS));
    if (await c.currentRoot() !== R(8)) throw new Error("recovery failed");
  });

  // --- a rollback must repudiate what it undoes, not just move the head ---
  //
  // Without this, isRootValid() keeps returning true for the very roots the rollback
  // exists to disavow, and a Merkle proof against the defective state still verifies
  // for every client following the documented procedure.
  await check("a rolled-back root is repudiated, not merely superseded", async () => {
    await ok(S.commitBatch("0x", pv(R(8), R(20), 200), GAS));
    await ok(S.commitBatch("0x", pv(R(20), R(21), 201), GAS));
    if (!await c.isRootValid(R(20))) throw new Error("precondition: R20 should be valid");
    await ok(c.pause(GAS));
    await ok(S.proposeRootRollback(R(8), GAS));
    await ok(c.approveRootRollback(R(8), GAS));
    await ok(c.unpause(GAS));
    if (await c.isRootValid(R(20))) throw new Error("disavowed root still valid");
    if (await c.isRootValid(R(21))) throw new Error("disavowed tip still valid");
    if (!await c.isRootValid(R(8))) throw new Error("rollback target must stay valid");
  });
  // The regression that rules out the tempting one-line fix. Gating validity on
  // `blockHeight <= currentBlockHeight` passes the test above and fails this one: once
  // the chain is rebuilt past the disavowed heights, those roots slip back under the
  // ceiling and become valid again.
  await check("a disavowed root stays invalid once the chain passes its height", async () => {
    await ok(S.commitBatch("0x", pv(R(8), R(22), 250), GAS));
    if (await c.isRootValid(R(20))) throw new Error("disavowed root came back to life");
    if (await c.isRootValid(R(21))) throw new Error("disavowed root came back to life");
    if (!await c.isRootValid(R(22))) throw new Error("new root should be valid");
    // one more batch reuses the index R(21) held; it must stay disavowed as well
    await ok(S.commitBatch("0x", pv(R(22), R(23), 251), GAS));
    if (await c.isRootValid(R(21))) throw new Error("disavowed root revived by index reuse");
    const [fValid, nHeight] = await c.verifyRootValidity(R(20));
    if (fValid || Number(nHeight) !== 0) throw new Error("verifyRootValidity reports a disavowed root");
    const [fValid23, nHeight23] = await c.verifyRootValidity(R(23));
    if (!fValid23 || Number(nHeight23) !== 251) throw new Error("verifyRootValidity misreports a valid root");
  });
  await check("a disavowed root cannot be proposed as a rollback target",
    () => reverts(S.proposeRootRollback(R(20), GAS), "UnknownRoot"));

  // --- owner and sequencer must stay distinct keys (H4) ---
  //
  // The constructor enforces this because the two-step flows are only a control if a
  // second, different key approves. Every later path that can change either role has
  // to enforce it too, or the guarantee is one transaction away from evaporating.
  await check("the sequencer cannot be pointed at the owner",
    () => reverts(c.updateSequencer(owner.address, GAS), "InvalidAddress"));
  await check("ownership cannot be offered to the sequencer",
    () => reverts(c.transferOwnership(seq.address, GAS), "InvalidAddress"));
  await check("the sequencer cannot accept an ownership offer made before it was rotated in", async () => {
    await ok(c.transferOwnership(seq2.address, GAS));   // legal: seq2 is not the sequencer yet
    await ok(c.updateSequencer(seq2.address, GAS));     // now it is
    await reverts(c.connect(seq2).acceptOwnership(GAS), "InvalidAddress");
    await ok(c.updateSequencer(seq.address, GAS));      // restore for the tests below
    await ok(c.cancelOwnershipTransfer(GAS));
  });

  // --- rotating the sequencer must not leave the old key's proposals approvable (M4) ---
  await check("rotating the sequencer cancels its pending rules change", async () => {
    await ok(S.proposeRulesChange(VK(7), V1, GAS));
    if (await c.pendingRulesVkey() !== VK(7)) throw new Error("proposal not stored");
    const ev = await events(c.updateSequencer(seq2.address, GAS), "RulesChangeReverted");
    if (await c.pendingRulesVkey() !== ZERO) throw new Error("revoked key's proposal survived");
    if (ev.length !== 1) throw new Error("cancellation was not announced");
    if (ev[0].rejectedVkey !== VK(7)) throw new Error("wrong vkey in the event");
    if (ev[0].rejectedBy !== owner.address) throw new Error("event does not name who cancelled");
  });
  await check("the cancelled proposal can no longer be approved", () => reverts(c.approveRulesChange(VK(7), V1, GAS), "NoPendingProposal"));
  await check("the rotated-out sequencer can no longer propose", () => reverts(S.proposeRulesChange(VK(8), V1, GAS), "NotSequencer"));
  await check("rotating the sequencer cancels a change it proposed even once approved", async () => {
    const S2 = c.connect(seq2);
    await ok(S2.proposeRulesChange(VK(7), V1, GAS));
    await ok(c.approveRulesChange(VK(7), V1, GAS));
    await ok(c.updateSequencer(seq.address, GAS));
    await ok(c.updateSequencer(seq2.address, GAS)); // back to seq2 for the rollback test below
    await travel(LOCK + 1);
    await reverts(X.activateRulesChange(GAS), "NotScheduled");
    if (await c.programVkey() !== VK(1)) throw new Error("revoked key's approved change took effect");
  });
  await check("rotating the sequencer cancels its pending rollback", async () => {
    const S2 = c.connect(seq2);
    await ok(S2.proposeRootRollback(R(5), GAS));
    if (await c.pendingRollbackRoot() !== R(5)) throw new Error("proposal not stored");
    const ev = await events(c.updateSequencer(seq.address, GAS), "RootRollbackReverted");
    if (await c.pendingRollbackRoot() !== ZERO) throw new Error("revoked key's rollback survived");
    if (ev.length !== 1 || ev[0].rejectedRoot !== R(5)) throw new Error("cancellation was not announced");
    if (ev[0].rejectedBy !== owner.address) throw new Error("event does not name who cancelled");
  });
  await check("a rotation with nothing pending announces only the rotation", async () => {
    const r = await (await c.updateSequencer(seq.address, GAS)).wait();
    const names = r.logs.map((l) => { try { return c.interface.parseLog(l).name; } catch { return null; } });
    if (!names.includes("SequencerUpdated")) throw new Error("rotation not announced");
    if (names.includes("RulesChangeReverted") || names.includes("RootRollbackReverted"))
      throw new Error("spurious cancellation event");
  });

  // --- the authorisation trail must be reconstructible from logs alone (M6) ---
  await check("RulesChangeScheduled names the approver", async () => {
    await ok(S.proposeRulesChange(VK(4), V1, GAS));
    const ev = await events(c.approveRulesChange(VK(4), V1, GAS), "RulesChangeScheduled");
    if (ev.length !== 1) throw new Error("no RulesChangeScheduled event");
    if (ev[0].approver !== owner.address) throw new Error("approver not recorded");
    if (ev[0].newVkey !== VK(4)) throw new Error("wrong vkey");
    await ok(c.revertRulesChange(GAS));
  });
  await check("RulesChangeProposed names the proposer", async () => {
    const ev = await events(S.proposeRulesChange(VK(5), V1, GAS), "RulesChangeProposed");
    if (ev.length !== 1 || ev[0].proposer !== seq.address) throw new Error("proposer not recorded");
    await ok(c.revertRulesChange(GAS));
  });
  await check("RootRolledBack names the approver", async () => {
    await ok(c.pause(GAS));
    await ok(S.proposeRootRollback(R(5), GAS));
    const nTipBefore = Number(await c.tipIndex());
    const ev = await events(c.approveRootRollback(R(5), GAS), "RootRolledBack");
    await ok(c.unpause(GAS));
    if (ev.length !== 1) throw new Error("no RootRolledBack event");
    if (ev[0].approver !== owner.address) throw new Error("approver not recorded");
    if (Number(ev[0].toBlockHeight) !== 101) throw new Error("height lost from the event");
    if (Number(ev[0].batchesUndone) !== nTipBefore - Number(await c.tipIndex()))
      throw new Error("event does not say how many batches were undone");
  });

  // --- ownership offers must be withdrawable from both sides (M5) ---
  await check("cancelling with no offer outstanding reverts", () => reverts(c.cancelOwnershipTransfer(GAS), "NoPendingProposal"));
  await check("declining with no offer outstanding reverts", () => reverts(X.declineOwnership(GAS), "NotPendingOwner"));
  await check("owner can withdraw an ownership offer", async () => {
    await ok(c.transferOwnership(stranger.address, GAS));
    const ev = await events(c.cancelOwnershipTransfer(GAS), "OwnershipTransferCanceled");
    if (await c.pendingOwner() !== ethers.ZeroAddress) throw new Error("offer not withdrawn");
    if (ev.length !== 1) throw new Error("withdrawal was not announced");
    if (ev[0].canceledOwner !== stranger.address) throw new Error("wrong nominee in the event");
    if (ev[0].canceledBy !== owner.address) throw new Error("event does not name who withdrew");
  });
  await check("a withdrawn offer can no longer be accepted", () => reverts(X.acceptOwnership(GAS), "NotPendingOwner"));
  await check("a stranger cannot withdraw an offer", async () => {
    await ok(c.transferOwnership(stranger.address, GAS));
    await reverts(c.connect(seq2).cancelOwnershipTransfer(GAS), "Unauthorized");
    if (await c.pendingOwner() !== stranger.address) throw new Error("offer cleared by a stranger");
  });
  await check("the nominee can decline, and the event names them", async () => {
    const ev = await events(X.declineOwnership(GAS), "OwnershipTransferCanceled");
    if (await c.pendingOwner() !== ethers.ZeroAddress) throw new Error("offer not declined");
    if (ev.length !== 1) throw new Error("decline was not announced");
    if (ev[0].canceledBy !== stranger.address) throw new Error("event does not name the decliner");
    if (await c.owner() !== owner.address) throw new Error("declining changed the owner");
  });
  await check("someone who is not the nominee cannot decline", async () => {
    await ok(c.transferOwnership(stranger.address, GAS));
    await reverts(c.connect(seq2).declineOwnership(GAS), "NotPendingOwner");
    if (await c.pendingOwner() !== stranger.address) throw new Error("offer cleared by a non-nominee");
  });

  await check("2-step ownership transfer", async () => {
    if (await c.owner() !== owner.address) throw new Error("owner changed too early");
    await reverts(c.acceptOwnership(GAS), "NotPendingOwner");
    await ok(X.acceptOwnership(GAS));
    if (await c.owner() !== stranger.address) throw new Error("ownership not transferred");
  });

  // A rollback disavows the roots it undoes, so re-committing the same batch afterwards -
  // the honest recovery after a reorg - must still be possible.
  await check("a disavowed root can be committed again after a rollback", async () => {
    const g = await deploy(seq.address); await g.waitForDeployment();
    const G = g.connect(seq);
    await ok(G.commitBatch("0x", pv(ZERO, R(1), 100), GAS));
    await ok(G.commitBatch("0x", pv(R(1), R(2), 101), GAS));
    await ok(g.pause(GAS));
    await ok(G.proposeRootRollback(R(1), GAS));
    await ok(g.approveRootRollback(R(1), GAS));
    await ok(g.unpause(GAS));
    await ok(G.commitBatch("0x", pv(R(1), R(2), 101), GAS));
    if (await g.currentRoot() !== R(2) || !(await g.isRootValid(R(2)))) throw new Error("re-commit not accepted");
  });

  // The old rollback walked and deleted every undone root, so its cost grew with depth
  // until a deep one could not fit in a block. Moving the tip is one write however deep.
  await check("a rollback costs the same however many batches it undoes", async () => {
    const gasToUndo = async (nBatches) => {
      const g = await deploy(seq.address); await g.waitForDeployment();
      const G = g.connect(seq);
      let prev = ZERO;
      for (let i = 1; i <= nBatches + 1; i++) {
        await ok(G.commitBatch("0x", pv(prev, R(i), 99 + i), GAS));
        prev = R(i);
      }
      await ok(g.pause(GAS));
      await ok(G.proposeRootRollback(R(1), GAS));
      const r = await (await g.approveRootRollback(R(1), GAS)).wait();
      return Number(r.gasUsed);
    };
    const nShallow = await gasToUndo(1), nDeep = await gasToUndo(40);
    if (nDeep !== nShallow) throw new Error("undoing 1 batch cost " + nShallow + " gas, undoing 40 cost " + nDeep);
  });

  // --- the real anchor, not the mock: batches are checked against the rules in force ---
  //
  // The mock skips verification, so it cannot show which rules a batch was checked
  // against. These use stand-in verifiers to show that an approved change does nothing
  // until it is activated, and that what it lets in afterwards is marked with its version.
  const realFactory = new ethers.ContractFactory(REAL.abi, "0x" + REAL.evm.bytecode.object, owner);
  const expectingFactory = new ethers.ContractFactory(EXPECTING.abi, "0x" + EXPECTING.evm.bytecode.object, owner);
  const VALID = ethers.hexlify(ethers.toUtf8Bytes("valid"));
  const JUNK = "0x1234";
  let real, RS, strAcceptAll;
  await check("the real anchor accepts what its verifier accepts, and nothing else", async () => {
    const v1 = await expectingFactory.deploy(VK(1)); await v1.waitForDeployment();
    const acceptAll = await acceptAllFactory.deploy(); await acceptAll.waitForDeployment();
    strAcceptAll = await acceptAll.getAddress();
    real = await realFactory.deploy(await v1.getAddress(), VK(1), 99, seq.address, LOCK);
    await real.waitForDeployment();
    RS = real.connect(seq);
    await ok(RS.commitBatch(VALID, pv(ZERO, R(1), 100), GAS));
    await ok(RS.commitBatch(VALID, pv(R(1), R(2), 101), GAS));
    await reverts(RS.commitBatch(JUNK, pv(R(2), R(3), 102), GAS), "Error"); // the verifier's "invalid proof"
  });
  await check("an approved accept-anything verifier changes nothing during its notice period", async () => {
    await ok(RS.proposeRulesChange(VK(1), strAcceptAll, GAS));
    await ok(real.approveRulesChange(VK(1), strAcceptAll, GAS));
    // the owner, acting as fallback sequencer, with a junk proof: still checked by the old rules
    await reverts(real.commitBatch(JUNK, pv(R(2), R(66), 102), GAS), "Error");
    if (await real.currentRoot() !== R(2)) throw new Error("forged root landed during the notice period");
  });
  await check("after activation, what it lets in carries the new epoch for clients to refuse", async () => {
    await travel(LOCK);
    await ok(real.activateRulesChange(GAS));
    await ok(real.commitBatch(JUNK, pv(R(2), R(66), 102), GAS));
    const st = await real.anchoredState();
    if (st.root !== R(66)) throw new Error("precondition: the new verifier should accept anything");
    if (Number(st.currentEpoch) !== 2) throw new Error("the root is not marked with the new epoch");
  });

  console.log("\n" + pass + " passed, " + fail + " failed");
  process.exit(fail === 0 ? 0 : 1);
})();
