// State-machine tests for PiNSAnchor, via MockPiNSAnchor so the SP1 verifier is bypassed
// and the contract's own logic is what is under test.
//
// Every state-changing call passes an explicit gasLimit: ganache's eth_estimateGas
// evaluates against stale state once a prior estimate has reverted, which produces
// spurious failures. With a fixed limit, reverts surface as receipt status 0 instead.
const ganache = require("ganache");
const { ethers } = require("ethers");
const A = require("./artifacts.json")["MockPiNSAnchor.sol"].MockPiNSAnchor;

const GAS = { gasLimit: 900000 };
const ZERO = "0x" + "00".repeat(32);
const DEAD = "0x000000000000000000000000000000000000dEaD";
const R = (n) => "0x" + n.toString(16).padStart(64, "0");
const VK = (n) => "0x" + ("ab" + n.toString(16).padStart(2, "0")).padEnd(64, "0");
const pv = (a, b, h) => ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "uint32"], [a, b, h]);

let pass = 0, fail = 0;
const check = async (name, fn) => {
  try { await fn(); console.log("  PASS  " + name); pass++; }
  catch (e) { console.log("  FAIL  " + name + "\n        " + String(e.message).slice(0, 140)); fail++; }
};
const ok = async (p) => { const r = await (await p).wait(); if (r.status !== 1) throw new Error("tx reverted"); };
const reverts = async (p) => {
  try { const r = await (await p).wait(); if (r.status === 0) return; }
  catch { return; }
  throw new Error("expected a revert, but it succeeded");
};

(async () => {
  const provider = new ethers.BrowserProvider(ganache.provider({ logging: { quiet: true } }));
  const [owner, seq, stranger, seq2] = [
    await provider.getSigner(0), await provider.getSigner(1),
    await provider.getSigner(2), await provider.getSigner(3),
  ];
  const factory = new ethers.ContractFactory(A.abi, "0x" + A.evm.bytecode.object, owner);
  const deploy = (sequencer) => factory.deploy(DEAD, VK(1), R(1), 100, sequencer);

  await check("constructor rejects sequencer == deployer", () => reverts(deploy(owner.address)));
  await check("constructor rejects zero sequencer", () => reverts(deploy(ethers.ZeroAddress)));

  // --- anchoring from an empty registry (M7) ---
  // The compact SMT folds an empty tree to bytes32(0), so deploying at the registrar
  // wallet's birthday means genesis IS the zero root. It must be accepted there, and
  // rejected everywhere else.
  await check("deploys with the empty-tree root as genesis", async () => {
    const g = await factory.deploy(DEAD, VK(1), ZERO, 3424542, seq.address);
    await g.waitForDeployment();
    if (await g.currentRoot() !== ZERO) throw new Error("genesis root not stored");
    if (Number(await g.currentBlockHeight()) !== 3424542) throw new Error("birthday height not stored");
    if (!(await g.isRootValid(ZERO))) throw new Error("empty tree not recorded as a valid state");
  });
  await check("the first batch builds on the empty tree", async () => {
    const g = await factory.deploy(DEAD, VK(1), ZERO, 3424542, seq.address);
    await g.waitForDeployment();
    const G = g.connect(seq);
    await ok(G.commitBatch("0x", pv(ZERO, R(2), 3424543), GAS));
    if (await g.currentRoot() !== R(2)) throw new Error("first batch did not land");
    if (Number(await g.currentBlockHeight()) !== 3424543) throw new Error("height did not advance");
  });
  await check("a batch still cannot commit the empty root", async () => {
    const g = await factory.deploy(DEAD, VK(1), ZERO, 3424542, seq.address);
    await g.waitForDeployment();
    await reverts(g.connect(seq).commitBatch("0x", pv(ZERO, ZERO, 3424543), GAS));
  });
  await check("rollback to the empty tree is still refused", async () => {
    const g = await factory.deploy(DEAD, VK(1), ZERO, 3424542, seq.address);
    await g.waitForDeployment();
    await ok(g.connect(seq).commitBatch("0x", pv(ZERO, R(2), 3424543), GAS));
    await reverts(g.connect(seq).proposeRootRollback(ZERO, GAS));
  });

  const c = await deploy(seq.address); await c.waitForDeployment();
  const S = c.connect(seq), X = c.connect(stranger);

  // Sends a transaction and returns the decoded args of every `name` event it emitted, so
  // a test can assert on what the log actually says rather than only on resulting state.
  const events = async (p, name) => {
    const r = await (await p).wait();
    if (r.status !== 1) throw new Error("tx reverted");
    const found = [];
    for (const log of r.logs) {
      let parsed = null;
      try { parsed = c.interface.parseLog(log); } catch { /* not one of ours */ }
      if (parsed && parsed.name === name) found.push(parsed.args);
    }
    return found;
  };

  await check("rejects publicValues of the wrong length", () => reverts(S.commitBatch("0x", "0x1234", GAS)));
  await check("rejects a wrong oldRoot", () => reverts(S.commitBatch("0x", pv(R(99), R(2), 101), GAS)));
  await check("rejects a non-increasing block height", () => reverts(S.commitBatch("0x", pv(R(1), R(2), 100), GAS)));
  await check("rejects a zero newRoot", () => reverts(S.commitBatch("0x", pv(R(1), ZERO, 101), GAS)));
  await check("rejects a stranger", () => reverts(X.commitBatch("0x", pv(R(1), R(2), 101), GAS)));
  await check("accepts a valid batch and advances state", async () => {
    await ok(S.commitBatch("0x", pv(R(1), R(2), 101), GAS));
    if (await c.currentRoot() !== R(2)) throw new Error("root not updated");
    if (Number(await c.currentBlockHeight()) !== 101) throw new Error("height not updated");
    if (!(await c.isRootValid(R(2)))) throw new Error("root not recorded");
    if (!(await c.isRootValid(R(1)))) throw new Error("genesis root lost from history");
  });
  await check("pause blocks commitBatch", async () => {
    await ok(c.pause(GAS));
    await reverts(S.commitBatch("0x", pv(R(2), R(3), 102), GAS));
    await ok(c.unpause(GAS));
  });

  // --- two-step program upgrade (M1) ---
  await check("owner cannot propose an upgrade (strict sequencer)", () => reverts(c.proposeProgramUpgrade(VK(2), GAS)));
  await check("stranger cannot propose an upgrade", () => reverts(X.proposeProgramUpgrade(VK(2), GAS)));
  await check("approving with no pending proposal reverts", () => reverts(c.approveProgramUpgrade(VK(2), GAS)));
  await check("sequencer proposes, owner approves", async () => {
    await ok(S.proposeProgramUpgrade(VK(2), GAS));
    if (await c.pendingProgramVkey() !== VK(2)) throw new Error("proposal not stored");
    await ok(c.approveProgramUpgrade(VK(2), GAS));
    if (await c.programVkey() !== VK(2)) throw new Error("vkey not applied");
    if (await c.pendingProgramVkey() !== ZERO) throw new Error("pending not cleared");
  });
  await check("sequencer cannot approve its own proposal", async () => {
    await ok(S.proposeProgramUpgrade(VK(3), GAS));
    await reverts(S.approveProgramUpgrade(VK(3), GAS));
  });
  await check("approving a key other than the one proposed reverts (TOCTOU guard)",
    () => reverts(c.approveProgramUpgrade(VK(9), GAS)));
  await check("owner can reject a proposal without changing the vkey", async () => {
    await ok(c.revertProgramUpgrade(GAS));
    if (await c.pendingProgramVkey() !== ZERO) throw new Error("pending not cleared");
    if (await c.programVkey() !== VK(2)) throw new Error("vkey changed on reject");
  });

  // --- two-step rollback (M2) ---
  await check("cannot propose a rollback to an unknown root", () => reverts(S.proposeRootRollback(R(1234), GAS)));
  await check("rollback approval requires pause", async () => {
    await ok(S.proposeRootRollback(R(1), GAS));
    await reverts(c.approveRootRollback(R(1), GAS));
  });
  await check("rollback restores the earlier root and height", async () => {
    await ok(c.pause(GAS));
    await ok(c.approveRootRollback(R(1), GAS));
    if (await c.currentRoot() !== R(1)) throw new Error("root not rolled back");
    if (Number(await c.currentBlockHeight()) !== 100) throw new Error("height not rolled back");
    await ok(c.unpause(GAS));
  });
  await check("the chain continues from the rolled-back state", async () => {
    await ok(S.commitBatch("0x", pv(R(1), R(5), 101), GAS));
    if (await c.currentRoot() !== R(5)) throw new Error("cannot build on the rolled-back root");
  });
  await check("rollback recovers a batch committed with a near-max uint32 height (H3)", async () => {
    await ok(S.commitBatch("0x", pv(R(5), R(6), 4294967290), GAS));
    await reverts(S.commitBatch("0x", pv(R(6), R(7), 4294967290), GAS)); // no height left
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
  });
  await check("a disavowed root cannot be proposed as a rollback target",
    () => reverts(S.proposeRootRollback(R(20), GAS)));

  // --- owner and sequencer must stay distinct keys (H4) ---
  //
  // The constructor enforces this because the two-step flows are only a control if a
  // second, different key approves. Every later path that can change either role has
  // to enforce it too, or the guarantee is one transaction away from evaporating.
  await check("the sequencer cannot be pointed at the owner",
    () => reverts(c.updateSequencer(owner.address, GAS)));
  await check("ownership cannot be offered to the sequencer",
    () => reverts(c.transferOwnership(seq.address, GAS)));
  await check("the sequencer cannot accept an ownership offer made before it was rotated in", async () => {
    await ok(c.transferOwnership(seq2.address, GAS));   // legal: seq2 is not the sequencer yet
    await ok(c.updateSequencer(seq2.address, GAS));     // now it is
    await reverts(c.connect(seq2).acceptOwnership(GAS));
    await ok(c.updateSequencer(seq.address, GAS));      // restore for the tests below
    await ok(c.cancelOwnershipTransfer(GAS));
  });

  // --- rotating the sequencer must not leave the old key's proposals approvable (M4) ---
  await check("rotating the sequencer cancels its pending program upgrade", async () => {
    await ok(S.proposeProgramUpgrade(VK(7), GAS));
    if (await c.pendingProgramVkey() !== VK(7)) throw new Error("proposal not stored");
    const ev = await events(c.updateSequencer(seq2.address, GAS), "ProgramUpgradeReverted");
    if (await c.pendingProgramVkey() !== ZERO) throw new Error("revoked key's proposal survived");
    if (ev.length !== 1) throw new Error("cancellation was not announced");
    if (ev[0].rejectedVkey !== VK(7)) throw new Error("wrong vkey in the event");
    if (ev[0].rejectedBy !== owner.address) throw new Error("event does not name who cancelled");
  });
  await check("the cancelled proposal can no longer be approved", () => reverts(c.approveProgramUpgrade(VK(7), GAS)));
  await check("the rotated-out sequencer can no longer propose", () => reverts(S.proposeProgramUpgrade(VK(8), GAS)));
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
    if (names.includes("ProgramUpgradeReverted") || names.includes("RootRollbackReverted"))
      throw new Error("spurious cancellation event");
  });

  // --- the authorisation trail must be reconstructible from logs alone (M6) ---
  await check("ProgramUpgraded names the approver", async () => {
    await ok(S.proposeProgramUpgrade(VK(4), GAS));
    const ev = await events(c.approveProgramUpgrade(VK(4), GAS), "ProgramUpgraded");
    if (ev.length !== 1) throw new Error("no ProgramUpgraded event");
    if (ev[0].approver !== owner.address) throw new Error("approver not recorded");
    if (ev[0].newVkey !== VK(4)) throw new Error("wrong vkey");
  });
  await check("ProgramUpgradeProposed names the proposer", async () => {
    const ev = await events(S.proposeProgramUpgrade(VK(5), GAS), "ProgramUpgradeProposed");
    if (ev.length !== 1 || ev[0].proposer !== seq.address) throw new Error("proposer not recorded");
    await ok(c.revertProgramUpgrade(GAS));
  });
  await check("RootRolledBack names the approver", async () => {
    await ok(c.pause(GAS));
    await ok(S.proposeRootRollback(R(5), GAS));
    const ev = await events(c.approveRootRollback(R(5), GAS), "RootRolledBack");
    await ok(c.unpause(GAS));
    if (ev.length !== 1) throw new Error("no RootRolledBack event");
    if (ev[0].approver !== owner.address) throw new Error("approver not recorded");
    if (Number(ev[0].toBlockHeight) !== 101) throw new Error("height lost from the event");
  });

  // --- ownership offers must be withdrawable from both sides (M5) ---
  await check("cancelling with no offer outstanding reverts", () => reverts(c.cancelOwnershipTransfer(GAS)));
  await check("declining with no offer outstanding reverts", () => reverts(X.declineOwnership(GAS)));
  await check("owner can withdraw an ownership offer", async () => {
    await ok(c.transferOwnership(stranger.address, GAS));
    const ev = await events(c.cancelOwnershipTransfer(GAS), "OwnershipTransferCanceled");
    if (await c.pendingOwner() !== ethers.ZeroAddress) throw new Error("offer not withdrawn");
    if (ev.length !== 1) throw new Error("withdrawal was not announced");
    if (ev[0].canceledOwner !== stranger.address) throw new Error("wrong nominee in the event");
    if (ev[0].canceledBy !== owner.address) throw new Error("event does not name who withdrew");
  });
  await check("a withdrawn offer can no longer be accepted", () => reverts(X.acceptOwnership(GAS)));
  await check("a stranger cannot withdraw an offer", async () => {
    await ok(c.transferOwnership(stranger.address, GAS));
    await reverts(c.connect(seq2).cancelOwnershipTransfer(GAS));
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
    await reverts(c.connect(seq2).declineOwnership(GAS));
    if (await c.pendingOwner() !== stranger.address) throw new Error("offer cleared by a non-nominee");
  });

  await check("2-step ownership transfer", async () => {
    if (await c.owner() !== owner.address) throw new Error("owner changed too early");
    await reverts(c.acceptOwnership(GAS));
    await ok(X.acceptOwnership(GAS));
    if (await c.owner() !== stranger.address) throw new Error("ownership not transferred");
  });

  console.log("\n" + pass + " passed, " + fail + " failed");
  process.exit(fail === 0 ? 0 : 1);
})();
