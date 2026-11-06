"use strict";

// Run the real batch controller without a browser or third-party DOM library.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../src/agent_vault/web_static/app.js"), "utf8");
const controller = source.slice(source.indexOf("function selectBackupArchive("), source.indexOf("async function openMemoryDetail("));

function fixture(transport) {
  const calls = [];
  const state = {
    csrfToken: "test-csrf", uploadMemoryBackupId: null, backupUploadPartition: null,
    backupUploadFiles: {}, backupUploadResults: {}, backupUploadMetadata: null, backupUploadBusy: false,
  };
  const elements = Object.fromEntries(Object.entries({
    name: "Lobster", description: "daily", version: "2026.11.6", owner_key_id: "key_lobster",
  }).map(([name, value]) => [name, { value }]));
  const context = vm.createContext({
    state, URLSearchParams,
    backupPartitions: { memory: { name: "memory" }, skills: { name: "Skill" }, other: { name: "other" } },
    memoryUploadForm: { elements, reportValidity: () => true },
    error: "", closed: false, snapshotFailure: false,
    clearFormError() { context.error = ""; },
    showFormError(_form, message) { context.error = message; },
    updateMemoryFileZone() {},
    closeMemoryUpload() { context.closed = true; },
    async loadSnapshot() { if (context.snapshotFailure) throw new Error("Snapshot unavailable"); },
    async fetch(url, options) {
      const query = new URLSearchParams(url.split("?")[1]);
      const call = { url, options, query, partition: query.get("partition") };
      calls.push(call);
      return transport ? transport(call, calls) : response(call);
    },
  });
  vm.runInContext(controller, context);
  return { context, state, calls, elements, submit: () => context.uploadMemoryBackup({ preventDefault() {} }) };
}

function response(call, ok = true) {
  return { ok, status: ok ? 201 : 400, json: async () => ok ? {
    backup: { id: "backup_" + call.partition, owner_key_id: call.query.get("owner_key_id"), partition: call.partition },
  } : { error: "Invalid archive" } };
}

function choose(context, partition, name = partition + ".zip") {
  context.selectBackupArchive(partition, [{ name, size: 128 }]);
}

test("one submission starts all three uploads and ignores a second click", { timeout: 1000 }, async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const f = fixture(async (call, calls) => {
    if (calls.length === 3) release();
    await gate;
    return response(call);
  });
  for (const partition of ["memory", "skills", "other"]) choose(f.context, partition);
  const running = f.submit();
  assert.equal(f.state.backupUploadBusy, true);
  await f.submit();
  await running;
  assert.equal(f.calls.length, 3);
  assert.equal(f.state.backupUploadBusy, false);
  for (const call of f.calls) {
    assert.equal(call.query.get("owner_key_id"), "key_lobster");
    assert.equal(call.query.get("version"), "2026.11.6");
    assert.equal(call.options.body, f.state.backupUploadFiles[call.partition]);
    assert.equal(f.state.backupUploadResults[call.partition].status, "success");
  }
  await f.submit();
  assert.equal(f.context.closed, true);
  assert.equal(f.calls.length, 3);
});

test("partial failure retries only the failed partition with the original owner and version", async () => {
  const attempts = {};
  const f = fixture((call) => {
    attempts[call.partition] = (attempts[call.partition] || 0) + 1;
    return response(call, call.partition !== "skills" || attempts.skills > 1);
  });
  for (const partition of ["memory", "skills", "other"]) choose(f.context, partition);
  await f.submit();
  assert.equal(f.state.backupUploadResults.skills.status, "failed");
  assert.equal(f.state.backupUploadResults.memory.status, "success");
  // Even programmatically altered form fields cannot change a partially saved batch.
  f.elements.owner_key_id.value = "key_other";
  f.elements.version.value = "different";
  await f.submit();
  assert.deepEqual(attempts, { memory: 1, skills: 2, other: 1 });
  assert.equal(f.calls.at(-1).query.get("owner_key_id"), "key_lobster");
  assert.equal(f.calls.at(-1).query.get("version"), "2026.11.6");
});

test("invalid files and multiple files in one partition prevent requests", async () => {
  const f = fixture();
  choose(f.context, "memory", "plain.txt");
  await f.submit();
  assert.equal(f.calls.length, 0);
  assert.equal(f.state.backupUploadResults.memory.status, "invalid");
  f.context.selectBackupArchive("memory", [{ name: "a.zip", size: 1 }, { name: "b.zip", size: 1 }]);
  assert.equal(f.state.backupUploadResults.memory.status, "invalid");
  f.context.selectBackupArchive("memory", [{ name: "large.zip", size: 100 * 1024 * 1024 + 1 }]);
  assert.equal(f.state.backupUploadResults.memory.status, "invalid");
  choose(f.context, "memory", "memory.tar.gz");
  await f.submit();
  assert.equal(f.calls.length, 1);
  choose(f.context, "skills", "plain.txt");
  await f.submit();
  assert.equal(f.context.closed, false);
  assert.equal(f.calls.length, 1);
});

test("appending a version only accepts the original partition and backup ID", async () => {
  const f = fixture();
  f.state.uploadMemoryBackupId = "backup_existing";
  f.state.backupUploadPartition = "other";
  choose(f.context, "memory");
  assert.equal(Object.keys(f.state.backupUploadFiles).length, 0);
  choose(f.context, "other");
  await f.submit();
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].query.get("backup_id"), "backup_existing");
  assert.equal(f.calls[0].query.get("partition"), "other");
  assert.equal(f.calls[0].query.get("name"), "Lobster");
});

test("a snapshot refresh failure never retries an already saved archive", async () => {
  const f = fixture();
  f.context.snapshotFailure = true;
  choose(f.context, "memory");
  await f.submit();
  assert.equal(f.state.backupUploadResults.memory.status, "success");
  assert.notEqual(f.context.error, "");
  await f.submit();
  assert.equal(f.calls.length, 1);
  assert.equal(f.context.closed, true);
});
