"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../src/agent_vault/web_static/app.js"), "utf8");
const code = source.slice(source.indexOf("function agentBackupSpaces("), source.indexOf("function updateBackupSpaceControls("));

class Element {
  constructor(tag, className = "", textContent = "") {
    Object.assign(this, { tag, className, textContent, children: [], attributes: {}, events: {} });
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, callback) { this.events[name] = callback; }
}

function fixture() {
  const state = {
    query: "",
    backupSpaces: [{ owner_key_id: "key_a", name: "Agent A", status: "active" }, { owner_key_id: "key_b", name: "Agent B", status: "active" }],
    memoryBackups: ["memory", "skills", "other"].map((partition, index) => ({
      id: "backup_" + partition, owner_key_id: "key_a", partition, name: "Archive " + partition,
      description: index === 1 ? "private tools" : "", updated_at: "2026-11-06T01:00:00Z", latest: { size_bytes: 100 },
    })),
  };
  const list = new Element("div");
  const summary = new Element("p");
  const context = vm.createContext({
    state,
    backupPartitions: { memory: { name: "memory", icon: "M" }, skills: { name: "Skill", icon: "S" }, other: { name: "other", icon: "O" } },
    document: { querySelector: (selector) => selector === "#memoryBackupList" ? list : summary },
    createElement: (...args) => new Element(...args), formatSize: (bytes) => bytes + " B", formatDateTime: (date) => date,
    openedOwner: null, openBackupSpaceEditor: (owner) => { context.openedOwner = owner; }, openMemoryUpload() {},
  });
  vm.runInContext(code, context);
  return { state, context, list };
}

test("three archive partitions produce one Agent card, including the empty second Agent", () => {
  const f = fixture();
  const spaces = f.context.agentBackupSpaces();
  assert.equal(spaces.length, 2);
  assert.equal(spaces[0].backups.length, 3);
  assert.equal(spaces[0].bytes, 300);
  for (const partition of ["memory", "skills", "other"]) assert.equal(spaces[0].partitions[partition], 1);
  assert.equal(spaces[1].backups.length, 0);
  f.context.renderMemoryBackups();
  assert.equal(f.list.children.length, 2);
  assert.ok(f.list.children.every((card) => card.tag === "button" && card.className.includes("entry-card")));
  f.list.children[0].events.click();
  assert.equal(f.context.openedOwner, "key_a");
  f.list.children[1].events.click();
  assert.equal(f.context.openedOwner, "key_b");
});

test("unbound archives remain separate and do not merge with an Agent", () => {
  const f = fixture();
  f.state.memoryBackups.push({ id: "memory_legacy", owner_key_id: null, partition: "memory", name: "Legacy" });
  const spaces = f.context.agentBackupSpaces();
  assert.equal(spaces.length, 3);
  assert.equal(spaces.find((space) => space.owner_key_id === "__unbound__").backups.length, 1);
  assert.equal(spaces.find((space) => space.owner_key_id === "key_a").backups.length, 3);
});

test("searching an archive note still opens its Agent card", () => {
  const f = fixture();
  f.state.query = "private tools";
  f.context.renderMemoryBackups();
  assert.equal(f.list.children.length, 1);
  f.list.children[0].events.click();
  assert.equal(f.context.openedOwner, "key_a");
  const html = fs.readFileSync(path.join(__dirname, "../src/agent_vault/web_static/index.html"), "utf8");
  assert.equal(html.includes('id="backupSpaceFilter"'), false);
  assert.equal(html.includes('id="backupSpaceEditorDialog"'), true);
});
