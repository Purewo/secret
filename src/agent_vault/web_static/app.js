"use strict";

const state = {
  csrfToken: "",
  snapshot: null,
  section: "overview",
  personalTab: "account",
  query: "",
  activeEntryId: null,
  entryPage: 1,
  entryPageSize: 12,
  activeCategory: "__all__",
  apiKeys: [],
  skills: [],
  skillCategories: [],
  activeSkillCategory: "__all__",
  activeSkillId: null,
  uploadSkillId: null,
  activePermissionKeyId: null,
  pendingApiKeyAction: null,
};

const labels = {
  overview: "总览",
  entries: "资源条目",
  secrets: "变量检索",
  skills: "Skill 仓库",
  settings: "个人中心",
};

const loginView = document.querySelector("#loginView");
const appView = document.querySelector("#appView");
const loginForm = document.querySelector("#loginForm");
const loginError = document.querySelector("#loginError");
const entryDialog = document.querySelector("#entryDialog");
const secretDialog = document.querySelector("#secretDialog");
const detailDialog = document.querySelector("#detailDialog");
const categoryDialog = document.querySelector("#categoryDialog");
const apiKeyDialog = document.querySelector("#apiKeyDialog");
const apiKeyRevealDialog = document.querySelector("#apiKeyRevealDialog");
const apiKeyPermissionDialog = document.querySelector("#apiKeyPermissionDialog");
const apiKeyActionDialog = document.querySelector("#apiKeyActionDialog");
const skillCategoryDialog = document.querySelector("#skillCategoryDialog");
const skillUploadDialog = document.querySelector("#skillUploadDialog");
const skillDetailDialog = document.querySelector("#skillDetailDialog");
const skillCategoryForm = document.querySelector("#skillCategoryForm");
const skillUploadForm = document.querySelector("#skillUploadForm");
const entryForm = document.querySelector("#entryForm");
const secretForm = document.querySelector("#secretForm");
const categoryCreateForm = document.querySelector("#categoryCreateForm");
const categoryAssignForm = document.querySelector("#categoryAssignForm");
const apiKeyForm = document.querySelector("#apiKeyForm");
const apiKeyPermissionForm = document.querySelector("#apiKeyPermissionForm");
const passwordForm = document.querySelector("#passwordForm");
const secretEntrySelect = document.querySelector("#secretEntry");
const secretValue = document.querySelector("#secretValue");
const searchInput = document.querySelector("#searchInput");
const variableSearchInput = document.querySelector("#variableSearchInput");

function createElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function normalizeTags(value) {
  return String(value || "")
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (state.csrfToken && options.method && options.method !== "GET") {
    headers.set("X-CSRF-Token", state.csrfToken);
  }
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    throw new Error(payload.error || `请求失败（${response.status}）`);
  }
  return payload;
}

function setLoading(button, loading) {
  if (!button) return;
  button.disabled = loading;
  if (!button.dataset.originalHtml) button.dataset.originalHtml = button.innerHTML;
  if (loading) {
    button.textContent = "正在处理…";
  } else {
    button.innerHTML = button.dataset.originalHtml;
  }
}

function showLogin() {
  state.csrfToken = "";
  state.snapshot = null;
  state.apiKeys = [];
  state.skills = [];
  state.skillCategories = [];
  resetPasswordForm();
  loginForm.elements.password.value = "";
  loginError.textContent = "";
  document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
  document.querySelector("#detailVariableList").replaceChildren();
  document.querySelector("#apiKeyList").replaceChildren();
  document.querySelector("#secretList").replaceChildren();
  appView.hidden = true;
  loginView.hidden = false;
  document.body.classList.remove("is-app");
  window.setTimeout(() => document.querySelector("#username")?.focus(), 40);
}

function showApp(session) {
  state.csrfToken = session.csrf_token;
  loginView.hidden = true;
  appView.hidden = false;
  document.body.classList.add("is-app");
}

function setToday() {
  const today = new Intl.DateTimeFormat("zh-CN", {
    month: "long",
    day: "numeric",
    weekday: "long",
  }).format(new Date());
  document.querySelector("#todayLabel").textContent = today;
}

async function loadSnapshot() {
  const [snapshot, apiKeyPayload, skillPayload, skillCategories] = await Promise.all([
    api("/api/snapshot"),
    api("/api/api-keys"),
    api("/api/skills"),
    api("/api/skills/categories"),
  ]);
  state.snapshot = snapshot;
  state.apiKeys = apiKeyPayload.api_keys || [];
  state.skills = skillPayload.skills || [];
  state.skillCategories = skillCategories.categories || [];
  renderSnapshot();
  if (!snapshot.status.ready) {
    toast("保险柜需要检查", "本地密钥或密文库状态异常。", "error");
  }
}

function renderSnapshot() {
  if (!state.snapshot) return;
  const { metrics } = state.snapshot;
  document.querySelector("#entryMetric").textContent = metrics.entries;
  document.querySelector("#secretMetric").textContent = metrics.secrets;
  document.querySelector("#unassignedMetric").textContent = metrics.unassigned;
  document.querySelector("#navEntryCount").textContent = metrics.entries;
  document.querySelector("#navSecretCount").textContent = metrics.unassigned;
  document.querySelector("#navApiKeyCount").textContent = state.apiKeys.length;
  document.querySelector("#navSkillCount").textContent = state.skills.length;
  document.querySelector("#lookupTotal").textContent = metrics.secrets;
  populateCategoryOptions(document.querySelector("#entryCategory"));
  populateCategoryOptions(document.querySelector("#detailCategorySelect"));
  populateCategoryOptions(document.querySelector("#categoryAssignTarget"));
  renderCategoryStrip();
  const entries = filteredEntries();
  const recentEntries = [...filteredEntries(false)].sort((left, right) => {
    const leftTime = Date.parse(left.updated_at || "") || 0;
    const rightTime = Date.parse(right.updated_at || "") || 0;
    return rightTime - leftTime || left.id.localeCompare(right.id);
  });
  renderEntries(document.querySelector("#recentEntries"), recentEntries.slice(0, 3), true);
  renderPaginatedEntries(entries);
  renderSecrets();
  renderApiKeys();
  renderSkills();
  populateEntrySelect();
}

function filteredEntries(includeCategory = true) {
  if (!state.snapshot) return [];
  const query = state.query.toLocaleLowerCase("zh-CN");
  let entries = state.snapshot.entries;
  if (includeCategory && state.activeCategory !== "__all__") {
    entries = entries.filter((entry) => categoryIdForEntry(entry) === state.activeCategory);
  }
  if (!query) return entries;
  return entries.filter((entry) => {
    const variableText = entry.variables
      .map((record) => `${record.name} ${record.note || ""} ${(record.tags || []).join(" ")}`)
      .join(" ");
    return `${entry.id} ${entry.description} ${(entry.tags || []).join(" ")} ${variableText}`
      .toLocaleLowerCase("zh-CN")
      .includes(query);
  });
}

function renderEntries(container, entries, compact) {
  container.replaceChildren();
  if (!entries.length) {
    container.append(emptyState(
      state.query ? "没有匹配的资源" : "还没有资源条目",
      state.query ? "换个关键词试试，变量名和备注也可以搜索。" : "先创建一个条目，把同一台服务器或同一个账号的秘密收在一起。",
      !state.query,
    ));
    return;
  }
  entries.forEach((entry) => {
    const card = createElement("button", "entry-card");
    card.type = "button";
    const top = createElement("div", "entry-card__top");
    const icon = createElement("span", "entry-card__icon", entry.id.slice(0, 2));
    const count = createElement("span", "entry-card__count", `${entry.secret_count} 个变量`);
    top.append(icon, count);

    const title = createElement("h3", "", entry.id);
    title.title = entry.id;
    const description = createElement("p", "", entry.description);
    const category = categoryForEntry(entry);
    const categoryLabel = createElement("span", `entry-card__category entry-card__category--${category.color}`);
    categoryLabel.append(createElement("i"), document.createTextNode(category.name));
    const tags = createElement("div", "tag-row");
    appendTags(tags, entry.tags);
    const openHint = createElement("span", "entry-card__open", "查看详情  →");
    card.append(top, title, description, categoryLabel, tags, openHint);
    card.addEventListener("click", () => openDetail(entry.id));
    container.append(card);
  });
  if (compact && entries.length > 3) {
    container.replaceChildren(...Array.from(container.children).slice(0, 3));
  }
}

function categories() {
  return state.snapshot?.categories || [
    { id: "__other__", name: "其他", color: "neutral", entry_count: state.snapshot?.entries?.length || 0, built_in: true },
  ];
}

function categoryIdForEntry(entry) {
  return categories().some((category) => category.id === entry.category) ? entry.category : "__other__";
}

function categoryForEntry(entry) {
  const categoryId = categoryIdForEntry(entry);
  return categories().find((category) => category.id === categoryId)
    || { id: "__other__", name: "其他", color: "neutral", built_in: true };
}

function renderCategoryStrip() {
  const container = document.querySelector("#categoryStrip");
  container.replaceChildren();
  const allCategory = {
    id: "__all__",
    name: "全部",
    color: "all",
    entry_count: state.snapshot?.entries?.length || 0,
  };
  [allCategory, ...categories()].forEach((category) => {
    const button = createElement("button", `category-pill category-pill--${category.color}`);
    button.type = "button";
    button.dataset.category = category.id;
    button.setAttribute("aria-pressed", String(state.activeCategory === category.id));
    button.append(
      createElement("i"),
      createElement("span", "", category.name),
      createElement("b", "", String(category.entry_count)),
    );
    if (state.activeCategory === category.id) button.classList.add("is-active");
    button.addEventListener("click", () => {
      state.activeCategory = category.id;
      state.entryPage = 1;
      renderCategoryStrip();
      renderPaginatedEntries(filteredEntries());
    });
    container.append(button);
  });
}

function populateCategoryOptions(select, selectedId = select.value || "__other__") {
  if (!select || !state.snapshot) return;
  select.replaceChildren();
  const other = categories().find((category) => category.id === "__other__");
  select.append(new Option(`${other?.name || "其他"}（默认）`, "__other__"));
  categories().filter((category) => !category.built_in).forEach((category) => {
    select.append(new Option(category.name, category.id));
  });
  select.value = categories().some((category) => category.id === selectedId) ? selectedId : "__other__";
}

function categoryIdFromName(name) {
  let base = name
    .normalize("NFKD")
    .toLocaleLowerCase("en-US")
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 56);
  if (!base || !/^[a-z]/.test(base)) base = `category_${Date.now().toString(36)}`;
  const existing = new Set(categories().map((category) => category.id));
  let candidate = base;
  let suffix = 2;
  while (existing.has(candidate)) {
    candidate = `${base.slice(0, 70)}_${suffix}`;
    suffix += 1;
  }
  return candidate;
}

function renderCategoryManager() {
  const categoryList = document.querySelector("#categoryManagerList");
  categoryList.replaceChildren();
  categories().forEach((category) => {
    const item = createElement("div", "category-manager-item");
    const identity = createElement("div", "category-manager-item__identity");
    identity.append(
      createElement("i", `category-color category-color--${category.color}`),
      createElement("strong", "", category.name),
    );
    item.append(identity, createElement("span", "", `${category.entry_count} 个资源`));
    categoryList.append(item);
  });

  populateCategoryOptions(document.querySelector("#categoryAssignTarget"));
  renderCategoryEntryPicker();
}

function renderCategoryEntryPicker() {
  const container = document.querySelector("#categoryEntryList");
  container.replaceChildren();
  (state.snapshot?.entries || []).forEach((entry) => {
    const category = categoryForEntry(entry);
    const label = createElement("label", "category-entry-item");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.name = "entries";
    checkbox.value = entry.id;
    checkbox.addEventListener("change", updateCategorySelection);
    const copy = createElement("span", "category-entry-item__copy");
    copy.append(createElement("strong", "", entry.id), createElement("small", "", category.name));
    label.append(checkbox, createElement("i", `category-color category-color--${category.color}`), copy);
    container.append(label);
  });
  document.querySelector("#categorySelectAll").checked = false;
  updateCategorySelection();
}

function updateCategorySelection() {
  const checkboxes = [...document.querySelectorAll("#categoryEntryList input[type='checkbox']")];
  const selected = checkboxes.filter((checkbox) => checkbox.checked).length;
  document.querySelector("#categorySelectedCount").textContent = `已选 ${selected} 个`;
  const selectAll = document.querySelector("#categorySelectAll");
  selectAll.checked = Boolean(checkboxes.length) && selected === checkboxes.length;
  selectAll.indeterminate = selected > 0 && selected < checkboxes.length;
}

function openCategoryDialog() {
  categoryCreateForm.reset();
  categoryCreateForm.elements.color.value = "mint";
  document.querySelector("[data-category-create-error]").textContent = "";
  document.querySelector("[data-category-assign-error]").textContent = "";
  renderCategoryManager();
  categoryDialog.showModal();
  window.setTimeout(() => categoryCreateForm.elements.name.focus(), 50);
}

function closeCategoryDialog() {
  if (categoryDialog.open) categoryDialog.close();
}

function renderPaginatedEntries(entries) {
  const container = document.querySelector("#allEntries");
  const pagination = document.querySelector("#entryPagination");
  const totalItems = entries.length;
  if (!totalItems) {
    renderEntries(container, [], false);
    pagination.hidden = true;
    return;
  }

  const totalPages = Math.max(1, Math.ceil(totalItems / state.entryPageSize));
  state.entryPage = Math.min(Math.max(1, state.entryPage), totalPages);
  const start = (state.entryPage - 1) * state.entryPageSize;
  const end = Math.min(start + state.entryPageSize, totalItems);
  renderEntries(container, entries.slice(start, end), false);

  document.querySelector("#entryPageRange").textContent = `第 ${start + 1}–${end} 个`;
  document.querySelector("#entryPageTotal").textContent = `共 ${totalItems} 个资源`;
  document.querySelector("#entryPageSize").value = String(state.entryPageSize);
  renderPageButtons(totalPages);
  pagination.hidden = false;
}

function renderPageButtons(totalPages) {
  const container = document.querySelector("#entryPageButtons");
  container.replaceChildren();
  container.append(pageButton("←", state.entryPage - 1, state.entryPage === 1, "上一页", "page-arrow"));

  pageSequence(state.entryPage, totalPages).forEach((page) => {
    if (page === "…") {
      container.append(createElement("span", "page-ellipsis", "…"));
      return;
    }
    const button = pageButton(String(page), page, false, `第 ${page} 页`, "page-number");
    if (page === state.entryPage) {
      button.classList.add("is-active");
      button.setAttribute("aria-current", "page");
    }
    container.append(button);
  });

  container.append(pageButton("→", state.entryPage + 1, state.entryPage === totalPages, "下一页", "page-arrow"));
}

function pageSequence(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1);
  const selected = new Set([1, total, current - 1, current, current + 1]);
  const pages = [...selected].filter((page) => page >= 1 && page <= total).sort((a, b) => a - b);
  const sequence = [];
  pages.forEach((page, index) => {
    if (index && page - pages[index - 1] > 1) sequence.push("…");
    sequence.push(page);
  });
  return sequence;
}

function pageButton(text, page, disabled, label, className) {
  const button = createElement("button", className, text);
  button.type = "button";
  button.disabled = disabled;
  button.setAttribute("aria-label", label);
  button.addEventListener("click", () => {
    state.entryPage = page;
    renderPaginatedEntries(filteredEntries());
    document.querySelector("#entriesSection").scrollIntoView({ behavior: "smooth", block: "start" });
  });
  return button;
}

function appendTags(container, tags) {
  const visible = (tags || []).slice(0, 4);
  if (!visible.length) {
    container.append(createElement("span", "tag tag--empty", "无标签"));
    return;
  }
  visible.forEach((tag) => container.append(createElement("span", "tag", tag)));
}

function allSecrets() {
  if (!state.snapshot) return [];
  const assigned = state.snapshot.entries.flatMap((entry) =>
    entry.variables.map((record) => ({ ...record, entryLabel: entry.id, entryId: entry.id })),
  );
  const unassigned = state.snapshot.unassigned.map((record) => ({ ...record, entryLabel: "待整理", entryId: null }));
  return [...assigned, ...unassigned].sort((a, b) => a.name.localeCompare(b.name));
}

function renderSecrets() {
  const container = document.querySelector("#secretList");
  const query = state.query.toLocaleLowerCase("zh-CN");
  const searching = Boolean(query);
  const source = searching ? allSecrets() : state.snapshot.unassigned.map((record) => ({ ...record, entryLabel: "待整理", entryId: null }));
  const matches = source.filter((record) => {
    if (!searching) return true;
    return `${record.name} ${record.note || ""} ${record.entryLabel} ${(record.tags || []).join(" ")}`
      .toLocaleLowerCase("zh-CN")
      .includes(query);
  });
  const records = searching ? matches.slice(0, 50) : matches;
  document.querySelector("#lookupMode").textContent = searching ? "SEARCH RESULTS" : "NEEDS A HOME";
  document.querySelector("#lookupTitle").textContent = searching ? "检索结果" : "待整理变量";
  document.querySelector("#lookupDescription").textContent = searching
    ? `正在查找与“${state.query}”有关的变量。`
    : "这些变量尚未归入任何资源，值得顺手整理一下。";
  document.querySelector("#lookupCount").textContent = matches.length > records.length
    ? `前 ${records.length} / 共 ${matches.length} 条`
    : `${records.length} 条`;
  container.replaceChildren();
  if (!records.length) {
    container.append(emptyState(
      searching ? "没有匹配的变量" : "已经整理得很干净",
      searching ? "换个变量名、资源名、公开备注或标签试试。" : "目前没有尚未归类的秘密变量。",
      false,
      true,
    ));
    return;
  }

  records.forEach((record) => {
    const row = createElement("div", "secret-row lookup-row");
    const name = createElement("div", "secret-name");
    const icon = createElement("span", "secret-name__icon", "◆");
    const nameText = createElement("div");
    const strong = createElement("strong", "", record.name);
    strong.title = record.name;
    const note = createElement("small", "", record.note || "没有公开备注");
    const inlineValue = createElement("code", "lookup-inline-value is-masked", "••••••••••••••••");
    inlineValue.hidden = true;
    nameText.append(strong, note, inlineValue);
    name.append(icon, nameText);

    const entry = createElement("span", "secret-entry", record.entryLabel);
    entry.title = record.entryLabel;
    const tags = createElement("div", "tag-row");
    appendTags(tags, record.tags);
    const date = createElement("span", "secret-date", formatDate(record.updated_at));
    const actions = createElement("div", "lookup-actions");
    if (record.entryId) {
      const open = createElement("button", "lookup-action lookup-action--open", "打开资源");
      open.type = "button";
      open.addEventListener("click", () => openDetail(record.entryId));
      actions.append(open);
    } else {
      const reveal = createElement("button", "lookup-action", "显示");
      reveal.type = "button";
      reveal.setAttribute("aria-label", `显示 ${record.name}`);
      reveal.addEventListener("click", () => toggleSecretValue(record.name, inlineValue, reveal));
      const copy = createElement("button", "lookup-action lookup-action--copy", "复制");
      copy.type = "button";
      copy.setAttribute("aria-label", `复制 ${record.name}`);
      copy.addEventListener("click", () => copySecretValue(record.name, copy));
      actions.append(reveal, copy);
    }
    row.append(name, entry, tags, date, actions);
    container.append(row);
  });
}

function renderApiKeys() {
  const container = document.querySelector("#apiKeyList");
  if (!container) return;
  container.replaceChildren();
  if (!state.apiKeys.length) {
    container.append(emptyState("还没有 API Key", "给受信任的 Agent 创建一把可撤销的访问钥匙。", false, true));
    return;
  }
  state.apiKeys.forEach((record) => {
    const row = createElement("article", "api-key-row");
    const identity = createElement("div", "api-key-identity");
    identity.append(createElement("span", "api-key-identity__icon", "⌁"));
    const identityText = createElement("div");
    identityText.append(createElement("strong", "", record.name), createElement("small", "", record.note || "没有公开备注"));
    identityText.append(createElement("small", "api-key-permission-summary", permissionLabel(record.permissions)));
    identity.append(identityText);

    const token = createElement("div", "api-key-token");
    const tokenValue = createElement("code", "", `${record.prefix}••••••••••••`);
    tokenValue.dataset.keyId = record.id;
    token.append(tokenValue);

    const status = createElement("span", `api-key-status ${record.status === "revoked" ? "api-key-status--revoked" : ""}`.trim(), record.status === "revoked" ? "已撤销" : "已启用");
    const actions = createElement("div", "api-key-actions");
    const reveal = createElement("button", "api-key-action", "显示");
    reveal.type = "button";
    reveal.title = "显示 API Key";
    reveal.setAttribute("aria-label", `显示 ${record.name} 的 API Key`);
    reveal.disabled = record.status === "revoked";
    reveal.addEventListener("click", () => revealApiKey(record, tokenValue, reveal));
    const permission = createElement("button", "api-key-action", "权限");
    permission.type = "button";
    permission.disabled = record.status === "revoked";
    permission.addEventListener("click", () => openApiKeyPermissionDialog(record));
    const statusAction = createElement("button", `api-key-action ${record.status === "revoked" ? "api-key-action--restore" : "api-key-action--revoke"}`, record.status === "revoked" ? "启用" : "撤销");
    statusAction.type = "button";
    statusAction.addEventListener("click", () => toggleApiKeyStatus(record, statusAction));
    const remove = createElement("button", "api-key-action api-key-action--delete", "删除");
    remove.type = "button";
    remove.addEventListener("click", () => deleteApiKey(record, remove));
    actions.append(reveal, permission, statusAction, remove);

    row.append(identity, token, status, actions);
    container.append(row);
  });
}

function permissionLabel(permissions) {
  const content = !permissions?.read ? "无内容权限" : `${permissions.add ? "可读 + 新增" : "只读"}${permissions.delete ? " · 可删除" : ""}`;
  const skills = permissions?.skill_categories?.length ? ` · Skill ${permissions.skill_categories.includes("__all__") ? "全部" : `${permissions.skill_categories.length} 类`}` : "";
  const uploads = permissions?.skill_upload_categories?.length ? " · 可上传" : "";
  return content + skills + uploads;
}

function openApiKeyPermissionDialog(record) {
  state.activePermissionKeyId = record.id;
  document.querySelector("#permissionKeyName").textContent = record.name;
  const permissions = record.permissions || { categories: [], read: false, add: false, delete: false };
  apiKeyPermissionForm.querySelectorAll("input[name='level']").forEach((input) => {
    input.checked = input.value === (permissions.read ? (permissions.add ? "add" : "read") : "none");
  });
  const categoryList = document.querySelector("#apiPermissionCategoryList");
  categoryList.replaceChildren();
  [{ id: "__all__", name: "全部内容分类（含未来）", entry_count: null }, ...(state.snapshot?.categories || [])].forEach((category) => {
    const label = createElement("label", "permission-category-item");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.name = "categories";
    checkbox.value = category.id;
    checkbox.checked = (permissions.categories || []).includes(category.id);
    label.append(checkbox, createElement("span", "", category.entry_count === null ? category.name : `${category.name} · ${category.entry_count}`));
    categoryList.append(label);
  });
  document.querySelector("#apiPermissionDelete").checked = Boolean(permissions.delete);
  const skillOptions = [{ id: "__all__", name: "全部 Skill 分类（含未来）", skill_count: null }, ...state.skillCategories];
  for (const [containerId, field] of [["apiPermissionSkillCategoryList", "skill_categories"], ["apiPermissionSkillUploadCategoryList", "skill_upload_categories"]]) {
    const container = document.querySelector(`#${containerId}`);
    container.replaceChildren();
    skillOptions.forEach((category) => {
      const label = createElement("label", "permission-category-item");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.name = field;
      checkbox.value = category.id;
      checkbox.checked = (permissions[field] || []).includes(category.id);
      label.append(checkbox, createElement("span", "", category.skill_count === null ? category.name : `${category.name} · ${category.skill_count} 个 Skill`));
      container.append(label);
    });
  }
  document.querySelector("[data-api-permission-error]").textContent = "";
  apiKeyPermissionDialog.showModal();
}

function closeApiKeyPermissionDialog() {
  state.activePermissionKeyId = null;
  if (apiKeyPermissionDialog.open) apiKeyPermissionDialog.close();
}

function formatSize(bytes) {
  return bytes < 1024 * 1024 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function renderSkills() {
  const strip = document.querySelector("#skillCategoryStrip");
  const list = document.querySelector("#skillList");
  strip.replaceChildren();
  list.replaceChildren();
  const categories = [{ id: "__all__", name: "全部", skill_count: state.skills.length }, ...state.skillCategories];
  categories.forEach((category) => {
    const button = createElement("button", `category-pill ${state.activeSkillCategory === category.id ? "is-active" : ""}`);
    button.type = "button";
    button.append(createElement("span", "", category.name), createElement("b", "", String(category.skill_count)));
    button.setAttribute("aria-pressed", String(state.activeSkillCategory === category.id));
    button.addEventListener("click", () => { state.activeSkillCategory = category.id; renderSkills(); });
    strip.append(button);
  });
  const visible = state.skills.filter((skill) => state.activeSkillCategory === "__all__" || skill.category === state.activeSkillCategory);
  if (!visible.length) {
    const empty = createElement("div", "skill-empty glass");
    empty.append(createElement("span", "", "✦"), createElement("strong", "", "这个分类还没有 Skill"), createElement("p", "", "上传一个 ZIP 包，让你的能力开始流动。"));
    list.append(empty);
    return;
  }
  visible.forEach((skill) => {
    const card = createElement("button", "skill-card glass");
    card.type = "button";
    const top = createElement("div", "skill-card__top");
    top.append(createElement("span", "skill-card__glyph", "✦"), createElement("span", "skill-card__version", `v${skill.latest_version}`));
    const name = createElement("h2", "", skill.name);
    const description = createElement("p", "", skill.description);
    const foot = createElement("div", "skill-card__foot");
    const category = state.skillCategories.find((item) => item.id === skill.category)?.name || "其他";
    foot.append(createElement("span", "", category), createElement("span", "", formatSize(skill.size_bytes)));
    card.append(top, name, description, foot);
    card.addEventListener("click", () => openSkillDetail(skill.id));
    list.append(card);
  });
}

function populateSkillCategorySelect() {
  const select = document.querySelector("#skillUploadCategory");
  select.replaceChildren();
  state.skillCategories.forEach((category) => select.append(new Option(category.name, category.id)));
  select.value = state.activeSkillCategory === "__all__" ? "__other__" : state.activeSkillCategory;
}

function openSkillUpload(skill = null) {
  skillUploadForm.reset();
  clearFormError(skillUploadForm);
  updateSkillFileZone();
  state.uploadSkillId = skill?.id || null;
  populateSkillCategorySelect();
  if (skill) {
    skillUploadForm.elements.name.value = skill.name;
    skillUploadForm.elements.description.value = skill.description;
    skillUploadForm.elements.category.value = skill.category;
    skillUploadForm.elements.version.value = "";
    skillDetailDialog.close();
  }
  skillUploadDialog.showModal();
}

function updateSkillFileZone() {
  const file = skillUploadForm.elements.package.files[0];
  const zone = document.querySelector("#skillFileDropzone");
  zone.classList.toggle("is-selected", Boolean(file));
  document.querySelector("#skillFileTitle").textContent = file ? file.name : "把 Skill 包拖到这里";
  document.querySelector("#skillFileSubtitle").textContent = file ? `${formatSize(file.size)} · 已选择 ZIP 包` : "或点击选择 ZIP 文件";
  document.querySelector("#skillFileAction").innerHTML = file ? "更换文件 <span>↗</span>" : "选择文件 <span>↗</span>";
}

async function openSkillDetail(id) {
  try {
    const { skill } = await api(`/api/skills/${encodeURIComponent(id)}`);
    state.activeSkillId = id;
    document.querySelector("#skillDetailName").textContent = skill.name;
    const body = document.querySelector("#skillDetailBody");
    body.replaceChildren();
    body.append(createElement("p", "skill-detail-copy", skill.description));
    skill.versions.forEach((version) => {
      const row = createElement("div", "skill-version-row");
      const info = createElement("div");
      info.append(createElement("strong", "", `v${version.version}`), createElement("small", "", `上传 ${formatDate(version.uploaded_at)} · ${formatSize(version.size_bytes)} · 下载 ${version.download_count} 次`));
      info.append(createElement("small", "", version.requires_environment ? `需要额外环境${version.environment_note ? `：${version.environment_note}` : ""}` : "开箱即用"));
      const hash = createElement("small", "skill-version-hash", `SHA-256 ${version.sha256}`);
      hash.title = version.sha256;
      info.append(hash);
      const download = createElement("a", "skill-download", "下载 ZIP ↓");
      download.href = version.download_url;
      download.download = `${skill.name}-${version.version}.zip`;
      row.append(info, download);
      body.append(row);
    });
    skillDetailDialog.showModal();
  } catch (error) {
    toast("获取 Skill 详情失败", error.message, "error");
  }
}

async function revealApiKey(record, tokenElement, button) {
  if (button.dataset.revealed === "true") {
    tokenElement.textContent = `${record.prefix}••••••••••••`;
    tokenElement.classList.remove("is-visible");
    button.dataset.revealed = "false";
    button.textContent = "显示";
    button.title = "显示 API Key";
    const copy = button.parentElement.querySelector(".api-key-copy");
    if (copy) copy.hidden = true;
    return;
  }
  button.disabled = true;
  try {
    const payload = await api(`/api/api-keys/${encodeURIComponent(record.id)}/reveal`, { method: "POST", body: "{}" });
    tokenElement.textContent = payload.api_key;
    tokenElement.classList.add("is-visible");
    button.dataset.revealed = "true";
    button.title = "隐藏 API Key";
    button.textContent = "隐藏";
    let copy = button.parentElement.querySelector(".api-key-copy");
    if (!copy) {
      copy = createElement("button", "api-key-action api-key-copy", "复制");
      copy.type = "button";
      copy.addEventListener("click", async () => {
        await navigator.clipboard.writeText(tokenElement.textContent);
        toast("已复制 API Key", "请通过安全渠道交给受信任的 Agent。 ");
      });
      button.parentElement.insertBefore(copy, button.nextSibling);
    }
    copy.hidden = false;
    payload.api_key = "";
  } catch (error) {
    toast("读取 API Key 失败", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function openApiKeyActionDialog(record, type, button) {
  state.pendingApiKeyAction = { record, type, button };
  const destructive = type === "delete";
  const restoring = type === "restore";
  document.querySelector("#apiKeyActionTitle").textContent = destructive ? "永久删除 API Key" : restoring ? "重新启用 API Key" : "撤销 API Key";
  document.querySelector("#apiKeyActionKicker").textContent = destructive ? "IRREVERSIBLE ACTION" : "CONFIRM ACTION";
  document.querySelector("#apiKeyActionName").textContent = record.name;
  document.querySelector("#apiKeyActionPrefix").textContent = `${record.prefix}••••••••••••`;
  document.querySelector("#apiKeyActionLead").textContent = destructive
    ? "这会永久删除这把钥匙，任何持有它的 Agent 都将立即失去访问权限。"
    : restoring
      ? "这会恢复这把钥匙当前保存的权限配置，持有它的 Agent 将重新获得访问权限。"
      : "这会立即阻止这把钥匙认证，但之后仍可以重新启用。";
  const warning = document.querySelector("#apiKeyActionWarning");
  warning.hidden = !destructive;
  const confirm = document.querySelector("#apiKeyActionConfirm");
  confirm.textContent = destructive ? "永久删除" : restoring ? "重新启用" : "撤销访问";
  confirm.className = destructive ? "danger-button" : "primary-button api-key-confirm-button";
  apiKeyActionDialog.showModal();
}

function closeApiKeyActionDialog() {
  state.pendingApiKeyAction = null;
  if (apiKeyActionDialog.open) apiKeyActionDialog.close();
}

async function toggleApiKeyStatus(record, button) {
  const revoked = record.status === "revoked";
  openApiKeyActionDialog(record, revoked ? "restore" : "revoke", button);
}

async function deleteApiKey(record, button) {
  openApiKeyActionDialog(record, "delete", button);
}

async function confirmApiKeyAction() {
  const pending = state.pendingApiKeyAction;
  if (!pending) return;
  const { record, type, button } = pending;
  button.disabled = true;
  closeApiKeyActionDialog();
  try {
    if (type === "delete") {
      await api(`/api/api-keys/${encodeURIComponent(record.id)}`, { method: "DELETE" });
    } else {
      await api(`/api/api-keys/${encodeURIComponent(record.id)}/${type}`, { method: "POST", body: "{}" });
    }
    await loadSnapshot();
    toast(type === "delete" ? "API Key 已永久删除" : type === "restore" ? "API Key 已启用" : "API Key 已撤销", type === "delete" ? `${record.name} 已从独立密钥库移除。` : type === "restore" ? `${record.name} 已恢复访问。` : `${record.name} 已不能继续访问内容 API。`);
  } catch (error) {
    button.disabled = false;
    toast(type === "delete" ? "删除失败" : "状态更新失败", error.message, "error");
  }
}

function openApiKeyDialog() {
  apiKeyForm.reset();
  clearFormError(apiKeyForm);
  apiKeyDialog.showModal();
  window.setTimeout(() => apiKeyForm.elements.name.focus(), 50);
}

function closeApiKeyDialog() {
  if (apiKeyDialog.open) apiKeyDialog.close();
}

function closeApiKeyRevealDialog() {
  document.querySelector("#apiKeyRevealValue").textContent = "avk_••••••••";
  if (apiKeyRevealDialog.open) apiKeyRevealDialog.close();
}

function openApiKeyRevealDialog(record) {
  document.querySelector("#apiKeyRevealName").textContent = record.name;
  document.querySelector("#apiKeyRevealValue").textContent = record.api_key;
  document.querySelector("#apiKeyRevealCopy").onclick = async () => {
    await navigator.clipboard.writeText(record.api_key);
    toast("已复制 API Key", "请通过安全渠道交给受信任的 Agent。 ");
  };
  apiKeyRevealDialog.showModal();
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return value;
  return new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", year: "numeric" }).format(date);
}

function emptyState(title, copy, showButton, secret = false) {
  const card = createElement("div", "empty-card");
  const inner = createElement("div", "empty-card__inner");
  const icon = createElement("span", "empty-card__icon", secret ? "◆" : "✦");
  inner.append(icon, createElement("strong", "", title), createElement("p", "", copy));
  if (showButton) {
    const button = createElement("button", "secondary-button", secret ? "＋ 添加秘密" : "＋ 创建条目");
    button.type = "button";
    button.addEventListener("click", () => secret ? openSecretDialog() : openEntryDialog());
    inner.append(button);
  }
  card.append(inner);
  return card;
}

function populateEntrySelect(selectedId = "") {
  secretEntrySelect.replaceChildren();
  const none = new Option("暂不归类", "");
  secretEntrySelect.append(none);
  (state.snapshot?.entries || []).forEach((entry) => {
    secretEntrySelect.append(new Option(`${entry.id} · ${entry.description}`, entry.id));
  });
  secretEntrySelect.value = selectedId;
}

function navigate(section) {
  if (!labels[section]) return;
  if (state.section === "settings" && section !== "settings") resetPasswordForm();
  if (state.section === "secrets" && section !== "secrets" && state.snapshot) renderSecrets();
  state.section = section;
  document.querySelectorAll(".page-section").forEach((element) => element.classList.remove("is-active"));
  document.querySelector(`#${section}Section`).classList.add("is-active");
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.toggle("is-active", item.dataset.section === section);
  });
  document.querySelector("#currentSection").textContent = labels[section];
  appView.classList.remove("sidebar-open");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function setPersonalTab(tab) {
  state.personalTab = tab;
  const account = tab === "account";
  document.querySelector("#personalAccountPanel").hidden = !account;
  document.querySelector("#personalApiPanel").hidden = account;
  document.querySelectorAll("[data-personal-tab]").forEach((button) => {
    const active = button.dataset.personalTab === tab;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
  });
}

function openEntryDialog() {
  entryForm.reset();
  clearFormError(entryForm);
  populateCategoryOptions(document.querySelector("#entryCategory"), "__other__");
  entryDialog.showModal();
  window.setTimeout(() => entryForm.elements.id.focus(), 50);
}

function openSecretDialog(entryId = "") {
  secretForm.reset();
  clearFormError(secretForm);
  secretValue.classList.add("is-masked");
  populateEntrySelect(entryId);
  secretDialog.showModal();
  window.setTimeout(() => secretForm.elements.name.focus(), 50);
}

function openDetail(entryId) {
  const entry = state.snapshot?.entries.find((item) => item.id === entryId);
  if (!entry) {
    toast("暂时打不开详情", "请刷新页面后再试。", "error");
    return;
  }
  state.activeEntryId = entry.id;
  document.querySelector("#detailIcon").textContent = entry.id.slice(0, 2);
  document.querySelector("#detailCount").textContent = `${entry.secret_count} 个变量`;
  document.querySelector("#detailTitle").textContent = entry.id;
  document.querySelector("#detailDescription").textContent = entry.description;
  populateCategoryOptions(document.querySelector("#detailCategorySelect"), categoryIdForEntry(entry));
  const tags = document.querySelector("#detailTags");
  tags.replaceChildren();
  appendTags(tags, entry.tags);
  renderDetailVariables(entry);
  detailDialog.showModal();
}

function renderDetailVariables(entry) {
  const container = document.querySelector("#detailVariableList");
  container.replaceChildren();
  if (!entry.variables.length) {
    container.append(emptyState(
      "这个条目还是空的",
      "添加第一枚秘密变量，让它真正开始工作。",
      false,
      true,
    ));
    return;
  }

  entry.variables.forEach((record, index) => {
    const item = createElement("section", "detail-variable");
    item.dataset.position = String(index + 1);

    const heading = createElement("div", "detail-variable__heading");
    const icon = createElement("span", "detail-variable__icon", "◆");
    const identity = createElement("div", "detail-variable__identity");
    const name = createElement("strong", "", record.name);
    name.title = record.name;
    const note = createElement("small", "", record.note || "没有公开备注");
    identity.append(name, note);
    heading.append(icon, identity);

    const valueRow = createElement("div", "detail-value-row");
    const value = createElement("code", "detail-value is-masked", "••••••••••••••••");
    value.setAttribute("aria-label", `${record.name} 当前为隐藏状态`);
    const actions = createElement("div", "detail-variable__actions");
    const reveal = createElement("button", "value-action", "显示");
    reveal.type = "button";
    reveal.setAttribute("aria-label", `显示 ${record.name}`);
    reveal.addEventListener("click", () => toggleSecretValue(record.name, value, reveal));
    const copy = createElement("button", "value-action value-action--copy", "复制");
    copy.type = "button";
    copy.setAttribute("aria-label", `复制 ${record.name}`);
    copy.addEventListener("click", () => copySecretValue(record.name, copy));
    actions.append(reveal, copy);
    valueRow.append(value, actions);

    const foot = createElement("div", "detail-variable__foot");
    const tagRow = createElement("div", "tag-row");
    appendTags(tagRow, record.tags);
    foot.append(tagRow, createElement("span", "", `更新于 ${formatDate(record.updated_at)}`));
    item.append(heading, valueRow, foot);
    container.append(item);
  });
}

async function requestSecretValue(name) {
  return api("/api/secrets/reveal", {
    method: "POST",
    body: JSON.stringify({ name }),
  });
}

async function toggleSecretValue(name, valueElement, button) {
  if (button.dataset.revealed === "true") {
    valueElement.textContent = "••••••••••••••••";
    valueElement.classList.add("is-masked");
    valueElement.setAttribute("aria-label", `${name} 当前为隐藏状态`);
    button.dataset.revealed = "false";
    button.textContent = "显示";
    button.setAttribute("aria-label", `显示 ${name}`);
    if (valueElement.classList.contains("lookup-inline-value")) valueElement.hidden = true;
    return;
  }

  button.disabled = true;
  button.textContent = "读取中";
  try {
    const payload = await requestSecretValue(name);
    valueElement.textContent = payload.value;
    valueElement.hidden = false;
    valueElement.classList.remove("is-masked");
    valueElement.setAttribute("aria-label", `${name} 的秘密值已显示`);
    button.dataset.revealed = "true";
    button.textContent = "隐藏";
    button.setAttribute("aria-label", `隐藏 ${name}`);
    payload.value = "";
  } catch (error) {
    button.textContent = "显示";
    if (valueElement.classList.contains("lookup-inline-value")) valueElement.hidden = true;
    toast("读取失败", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function copySecretValue(name, button) {
  button.disabled = true;
  const original = button.textContent;
  button.textContent = "复制中";
  try {
    const payload = await requestSecretValue(name);
    await navigator.clipboard.writeText(payload.value);
    payload.value = "";
    button.textContent = "已复制";
    toast("已复制到剪贴板", `${name} 的值已复制，请在使用后及时清理剪贴板。`);
    window.setTimeout(() => {
      if (button.isConnected) button.textContent = original;
    }, 1800);
  } catch (error) {
    button.textContent = original;
    toast("复制失败", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function closeDetail() {
  state.activeEntryId = null;
  document.querySelector("#detailVariableList").replaceChildren();
  if (detailDialog.open) detailDialog.close();
}

function closeDialog(dialog) {
  if (dialog === secretDialog) {
    secretForm.reset();
    secretValue.value = "";
    secretValue.classList.add("is-masked");
  }
  dialog.close();
}

function showFormError(form, message) {
  const region = form.querySelector("[data-form-error]");
  if (region) region.textContent = message;
}

function clearFormError(form) {
  showFormError(form, "");
}

function toast(title, copy, type = "success") {
  const region = document.querySelector("#toastRegion");
  const item = createElement("div", `toast ${type === "error" ? "toast--error" : ""}`.trim());
  const icon = createElement("span", "toast__icon", type === "error" ? "!" : "✓");
  const text = createElement("div");
  text.append(createElement("strong", "", title), createElement("small", "", copy));
  item.append(icon, text);
  region.append(item);
  window.setTimeout(() => {
    item.classList.add("is-leaving");
    window.setTimeout(() => item.remove(), 300);
  }, 3600);
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginError.textContent = "";
  if (!loginForm.reportValidity()) return;
  const button = document.querySelector("#loginButton");
  setLoading(button, true);
  try {
    const session = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: loginForm.elements.username.value,
        password: loginForm.elements.password.value,
      }),
    });
    loginForm.elements.password.value = "";
    showApp(session);
    await loadSnapshot();
    toast("欢迎回来", "保险柜已经为你打开。");
  } catch (error) {
    loginError.textContent = error.message;
  } finally {
    setLoading(button, false);
  }
});

entryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearFormError(entryForm);
  if (!entryForm.reportValidity()) return;
  const button = entryForm.querySelector("button[type='submit']");
  setLoading(button, true);
  const entryId = entryForm.elements.id.value.trim();
  try {
    await api("/api/entries", {
      method: "POST",
      body: JSON.stringify({
        id: entryId,
        description: entryForm.elements.description.value.trim(),
        category: entryForm.elements.category.value === "__other__" ? "" : entryForm.elements.category.value,
        tags: normalizeTags(entryForm.elements.tags.value),
      }),
    });
    closeDialog(entryDialog);
    await loadSnapshot();
    toast("条目创建成功", "现在可以在详情里添加变量。");
    window.setTimeout(() => openDetail(entryId), 220);
  } catch (error) {
    showFormError(entryForm, error.message);
  } finally {
    setLoading(button, false);
  }
});

categoryCreateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorRegion = document.querySelector("[data-category-create-error]");
  errorRegion.textContent = "";
  if (!categoryCreateForm.reportValidity()) return;
  const button = categoryCreateForm.querySelector("button[type='submit']");
  const name = categoryCreateForm.elements.name.value.trim();
  const categoryId = categoryIdFromName(name);
  setLoading(button, true);
  try {
    await api("/api/categories", {
      method: "POST",
      body: JSON.stringify({ id: categoryId, name, color: categoryCreateForm.elements.color.value }),
    });
    categoryCreateForm.reset();
    await loadSnapshot();
    renderCategoryManager();
    document.querySelector("#categoryAssignTarget").value = categoryId;
    toast("分类已创建", `${name} 已加入分类栏。`);
  } catch (error) {
    errorRegion.textContent = error.message;
  } finally {
    setLoading(button, false);
  }
});

categoryAssignForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorRegion = document.querySelector("[data-category-assign-error]");
  errorRegion.textContent = "";
  const selected = [...document.querySelectorAll("#categoryEntryList input[type='checkbox']:checked")]
    .map((checkbox) => checkbox.value);
  if (!selected.length) {
    errorRegion.textContent = "请至少选择一个资源。";
    return;
  }
  const button = categoryAssignForm.querySelector("button[type='submit']");
  const categoryId = categoryAssignForm.elements.category.value;
  const categoryName = categories().find((category) => category.id === categoryId)?.name || "其他";
  setLoading(button, true);
  try {
    await api("/api/categories/assign", {
      method: "POST",
      body: JSON.stringify({ category: categoryId, entries: selected }),
    });
    await loadSnapshot();
    renderCategoryManager();
    toast("资源已移动", `${selected.length} 个资源已归入“${categoryName}”。`);
  } catch (error) {
    errorRegion.textContent = error.message;
  } finally {
    setLoading(button, false);
  }
});

apiKeyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearFormError(apiKeyForm);
  if (!apiKeyForm.reportValidity()) return;
  const button = apiKeyForm.querySelector("button[type='submit']");
  setLoading(button, true);
  try {
    const payload = await api("/api/api-keys", {
      method: "POST",
      body: JSON.stringify({
        name: apiKeyForm.elements.name.value.trim(),
        note: apiKeyForm.elements.note.value.trim(),
      }),
    });
    closeApiKeyDialog();
    await loadSnapshot();
    openApiKeyRevealDialog(payload.api_key);
    toast("API Key 已创建", "它已独立存储，并拥有当前版本的管理员权限。 ");
  } catch (error) {
    showFormError(apiKeyForm, error.message);
  } finally {
    setLoading(button, false);
  }
});

apiKeyPermissionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorRegion = document.querySelector("[data-api-permission-error]");
  errorRegion.textContent = "";
  const level = apiKeyPermissionForm.querySelector("input[name='level']:checked")?.value || "none";
  const categories = [...apiKeyPermissionForm.querySelectorAll("input[name='categories']:checked")].map((input) => input.value);
  const skillCategories = [...apiKeyPermissionForm.querySelectorAll("input[name='skill_categories']:checked")].map((input) => input.value);
  const skillUploadCategories = [...apiKeyPermissionForm.querySelectorAll("input[name='skill_upload_categories']:checked")].map((input) => input.value);
  const permissions = {
    categories,
    skill_categories: skillCategories,
    skill_upload_categories: skillUploadCategories,
    read: level !== "none",
    add: level === "add",
    delete: document.querySelector("#apiPermissionDelete").checked,
  };
  const button = apiKeyPermissionForm.querySelector("button[type='submit']");
  setLoading(button, true);
  try {
    await api(`/api/api-keys/${encodeURIComponent(state.activePermissionKeyId)}/permissions`, {
      method: "POST",
      body: JSON.stringify(permissions),
    });
    closeApiKeyPermissionDialog();
    await loadSnapshot();
    toast("权限已保存", "新的分类范围会在下一次 Agent 请求时生效。");
  } catch (error) {
    errorRegion.textContent = error.message;
  } finally {
    setLoading(button, false);
  }
});

document.querySelector("#skillUploadOpen").addEventListener("click", () => openSkillUpload());
const skillPackageInput = document.querySelector("#skillPackageInput");
const skillFileDropzone = document.querySelector("#skillFileDropzone");
skillPackageInput.addEventListener("change", () => {
  const file = skillPackageInput.files[0];
  if (file && (!file.name.toLowerCase().endsWith(".zip") || file.size > 25 * 1024 * 1024)) {
    skillPackageInput.value = "";
    showFormError(skillUploadForm, "请选择不超过 25 MB 的 ZIP 文件。");
  } else {
    clearFormError(skillUploadForm);
  }
  updateSkillFileZone();
});
skillFileDropzone.addEventListener("dragover", (event) => {
  event.preventDefault();
  skillFileDropzone.classList.add("is-dragover");
});
skillFileDropzone.addEventListener("dragleave", (event) => {
  if (!skillFileDropzone.contains(event.relatedTarget)) skillFileDropzone.classList.remove("is-dragover");
});
skillFileDropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  skillFileDropzone.classList.remove("is-dragover");
  const file = event.dataTransfer?.files?.[0];
  if (!file) return;
  const transfer = new DataTransfer();
  transfer.items.add(file);
  skillPackageInput.files = transfer.files;
  skillPackageInput.dispatchEvent(new Event("change", { bubbles: true }));
});
document.querySelector("#skillCategoryOpen").addEventListener("click", () => {
  skillCategoryForm.reset();
  skillCategoryForm.elements.id.value = `category_${Math.random().toString(36).slice(2, 10)}`;
  clearFormError(skillCategoryForm);
  skillCategoryDialog.showModal();
});
document.querySelector("#skillUploadVersion").addEventListener("click", async () => {
  if (!state.activeSkillId) return;
  try {
    const { skill } = await api(`/api/skills/${encodeURIComponent(state.activeSkillId)}`);
    openSkillUpload(skill);
  } catch (error) { toast("打开上传失败", error.message, "error"); }
});
document.querySelectorAll("[data-close-skill-dialog]").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));

skillCategoryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearFormError(skillCategoryForm);
  if (!skillCategoryForm.reportValidity()) return;
  const button = skillCategoryForm.querySelector("button[type='submit']");
  setLoading(button, true);
  try {
    const { category } = await api("/api/skills/categories", { method: "POST", body: JSON.stringify({
      id: skillCategoryForm.elements.id.value.trim(), name: skillCategoryForm.elements.name.value.trim(),
    }) });
    skillCategoryDialog.close();
    state.activeSkillCategory = category.id;
    await loadSnapshot();
    toast("分类已创建", category.name);
  } catch (error) { showFormError(skillCategoryForm, error.message); }
  finally { setLoading(button, false); }
});

skillUploadForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearFormError(skillUploadForm);
  if (!skillUploadForm.reportValidity()) return;
  const file = skillUploadForm.elements.package.files[0];
  if (!file || !file.name.toLowerCase().endsWith(".zip") || file.size > 25 * 1024 * 1024) {
    showFormError(skillUploadForm, "请选择不超过 25 MB 的 ZIP 文件。");
    return;
  }
  const button = skillUploadForm.querySelector("button[type='submit']");
  setLoading(button, true);
  const query = new URLSearchParams({
    name: skillUploadForm.elements.name.value.trim(),
    description: skillUploadForm.elements.description.value.trim(),
    version: skillUploadForm.elements.version.value.trim(),
    category: skillUploadForm.elements.category.value,
    environment: skillUploadForm.elements.environment.value,
    environment_note: skillUploadForm.elements.environment_note.value.trim(),
  });
  if (state.uploadSkillId) query.set("skill_id", state.uploadSkillId);
  try {
    const response = await fetch(`/api/skills/upload?${query}`, {
      method: "POST", credentials: "same-origin", body: file,
      headers: { "Content-Type": "application/zip", "X-CSRF-Token": state.csrfToken },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `上传失败（${response.status}）`);
    skillUploadDialog.close();
    state.uploadSkillId = null;
    await loadSnapshot();
    toast("Skill 已入库", `${payload.skill.name} · v${payload.skill.latest_version}`);
  } catch (error) { showFormError(skillUploadForm, error.message); }
  finally { setLoading(button, false); }
});

function resetPasswordForm() {
  passwordForm.reset();
  passwordForm.querySelectorAll("input").forEach((input) => { input.type = "password"; });
  passwordForm.querySelectorAll("[data-toggle-password]").forEach((button) => {
    button.setAttribute("aria-label", button.getAttribute("aria-label").replace("隐藏", "显示"));
    button.setAttribute("aria-pressed", "false");
  });
  document.querySelector("[data-password-error]").textContent = "";
}

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorRegion = document.querySelector("[data-password-error]");
  errorRegion.textContent = "";
  if (!passwordForm.reportValidity()) return;
  const newPassword = passwordForm.elements.new_password.value;
  if (newPassword !== passwordForm.elements.confirm_password.value) {
    errorRegion.textContent = "两次输入的新密码不一致。";
    return;
  }
  const button = passwordForm.querySelector("button[type='submit']");
  setLoading(button, true);
  try {
    await api("/api/settings/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: passwordForm.elements.current_password.value,
        new_password: newPassword,
        confirm_password: passwordForm.elements.confirm_password.value,
      }),
    });
    passwordForm.reset();
    showLogin();
    loginError.textContent = "密码已修改，请使用新密码重新登录。";
  } catch (error) {
    errorRegion.textContent = error.message;
  } finally {
    setLoading(button, false);
  }
});

secretForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearFormError(secretForm);
  if (!secretForm.reportValidity()) return;
  const button = secretForm.querySelector("button[type='submit']");
  setLoading(button, true);
  try {
    const variableName = secretForm.elements.name.value.trim();
    await api("/api/secrets", {
      method: "POST",
      body: JSON.stringify({
        name: variableName,
        value: secretForm.elements.value.value,
        entry: secretForm.elements.entry.value,
        tags: normalizeTags(secretForm.elements.tags.value),
        note: secretForm.elements.note.value.trim(),
      }),
    });
    closeDialog(secretDialog);
    await loadSnapshot();
    toast("秘密已加密保存", `${variableName} 已安全写入保险柜。`);
  } catch (error) {
    showFormError(secretForm, error.message);
  } finally {
    setLoading(button, false);
  }
});

document.querySelectorAll("[data-toggle-password]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.querySelector(`#${button.dataset.togglePassword}`);
    const reveal = input.type === "password";
    input.type = reveal ? "text" : "password";
    button.setAttribute("aria-label", button.getAttribute("aria-label").replace(reveal ? "显示" : "隐藏", reveal ? "隐藏" : "显示"));
    button.setAttribute("aria-pressed", String(reveal));
  });
});

document.querySelector("[data-toggle-secret]").addEventListener("click", (event) => {
  const reveal = secretValue.classList.toggle("is-masked") === false;
  event.currentTarget.setAttribute("aria-label", reveal ? "隐藏秘密值" : "显示秘密值");
});

document.querySelectorAll("[data-close-dialog]").forEach((button) => {
  button.addEventListener("click", () => closeDialog(button.closest("dialog")));
});

[entryDialog, secretDialog].forEach((dialog) => {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) closeDialog(dialog);
  });
});

document.querySelectorAll("[data-close-category]").forEach((button) => {
  button.addEventListener("click", closeCategoryDialog);
});

document.querySelectorAll("[data-close-api-key]").forEach((button) => {
  button.addEventListener("click", closeApiKeyDialog);
});

document.querySelectorAll("[data-close-api-key-reveal]").forEach((button) => {
  button.addEventListener("click", closeApiKeyRevealDialog);
});

document.querySelectorAll("[data-close-api-permission]").forEach((button) => {
  button.addEventListener("click", closeApiKeyPermissionDialog);
});

document.querySelectorAll("[data-close-api-action]").forEach((button) => {
  button.addEventListener("click", closeApiKeyActionDialog);
});

categoryDialog.addEventListener("click", (event) => {
  if (event.target === categoryDialog) closeCategoryDialog();
});

apiKeyDialog.addEventListener("click", (event) => {
  if (event.target === apiKeyDialog) closeApiKeyDialog();
});

apiKeyRevealDialog.addEventListener("click", (event) => {
  if (event.target === apiKeyRevealDialog) closeApiKeyRevealDialog();
});

apiKeyPermissionDialog.addEventListener("click", (event) => {
  if (event.target === apiKeyPermissionDialog) closeApiKeyPermissionDialog();
});

apiKeyActionDialog.addEventListener("click", (event) => {
  if (event.target === apiKeyActionDialog) closeApiKeyActionDialog();
});

document.querySelector("#apiKeyActionConfirm").addEventListener("click", confirmApiKeyAction);

document.querySelectorAll("[data-close-detail]").forEach((button) => {
  button.addEventListener("click", closeDetail);
});

detailDialog.addEventListener("click", (event) => {
  if (event.target === detailDialog) closeDetail();
});

detailDialog.addEventListener("close", () => {
  state.activeEntryId = null;
  document.querySelector("#detailVariableList").replaceChildren();
});

document.querySelector("#detailAddSecret").addEventListener("click", () => {
  const entryId = state.activeEntryId;
  closeDetail();
  openSecretDialog(entryId || "");
});

document.querySelector("#detailCategorySave").addEventListener("click", async (event) => {
  if (!state.activeEntryId) return;
  const button = event.currentTarget;
  const categoryId = document.querySelector("#detailCategorySelect").value;
  const categoryName = categories().find((category) => category.id === categoryId)?.name || "其他";
  setLoading(button, true);
  try {
    await api("/api/categories/assign", {
      method: "POST",
      body: JSON.stringify({ category: categoryId, entries: [state.activeEntryId] }),
    });
    await loadSnapshot();
    toast("归类已更新", `${state.activeEntryId} 已归入“${categoryName}”。`);
  } catch (error) {
    toast("归类失败", error.message, "error");
  } finally {
    setLoading(button, false);
  }
});

document.querySelectorAll("[data-section]").forEach((button) => {
  button.addEventListener("click", (event) => {
    event.preventDefault();
    navigate(button.dataset.section);
  });
});

document.querySelectorAll("[data-personal-tab]").forEach((button) => {
  button.addEventListener("click", () => setPersonalTab(button.dataset.personalTab));
});

document.querySelectorAll("[data-open-entry]").forEach((button) => button.addEventListener("click", openEntryDialog));
document.querySelector("#newEntryButton").addEventListener("click", openEntryDialog);
document.querySelector("#manageCategoriesButton").addEventListener("click", openCategoryDialog);
document.querySelectorAll("[data-open-api-key]").forEach((button) => button.addEventListener("click", openApiKeyDialog));
document.querySelector("#categorySelectAll").addEventListener("change", (event) => {
  document.querySelectorAll("#categoryEntryList input[type='checkbox']").forEach((checkbox) => {
    checkbox.checked = event.currentTarget.checked;
  });
  updateCategorySelection();
});
document.querySelector("#unassignedCard").addEventListener("click", () => {
  updateSearch("", null);
  navigate("secrets");
});

function updateSearch(value, source) {
  state.query = value.trim();
  if (source !== searchInput) searchInput.value = value;
  if (source !== variableSearchInput) variableSearchInput.value = value;
  state.entryPage = 1;
  renderSnapshot();
}

searchInput.addEventListener("input", () => updateSearch(searchInput.value, searchInput));
variableSearchInput.addEventListener("input", () => updateSearch(variableSearchInput.value, variableSearchInput));

document.querySelector("#entryPageSize").addEventListener("change", (event) => {
  state.entryPageSize = Number(event.currentTarget.value);
  state.entryPage = 1;
  renderPaginatedEntries(filteredEntries());
});

document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k" && !appView.hidden) {
    event.preventDefault();
    (state.section === "secrets" ? variableSearchInput : searchInput).focus();
  }
});

document.querySelector("#mobileMenu").addEventListener("click", () => appView.classList.add("sidebar-open"));
document.querySelector("#mobileClose").addEventListener("click", () => appView.classList.remove("sidebar-open"));
document.querySelector("#sidebarBackdrop").addEventListener("click", () => appView.classList.remove("sidebar-open"));

document.querySelector("#tipDismiss").addEventListener("click", (event) => {
  event.currentTarget.closest(".tip-banner").remove();
});

document.querySelector("#logoutButton").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST", body: "{}" });
  } catch (error) {
    toast("退出遇到问题", error.message, "error");
  } finally {
    showLogin();
  }
});

async function bootstrap() {
  setToday();
  secretValue.classList.add("is-masked");
  try {
    const session = await api("/api/session");
    if (!session.authenticated) {
      showLogin();
      return;
    }
    showApp(session);
    await loadSnapshot();
  } catch (_error) {
    showLogin();
  }
}

bootstrap();
