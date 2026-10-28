"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const root = document.getElementById("dnsmanager");
  if (!root) return;
  const element = (id) => document.getElementById(`dns-${id}`);
  const base = root.dataset.base;
  const providers = JSON.parse(root.dataset.providers);
  const definition = (id) => providers.find((item) => item.id === id);
  const selectedProvider = () => definition(element("provider").value);
  let accounts = [];
  let page = 1;
  let auditPage = 1;
  let recordFilter = { rr: "", type: "" };
  let edited = null;
  let editingAccount = null;
  let currentView = "accounts";
  let lastHash = null;
  let busy = false;
  let unknown = false;
  const account = () => element("account").value;
  const domain = () => element("domain").value;
  const uuid = () => {
    if (crypto.randomUUID) return crypto.randomUUID();
    return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (value) =>
      (
        Number(value) ^
        (crypto.getRandomValues(new Uint8Array(1))[0] &
          (15 >> (Number(value) / 4)))
      ).toString(16),
    );
  };
  function message(text, error = false) {
    element("message").hidden = !text;
    element("message").textContent = text;
    element("message").className =
      `alert ${error ? "alert-danger" : "alert-info"}`;
  }
  async function api(path, data) {
    let response;
    try {
      response = await fetch(`${base}${path}`, {
        method: data ? "POST" : "GET",
        credentials: "same-origin",
        redirect: "error",
        headers: data
          ? {
              "Content-Type": "application/json",
              "X-CSRFToken": element("csrf").value,
            }
          : { Accept: "application/json" },
        body: data ? JSON.stringify(data) : undefined,
      });
      const payload = await response.json();
      if (!response.ok)
        throw Object.assign(
          new Error(payload.error || `HTTP ${response.status}`),
          payload,
        );
      return payload;
    } catch (error) {
      // A lost response does not prove that a mutation failed.
      if (data && (!response || error instanceof SyntaxError))
        error.outcome_unknown = true;
      throw error;
    }
  }
  function report(error) {
    if (error.outcome_unknown) unknown = true;
    message(
      `${error.message}${error.operation_id ? `；操作 ID：${error.operation_id}` : ""}${error.request_id ? `；请求 ID：${error.request_id}` : ""}${error.outcome_unknown ? "；结果未确认，请核对审计及云端记录，不要重复提交。" : ""}`,
      true,
    );
  }
  function go(view, updateHash = true) {
    const profile = accounts.find((item) => item.id === account());
    if (!profile) view = "accounts";
    currentView = view;
    for (const name of ["accounts", "domains", "records"])
      element(`${name}-view`).hidden = name !== view;
    element("view-title").textContent =
      view === "accounts" ? "DNS 凭据" : view === "domains" ? "域名" : domain();
    element("view-description").textContent =
      view === "accounts"
        ? "选择凭据，管理对应的域名与解析记录"
        : view === "domains"
          ? `当前凭据：${profile.label}`
          : `解析记录 · ${profile.label}`;
    element("crumb-profile-item").hidden = view === "accounts";
    element("crumb-domain-item").hidden = view !== "records";
    element("crumb-domains").textContent = profile?.label || "";
    element("crumb-domain").textContent = domain();
    message("");
    if (updateHash) {
      const hash =
        view === "accounts"
          ? "#credentials"
          : view === "domains"
            ? `#domains/${encodeURIComponent(account())}`
            : `#records/${encodeURIComponent(account())}/${encodeURIComponent(domain())}`;
      lastHash = hash;
      if (location.hash !== hash) location.hash = hash;
    }
  }
  async function restoreNavigation() {
    const hash = location.hash;
    if (hash === lastHash) return;
    lastHash = hash;
    try {
      const [kind, id, zone] = hash.slice(1).split("/").map(decodeURIComponent);
      const profile = accounts.find((item) => item.id === id);
      if (profile && ["domains", "records"].includes(kind)) {
        element("account").value = profile.id;
        await loadDomains();
        if (kind === "records" && profile.domains.includes(zone)) {
          element("domain").value = zone;
          go("records", false);
          await loadRecords();
        } else go("domains", false);
      } else go("accounts", false);
    } catch {
      go("accounts", false);
    }
  }
  function resetRecordFilter() {
    recordFilter = { rr: "", type: "" };
    element("record-filter-form").reset();
    page = 1;
  }
  function boundCredential(profile, key) {
    const masked = profile[key + "_masked"];
    if (!masked) return "仅管理员可见";
    return masked === "未配置" ? "未配置" : `已配置 · ${masked}`;
  }
  function showRecords(name) {
    element("domain").value = name;
    resetRecordFilter();
    resetEdit();
    go("records");
    loadRecords().catch(report);
  }
  function resetEdit() {
    edited = null;
    element("record-editor")?.close();
    element("record-form")?.reset();
    const defaults =
      accounts.find((item) => item.id === account())?.options || {};
    if (element("ttl")) element("ttl").value = defaults.ttl ?? 600;
    if (element("line")) element("line").value = defaults.line ?? "default";
    if (element("edit-title"))
      element("edit-title").textContent = "新增解析记录";
  }
  function button(label, action) {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "btn btn-sm btn-outline-primary me-1";
    item.textContent = label;
    item.addEventListener("click", action);
    return item;
  }
  function cell(row, text) {
    const item = document.createElement("td");
    item.textContent = String(text ?? "");
    row.append(item);
    return item;
  }
  function showAccountDetails(profile) {
    const details = element("account-detail-values");
    details.replaceChildren();
    const values = [
      ["账号名称", profile.label],
      ["账号 ID", profile.id],
      [
        "供应商",
        profile.provider_name ||
          definition(profile.provider_id)?.name ||
          "未知提供商",
      ],
      ["授权域名", profile.domains.join(", ")],
      ["版本", profile.revision],
      ...(definition(profile.provider_id)?.options || []).map((field) => [
        field.label,
        profile.options?.[field.key] ?? field.default,
      ]),
      ["更新时间", profile.updated_at],
    ];
    if (root.dataset.admin === "yes") {
      for (const field of definition(profile.provider_id)?.fields || [])
        values.push([field.label, boundCredential(profile, field.key)]);
    }
    values.forEach(([label, value]) => {
      const term = document.createElement("dt");
      term.className = "col-sm-3";
      term.textContent = label;
      const description = document.createElement("dd");
      description.className = "col-sm-9 text-break";
      description.textContent = String(value);
      details.append(term, description);
    });
    element("account-details").showModal();
  }
  async function testConnection(profile) {
    message(`正在测试 ${profile.label} 的 API 连接与首个授权域名读取权限…`);
    const result = await api(
      `/accounts/test?${new URLSearchParams({ account: profile.id })}`,
    );
    message(
      `API 连接及域名读取成功：${result.domain}。使用该账号的认证方式、区域与 HTTP 超时；不代表 DNS 已传播。`,
    );
  }
  function renderAccounts() {
    const table = element("accounts");
    const query = element("account-search").value.trim().toLowerCase();
    table.replaceChildren();
    accounts
      .filter((profile) =>
        [profile.label, ...profile.domains].some((value) =>
          value.toLowerCase().includes(query),
        ),
      )
      .forEach((profile) => {
        const row = document.createElement("tr");
        [
          profile.label,
          profile.provider_name ||
            definition(profile.provider_id)?.name ||
            "未知提供商",
          profile.domains.length,
          new Date(profile.updated_at).toLocaleString("zh-CN", {
            hour12: false,
          }),
        ].forEach((value) => cell(row, value));
        const actions = cell(row, "");
        actions.append(
          button("管理域名", () => selectAccount(profile.id).catch(report)),
          button("详情", () => showAccountDetails(profile)),
          button("连接测试", () => testConnection(profile).catch(report)),
        );
        if (root.dataset.admin === "yes" && root.dataset.write === "yes")
          actions.append(
            button("编辑", () => editAccount(profile)),
            button("删除", () => deleteAccount(profile)),
          );
        table.append(row);
      });
    element("account-empty").hidden = table.children.length > 0;
    element("account-count").textContent = `共 ${accounts.length} 个凭据`;
  }
  function currentOptions() {
    return Object.fromEntries(
      (selectedProvider()?.options || []).map((field) => [
        field.key,
        field.type === "number"
          ? Number(element(`option-${field.key}`).value)
          : element(`option-${field.key}`).value,
      ]),
    );
  }
  function renderProviderOptions() {
    const container = element("provider-options");
    container.replaceChildren();
    element("auth-options").replaceChildren();
    const sameProvider =
      editingAccount?.provider_id === element("provider").value;
    for (const field of selectedProvider()?.options || []) {
      const column = document.createElement("div");
      column.className = "col-md-6";
      const label = document.createElement("label");
      label.className = "form-label";
      label.textContent = field.label;
      label.htmlFor = `dns-option-${field.key}`;
      const input = document.createElement(
        field.type === "select" ? "select" : "input",
      );
      input.id = `dns-option-${field.key}`;
      input.required = true;
      input.className =
        field.type === "select" ? "form-select" : "form-control";
      if (field.type === "select")
        for (const choice of field.choices) {
          const option = document.createElement("option");
          option.value = choice.value;
          option.textContent = choice.label;
          input.append(option);
        }
      else {
        input.type = field.type;
        if (field.type === "number") {
          input.min = field.min;
          input.max = field.max;
          input.step = 1;
        } else input.maxLength = 128;
      }
      input.value = sameProvider
        ? (editingAccount.options?.[field.key] ?? field.default)
        : field.default;
      if (field.key === "auth_mode")
        input.addEventListener("change", renderCredentialFields);
      column.append(label, input);
      (field.key === "auth_mode" ? element("auth-options") : container).append(
        column,
      );
    }
    renderCredentialFields();
  }
  function activeCredentialFields() {
    const mode = element("option-auth_mode")?.value;
    return (selectedProvider()?.fields || []).filter(
      (field) => !field.auth_mode || field.auth_mode === mode,
    );
  }
  function renderCredentialFields() {
    const container = element("credential-fields");
    container.replaceChildren();
    for (const field of activeCredentialFields()) {
      const column = document.createElement("div");
      column.className = "col-md-6";
      const label = document.createElement("label");
      label.className = "form-label";
      label.htmlFor = `dns-${field.id}`;
      label.textContent = field.label + (field.required ? "" : "（可选）");
      const input = document.createElement("input");
      input.id = `dns-${field.id}`;
      input.className = "form-control";
      input.type = "password";
      input.autocomplete = "new-password";
      column.append(label, input);
      container.append(column);
    }
    credentialInputs();
  }
  function credentialInputs() {
    const changingProvider = Boolean(
      editingAccount &&
        editingAccount.provider_id !== element("provider").value,
    );
    const rotating =
      !editingAccount ||
      changingProvider ||
      element("rotate-credentials").checked;
    element("rotate-credentials").disabled =
      !editingAccount || changingProvider;
    if (changingProvider) element("rotate-credentials").checked = true;
    if (element("option-auth_mode"))
      element("option-auth_mode").disabled = !rotating;
    for (const field of activeCredentialFields()) {
      const input = element(field.id);
      input.disabled = !rotating;
      input.required = rotating && field.required;
      input.type = rotating ? "password" : "text";
      input.value = rotating
        ? ""
        : editingAccount?.[field.key + "_masked"] || "凭据状态不可用";
    }
    element("credential-help").textContent = rotating
      ? "填写完整新凭据；完整值不会回填。"
      : "保留已保存凭据及认证方式，可修改名称、授权 DNS 区域和 API / 解析配置。";
  }
  function domainInputs() {
    return [...element("account-domains").querySelectorAll("input")];
  }
  function validateDomainRows() {
    const inputs = domainInputs();
    const values = inputs.map((input) =>
      input.value.trim().replace(/\.$/, "").toLowerCase(),
    );
    inputs.forEach((input, index) => {
      const value = input.value.trim();
      input.setCustomValidity(
        /[\s,，/]/.test(value)
          ? "每行只填写一个 DNS 区域，不含空格、逗号或路径。"
          : values[index] && values.indexOf(values[index]) !== index
            ? "该 DNS 区域已添加。"
            : "",
      );
      input.setAttribute("aria-label", `授权 DNS 区域 ${index + 1}`);
      const remove = input.parentElement.querySelector("button");
      remove.disabled = inputs.length === 1;
      remove.setAttribute("aria-label", `删除授权 DNS 区域 ${index + 1}`);
    });
    element("add-domain").disabled = inputs.length >= 200;
  }
  function addDomainRow(value = "") {
    if (domainInputs().length >= 200) return;
    const row = document.createElement("div");
    row.className = "d-flex gap-2 mb-2";
    const input = document.createElement("input");
    input.className = "form-control";
    input.type = "text";
    input.required = true;
    input.maxLength = 253;
    input.placeholder = "example.com";
    input.value = value;
    input.autocomplete = "off";
    input.addEventListener("input", validateDomainRows);
    const remove = button("删除", () => {
      row.remove();
      validateDomainRows();
    });
    remove.classList.add("flex-shrink-0", "text-nowrap");
    row.append(input, remove);
    element("account-domains").append(row);
    validateDomainRows();
    return input;
  }
  function toggleCredentialRotation() {
    if (
      editingAccount &&
      !element("rotate-credentials").checked &&
      element("provider").value === editingAccount.provider_id &&
      element("option-auth_mode")
    )
      element("option-auth_mode").value =
        editingAccount.options?.auth_mode || "access_key";
    renderCredentialFields();
  }
  function editAccount(profile = null) {
    editingAccount = profile;
    element("account-form").reset();
    element("account-label").value = profile?.label || "";
    element("account-domains").replaceChildren();
    for (const zone of profile?.domains || [""]) addDomainRow(zone);
    element("provider").value = profile?.provider_id || providers[0]?.id || "";
    element("rotate-credentials").checked = !profile;
    element("rotate-credentials").disabled = !profile;
    element("account-editor-title").textContent = profile
      ? `编辑凭据：${profile.label}`
      : "新增凭据";
    renderProviderOptions();
    element("account-editor").showModal();
    element("account-label").focus();
  }
  function closeAccountEditor() {
    editingAccount = null;
    element("account-form")?.reset();
    element("account-editor")?.close();
  }
  async function selectAccount(id) {
    if (busy) return;
    element("account").value = id;
    renderAccounts();
    await loadDomains();
    go("domains");
  }
  async function deleteAccount(profile) {
    if (busy || unknown) return;
    if (
      !window.confirm(
        `确认删除本地凭据“${profile.label}”？云端域名、解析记录及证书签发凭据不受影响。`,
      )
    )
      return;
    busy = true;
    let acknowledged = false;
    try {
      await api("/accounts/delete", {
        id: profile.id,
        revision: profile.revision,
        operation_id: uuid(),
      });
      acknowledged = true;
      if (editingAccount?.id === profile.id) closeAccountEditor();
      element("account-details").close();
      await loadAccounts();
      await loadAudit();
      message("本地凭据已删除；云端解析记录和证书签发凭据未改变。");
    } catch (error) {
      if (acknowledged)
        message("凭据已删除，但页面刷新失败，请刷新页面。", true);
      else report(error);
    } finally {
      busy = false;
    }
  }
  async function loadRecords(manual = false) {
    if (!account() || !domain()) {
      element("records").replaceChildren();
      element("page").textContent = "尚未选择域名";
      element("prev").disabled = true;
      element("next").disabled = true;
      return;
    }
    const query = new URLSearchParams({
      account: account(),
      domain: domain(),
      page,
      ...recordFilter,
    });
    const data = await api(`/records?${query}`);
    if (
      query.get("account") !== account() ||
      query.get("domain") !== domain() ||
      query.get("page") !== String(page) ||
      query.get("rr") !== recordFilter.rr ||
      query.get("type") !== recordFilter.type
    )
      return;
    element("records").replaceChildren();
    data.records.forEach((record) => {
      const row = document.createElement("tr");
      [
        record.RR,
        record.Type,
        record.Value,
        record.TTL,
        record.Line,
        record.Status === "ENABLE" ? "已启用" : "已暂停",
      ].forEach((value, index) => {
        const content = String(value ?? "");
        const item = cell(
          row,
          index === 2 && content.length > 80
            ? content.slice(0, 77) + "…"
            : content,
        );
        if (index === 2) item.title = content;
      });
      const actions = cell(row, "");
      if (
        ["A", "AAAA", "CNAME", "TXT"].includes(record.Type) &&
        !record.RR.includes("*")
      )
        actions.append(
          button("解析测试", () => testResolution(record).catch(report)),
        );
      if (root.dataset.write === "yes") {
        actions.append(
          button("编辑", () => {
            edited = record;
            element("edit-title").textContent = `修改 ${record.RR}.${domain()}`;
            for (const [id, key] of [
              ["rr", "RR"],
              ["type", "Type"],
              ["value", "Value"],
              ["ttl", "TTL"],
              ["line", "Line"],
              ["priority", "Priority"],
            ]) {
              element(id).value = record[key] ?? (key === "Priority" ? 1 : "");
            }
            element("record-editor").showModal();
          }),
          button(record.Status === "ENABLE" ? "暂停" : "启用", () =>
            mutate("status", record),
          ),
          button("删除", () => mutate("delete", record)),
        );
      }
      element("records").append(row);
    });
    element("record-empty").hidden = data.records.length > 0;
    element("page").textContent = `共 ${data.total} 条 · 第 ${page} 页`;
    element("prev").disabled = page <= 1;
    element("next").disabled = page * 50 >= data.total;
    if (manual) {
      unknown = false;
      resetEdit();
    }
    if (manual) message("记录已刷新。");
  }
  async function loadAccounts() {
    const selected = account();
    const data = await api("/accounts");
    accounts = data.accounts;
    element("account").replaceChildren();
    accounts.forEach((item) => {
      const option = document.createElement("option");
      option.value = item.id;
      option.textContent = item.label;
      element("account").append(option);
    });
    if (accounts.some((item) => item.id === selected))
      element("account").value = selected;
    renderAccounts();
    await loadDomains();
    if (lastHash === null) await restoreNavigation();
    else {
      go(currentView);
      if (currentView === "records") await loadRecords();
    }
    if (!accounts.length)
      message("尚未配置云账号；请由管理员配置授权域名和独立 DNS 凭据。");
  }
  function renderDomains() {
    const profile = accounts.find((item) => item.id === account());
    const table = element("domains");
    const query = element("domain-search").value.trim().toLowerCase();
    table.replaceChildren();
    for (const name of profile?.domains || []) {
      if (!name.toLowerCase().includes(query)) continue;
      const row = document.createElement("tr");
      cell(row, name);
      cell(row, profile.label);
      const actions = cell(row, "");
      actions.append(button("管理解析", () => showRecords(name)));
      table.append(row);
    }
    element("domain-empty").hidden = table.children.length > 0;
    element("domain-count").textContent =
      `共 ${profile?.domains.length || 0} 个授权域名`;
  }
  async function loadDomains() {
    resetRecordFilter();
    resetEdit();
    page = 1;
    const previous = domain();
    element("domain").replaceChildren();
    const profile = accounts.find((item) => item.id === account());
    for (const name of profile?.domains || []) {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      element("domain").append(option);
    }
    if (profile?.domains.includes(previous)) element("domain").value = previous;
    element("domain-search").value = "";
    renderDomains();
  }
  async function mutate(action, record = null, values = null) {
    if (busy || unknown) {
      message(
        unknown ? "请先核对未确认操作并手动刷新记录。" : "已有操作进行中。",
        true,
      );
      return;
    }
    const selectedDomain = domain();
    if (!account() || !selectedDomain) return;
    const description = values
      ? JSON.stringify(values)
      : `${record.RR} ${record.Type} ${record.Value}`;
    const actionLabel = {
      add: "新增",
      update: "修改",
      delete: "删除",
      status: "启停",
    }[action];
    if (
      !window.confirm(
        `确认对 ${selectedDomain} 执行${actionLabel}？\n${description}`,
      )
    )
      return;
    busy = true;
    const operationId = uuid();
    let acknowledged = false;
    try {
      const result = await api("/records/write", {
        operation_id: operationId,
        account: account(),
        domain: selectedDomain,
        action,
        confirmed: true,
        record_id: record?.RecordId,
        fingerprint: record?.fingerprint,
        values,
        status: record?.Status === "ENABLE" ? "DISABLE" : "ENABLE",
      });
      acknowledged = true;
      resetEdit();
      await loadRecords();
      message(
        `操作成功；操作 ID：${result.operation_id}。解析缓存按 TTL 逐步更新。`,
      );
    } catch (error) {
      if (acknowledged)
        message("写入已成功，但刷新失败。请手动刷新，不要重复提交。", true);
      else {
        error.operation_id = operationId;
        report(error);
      }
    } finally {
      busy = false;
      loadAudit().catch(report);
    }
  }
  let checkRun = 0;
  async function testResolution(record) {
    const run = ++checkRun;
    const accountId = account(),
      zone = domain();
    const options =
      accounts.find((item) => item.id === accountId)?.options || {};
    const deadline = Date.now() + (options.propagation_timeout ?? 60) * 1000;
    element("resolution-result").textContent =
      "正在检查 AliDNS 公共递归解析结果…";
    element("resolution-dialog").showModal();
    while (run === checkRun && element("resolution-dialog").open) {
      const remaining = Math.floor((deadline - Date.now()) / 1000);
      if (remaining < 1) {
        element("resolution-result").textContent +=
          "\n等待超时：尚未在该递归解析器观察到匹配值。";
        return;
      }
      try {
        const result = await api(
          `/records/test?${new URLSearchParams({ account: accountId, domain: zone, record_id: record.RecordId, remaining: Math.min(600, remaining) })}`,
        );
        if (run !== checkRun || !element("resolution-dialog").open) return;
        element("resolution-result").textContent =
          `${result.name} (${result.type})\n预期：${result.expected}\n查询结果：${result.answers.join(", ") || "无匹配类型结果"}\n${result.matched ? "已观察到匹配值" : "尚未匹配，继续等待"}\n检测范围：AliDNS 公共递归解析器，不代表全部线路或全球缓存已生效。`;
        if (result.matched) return;
      } catch (error) {
        if (run !== checkRun || !element("resolution-dialog").open) return;
        element("resolution-result").textContent =
          `查询失败：${error.message}，将在等待时限内重试。`;
      }
      const delay = Math.min(
        (options.polling_interval ?? 2) * 1000,
        Math.max(0, deadline - Date.now()),
      );
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  element("close-resolution").addEventListener("click", () => {
    checkRun++;
    element("resolution-dialog").close();
  });
  element("resolution-dialog").addEventListener("close", () => {
    checkRun++;
  });
  async function loadAudit() {
    const result = await api(`/audit?page=${auditPage}`);
    element("audit").replaceChildren();
    result.events.forEach((event) => {
      const row = document.createElement("tr");
      cell(row, `${event.created_at}\n${event.id}`);
      cell(row, event.actor);
      cell(row, `${event.action}\n${event.status}`);
      cell(row, JSON.stringify({ intent: event.intent, result: event.result }));
      element("audit").append(row);
    });
    element("audit-page").textContent = `第 ${auditPage} 页`;
    element("audit-prev").disabled = auditPage <= 1;
    element("audit-next").disabled = result.events.length < 50;
  }
  async function saveAccount() {
    if (busy || unknown) {
      if (unknown)
        message("请核对未确认操作的审计及云端状态，再重新加载页面。", true);
      return;
    }
    const form = element("account-form");
    if (!form.reportValidity()) return;
    const profile = editingAccount;
    const update = Boolean(profile);
    if (
      !window.confirm(
        update
          ? "确认更新所编辑账号？未勾选更换凭据时，原密钥保持不变。"
          : "确认创建 DNS 管理账号？",
      )
    )
      return;
    busy = true;
    let acknowledged = false;
    try {
      await api("/accounts/save", {
        id: update ? profile.id : uuid(),
        revision: update ? profile.revision : 0,
        label: element("account-label").value,
        domains: domainInputs().map((input) => input.value.trim()),
        provider_id: element("provider").value,
        options: currentOptions(),
        credentials:
          !update || element("rotate-credentials").checked
            ? Object.fromEntries(
                activeCredentialFields().map((field) => [
                  field.key,
                  element(field.id).value,
                ]),
              )
            : null,
        operation_id: uuid(),
      });
      acknowledged = true;
      closeAccountEditor();
      await loadAccounts();
      await loadAudit();
      message("凭据已保存。");
    } catch (error) {
      if (acknowledged)
        message("凭据已保存，但刷新失败，请刷新页面，不要重复提交。", true);
      else report(error);
    } finally {
      busy = false;
    }
  }
  element("account").addEventListener("change", () => {
    renderAccounts();
    loadDomains().catch(report);
  });
  element("domain").addEventListener("change", () => {
    page = 1;
    resetEdit();
    loadRecords().catch(report);
  });
  element("record-filter-form").addEventListener("submit", (event) => {
    event.preventDefault();
    recordFilter = {
      rr: element("record-rr-filter").value.trim(),
      type: element("record-type-filter").value,
    };
    page = 1;
    loadRecords().catch(report);
  });
  element("reset-record-filter").addEventListener("click", () => {
    resetRecordFilter();
    loadRecords().catch(report);
  });
  element("refresh").addEventListener("click", () =>
    loadRecords(true).catch(report),
  );
  element("prev").addEventListener("click", () => {
    if (page > 1) page--;
    loadRecords().catch(report);
  });
  element("next").addEventListener("click", () => {
    page++;
    loadRecords().catch(report);
  });
  element("reset-record")?.addEventListener("click", resetEdit);
  element("record-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    const values = {
      RR: element("rr").value,
      Type: element("type").value,
      Value: element("value").value,
      TTL: Number(element("ttl").value),
      Line: element("line").value,
    };
    if (values.Type === "MX")
      values.Priority = Number(element("priority").value);
    mutate(edited ? "update" : "add", edited, values);
  });
  element("account-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    saveAccount().catch(report);
  });
  element("new-account")?.addEventListener("click", () => editAccount());
  element("cancel-account")?.addEventListener("click", closeAccountEditor);
  element("rotate-credentials")?.addEventListener(
    "change",
    toggleCredentialRotation,
  );
  element("add-domain")?.addEventListener("click", () =>
    addDomainRow()?.focus(),
  );
  element("provider")?.addEventListener("change", renderProviderOptions);
  element("account-search").addEventListener("input", renderAccounts);
  element("close-account-details").addEventListener("click", () => {
    element("account-details").close();
  });
  element("audit-refresh").addEventListener("click", () =>
    loadAudit().catch(report),
  );
  element("audit-prev").addEventListener("click", () => {
    if (auditPage > 1) auditPage--;
    loadAudit().catch(report);
  });
  element("audit-next").addEventListener("click", () => {
    auditPage++;
    loadAudit().catch(report);
  });
  element("domain-search").addEventListener("input", renderDomains);
  element("crumb-accounts").addEventListener("click", () => go("accounts"));
  element("crumb-domains").addEventListener("click", () => go("domains"));
  element("edit-scope")?.addEventListener("click", () =>
    editAccount(accounts.find((item) => item.id === account())),
  );
  element("new-record")?.addEventListener("click", () => {
    resetEdit();
    element("record-editor").showModal();
  });
  element("open-audit").addEventListener("click", () => {
    element("audit-dialog").showModal();
    loadAudit().catch(report);
  });
  element("close-audit").addEventListener("click", () =>
    element("audit-dialog").close(),
  );
  element("account-editor")?.addEventListener("close", () => {
    editingAccount = null;
    element("account-form").reset();
  });
  element("record-editor")?.addEventListener("close", () => {
    edited = null;
    element("record-form").reset();
  });
  window.addEventListener("hashchange", () =>
    restoreNavigation().catch(report),
  );
  loadAccounts().catch(report);
});
