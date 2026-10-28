"use strict";
// Run only against serve_dnsmanager_fixture.py, never a real credential store.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const base = process.env.DNS_FIXTURE_URL || "http://127.0.0.1:18711";
assert(
  ["127.0.0.1", "localhost"].includes(new URL(base).hostname) ||
    process.env.DNS_FIXTURE_ALLOW_REMOTE === "yes",
  "Remote fixtures require DNS_FIXTURE_ALLOW_REMOTE=yes; never use a real credential store",
);
assert.equal(new URL(base).port, "18711");
(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.BROWSER_EXECUTABLE || undefined,
  });
  const context = await browser.newContext({
    extraHTTPHeaders: { "X-Test-User": "admin" },
    viewport: { width: 1440, height: 1000 },
  });
  const page = await context.newPage();
  const errors = [];
  const saves = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("dialog", (dialog) => dialog.accept());
  page.on("request", (request) => {
    if (request.url().endsWith("/accounts/save"))
      saves.push(request.postDataJSON());
  });
  const rows = page.locator("#dns-accounts tr");
  async function countRows(expected) {
    await page.waitForFunction(
      (n) => document.querySelectorAll("#dns-accounts tr").length === n,
      expected,
    );
  }
  function row(label) {
    return rows.filter({
      has: page.locator("td:first-child", { hasText: label }),
    });
  }
  try {
    await page.goto(base + "/dnsmanager");
    await countRows(2);
    assert(
      !(await page.locator("#dns-accounts-view thead").innerText()).includes(
        "AccessKey",
      ),
    );
    assert(!(await page.locator("#dns-accounts").innerText()).includes("••••"));
    await row("Acceptance")
      .getByRole("button", { name: "连接测试", exact: true })
      .click();
    await page.waitForFunction(() =>
      document
        .querySelector("#dns-message")
        .textContent.includes("API 连接及域名读取成功"),
    );
    assert(await page.locator("#dns-accounts-view").isVisible());
    assert(await page.locator("#dns-domains-view").isHidden());
    assert(await page.locator("#dns-records-view").isHidden());
    assert.equal(await page.locator("#dns-records tr").count(), 0);
    await page.screenshot({
      path: "/tmp/bw-dnsmanager-051-credentials.png",
      fullPage: true,
    });
    await row("Acceptance")
      .getByRole("button", { name: "管理域名", exact: true })
      .click();
    assert(await page.locator("#dns-domains-view").isVisible());
    assert(await page.locator("#dns-accounts-view").isHidden());
    await page.screenshot({
      path: "/tmp/bw-dnsmanager-051-domains.png",
      fullPage: true,
    });
    await page
      .locator("#dns-domains")
      .getByRole("button", { name: "管理解析", exact: true })
      .first()
      .click();
    await page.locator("#dns-records tr").first().waitFor();
    assert(await page.locator("#dns-records-view").isVisible());
    await page
      .locator("#dns-records")
      .getByRole("button", { name: "解析测试", exact: true })
      .first()
      .click();
    await page.waitForFunction(() =>
      document
        .querySelector("#dns-resolution-result")
        .textContent.includes("已观察到匹配值"),
    );
    await page.locator("#dns-close-resolution").click();
    assert(await page.locator("#dns-domains-view").isHidden());
    await page.screenshot({
      path: "/tmp/bw-dnsmanager-051-records.png",
      fullPage: true,
    });
    await page.locator("#dns-record-type-filter").selectOption("CNAME");
    await page
      .locator("#dns-record-filter-form")
      .getByRole("button", { name: "搜索", exact: true })
      .click();
    await page.waitForFunction(() =>
      document.getElementById("dns-page").textContent.includes("共 0 条"),
    );
    assert.equal(await page.locator("#dns-records tr").count(), 0);
    assert(await page.locator("#dns-record-empty").isVisible());
    await page.locator("#dns-record-type-filter").selectOption("A");
    await page.locator("#dns-record-rr-filter").fill("www");
    await page
      .locator("#dns-record-filter-form")
      .getByRole("button", { name: "搜索", exact: true })
      .click();
    await page.locator("#dns-records tr").first().waitFor();
    await page.locator("#dns-reset-record-filter").click();
    assert.equal(
      await page.locator("#dns-record-type-filter").inputValue(),
      "",
    );
    assert.equal(await page.locator("#dns-record-rr-filter").inputValue(), "");
    await page.screenshot({
      path: "/tmp/bw-dnsmanager-051-records.png",
      fullPage: true,
    });
    await page.locator("#dns-new-record").click();
    assert(await page.locator("#dns-record-editor").isVisible());
    await page.locator("#dns-reset-record").click();
    await page.locator("#dns-crumb-domains").click();
    await page.locator("#dns-crumb-accounts").click();
    await page.goBack();
    await page.waitForFunction(
      () => !document.getElementById("dns-domains-view").hidden,
    );
    await page.locator("#dns-crumb-accounts").click();
    await row("Acceptance")
      .getByRole("button", { name: "详情", exact: true })
      .click();
    assert(
      (await page.locator("#dns-account-details").innerText()).includes("••••"),
    );
    assert(!(await page.locator("body").innerText()).includes("fake-secret"));
    await page.locator("#dns-close-account-details").click();
    await page.locator("#dns-account-search").fill("Second");
    await countRows(1);
    await row("Second fixture")
      .getByRole("button", { name: "管理域名", exact: true })
      .click();
    assert.equal(await page.locator("#dns-domains tr").count(), 2);
    await page
      .locator("#dns-domains tr")
      .filter({ hasText: "sub.example.net" })
      .getByRole("button", { name: "管理解析" })
      .click();
    assert.equal(
      await page.locator("#dns-domain").inputValue(),
      "sub.example.net",
    );
    await page.locator("#dns-crumb-accounts").click();
    await page.locator("#dns-account-search").fill("");
    await countRows(2);
    await row("Acceptance")
      .getByRole("button", { name: "编辑", exact: true })
      .click();
    assert.equal(
      await page.locator("#dns-account-label").inputValue(),
      "Acceptance",
    );
    assert.equal(
      await page.locator("#dns-account-domains input").first().inputValue(),
      "example.com",
    );
    assert(await page.locator("#dns-key-secret").isDisabled());
    assert(
      (await page.locator("#dns-key-secret").inputValue()).includes("••••"),
    );
    assert.equal(
      await page.locator("#dns-key-secret").getAttribute("type"),
      "text",
    );
    assert((await page.locator("#dns-key-id").inputValue()).includes("••••"));
    await page.screenshot({
      path: "/tmp/bw-dnsmanager-051-editor.png",
      fullPage: true,
    });
    await page.screenshot({
      path: "/tmp/bw-dnsmanager-051-credentials.png",
      fullPage: true,
    });
    assert.equal(await page.locator("#dns-provider").inputValue(), "alidns");
    assert(await page.locator("#dns-provider").isEnabled());
    assert.equal(await page.locator("#dns-provider option").count(), 2);
    await page.locator("#dns-provider").selectOption("alidns");
    await page.screenshot({
      path: "/tmp/bw-dnsmanager-051-provider-edit.png",
      fullPage: true,
    });
    assert.equal(
      await page.locator("#dns-option-http_timeout").inputValue(),
      "10",
    );
    await page.locator("#dns-option-http_timeout").fill("17");
    await page.locator("#dns-option-ttl").fill("120");
    await page.locator("#dns-option-line").fill("telecom");
    await page.locator("#dns-option-propagation_timeout").fill("120");
    await page.locator("#dns-add-domain").click();
    assert.equal(await page.locator("#dns-account-domains input").count(), 2);
    await page.locator("#dns-account-domains input").nth(1).fill("example.org");
    await page.locator("#dns-account-label").fill("Renamed acceptance");
    await page.locator("#dns-save-account").click();
    await row("Renamed acceptance").waitFor();
    assert.equal(saves[0].credentials, null);
    assert.equal(saves[0].provider_id, "alidns");
    assert.equal(saves[0].options.http_timeout, 17);
    assert.deepEqual(saves[0].domains, ["example.com", "example.org"]);
    await row("Renamed acceptance")
      .getByRole("button", { name: "编辑", exact: true })
      .click();
    assert.equal(
      await page.locator("#dns-option-http_timeout").inputValue(),
      "17",
    );
    assert.equal(await page.locator("#dns-account-domains input").count(), 2);
    await page.locator("#dns-account-domains button").nth(1).click();
    assert.equal(await page.locator("#dns-account-domains input").count(), 1);
    assert(
      await page.locator("#dns-account-domains button").first().isDisabled(),
    );
    assert(await page.locator("#dns-option-auth_mode").isDisabled());
    await page.locator("#dns-rotate-credentials").check();
    assert(await page.locator("#dns-option-auth_mode").isEnabled());
    await page.locator("#dns-option-auth_mode").selectOption("ecs_ram_role");
    assert.equal(await page.locator("#dns-key-id").count(), 0);
    assert(await page.locator("#dns-ram-role").isVisible());
    assert(await page.locator("#dns-ram-role").evaluate((el) => el.required));
    await page.locator("#dns-rotate-credentials").uncheck();
    assert.equal(
      await page.locator("#dns-option-auth_mode").inputValue(),
      "access_key",
    );
    assert(await page.locator("#dns-option-auth_mode").isDisabled());
    assert((await page.locator("#dns-key-id").inputValue()).includes("••••"));
    assert.equal(await page.locator("#dns-ram-role").count(), 0);
    await page.locator("#dns-cancel-account").click();
    await row("Renamed acceptance")
      .getByRole("button", { name: "管理域名", exact: true })
      .click();
    await page
      .locator("#dns-domains")
      .getByRole("button", { name: "管理解析", exact: true })
      .first()
      .click();
    await page.locator("#dns-new-record").click();
    assert.equal(await page.locator("#dns-ttl").inputValue(), "120");
    assert.equal(await page.locator("#dns-line").inputValue(), "telecom");
    await page.locator("#dns-reset-record").click();
    await page.locator("#dns-crumb-accounts").click();
    assert(await page.locator("#dns-account-editor").isHidden());
    await page.locator("#dns-new-account").click();
    assert.equal(await page.locator("#dns-provider").inputValue(), "alidns");
    assert(await page.locator("#dns-provider").isEnabled());
    await page.locator("#dns-key-id").fill("temporary-id");
    await page.locator("#dns-provider").selectOption("fixture");
    assert.equal(await page.locator("#dns-key-id").count(), 0);
    assert.equal(await page.locator("#dns-fixture-token").count(), 1);
    assert.equal(await page.locator("#dns-fixture-token").inputValue(), "");
    assert(
      await page
        .locator("#dns-fixture-token")
        .evaluate((input) => input.required),
    );
    await page.locator("#dns-provider").selectOption("alidns");
    assert.equal(await page.locator("#dns-fixture-token").count(), 0);
    assert.equal(await page.locator("#dns-key-id").inputValue(), "");
    await page.locator("#dns-account-label").fill("New browser account");
    await page
      .locator("#dns-account-domains input")
      .first()
      .fill("example.org");
    await page.locator("#dns-key-id").fill("new-fixture-id");
    await page.locator("#dns-key-secret").fill("new-fixture-secret-12345");
    await page.locator("#dns-save-account").click();
    await countRows(3);
    await row("New browser account")
      .getByRole("button", { name: "编辑", exact: true })
      .click();
    await page.locator("#dns-rotate-credentials").check();
    await page.locator("#dns-key-id").fill("rotated-fixture-id");
    await page.locator("#dns-key-secret").fill("rotated-fixture-secret");
    await page.locator("#dns-security-token").fill("rotated-fixture-sts-token");
    await page.locator("#dns-save-account").click();
    await page.waitForFunction(
      () => !document.querySelector("#dns-account-editor").open,
    );
    assert.equal(
      saves.at(-1).credentials.security_token,
      "rotated-fixture-sts-token",
    );
    await row("New browser account")
      .getByRole("button", { name: "详情", exact: true })
      .click();
    assert(
      !(await page.locator("#dns-account-details").innerText()).includes(
        "rotated-fixture-secret",
      ),
    );
    await page.locator("#dns-close-account-details").click();
    await row("New browser account")
      .getByRole("button", { name: "删除", exact: true })
      .click();
    await countRows(2);
    await page.locator("#dns-account-search").fill("no-such-account");
    await countRows(0);
    assert(await page.locator("#dns-account-empty").isVisible());
    await page.locator("#dns-account-search").fill("");
    await countRows(2);
    await page.screenshot({
      path: "/tmp/bw-dnsmanager-051-desktop.png",
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    assert(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth + 2,
      ),
    );
    await page.screenshot({
      path: "/tmp/bw-dnsmanager-051-mobile.png",
      fullPage: true,
    });
    for (const role of ["reader", "writer"]) {
      const other = await browser.newContext({
        extraHTTPHeaders: { "X-Test-User": role },
      });
      const view = await other.newPage();
      await view.goto(base + "/dnsmanager");
      await view.waitForSelector("#dns-accounts tr");
      assert.equal(await view.locator("#dns-new-account").count(), 0);
      assert.equal(
        await view
          .locator("#dns-accounts button")
          .filter({ hasText: /^(编辑|删除)$/ })
          .count(),
        0,
      );
      const reply = await view.request.get(base + "/dnsmanager/accounts");
      assert(!(await reply.text()).includes("access_key_id_masked"));
      await other.close();
    }
    assert.deepEqual(errors, []);
    const result = {
      passed: true,
      scope:
        "actual plugin Flask/SQLite with synthetic accounts and mocked cloud; real browser, native CSS; no business DNS writes",
      checks: [
        "list excludes AccessKey column and masks",
        "provider options round trip",
        "auth-mode fields and rotation",
        "record defaults inherited",
        "connection check",
        "resolution check UI",
        "authorization domain rows add remove and round trip",
        "auth mode disabled unless rotating and restored on uncheck",
        "account list/search/empty",
        "masked details",
        "credential-domain-record selection",
        "edit correct account while another selected",
        "metadata-only update keeps keys",
        "create",
        "explicit full rotation incl STS",
        "delete and refresh",
        "reader/writer cannot manage credentials",
        "no complete key returned",
        "mobile has no page overflow",
        "no JavaScript errors",
        "one view at a time",
        "browser back restores parent",
        "forms only in dialogs",
        "record RR/type search/reset",
        "empty filtered results",
        "masked values visible in edit inputs",
        "provider selector on create/edit",
        "provider sent to server",
        "provider-specific fields and clearing on switch",
      ],
    };
    fs.writeFileSync(
      "/tmp/bw-dnsmanager-051-browser.json",
      JSON.stringify(result, null, 2) + "\n",
    );
    console.log(JSON.stringify(result));
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
