// Smoke test of the chat page (web/index.html + web/app.js) in jsdom: sign-in storage and the answer renderers
// build nodes, so markup in model output, history or tool results stays text. fetch is stubbed; no network.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const ROOT = path.join(__dirname, "..", "..");
const read = (file) => fs.readFileSync(path.join(ROOT, file), "utf8");
const SUB = "alex@example.com";
const tick = () => new Promise((resolve) => setTimeout(resolve, 20));

function boot(prepare) {
  const html = read("web/index.html").replace("__EXAMPLES__", "null");
  const dom = new JSDOM(html, { url: "https://chat.example.com/?analysis=a1&p.pStation=ST1", runScripts: "outside-only" });
  const w = dom.window;
  const calls = [];
  w.fetch = async (url, options = {}) => {
    calls.push({ url, options });
    const body = url.startsWith("/binding") ? { parameters: ["pStation"] }
      : url.startsWith("/examples") ? { groups: null, can_edit: false } : {};
    return { status: 200, ok: true, json: async () => body };
  };
  w.HTMLElement.prototype.scrollIntoView = () => {};
  if (prepare) prepare(w);
  for (const file of ["web/vendor/marked-18.1.1.umd.js", "web/vendor/purify-3.4.17.min.js", "web/render.js", "web/app.js"]) {
    w.eval(read(file));
  }
  return { w, log: w.document.getElementById("log"), calls };
}

test("signed out: login prompt; a token left in localStorage by an older version is dropped", () => {
  const { w, log } = boot((w) => {
    w.localStorage.setItem("qsca:auth", JSON.stringify({ token: "old", user: { sub: SUB, exp: Date.now() / 1000 + 3600 } }));
  });
  assert.equal(w.localStorage.getItem("qsca:auth"), null);
  assert.ok(log.querySelector(".msg.login #loginBtn"));
  assert.equal(w.document.getElementById("q").disabled, true);
});

test("signed in (sessionStorage): replayed history renders markup as text and wires the change buttons", async () => {
  const change = { id: "c".repeat(32), summary: "<b>改标题</b>", expires_at: Date.now() / 1000 + 600 };
  const turns = [
    { role: "user", content: "<img src=x onerror=alert(1)> 趋势" },
    { role: "assistant", content: "**结论：**<script>alert(1)</script>上涨", model: "m<i>", totalMs: 1200, changes: {},
      charts: [{ type: "table", title: "<b>表</b>", columns: ["<i>站</i>"], rows: [["<i>1</i>", null]], notes: ["<u>n</u>"] },
               { type: "none", title: "无图", pending_change: change }],
      controls: [{ control: "<b>场站</b>", parameter: "pStation", value: '"><img src=x>-long-value' }],
      steps: [{ tool: "query_dataset", ok: true, arguments: { a: "<b>" } }] },
  ];
  const { w, log, calls } = boot((w) => {
    w.sessionStorage.setItem("qsca:auth", JSON.stringify({ token: "tok", user: { sub: SUB, name: "<b>Alex</b>", exp: Date.now() / 1000 + 3600 } }));
    w.localStorage.setItem(`qsca:history:${SUB}:a1`, JSON.stringify({ at: Date.now(), turns }));
  });
  await tick();
  assert.equal(w.document.getElementById("q").disabled, false);
  assert.equal(w.document.querySelector("#who span").textContent, "<b>Alex</b>");
  assert.equal(log.querySelector("img, script, b, i, u"), null, log.innerHTML);
  assert.equal(log.querySelector(".msg.user").textContent.trim(), "趋势");  // Markdown: raw HTML is sanitized away
  assert.equal(log.querySelector(".msg.bot strong").textContent, "结论：");
  assert.equal(log.querySelector(".ptable td").textContent, "<i>1</i>");
  assert.equal(log.querySelector(".box button.copy").dataset.copy, '"><img src=x>-long-value');
  assert.equal(log.querySelector("details.steps summary").textContent, "工具调用 1 次 · 1.2 秒 · m<i>");
  assert.ok(calls.every((c) => c.options.headers.Authorization === "Bearer tok"));

  log.querySelector(".box[data-change] .discard-change").click();
  assert.equal(log.querySelector(".box[data-change]"), null);
  assert.equal(log.querySelector(".box.off").textContent, "已放弃，分析未修改。");

  w.document.querySelector("#who button").click();  // 退出: token forgotten, server revocation requested
  assert.equal(w.sessionStorage.getItem("qsca:auth"), null);
  assert.ok(calls.some((c) => c.url === "/auth/logout" && c.options.headers.Authorization === "Bearer tok"));
  assert.ok(log.querySelector(".msg.login #loginBtn"));
});
