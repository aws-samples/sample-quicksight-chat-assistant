// Tests of the chat page's safe rendering (web/render.js) with the vendored marked and DOMPurify, in jsdom.
// Run: cd tests/js && npm ci && npm test
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const ROOT = path.join(__dirname, "..", "..");
const read = (file) => fs.readFileSync(path.join(ROOT, file), "utf8");
const SCRIPTS = ["web/vendor/marked-18.1.1.umd.js", "web/vendor/purify-3.4.17.min.js", "web/render.js"];

function page(scripts = SCRIPTS) {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { runScripts: "outside-only" });
  for (const file of scripts) dom.window.eval(read(file));
  return dom.window;
}
function rendered(window, md) {
  const box = window.document.createElement("div");
  box.append(window.QscaRender.markdown(md));
  return box;
}

test("markdown returns a sanitized fragment without active content", () => {
  const w = page();
  const out = w.QscaRender.markdown("hello");
  assert.equal(out.nodeType, w.Node.DOCUMENT_FRAGMENT_NODE);
  const box = rendered(w, [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<iframe src=https://evil.example></iframe>",
    '<p style="color:red" class="msg user" onclick="alert(1)">styled</p>', "<div>block</div><span>inline</span>",
    "<svg><a xlink:href=javascript:alert(1)>x</a></svg>", "<form><input name=q></form>",
  ].join("\n\n"));
  assert.equal(box.querySelector("script, img, iframe, svg, form, input, div, span"), null, box.innerHTML);
  assert.equal(box.querySelector("[style], [class], [onclick], [onerror]"), null, box.innerHTML);
  assert.match(box.textContent, /styled/);
  assert.match(box.textContent, /block/);
});

test("links: only http(s) hrefs, always a new tab without opener", () => {
  const w = page();
  const box = rendered(w, "[bad](javascript:alert(1)) [data](data:text/html,x) [ok](https://example.com/a)");
  const links = [...box.querySelectorAll("a")];
  assert.ok(links.length >= 1);
  for (const a of links) {
    assert.equal(a.getAttribute("target"), "_blank");
    assert.equal(a.getAttribute("rel"), "noopener noreferrer");
    assert.ok(!a.hasAttribute("href") || /^https:\/\/example\.com\//.test(a.getAttribute("href")), a.outerHTML);
  }
  assert.ok(links.some((a) => a.getAttribute("href") === "https://example.com/a"));
});

test("tables are wrapped after sanitizing; CJK bold works", () => {
  const w = page();
  const box = rendered(w, "| a | b |\n|---|--:|\n| 1 | 2 |\n\n**结论：**省内电价上涨");
  const wrapper = box.querySelector("div.md-table");
  assert.ok(wrapper && wrapper.firstElementChild.tagName === "TABLE", box.innerHTML);
  assert.equal(box.querySelector("td[align=right]").textContent, "2");
  assert.equal(box.querySelector("strong").textContent, "结论：");
});

test("plain fallback and el() treat strings as text", () => {
  const w = page();
  const { el, fragment, plain } = w.QscaRender;
  const p = el("p", { class: "note", dataset: { copy: '"><b>x' }, title: null }, "<b>x</b>", 3, null, [el("br")]);
  assert.equal(p.querySelector("b"), null);
  assert.equal(p.textContent, "<b>x</b>3");
  assert.equal(p.dataset.copy, '"><b>x');
  assert.ok(!p.hasAttribute("title"));
  assert.throws(() => el("button", { onclick: "alert(1)" }), /not allowed/);
  assert.equal(fragment("a", null, el("i", null, "b")).textContent, "ab");
  const box = w.document.createElement("div");
  box.append(plain("<img src=x onerror=alert(1)> **bold** `code`\n\n- one\n- two"));
  assert.equal(box.querySelector("img"), null);
  assert.equal(box.querySelector("strong").textContent, "bold");
  assert.equal(box.querySelector("code").textContent, "code");
  assert.equal(box.querySelectorAll("li").length, 2);
});

test("markdown falls back to plain text when the libraries are missing", () => {
  const w = page(["web/render.js"]);
  const box = rendered(w, "<script>alert(1)</script> **b**");
  assert.equal(box.querySelector("script"), null);
  assert.equal(box.querySelector("strong").textContent, "b");
  assert.match(box.textContent, /<script>alert\(1\)<\/script>/);
});

test("one sanitizer boundary; no HTML sinks in the page script", () => {
  assert.equal(read("web/render.js").match(/DOMPurify\.sanitize\(/g).length, 1);
  const app = read("web/app.js");
  for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "DOMPurify", "marked."]) {
    assert.ok(!app.includes(sink), `web/app.js uses ${sink}`);
  }
});
