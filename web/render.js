// Safe rendering for the chat page (loaded after marked and DOMPurify, before app.js).
// First-party UI is built from DOM nodes: el() sets fixed attributes and appends strings as text nodes, never as HTML.
// Markdown (assistant answers, user questions) has exactly one sanitizing boundary, markdown(): marked -> DOMPurify
// with an allow-list, returned as a DOM fragment. No HTML string is assigned to the page anywhere.
(function () {
  "use strict";
  // No <img>/<iframe>/style/class/div/span: model output must not make the page fetch remote URLs (data exfiltration
  // via prompt injection) or borrow the page's own classes. Tables get their scroll wrapper after sanitizing.
  const MD_TAGS = ["p", "br", "strong", "em", "b", "i", "del", "s", "code", "pre", "blockquote", "ul", "ol", "li",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "table", "thead", "tbody", "tr", "th", "td", "a"];
  const MD_ATTRS = ["href", "title", "align", "start"];

  function append(node, children) {
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined) continue;
      node.append(child instanceof window.Node ? child : String(child));  // strings become text nodes
    }
    return node;
  }
  // el("button", { type: "button", class: "primary", dataset: { change: id } }, "text", node, [more]).
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (/^on/i.test(name)) throw new Error(`el(): event handler attribute ${name} not allowed`);
      if (name === "class") node.className = value;
      else if (name === "dataset") for (const [key, v] of Object.entries(value)) node.dataset[key] = String(v);
      else node.setAttribute(name, value === true ? "" : String(value));
    }
    return append(node, children);
  }
  function fragment(...children) { return append(document.createDocumentFragment(), children); }

  // CommonMark does not close "**" after punctuation when a letter follows, so "**结论：**省内…" (common in Chinese)
  // stays literal. Bold any "**…**" span on one line whose ends are not spaces; code spans are tokenized first.
  if (window.marked) {
    window.marked.use({ extensions: [{
      name: "cjkStrong", level: "inline",
      start(src) { const i = src.indexOf("**"); return i < 0 ? undefined : i; },
      tokenizer(src) {
        const match = /^\*\*(?![\s*])([^\n]*?[^\s*])\*\*(?!\*)/.exec(src);
        if (match) return { type: "strong", raw: match[0], text: match[1], tokens: this.lexer.inlineTokens(match[1]) };
      },
    }] });
  }
  if (window.DOMPurify) {
    window.DOMPurify.addHook("afterSanitizeAttributes", (node) => {
      if (node.tagName === "A") {
        if (!/^https?:\/\//i.test(node.getAttribute("href") || "")) node.removeAttribute("href");
        node.setAttribute("target", "_blank");
        node.setAttribute("rel", "noopener noreferrer");
      }
    });
  }

  // Markdown -> sanitized DocumentFragment (the page's only sanitizer call).
  function markdown(md) {
    if (!window.marked || !window.DOMPurify) return plain(md);
    let out;
    try {
      const html = window.marked.parse(String(md ?? ""), { gfm: true, breaks: true, async: false });
      out = window.DOMPurify.sanitize(html, { ALLOWED_TAGS: MD_TAGS, ALLOWED_ATTR: MD_ATTRS, ALLOW_DATA_ATTR: false,
        RETURN_DOM_FRAGMENT: true });
    } catch (e) {
      return plain(md);
    }
    for (const table of [...out.querySelectorAll("table")]) {
      const wrapper = el("div", { class: "md-table" });
      table.replaceWith(wrapper);
      wrapper.append(table);
    }
    return out;
  }

  // Fallback when the Markdown libraries failed to load: bold, inline code, bullet lists, paragraphs - as nodes.
  function inline(text) {
    const out = [];
    const pattern = /\*\*(.+?)\*\*|`([^`]+)`/g;
    let last = 0;
    for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
      if (m.index > last) out.push(text.slice(last, m.index));
      out.push(m[1] !== undefined ? el("strong", null, m[1]) : el("code", null, m[2]));
      last = pattern.lastIndex;
    }
    if (last < text.length) out.push(text.slice(last));
    return out;
  }
  function plain(md) {
    const out = document.createDocumentFragment();
    for (const block of String(md ?? "").split(/\n{2,}/)) {
      const lines = block.split("\n");
      const item = /^\s*([-*]|\d+\.)\s+/;
      if (lines.every((l) => item.test(l))) {
        out.append(el("ul", null, lines.map((l) => el("li", null, inline(l.replace(item, ""))))));
      } else {
        out.append(el("p", null, lines.map((l, i) => [i ? el("br") : null, inline(l)])));
      }
    }
    return out;
  }

  window.QscaRender = Object.freeze({ el, fragment, markdown, plain });
})();
