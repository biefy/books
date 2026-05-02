/* Inline kernel source viewer.
 *
 * Scans the content for inline-code mentions of kernel file paths
 * (e.g., `net/ipv6/ip6_input.c:344`), wraps them in a click target,
 * and on click fetches the file from raw.githubusercontent.com,
 * extracts ~30 lines around the target line, and shows them inline.
 *
 * Caches fetched files in memory per session.
 */
(function () {
  // Pin to a kernel tag: line numbers in the books are verified against this.
  // Update both this constant AND the books' README "verified against" line
  // when bumping.
  var KERNEL_TAG = "v7.1-rc1";
  var RAW_BASE = "https://raw.githubusercontent.com/torvalds/linux/" + KERNEL_TAG + "/";
  var BLOB_BASE = "https://github.com/torvalds/linux/blob/" + KERNEL_TAG + "/";
  var CONTEXT_LINES = 12;

  // Recognise kernel paths inside <code> spans.
  // Top-level kernel directories — restrict so we don't match unrelated paths.
  var DIR_RE = "(?:arch|block|certs|crypto|drivers|fs|include|init|io_uring|ipc|kernel|lib|mm|net|samples|scripts|security|sound|tools|usr|virt|Documentation)";
  // Match path[:line]
  var PATH_RE = new RegExp(
    "^" + DIR_RE + "/[A-Za-z0-9_./-]+\\.(?:c|h|S|rs|sh|py|rst|md)(?::(\\d+))?$"
  );

  // In-memory cache of fetched files.
  var cache = {};

  function init() {
    var content = document.querySelector("#content");
    if (!content) return;

    var codes = content.querySelectorAll("code");
    codes.forEach(function (code) {
      var text = code.textContent.trim();
      var m = text.match(PATH_RE);
      if (!m) return;
      // Skip if already inside a kernel-link (idempotent)
      if (code.classList.contains("ksrc-link")) return;
      enhance(code, text, m[1] ? parseInt(m[1], 10) : null);
    });
  }

  function enhance(codeEl, ref, line) {
    codeEl.classList.add("ksrc-link");
    codeEl.title = "Click to view source from Linux " + KERNEL_TAG;

    // Build expansion container, placed right after the parent paragraph
    // or list item, so the inline reference stays in flow.
    var details = document.createElement("details");
    details.className = "ksrc-details";
    var summary = document.createElement("summary");
    summary.textContent = "View " + ref + " (Linux " + KERNEL_TAG + ")";
    details.appendChild(summary);
    var body = document.createElement("div");
    body.className = "ksrc-body";
    body.innerHTML = '<div class="ksrc-loading">Loading source...</div>';
    details.appendChild(body);

    // Place after the nearest block ancestor (li, p, h*, td, etc.)
    var anchor = codeEl;
    while (anchor && anchor.parentElement && anchor.parentElement !== content()) {
      var tag = anchor.parentElement.tagName;
      if (/^(P|LI|H[1-6]|TD|BLOCKQUOTE|DT|DD)$/.test(tag)) {
        anchor = anchor.parentElement;
        break;
      }
      anchor = anchor.parentElement;
    }
    if (anchor && anchor.parentElement) {
      anchor.parentElement.insertBefore(details, anchor.nextSibling);
    } else {
      codeEl.after(details);
    }

    // Make the inline code itself a click trigger that toggles the details.
    codeEl.style.cursor = "pointer";
    codeEl.addEventListener("click", function (e) {
      e.preventDefault();
      details.open = !details.open;
      if (details.open) {
        loadSource(body, ref, line);
        // Scroll the expanded source into view
        setTimeout(function () {
          details.scrollIntoView({ behavior: "smooth", block: "nearest" });
        }, 50);
      }
    });

    details.addEventListener("toggle", function () {
      if (details.open) loadSource(body, ref, line);
    });
  }

  function content() {
    return document.querySelector("#content");
  }

  function loadSource(body, ref, line) {
    if (body.dataset.loaded === "1") return;
    body.dataset.loaded = "1";

    var slash = ref.indexOf(":");
    var path = slash >= 0 ? ref.slice(0, slash) : ref;

    var p = cache[path] || (cache[path] = fetch(RAW_BASE + path).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.text();
    }));

    p.then(function (text) {
      render(body, path, text, line);
    }).catch(function (err) {
      body.innerHTML =
        '<div class="ksrc-error">Could not load source (' +
        err.message +
        '). <a href="' + BLOB_BASE + path + (line ? "#L" + line : "") + '" target="_blank" rel="noopener">Open on GitHub</a>.</div>';
    });
  }

  function escapeHtml(s) {
    return s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function render(body, path, text, line) {
    var lines = text.split("\n");

    var startLine, endLine;
    if (line) {
      startLine = Math.max(1, line - CONTEXT_LINES);
      endLine = Math.min(lines.length, line + CONTEXT_LINES);
    } else {
      startLine = 1;
      endLine = Math.min(lines.length, 60);
    }

    var url = BLOB_BASE + path + (line ? "#L" + line : "");

    var html =
      '<div class="ksrc-header">' +
      '<a href="' + url + '" target="_blank" rel="noopener">' +
      escapeHtml(path) + (line ? ":" + line : "") + " ↗" +
      "</a>" +
      ' <span class="ksrc-meta">Linux ' + KERNEL_TAG +
      (line ? ", lines " + startLine + "–" + endLine : ", first " + endLine + " lines") +
      "</span>" +
      "</div>";

    var pre = '<pre class="ksrc-code"><code>';
    for (var i = startLine; i <= endLine; i++) {
      var lineText = lines[i - 1] || "";
      var cls = "ksrc-line" + (i === line ? " ksrc-line-target" : "");
      pre +=
        '<span class="' + cls + '">' +
        '<span class="ksrc-lineno">' + i + "</span>" +
        '<span class="ksrc-linetext">' + escapeHtml(lineText) + "</span>" +
        "</span>\n";
    }
    pre += "</code></pre>";

    body.innerHTML = html + pre;

    // Scroll the highlighted line into view inside the code block
    if (line) {
      var target = body.querySelector(".ksrc-line-target");
      if (target) target.scrollIntoView({ block: "center" });
    }
  }

  if (document.readyState !== "loading") {
    init();
  } else {
    document.addEventListener("DOMContentLoaded", init);
  }
})();
