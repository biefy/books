/* Turn inline code spans that look like kernel paths (e.g., `net/ipv6/ip6_input.c:344`)
 * into hyperlinks that open the source on GitHub at the pinned kernel tag.
 * No inline fetch, no expansion — just a clickable reference.
 */
(function () {
  // Pin to a kernel tag; line numbers in the books are verified against this.
  var KERNEL_TAG = "v7.1-rc1";
  var BLOB_BASE = "https://github.com/torvalds/linux/blob/" + KERNEL_TAG + "/";

  // Top-level kernel directories — restrict so we don't match unrelated paths.
  var DIR_RE = "(?:arch|block|certs|crypto|drivers|fs|include|init|io_uring|ipc|kernel|lib|mm|net|samples|scripts|security|sound|tools|usr|virt|Documentation)";
  var PATH_RE = new RegExp(
    "^" + DIR_RE + "/[A-Za-z0-9_./-]+\\.(?:c|h|S|rs|sh|py|rst|md)(?::(\\d+))?$"
  );

  function init() {
    var content = document.querySelector(".content");
    if (!content) return;

    var codes = content.querySelectorAll("code");
    codes.forEach(function (code) {
      var text = code.textContent.trim();
      var m = text.match(PATH_RE);
      if (!m) return;
      // Skip if already wrapped (idempotent)
      if (code.parentElement && code.parentElement.classList.contains("ksrc-link-wrap")) return;

      var line = m[1] ? parseInt(m[1], 10) : null;
      var slash = text.indexOf(":");
      var path = slash >= 0 ? text.slice(0, slash) : text;
      var url = BLOB_BASE + path + (line ? "#L" + line : "");

      var a = document.createElement("a");
      a.href = url;
      a.target = "_blank";
      a.rel = "noopener";
      a.className = "ksrc-link-wrap";
      a.title = "Open in Linux " + KERNEL_TAG + " on GitHub";

      // Insert: replace code with anchor wrapping code.
      code.parentNode.insertBefore(a, code);
      a.appendChild(code);
    });
  }

  if (document.readyState !== "loading") {
    init();
  } else {
    document.addEventListener("DOMContentLoaded", init);
  }
})();
