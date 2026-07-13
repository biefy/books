(function () {
  "use strict";

  var initialized = false;
  var loading;

  function context() {
    var path = window.location.pathname;
    var match = path.match(/\/(?:linux-net|ebpf)(?=\/|$)/);
    if (!match) return null;
    return {
      root: path.slice(0, match.index + 1),
      isChinese: document.documentElement.lang.toLowerCase().indexOf("zh") === 0
    };
  }

  function loadPagefind(root) {
    if (window.PagefindUI) return Promise.resolve();
    if (loading) return loading;

    var stylesheet = document.createElement("link");
    stylesheet.rel = "stylesheet";
    stylesheet.href = root + "pagefind/pagefind-ui.css";
    document.head.appendChild(stylesheet);

    loading = new Promise(function (resolve, reject) {
      var script = document.createElement("script");
      script.src = root + "pagefind/pagefind-ui.js";
      script.onload = resolve;
      script.onerror = function () { reject(new Error("Unable to load Pagefind")); };
      document.head.appendChild(script);
    });
    return loading;
  }

  function localizeResult(result, root) {
    if (root !== "/" && result.url && result.url.charAt(0) === "/" && result.url.indexOf(root) !== 0) {
      result.url = root.slice(0, -1) + result.url;
    }
    return result;
  }

  function init() {
    var page = context();
    var controls = document.querySelector(".right-buttons");
    if (!page || !controls || controls.querySelector(".pagefind-search-button")) return;

    var labels = page.isChinese
      ? { search: "搜索", close: "关闭搜索", placeholder: "搜索这些书…", empty: "没有找到“[SEARCH_TERM]”的结果" }
      : { search: "Search", close: "Close search", placeholder: "Search the books…", empty: "No results for “[SEARCH_TERM]”" };

    var button = document.createElement("button");
    button.type = "button";
    button.className = "icon-button pagefind-search-button";
    button.title = labels.search;
    button.setAttribute("aria-label", labels.search);
    button.setAttribute("aria-controls", "pagefind-search-dialog");
    button.setAttribute("aria-haspopup", "dialog");
    button.innerHTML = '<span aria-hidden="true">⌕</span>';
    controls.insertBefore(button, controls.firstChild);

    var dialog = document.createElement("dialog");
    dialog.id = "pagefind-search-dialog";
    dialog.className = "pagefind-search-dialog";
    dialog.setAttribute("aria-label", labels.search);
    dialog.innerHTML =
      '<div class="pagefind-search-header">' +
      '<strong>' + labels.search + '</strong>' +
      '<button type="button" class="pagefind-search-close" aria-label="' + labels.close + '">×</button>' +
      '</div><div id="pagefind-search"></div>';
    document.body.appendChild(dialog);

    function close() {
      if (typeof dialog.close === "function") dialog.close();
      else dialog.removeAttribute("open");
    }

    dialog.querySelector(".pagefind-search-close").addEventListener("click", close);
    dialog.addEventListener("click", function (event) {
      if (event.target === dialog) close();
    });

    button.addEventListener("click", function () {
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");

      loadPagefind(page.root).then(function () {
        if (!initialized) {
          new window.PagefindUI({
            element: "#pagefind-search",
            bundlePath: page.root + "pagefind/",
            showSubResults: true,
            autofocus: true,
            translations: {
              placeholder: labels.placeholder,
              zero_results: labels.empty
            },
            processResult: function (result) { return localizeResult(result, page.root); }
          });
          initialized = true;
        }
        var input = dialog.querySelector("input");
        if (input) input.focus();
      }).catch(function (error) {
        dialog.querySelector("#pagefind-search").textContent = error.message;
      });
    });
  }

  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
})();
