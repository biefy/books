(function () {
  "use strict";

  function pageContext() {
    var path = window.location.pathname;
    var match = path.match(/\/(linux-net|ebpf)(?=\/|$)/);
    if (!match) return null;

    var root = path.slice(0, match.index + 1);
    var book = match[1];
    var rest = path.slice(match.index + match[0].length);
    if (rest.charAt(0) === "/") rest = rest.slice(1);
    var isChinese = rest.indexOf("zh-CN/") === 0 || rest === "zh-CN";
    var targetRest = isChinese
      ? rest.replace(/^zh-CN\/?/, "")
      : "zh-CN/" + rest;
    var target = new URL(window.location.href);
    target.pathname = root + book + "/" + targetRest;
    target.hash = "";
    return { isChinese: isChinese, target: target.href };
  }

  function init() {
    var context = pageContext();
    var controls = document.querySelector(".right-buttons");
    if (!context || !controls || controls.querySelector(".language-switcher")) return;

    var link = document.createElement("a");
    link.className = "icon-button language-switcher";
    link.href = context.target;
    link.hreflang = context.isChinese ? "en" : "zh-CN";
    link.lang = context.isChinese ? "en" : "zh-CN";
    link.title = context.isChinese ? "Switch to English" : "切换到简体中文";
    link.setAttribute("aria-label", link.title);

    var label = document.createElement("span");
    label.className = "language-switcher-label";
    label.textContent = context.isChinese ? "English" : "中文";
    link.appendChild(label);
    controls.insertBefore(link, controls.firstChild);
  }

  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
})();
