(function () {
  function classify(img) {
    // Diagrams fill the column width by default (see lightbox.css). Narrow
    // native images stay at their natural width; portrait diagrams use less of
    // the column so their labels match the scale of neighbouring diagrams.
    var isSmall = img.naturalWidth < 560;
    var aspect = img.naturalWidth / img.naturalHeight;

    img.classList.toggle("diagram-small", isSmall);
    img.classList.toggle("diagram-portrait",
                         !isSmall && aspect >= 0.33 && aspect < 0.65);
    img.classList.toggle("diagram-portrait-tall",
                         !isSmall && aspect < 0.33);
    img.classList.toggle("diagram-portrait-compact",
                         img.naturalWidth >= 500 &&
                         img.naturalWidth <= 560 && aspect < 0.33);

    var isDetail = img.naturalWidth >= 3000;
    var isWide = !isDetail && img.naturalWidth >= 1400 && aspect > 1.8;
    img.classList.toggle("diagram-detail", isDetail);
    img.classList.toggle("diagram-wide", isWide);
    if (isDetail || isWide) {
      var factor = isDetail ? 0.5 : 1.0;
      img.style.setProperty("--diagram-scroll-width",
                            Math.round(img.naturalWidth * factor) + "px");
      if (!img.parentElement.classList.contains("diagram-scroll")) {
        var scroll = document.createElement("span");
        scroll.className = "diagram-scroll";
        img.parentNode.insertBefore(scroll, img);
        scroll.appendChild(img);
      }
    }
  }

  function init() {
    var content = document.querySelector(".content");
    if (!content) return;

    var imgs = content.querySelectorAll("img");
    imgs.forEach(function (img) {
      img.title = "Click to zoom";
      if (img.complete && img.naturalWidth) {
        classify(img);
      } else {
        img.addEventListener("load", function () { classify(img); }, { once: true });
      }
      img.addEventListener("click", function (e) {
        e.preventDefault();
        openLightbox(img.currentSrc || img.src, img.alt || "");
      });
    });

    var overlay;
    function getOverlay() {
      if (overlay) return overlay;
      overlay = document.createElement("div");
      overlay.id = "lightbox-overlay";
      overlay.innerHTML =
        '<button class="lightbox-close" aria-label="Close">×</button>' +
        '<div class="lightbox-content">' +
        '<img class="lightbox-img" alt="">' +
        '<div class="lightbox-caption"></div>' +
        '</div>';
      overlay.addEventListener("click", function (e) {
        if (e.target === overlay || e.target.classList.contains("lightbox-close")) {
          closeLightbox();
        }
      });
      document.body.appendChild(overlay);
      return overlay;
    }

    function openLightbox(src, caption) {
      var box = getOverlay();
      box.querySelector(".lightbox-img").src = src;
      box.querySelector(".lightbox-caption").textContent = caption;
      box.classList.add("open");
      document.body.style.overflow = "hidden";
    }

    function closeLightbox() {
      if (!overlay) return;
      overlay.classList.remove("open");
      document.body.style.overflow = "";
    }

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeLightbox();
    });
  }

  if (document.readyState !== "loading") {
    init();
  } else {
    document.addEventListener("DOMContentLoaded", init);
  }
})();
