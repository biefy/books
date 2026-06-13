(function () {
  function classify(img) {
    // Diagrams fill the column width by default (see lightbox.css). The only
    // special case is a genuinely small diagram (narrow native width): it must
    // NOT be upscaled to the column (it would blur), so tag it to render at its
    // natural size, centered.
    img.classList.toggle("diagram-small", img.naturalWidth < 560);
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
