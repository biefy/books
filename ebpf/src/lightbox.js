/* Click-to-zoom on diagrams.
 * Wraps any <img> in book content with a click handler that opens
 * a fullscreen overlay showing the image at natural size.
 */
(function () {
  function init() {
    var content = document.querySelector("#content");
    if (!content) return;

    // Add zoom cursor to all content images
    var imgs = content.querySelectorAll("img");
    imgs.forEach(function (img) {
      img.style.cursor = "zoom-in";
      img.title = "Click to zoom";
      img.addEventListener("click", function (e) {
        e.preventDefault();
        openLightbox(img.src, img.alt || "");
      });
    });

    // Build the lightbox overlay (lazy)
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

    // Close on Escape
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
