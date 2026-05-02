(function () {
  function classify(img) {
    var ratio = img.naturalWidth / Math.max(img.naturalHeight, 1);
    img.classList.toggle("diagram-wide", ratio >= 2.2);
    img.classList.toggle("diagram-tall", ratio <= 0.55 && img.naturalHeight > 700);

    if (img.classList.contains("diagram-wide") && !img.parentElement.classList.contains("diagram-scroll")) {
      var wrapper = document.createElement("div");
      wrapper.className = "diagram-scroll";
      img.parentNode.insertBefore(wrapper, img);
      wrapper.appendChild(img);
    }
  }

  function init() {
    var content = document.querySelector("#content");
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
