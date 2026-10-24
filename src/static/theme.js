// Runs before paint so the saved theme never flashes.
// Stores only the user's theme preference.
(function () {
  var t = null;

  try {
    t = localStorage.getItem("tv-theme");
  } catch (e) {
    // Storage may be unavailable.
  }

  if (t !== "light" && t !== "dark") {
    t =
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
  }

  document.documentElement.setAttribute("data-theme", t);
})();
