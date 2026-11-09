// Copy buttons and the screenshot tabs of the project page. The page works without it.
(function () {
  var root = document.documentElement;
  root.classList.remove("nojs");
  root.classList.add("js");

  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    var label = btn.textContent;
    btn.addEventListener("click", function () {
      var text = btn.getAttribute("data-copy");
      var done = function () {
        btn.textContent = btn.getAttribute("data-done") || "Copied";
        setTimeout(function () { btn.textContent = label; }, 1600);
      };
      try {
        navigator.clipboard.writeText(text).then(done, function () {});
      } catch (e) {
        /* no clipboard access: leave the text selectable */
      }
    });
  });

  var tabs = document.querySelectorAll('[role="tab"]');
  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute("aria-selected", on ? "true" : "false");
        var panel = document.getElementById(t.getAttribute("aria-controls"));
        if (panel) panel.hidden = !on;
      });
    });
  });
})();
