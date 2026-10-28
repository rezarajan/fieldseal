// Tabs for server-rendered panels. Without this script every panel is in the page, one after
// the other; with it, only the panel named by the URL hash (default the first) shows.
for (const root of document.querySelectorAll("[data-tabs]")) {
  const tabs = [...root.querySelectorAll(".tablist > .tab")];
  const panels = tabs.map((t) => root.querySelector("#" + CSS.escape(t.getAttribute("aria-controls"))));
  const pick = (id, scroll) => {
    let at = panels.findIndex((p) => p && p.id === id);
    if (at < 0) at = 0;
    tabs.forEach((t, i) => {
      t.setAttribute("aria-selected", String(i === at));
      t.tabIndex = i === at ? 0 : -1;
    });
    panels.forEach((p, i) => p && p.classList.toggle("active", i === at));
    if (scroll) tabs[at].scrollIntoView({ block: "nearest" });
  };
  root.classList.add("ready");
  pick(location.hash.slice(1), false);
  for (const t of tabs) {
    t.addEventListener("click", (e) => {
      e.preventDefault();
      const id = t.getAttribute("aria-controls");
      history.replaceState(null, "", "#" + id);
      pick(id, false);
    });
    t.addEventListener("keydown", (e) => {
      const step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (!step) return;
      const next = tabs[(tabs.indexOf(t) + step + tabs.length) % tabs.length];
      next.focus();
      next.click();
    });
  }
  window.addEventListener("hashchange", () => pick(location.hash.slice(1), true));
}
