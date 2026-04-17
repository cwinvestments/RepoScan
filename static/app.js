/* RepoScan UI — small vanilla JS. No framework, no deps. */
(function () {
    "use strict";

    // 1) Scan form spinner
    var form = document.getElementById("scan-form");
    var spinner = document.getElementById("scan-spinner");
    var btn = document.getElementById("scan-btn");
    if (form && spinner && btn) {
        form.addEventListener("submit", function () {
            spinner.hidden = false;
            btn.disabled = true;
            btn.textContent = "Scanning...";
        });
    }

    // 2) Copy-to-clipboard buttons
    document.querySelectorAll("[data-copy-target]").forEach(function (el) {
        el.addEventListener("click", function () {
            var sel = el.getAttribute("data-copy-target");
            var node = sel ? document.querySelector(sel) : null;
            if (!node) return;
            var text = node.innerText || node.textContent || "";
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function () {
                    flashButton(el, "Copied!");
                }).catch(function () {
                    fallbackCopy(text, el);
                });
            } else {
                fallbackCopy(text, el);
            }
        });
    });

    function fallbackCopy(text, el) {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); flashButton(el, "Copied!"); }
        catch (e) { flashButton(el, "Copy failed"); }
        document.body.removeChild(ta);
    }

    function flashButton(el, label) {
        var orig = el.textContent;
        el.textContent = label;
        setTimeout(function () { el.textContent = orig; }, 1200);
    }

    // 3) Dismiss form — fetch-based, update DOM in place so the page
    //    doesn't lose scroll position on a full redirect.
    document.querySelectorAll(".dismiss-form").forEach(function (f) {
        f.addEventListener("submit", function (e) {
            // Only hijack when we have fetch + FormData; otherwise let the
            // browser do the normal POST+redirect and everything still works.
            if (!window.fetch || !window.FormData) return;
            e.preventDefault();
            var fd = new FormData(f);
            fetch(f.action, { method: "POST", body: fd, credentials: "same-origin" })
                .then(function () {
                    var row = f.closest(".finding-row");
                    if (!row) return;
                    row.classList.add("dismissed");
                    var reason = (fd.get("reason") || "").toString();
                    f.remove();
                    var note = document.createElement("div");
                    note.className = "dismiss-note";
                    note.textContent = reason ? ("Dismissed — " + reason) : "Dismissed";
                    row.appendChild(note);
                })
                .catch(function () { f.submit(); });
        });
    });

    // 4) Rate-limit banner dismiss — remembered per scan in localStorage
    var banner = document.getElementById("rate-limit-banner");
    if (banner) {
        var scanId = banner.getAttribute("data-scan-id") || "global";
        var key = "reposcan.rate-limit-dismissed." + scanId;
        try {
            if (localStorage.getItem(key) === "1") { banner.hidden = true; }
        } catch (e) { /* localStorage disabled */ }
        var dbtn = banner.querySelector(".banner-dismiss");
        if (dbtn) {
            dbtn.addEventListener("click", function () {
                banner.hidden = true;
                try { localStorage.setItem(key, "1"); } catch (e) {}
            });
        }
    }
})();
