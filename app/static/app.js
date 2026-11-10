/* ==========================================================================
   OSINT Hub front-end

   Three pieces of real work here:
     1. headline()  — renders the hero title as a dot-matrix on a canvas, the
                      way the live site does, with a hidden <h1> for a11y.
     2. sweep()     — opens a streaming fetch to /api/scan/stream and updates
                      the counters, the live source log and the match cards as
                      each endpoint resolves.
     3. typeTabs()  — switches the search type, its placeholder and its cost.
   ========================================================================== */
(function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /* dot-matrix headline                                                 */
  /* ------------------------------------------------------------------ */

  var headlineState = { paused: false, raf: null };

  function monoFont(size, weight) {
    return (weight || 700) + " " + size + 'px "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
  }

  /* Render text into a dot grid.

     The text is drawn once at high resolution (supersampled), then each cell
     of the dot grid is lit if the block of pixels underneath it contains
     enough ink. That gives the chunky LED-matrix look rather than smooth
     type. Lines are wrapped to the grid width, so the headline breaks the
     same way the reference does on a narrow column.
  */
  function drawHeadline(canvas, text, opts) {
    var dpr = window.devicePixelRatio || 1;
    var rect = canvas.getBoundingClientRect();
    var w = Math.max(1, Math.floor(rect.width));
    var h = Math.max(1, Math.floor(rect.height));
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    var ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    var compact = w < 520;
    var cell = compact ? 4 : 5;
    var gap = compact ? 1 : 2;
    var step = cell + gap;
    var cols = Math.max(4, Math.floor(w / step));
    var rows = Math.max(4, Math.floor(h / step));

    var ROWS_PER_LINE = compact ? 6 : 7;
    var LINE_GAP = compact ? 2 : 3;
    var K = 4; // supersampling factor

    var off = document.createElement("canvas");
    var octx = off.getContext("2d");

    var lines = [];
    var fontSize = 0;
    var rowOffset = 0;

    // The glyph height is fixed by the matrix: ROWS_PER_LINE dots tall. That
    // fixes the font size, which in turn fixes how many characters fit on a
    // line. If the wrapped result is too tall for the grid, scale down and
    // try again — fewer characters per line means fewer lines.
    var scale = 1;
    for (var attempt = 0; attempt < 10; attempt++) {
      var size = Math.floor((ROWS_PER_LINE * K) / 0.7 * scale);
      if (size < 5) break;
      octx.font = monoFont(size);
      var adv = octx.measureText("M").width || size * 0.6;
      var maxChars = Math.max(1, Math.floor((cols * K) / adv));
      lines = wrapText(text, maxChars);
      var totalRows = lines.length * ROWS_PER_LINE + (lines.length - 1) * LINE_GAP;
      if (totalRows <= rows) {
        fontSize = size;
        rowOffset = Math.floor((rows - totalRows) / 2);
        break;
      }
      scale *= 0.92;
    }
    if (!fontSize) {
      fontSize = Math.max(5, Math.floor((ROWS_PER_LINE * K) / 0.7 * scale));
      lines = wrapText(text, Math.max(1, Math.floor((cols * K) / (fontSize * 0.6))));
      rowOffset = 0;
    }

    off.width = cols * K;
    off.height = rows * K;
    octx = off.getContext("2d");
    octx.clearRect(0, 0, off.width, off.height);
    octx.font = monoFont(fontSize);
    octx.fillStyle = "#fff";
    octx.textBaseline = "top";

    var lineHeightCells = ROWS_PER_LINE + LINE_GAP;
    lines.forEach(function (line, i) {
      octx.fillText(line, 0, (rowOffset + i * lineHeightCells) * K);
    });

    // Light a dot wherever the block underneath has ink.
    var data = octx.getImageData(0, 0, off.width, off.height).data;
    var dots = [];
    var threshold = 0.32;
    for (var gy = 0; gy < rows; gy++) {
      for (var gx = 0; gx < cols; gx++) {
        var ink = 0;
        for (var ky = 0; ky < K; ky++) {
          var py = gy * K + ky;
          if (py >= off.height) break;
          for (var kx = 0; kx < K; kx++) {
            var px = gx * K + kx;
            if (px >= off.width) break;
            if (data[(py * off.width + px) * 4 + 3] > 90) ink++;
          }
        }
        if (ink / (K * K) >= threshold) dots.push([gx, gy]);
      }
    }

    var phase = 0;
    function frame() {
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = "#ffffff";
      for (var i = 0; i < dots.length; i++) {
        var d = dots[i];
        // A slow shimmer travelling across the matrix.
        var wave = Math.sin((d[0] * 0.22) + (d[1] * 0.13) - phase);
        var alpha = 0.62 + 0.38 * (0.5 + 0.5 * wave);
        ctx.globalAlpha = alpha;
        ctx.fillRect(d[0] * step, d[1] * step, cell, cell);
      }
      ctx.globalAlpha = 1;
      if (!headlineState.paused) phase += 0.03;
      headlineState.raf = requestAnimationFrame(frame);
    }
    frame();
  }

  function wrapText(text, maxChars) {
    var words = text.split(/\s+/);
    var lines = [];
    var current = "";
    words.forEach(function (word) {
      var candidate = current ? current + " " + word : word;
      if (current && candidate.length > maxChars) {
        lines.push(current);
        current = word;
      } else {
        current = candidate;
      }
    });
    if (current) lines.push(current);
    return lines;
  }

  function initHeadline() {
    var canvas = document.getElementById("headline-canvas");
    if (!canvas) return;
    var h1 = document.getElementById("hero-heading");
    var text = (h1 && h1.textContent.trim()) || "A live OSINT search engine.";
    var pauseBtn = document.getElementById("headline-pause");

    function render() {
      var rect = canvas.getBoundingClientRect();
      if (rect.width < 10) return;
      try {
        drawHeadline(canvas, text, {});
        // The canvas now carries the visual; the h1 stays in the DOM for
        // screen readers but is no longer painted.
        if (h1) h1.style.opacity = "0";
      } catch (err) {
        // Canvas unavailable — the plain h1 remains visible as the fallback.
        if (h1) h1.style.opacity = "1";
      }
    }

    var resizeTimer = null;
    window.addEventListener("resize", function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(render, 120);
    });

    if (pauseBtn) {
      pauseBtn.addEventListener("click", function () {
        headlineState.paused = !headlineState.paused;
        pauseBtn.querySelector("span").textContent =
          headlineState.paused ? "[ play ]" : "[ pause ]";
        pauseBtn.setAttribute("aria-label",
          headlineState.paused ? "Resume headline animation" : "Pause headline animation");
      });
    }

    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      headlineState.paused = true;
      if (pauseBtn) pauseBtn.querySelector("span").textContent = "[ play ]";
    }

    // Fonts change the measured text width, so redraw once they land.
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(render);
    }
    render();
    setTimeout(render, 300);
  }

  /* ------------------------------------------------------------------ */
  /* search type tabs                                                    */
  /* ------------------------------------------------------------------ */

  function initTypeTabs() {
    var wrap = document.getElementById("type-tabs");
    var input = document.getElementById("sweep-input");
    var blurb = document.getElementById("type-blurb");
    if (!wrap) return { current: "username" };

    var tabs = Array.prototype.slice.call(wrap.querySelectorAll(".type-tab[data-type]"));
    var current = "username";

    function apply(tab, focus) {
      if (!tab) return;
      tabs.forEach(function (t) {
        t.setAttribute("aria-selected", t === tab ? "true" : "false");
        t.setAttribute("tabindex", t === tab ? "0" : "-1");
        t.classList.toggle("is-active", t === tab);
      });
      current = tab.getAttribute("data-type");
      if (blurb) blurb.textContent = tab.getAttribute("data-blurb") || "";
      if (input && !focus) {
        input.placeholder = tab.getAttribute("data-placeholder") || "";
        input.setAttribute("aria-label", tab.getAttribute("data-placeholder") || "Value to scan");
      }
      if (window.history && window.history.replaceState) {
        var params = new URLSearchParams(window.location.search);
        params.set("type", current);
        window.history.replaceState({}, "",
          window.location.pathname + "?" + params.toString());
      }
    }

    tabs.forEach(function (tab, i) {
      tab.addEventListener("click", function () { apply(tab, false); });
      tab.addEventListener("keydown", function (ev) {
        var next = null;
        if (ev.key === "ArrowRight" || ev.key === "ArrowDown") next = tabs[(i + 1) % tabs.length];
        else if (ev.key === "ArrowLeft" || ev.key === "ArrowUp") next = tabs[(i - 1 + tabs.length) % tabs.length];
        else if (ev.key === "Home") next = tabs[0];
        else if (ev.key === "End") next = tabs[tabs.length - 1];
        if (!next) return;
        ev.preventDefault();
        apply(next, true);
        next.focus();
      });
    });

    var active = wrap.querySelector(".type-tab.is-active") ||
      wrap.querySelector(".type-tab[aria-selected=true]") || tabs[0];
    apply(active, false);

    return {
      current: function () { return current; },
      set: function (type) {
        var tab = wrap.querySelector('.type-tab[data-type="' + type + '"]');
        if (tab) apply(tab, false);
        return current;
      }
    };
  }

  /* ------------------------------------------------------------------ */
  /* live sweep                                                          */
  /* ------------------------------------------------------------------ */

  var MAX_LOG_ROWS = 60;

  function initSweep() {
    var form = document.getElementById("sweep-form");
    if (!form) return;

    var input = document.getElementById("sweep-input");
    var statusEl = document.getElementById("sweep-status");
    var subEl = document.getElementById("sweep-substatus");
    var liveEl = document.getElementById("sweep-live");
    var viewBtn = document.getElementById("view-results");
    var resultsSection = document.getElementById("results-section");
    var resultsList = document.getElementById("results-list");
    var resultsTitle = document.getElementById("results-title");
    var resultsMeta = document.getElementById("results-meta");
    var stateEl = document.getElementById("sweep-state-label");
    var stateWrap = document.getElementById("sweep-state");
    var countEl = document.getElementById("sweep-count");
    var timeEl = document.getElementById("sweep-time");
    var foundEl = document.getElementById("sweep-found");
    var logEl = document.getElementById("sweep-groups");
    var newScanBtn = document.getElementById("new-scan");

    var tabs = initTypeTabs();

    var controller = null;   // AbortController for the running scan
    var startedAt = 0;
    var timer = null;
    var allResults = [];
    var total = 0;
    var running = false;

    function fmtTime(sec) {
      sec = Math.max(0, Math.floor(sec));
      var m = String(Math.floor(sec / 60)).padStart(2, "0");
      var s = String(sec % 60).padStart(2, "0");
      return m + ":" + s;
    }

    function setState(state, label) {
      stateWrap.setAttribute("data-state", state);
      stateEl.textContent = label;
    }

    function clearLog() {
      if (!logEl) return;
      logEl.innerHTML = "";
      var empty = document.createElement("div");
      empty.className = "sweep-empty";
      empty.innerHTML = '<p class="muted">Waiting for the first source to answer…</p>';
      logEl.appendChild(empty);
    }

    function reset() {
      allResults = [];
      clearLog();
      if (resultsList) resultsList.innerHTML = "";
      if (viewBtn) viewBtn.hidden = true;
      if (resultsSection) resultsSection.hidden = true;
      foundEl.textContent = "000";
      countEl.textContent = "000 / " + String(total).padStart(3, "0");
      timeEl.textContent = "00:00";
    }

    /* -- the live source log (replaces the old glyph grid) --------------- */

    function logRow(res) {
      var row = document.createElement("div");
      row.className = "source-row";
      row.setAttribute("data-s", res.status);

      var dot = document.createElement("span");
      dot.className = "source-dot";
      dot.setAttribute("aria-hidden", "true");

      var name = document.createElement("span");
      name.className = "source-name";
      name.textContent = res.name;

      var cat = document.createElement("span");
      cat.className = "source-cat";
      cat.textContent = res.category;

      var ms = document.createElement("span");
      ms.className = "source-ms";
      ms.textContent = res.ms ? res.ms + "ms" : "";

      row.appendChild(dot);
      row.appendChild(name);
      row.appendChild(cat);
      row.appendChild(ms);

      if (res.status === "hit" && res.url) {
        var link = document.createElement("a");
        link.className = "source-link";
        link.href = res.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = "open";
        row.appendChild(link);
      }
      return row;
    }

    function pushLog(res) {
      if (!logEl) return;
      var empty = logEl.querySelector(".sweep-empty");
      if (empty) empty.remove();
      logEl.appendChild(logRow(res));
      while (logEl.children.length > MAX_LOG_ROWS) {
        logEl.removeChild(logEl.firstChild);
      }
      logEl.scrollTop = logEl.scrollHeight;
    }

    /* -- match cards ----------------------------------------------------- */

    function faviconFor(url) {
      try {
        var host = new URL(url).hostname;
        return "https://" + host + "/favicon.ico";
      } catch (e) {
        return "";
      }
    }

    function makeAvatar(res) {
      var avatar = document.createElement("div");
      avatar.className = "match-avatar";

      var monogram = document.createElement("span");
      monogram.className = "match-monogram";
      monogram.textContent = (res.name || "?").charAt(0).toUpperCase();
      avatar.appendChild(monogram);

      var img = document.createElement("img");
      img.loading = "lazy";
      img.alt = "";
      img.referrerPolicy = "no-referrer";
      img.src = res.avatar || faviconFor(res.url);
      img.addEventListener("load", function () {
        avatar.classList.add("has-img");
      });
      img.addEventListener("error", function () {
        img.remove();
      });
      avatar.appendChild(img);
      return avatar;
    }

    function renderResult(res) {
      if (res.status !== "hit") return;
      allResults.push(res);

      var card = document.createElement("article");
      card.className = "match-card";
      card.setAttribute("data-id", res.id);
      card.setAttribute("data-category", res.category || "");

      card.appendChild(makeAvatar(res));

      var body = document.createElement("div");
      body.className = "match-body";

      var top = document.createElement("div");
      top.className = "match-top";

      var link = document.createElement("a");
      link.className = "match-name";
      link.href = res.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = res.name;
      top.appendChild(link);

      var display = document.createElement("span");
      display.className = "match-display";
      display.hidden = true;
      top.appendChild(display);

      var cat = document.createElement("span");
      cat.className = "match-cat";
      cat.textContent = res.category || "";
      top.appendChild(cat);

      body.appendChild(top);

      var sub = document.createElement("div");
      sub.className = "match-sub";
      sub.textContent = res.url;
      body.appendChild(sub);

      var detail = document.createElement("div");
      detail.className = "match-detail";
      detail.textContent = res.detail || "";
      body.appendChild(detail);

      card.appendChild(body);

      var side = document.createElement("div");
      side.className = "match-side";
      var status = document.createElement("span");
      status.className = "match-status";
      status.setAttribute("data-s", res.status);
      status.textContent = "match";
      side.appendChild(status);
      if (res.ms) {
        var ms = document.createElement("span");
        ms.className = "match-ms";
        ms.textContent = res.ms + "ms";
        side.appendChild(ms);
      }
      var open = document.createElement("a");
      open.className = "match-open";
      open.href = res.url;
      open.target = "_blank";
      open.rel = "noopener noreferrer";
      open.textContent = "Open profile";
      side.appendChild(open);
      card.appendChild(side);

      resultsList.insertBefore(card, resultsList.firstChild);
    }

    function renderEnrich(data) {
      var card = resultsList.querySelector('[data-id="' + cssEscape(data.id) + '"]');
      if (!card) return;
      var display = card.querySelector(".match-display");
      if (display && data.display_name) {
        display.textContent = data.display_name;
        display.hidden = false;
      }
      var detail = card.querySelector(".match-detail");
      if (detail && data.meta && data.meta.length) {
        var bits = data.meta.map(function (m) { return m[0] + ": " + m[1]; });
        detail.textContent = bits.join("  ·  ");
        detail.title = bits.join("\n");
      }
      if (data.avatar) {
        var wrap = card.querySelector(".match-avatar");
        var img = wrap.querySelector("img");
        if (!img) {
          img = document.createElement("img");
          img.loading = "lazy";
          img.alt = "";
          img.referrerPolicy = "no-referrer";
          img.addEventListener("load", function () {
            wrap.classList.add("has-img");
          });
          img.addEventListener("error", function () { img.remove(); });
          wrap.appendChild(img);
        }
        img.src = data.avatar;
      }
    }

    function cssEscape(value) {
      if (window.CSS && window.CSS.escape) return window.CSS.escape(value);
      return String(value).replace(/["\\]/g, "\\$&");
    }

    /* -- the stream ------------------------------------------------------ */

    function handleEvent(event, payload) {
      if (event === "start") {
        total = payload.total || 0;
        reset();
        countEl.textContent = "000 / " + String(total).padStart(3, "0");
        if (timer) clearInterval(timer);
        timer = setInterval(function () {
          timeEl.textContent = fmtTime((Date.now() - startedAt) / 1000);
        }, 250);
        return;
      }
      if (event === "result") {
        pushLog(payload);
        if (payload.status === "hit") renderResult(payload);
        countEl.textContent = String(payload.checked).padStart(3, "0") + " / " +
          String(payload.total).padStart(3, "0");
        foundEl.textContent = String(payload.found).padStart(3, "0");
        timeEl.textContent = fmtTime(payload.elapsed);
        return;
      }
      if (event === "enrich") {
        renderEnrich(payload);
        return;
      }
      if (event === "done") {
        if (timer) clearInterval(timer);
        timer = null;
        running = false;
        timeEl.textContent = fmtTime(payload.elapsed);
        countEl.textContent = String(payload.checked).padStart(3, "0") + " / " +
          String(payload.total).padStart(3, "0");
        foundEl.textContent = String(payload.found).padStart(3, "0");
        setState("done", "Complete");
        statusEl.textContent = "Scan complete · " + payload.found + " matches";
        subEl.textContent = payload.checked + " checks, " + payload.found +
          " found, " + payload.misses + " no match, " + payload.unresolved +
          " unresolved.";
        if (liveEl) {
          liveEl.textContent = "Scan complete. " + payload.found + " matches.";
        }
        if (viewBtn) {
          viewBtn.hidden = false;
          viewBtn.textContent = "View " + payload.found + " matches";
        }
        if (resultsTitle) resultsTitle.textContent = payload.value || "";
        if (resultsMeta) {
          resultsMeta.textContent = payload.found + " matches · " +
            payload.checked + " checks · " + fmtTime(payload.elapsed);
        }
        if (resultsSection && payload.found > 0) resultsSection.hidden = false;
        return;
      }
      if (event === "error") {
        throw new Error(payload.message || "Scan failed.");
      }
    }

    function parseSseBlock(block) {
      var event = "message";
      var data = [];
      block.split("\n").forEach(function (line) {
        line = line.replace(/\r$/, "");
        if (line.indexOf("event:") === 0) event = line.slice(6).trim();
        else if (line.indexOf("data:") === 0) data.push(line.slice(5).trim());
      });
      if (!data.length) return null;
      var raw = data.join("\n");
      try {
        return { event: event, payload: JSON.parse(raw) };
      } catch (e) {
        return null;
      }
    }

    function fail(message, action) {
      if (timer) clearInterval(timer);
      timer = null;
      running = false;
      setState("idle", "Stopped");
      statusEl.textContent = message;
      subEl.textContent = "";
      if (action) {
        var link = document.createElement("a");
        link.className = "status-action";
        link.href = action.href;
        link.textContent = action.label;
        subEl.textContent = "";
        subEl.appendChild(link);
      }
      if (liveEl) liveEl.textContent = message;
    }

    function startScan(query, kind) {
      if (running && controller) controller.abort();
      if (timer) clearInterval(timer);
      timer = null;
      running = true;
      allResults = [];
      total = 0;
      startedAt = Date.now();

      statusEl.textContent = "Scanning " + query + "…";
      subEl.textContent = "";
      setState("running", "Running");
      if (viewBtn) viewBtn.hidden = true;
      if (resultsList) resultsList.innerHTML = "";
      if (resultsSection) resultsSection.hidden = true;
      clearLog();

      controller = new AbortController();
      var url = "/api/scan/stream?q=" + encodeURIComponent(query) +
        "&type=" + encodeURIComponent(kind || "username");

      fetch(url, {
        headers: { "Accept": "text/event-stream" },
        credentials: "same-origin",
        signal: controller.signal
      }).then(function (res) {
        if (!res.ok) {
          return res.json().catch(function () { return {}; }).then(function (body) {
            var err = new Error(body.message || ("Request failed (" + res.status + ")"));
            err.status = res.status;
            err.body = body;
            throw err;
          });
        }
        return readStream(res);
      }).then(function () {
        running = false;
        controller = null;
      }).catch(function (err) {
        if (err && err.name === "AbortError") return;
        running = false;
        controller = null;
        var status = err && err.status;
        if (status === 401) {
          fail("Log in to run a search.", {
            href: "/login?next=" + encodeURIComponent(window.location.pathname + window.location.search),
            label: "Log in →"
          });
        } else if (status === 403) {
          fail((err && err.message) || "That search type needs the Pro plan.", {
            href: "/pricing",
            label: "See plans →"
          });
        } else if (status === 402) {
          fail((err && err.message) || "You are out of credits.", {
            href: "/pricing",
            label: "Top up →"
          });
        } else {
          fail((err && err.message) || "Scan failed.");
        }
      });
    }

    function readStream(res) {
      if (!res.body || !res.body.getReader) {
        return res.text().then(function (text) {
          text.split("\n\n").forEach(function (block) {
            var parsed = parseSseBlock(block);
            if (parsed) handleEvent(parsed.event, parsed.payload);
          });
        });
      }
      var reader = res.body.getReader();
      var decoder = new TextDecoder();
      var buffer = "";

      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) {
            if (buffer.trim()) {
              var parsed = parseSseBlock(buffer);
              if (parsed) handleEvent(parsed.event, parsed.payload);
            }
            return;
          }
          buffer += decoder.decode(chunk.value, { stream: true });
          var blocks = buffer.split("\n\n");
          buffer = blocks.pop();
          blocks.forEach(function (block) {
            var parsed = parseSseBlock(block);
            if (parsed) handleEvent(parsed.event, parsed.payload);
          });
          return pump();
        });
      }
      return pump();
    }

    /* -- wiring ---------------------------------------------------------- */

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var query = input.value.trim();
      if (!query) {
        input.focus();
        return;
      }
      startScan(query, tabs.current());
    });

    if (viewBtn) {
      viewBtn.addEventListener("click", function () {
        if (resultsSection) {
          resultsSection.hidden = false;
          resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      });
    }

    if (newScanBtn) {
      newScanBtn.addEventListener("click", function () {
        input.focus();
        input.select();
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    }

    // "Try" example handles
    Array.prototype.forEach.call(document.querySelectorAll("[data-try]"), function (btn) {
      btn.addEventListener("click", function () {
        input.value = btn.getAttribute("data-try");
        var type = btn.getAttribute("data-try-type");
        if (type) tabs.set(type);
        startScan(input.value, tabs.current());
      });
    });

    // Pre-fill from ?q= and ?type=, then run automatically.
    var params = new URLSearchParams(window.location.search);
    var initial = params.get("q");
    var initialType = params.get("type");
    if (initialType) tabs.set(initialType);
    if (initial) {
      input.value = initial;
      startScan(initial, tabs.current());
    } else {
      setState("idle", "Ready");
      countEl.textContent = "000 / " + String(total || 773).padStart(3, "0");
    }
  }

  /* ------------------------------------------------------------------ */
  /* mobile navigation                                                    */
  /* ------------------------------------------------------------------ */

  function initNav() {
    var toggle = document.getElementById("nav-toggle");
    var links = document.getElementById("nav-links");
    if (!toggle || !links) return;

    function setOpen(open) {
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      toggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
      links.classList.toggle("is-open", open);
    }

    toggle.addEventListener("click", function () {
      setOpen(toggle.getAttribute("aria-expanded") !== "true");
    });

    links.addEventListener("click", function (ev) {
      if (ev.target.closest("a")) setOpen(false);
    });

    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") setOpen(false);
    });
  }

  /* ------------------------------------------------------------------ */
  /* boot                                                                */
  /* ------------------------------------------------------------------ */

  function boot() {
    initNav();
    initHeadline();
    initSweep();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
