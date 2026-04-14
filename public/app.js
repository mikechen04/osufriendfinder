// tiny front-end helpers. nothing fancy.

// when no avatar or empty browse state
const AVATAR_PLACEHOLDER = "https://a.ppy.sh/12742221?1773291467.png";

// escape html special chars before sticking user data into innerHTML
function escHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function qs(sel) {
  return document.querySelector(sel);
}

function setText(el, text) {
  if (!el) return;
  el.textContent = text == null ? "" : String(text);
}

function setHtml(el, html) {
  if (!el) return;
  el.innerHTML = html || "";
}

// what the browsed user saved in preferences (shown under their bio as bubbles)
function formatTheirPrefs(tp) {
  if (!tp) return "";

  var bubbles = [];

  // age bubble
  if (tp.min_age != null && tp.max_age != null) bubbles.push(`ages ${tp.min_age}–${tp.max_age}`);
  else if (tp.min_age != null) bubbles.push(`ages ${tp.min_age}+`);
  else if (tp.max_age != null) bubbles.push(`up to ${tp.max_age}`);

  // gender bubbles
  if (tp.genders && tp.genders.length) {
    tp.genders.forEach(function(g) { bubbles.push(g); });
  }

  // rank bubble
  if (tp.rank_max != null && typeof tp.rank_max === "number") bubbles.push(`#${tp.rank_max}+`);

  if (bubbles.length === 0) return "";

  var tags = bubbles.map(function(b) {
    return `<span class="tag">${escHtml(b)}</span>`;
  }).join(" ");

  return tags;
}

function renderHomeShowcase() {
  const wrap = qs("[data-home-showcase]");
  const grid = qs("[data-home-showcase-grid]");
  if (!wrap || !grid) return;

  // server bakes this into the page so no fetch needed — always reliable
  const users = (window.__SHOWCASE__ && Array.isArray(window.__SHOWCASE__)) ? window.__SHOWCASE__ : [];
  if (users.length === 0) return;

  wrap.hidden = false;

  const cards = users
    .map(u => {
      const rank = u.global_rank ? ` #${u.global_rank}` : "";
      const badges = typeof u.badge_count === "number" ? ` · ${u.badge_count} badges` : "";
      const tags = [
        u.age ? `${u.age}+` : "",
        u.gender ? u.gender : "",
        u.country_code ? u.country_code : "",
        typeof u.badge_count === "number" ? `${u.badge_count} badges` : "",
      ]
        .filter(Boolean)
        .join(" · ");

      return `
        <a class="showcase-card${u.cute_tint ? " showcase-card-cute" : ""}" href="/browse" title="browse">
          <img class="avatar smol" src="${escHtml(u.avatar_url || AVATAR_PLACEHOLDER)}" alt="${escHtml(u.username)}" />
          <div class="showcase-name">${escHtml(u.username)}${escHtml(rank)}${escHtml(badges)}</div>
          <div class="muted showcase-tags">${escHtml(tags)}</div>
        </a>
      `;
    })
    .join("");

  grid.innerHTML = cards;
}

function renderBrowseStack() {
  const root = qs("[data-browse-root]");
  if (!root) return;

  const raw = root.getAttribute("data-users-json") || "[]";
  let users = [];
  try {
    users = JSON.parse(raw);
  } catch (e) {
    users = [];
  }

  const idxEl = qs("[data-browse-idx]");
  const totalEl = qs("[data-browse-total]");
  const prevBtn = qs("[data-browse-prev]");
  const nextBtn = qs("[data-browse-next]");

  const avatarEl = qs("[data-browse-avatar]");
  const nameEl = qs("[data-browse-name]");
  const tagsEl = qs("[data-browse-tags]");
  const bioEl = qs("[data-browse-bio]");
  const osuLinkEl = qs("[data-browse-osu-link]");
  const toUserIdEl = qs("[data-browse-to-user-id]");
  const blockUserIdEl = qs("[data-browse-block-user-id]");
  const reportToUserIdEl = qs("[data-report-to-user-id]");
  const theirPrefsEl = qs("[data-browse-their-prefs]");
  const tourneyModsEl = qs("[data-browse-tourney-mods]");
  const tourneySkillsetsEl = qs("[data-browse-tourney-skillsets]");
  const tourneyRanksEl = qs("[data-browse-tourney-ranks]");
  const tourneyDiscordEl = qs("[data-browse-tourney-discord]");
  const isTourney = root.getAttribute("data-browse-mode") === "tourney";

  const openReportBtn = qs("[data-open-report]");
  const closeReportBtn = qs("[data-close-report]");
  const reportBackdrop = qs("[data-report-backdrop]");

  let idx = 0;

  // build tag bubbles from an array of strings
  function tagsHtml(arr, extraClass) {
    if (!arr || !arr.length) return '<span class="muted" style="font-size:0.82rem">none listed</span>';
    return arr.map(function(v) {
      return `<span class="tag ${extraClass || ''}">${escHtml(v)}</span>`;
    }).join(" ");
  }

  function draw() {
    setText(totalEl, users.length);

    if (users.length === 0) {
      setText(idxEl, "0");
      setText(nameEl, isTourney ? "no tourney players yet" : "nobody here yet");
      if (avatarEl) avatarEl.src = AVATAR_PLACEHOLDER;
      setHtml(tagsEl, "");
      setText(bioEl, isTourney ? "set your tourney preferences to show up here" : "tell ur friends to make a profile so u have ppl to browse");
      if (osuLinkEl) osuLinkEl.href = "#";
      if (toUserIdEl) toUserIdEl.value = "";
      if (blockUserIdEl) blockUserIdEl.value = "";
      if (reportToUserIdEl) reportToUserIdEl.value = "";
      if (theirPrefsEl) setHtml(theirPrefsEl, "");
      if (tourneyModsEl) setHtml(tourneyModsEl, "");
      if (tourneySkillsetsEl) setHtml(tourneySkillsetsEl, "");
      if (tourneyRanksEl) setHtml(tourneyRanksEl, "");
      if (tourneyDiscordEl) setText(tourneyDiscordEl, "");
      root.classList.remove("profile-card-cute");
      if (prevBtn) prevBtn.disabled = true;
      if (nextBtn) nextBtn.disabled = true;
      return;
    }

    if (idx < 0) idx = 0;
    if (idx > users.length - 1) idx = users.length - 1;

    const u = users[idx];

    setText(idxEl, idx + 1);
    const rankText = u.global_rank ? ` (#${u.global_rank})` : "";
    setText(nameEl, `${u.username}${rankText}`);
    if (avatarEl) avatarEl.src = u.avatar_url || AVATAR_PLACEHOLDER;

    const pieces = [];
    if (u.age) pieces.push(`<span class="tag">${escHtml(u.age)}+</span>`);
    if (u.gender) pieces.push(`<span class="tag">${escHtml(u.gender)}</span>`);
    if (u.country_code) pieces.push(`<span class="tag">${escHtml(u.country_code)}</span>`);
    if (typeof u.badge_count === "number") pieces.push(`<span class="tag">${escHtml(u.badge_count)} badges</span>`);
    setHtml(tagsEl, pieces.join(" "));

    var showBio = isTourney ? (u.tourney_bio || u.bio || "") : (u.bio || "");
    setText(bioEl, showBio);

    if (tourneyDiscordEl) {
      var disc = u.discord ? String(u.discord).trim() : "";
      setText(tourneyDiscordEl, disc || "not listed");
    }

    if (theirPrefsEl) setHtml(theirPrefsEl, formatTheirPrefs(u.their_prefs));

    // tourney fields
    if (tourneyModsEl) {
      var tp = u.tourney_prefs || {};
      setHtml(tourneyModsEl, tagsHtml(tp.mods, "tag-mod"));
    }
    if (tourneySkillsetsEl) {
      var tp2 = u.tourney_prefs || {};
      setHtml(tourneySkillsetsEl, tagsHtml(tp2.skillsets, "tag-skill"));
    }
    if (tourneyRanksEl) {
      var tp3 = u.tourney_prefs || {};
      setHtml(tourneyRanksEl, tagsHtml(tp3.rank_ranges, "tag-rank"));
    }

    if (u.cute_tint) root.classList.add("profile-card-cute");
    else root.classList.remove("profile-card-cute");
    if (osuLinkEl) osuLinkEl.href = `https://osu.ppy.sh/users/${u.osu_id}`;
    if (toUserIdEl) toUserIdEl.value = u.id;
    if (blockUserIdEl) blockUserIdEl.value = u.id;
    if (reportToUserIdEl) reportToUserIdEl.value = u.id;

    if (prevBtn) prevBtn.disabled = idx === 0;
    if (nextBtn) nextBtn.disabled = idx === users.length - 1;
  }

  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      idx -= 1;
      draw();
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      idx += 1;
      draw();
    });
  }

  draw();
}

// handle preference pill bubbles + dual range slider on the preferences page
function initPrefPills() {
  // dual range age slider
  var minSlider = document.getElementById("age-min-slider");
  var maxSlider = document.getElementById("age-max-slider");
  var minLabel = document.getElementById("age-min-label");
  var maxLabel = document.getElementById("age-max-label");
  var fill = document.getElementById("age-fill");
  var minHidden = document.getElementById("hidden-min-age");
  var maxHidden = document.getElementById("hidden-max-age");

  function updateSlider() {
    var min = parseInt(minSlider.value);
    var max = parseInt(maxSlider.value);

    // stop them from crossing over
    if (min > max) {
      if (document.activeElement === minSlider) {
        minSlider.value = max;
        min = max;
      } else {
        maxSlider.value = min;
        max = min;
      }
    }

    // update the fill bar position
    var pMin = ((min - 18) / (67 - 18)) * 100;
    var pMax = ((max - 18) / (67 - 18)) * 100;
    if (fill) {
      fill.style.left = pMin + "%";
      fill.style.width = (pMax - pMin) + "%";
    }

    if (minLabel) minLabel.textContent = min;
    if (maxLabel) maxLabel.textContent = max;

    // send empty string when at the absolute min/max so server treats it as "any"
    if (minHidden) minHidden.value = min === 18 ? "" : min;
    if (maxHidden) maxHidden.value = max === 67 ? "" : max;
  }

  if (minSlider && maxSlider) {
    minSlider.addEventListener("input", updateSlider);
    maxSlider.addEventListener("input", updateSlider);
    updateSlider(); // init the fill on page load
  }

  // gender checkboxes styled as pills
  var genderPills = document.querySelectorAll(".pref-pill input[type='checkbox']");
  genderPills.forEach(function(input) {
    input.addEventListener("change", function() {
      input.closest(".pref-pill").classList.toggle("active", input.checked);
    });
  });

  // rank radio buttons styled as pills
  var rankPills = document.querySelectorAll(".pref-pill input[type='radio']");
  rankPills.forEach(function(input) {
    input.addEventListener("change", function() {
      rankPills.forEach(function(r) {
        r.closest(".pref-pill").classList.toggle("active", r.checked);
      });
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initPrefPills();
  // 18+ gate (only shows once)
  try {
    // mark current page as visited so modal checkboxes can be unlocked
    var path = window.location.pathname;
    if (path === "/terms") localStorage.setItem("visited_terms", "1");
    if (path === "/privacy") localStorage.setItem("visited_privacy", "1");
    if (path === "/disclaimer") localStorage.setItem("visited_disclaimer", "1");

    // legal pages are immune to the popup — skip gate entirely on those pages
    var legalPages = ["/terms", "/privacy", "/disclaimer"];
    var onLegalPage = legalPages.includes(path);

    const ageBackdrop = onLegalPage ? null : qs("[data-age-backdrop]");
    const ageAgreeBtn = onLegalPage ? null : qs("[data-age-agree]");
    const ageLegalCbs = onLegalPage ? [] : document.querySelectorAll(".age-legal-cb");
    if (ageBackdrop && ageAgreeBtn) {
      const ok = localStorage.getItem("age_ok") === "1";
      if (!ok) {
        ageBackdrop.hidden = false;
        document.body.style.overflow = "hidden";
        // move focus into the dialog so keyboard users aren't stuck outside
        var ageDialog = ageBackdrop.querySelector("[role='dialog']");
        if (ageDialog) ageDialog.focus();
      }

      // trap Tab/Shift+Tab inside the dialog while it's open
      ageBackdrop.addEventListener("keydown", function(e) {
        if (e.key !== "Tab") return;
        var dialog = ageBackdrop.querySelector("[role='dialog']");
        if (!dialog) return;
        var focusable = Array.from(dialog.querySelectorAll(
          'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )).filter(function(el) { return !el.closest("[hidden]"); });
        if (focusable.length === 0) return;
        var first = focusable[0];
        var last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      });

      // check which pages have been visited and unlock those checkboxes
      var visitKeys = ["visited_terms", "visited_privacy", "visited_disclaimer"];
      function updateCheckboxStates() {
        ageLegalCbs.forEach(function(cb, i) {
          var visited = localStorage.getItem(visitKeys[i]) === "1";
          // unlock checkbox only after they visited the page — never auto-check it
          cb.disabled = !visited;
          // set checkbox opacity directly so it cant be overridden by global input css
          cb.style.opacity = visited ? "1" : "0.35";
          // also fade the prefix text via the .visited class
          var row = cb.closest(".age-terms-check");
          if (row) {
            if (visited) row.classList.add("visited");
            else row.classList.remove("visited");
          }
        });
        updateAgreeBtn();
      }

      var age18Cb = onLegalPage ? null : qs("#age-18-cb");

      function updateAgreeBtn() {
        var allLegalChecked = Array.from(ageLegalCbs).every(function(cb) { return cb.checked; });
        var ageChecked = age18Cb ? age18Cb.checked : true;
        ageAgreeBtn.disabled = !(allLegalChecked && ageChecked);
      }

      ageLegalCbs.forEach(function(cb) {
        cb.addEventListener("change", updateAgreeBtn);
      });
      if (age18Cb) age18Cb.addEventListener("change", updateAgreeBtn);

      // re-check when user returns from a legal page tab
      document.addEventListener("visibilitychange", function() {
        if (!document.hidden) updateCheckboxStates();
      });

      updateCheckboxStates();

      ageAgreeBtn.addEventListener("click", function() {
        localStorage.setItem("age_ok", "1");
        ageBackdrop.hidden = true;
        document.body.style.overflow = "";
      });
    }
  } catch (e) {
    // ignore
  }

  // site announcement — close saves which expiry you dismissed so new posts show again
  try {
    const annEl = qs(".site-announcement[data-announcement-expires]");
    if (annEl) {
      const exp = annEl.getAttribute("data-announcement-expires");
      const key = "announcementDismissedExpires";
      if (exp && localStorage.getItem(key) === exp) {
        annEl.hidden = true;
      }
      const closeBtn = annEl.querySelector(".site-announcement-close");
      if (closeBtn) {
        closeBtn.addEventListener("click", () => {
          if (exp) localStorage.setItem(key, exp);
          annEl.hidden = true;
        });
      }
    }
  } catch (e) {
    // ignore
  }

  renderHomeShowcase();
  renderBrowseStack();

  // landing: talking cat bubble cycles through phrases
  const meowBubble = qs(".rr-meow-bubble");
  if (meowBubble) {
    const meowPhases = [
      "meow meow meow mlep mrrp",
      "im a homosexual",
      "im gay",
      "meowwwwwwwwww",
      "ARF ARF",
    ];
    let meowIdx = 0;
    setInterval(() => {
      meowIdx = (meowIdx + 1) % meowPhases.length;
      meowBubble.textContent = meowPhases[meowIdx];
    }, 3500);
  }

  // report modal
  const reportBackdrop = qs("[data-report-backdrop]");
  const openReportBtn = qs("[data-open-report]");
  const closeReportBtn = qs("[data-close-report]");
  if (reportBackdrop && openReportBtn && closeReportBtn) {
    function openModal() {
      reportBackdrop.hidden = false;
      const ta = qs("#report_body");
      if (ta) ta.focus();
    }
    function closeModal() {
      reportBackdrop.hidden = true;
    }

    openReportBtn.addEventListener("click", openModal);
    closeReportBtn.addEventListener("click", closeModal);
    reportBackdrop.addEventListener("click", e => {
      if (e.target === reportBackdrop) closeModal();
    });
    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && !reportBackdrop.hidden) closeModal();
    });
  }
});

