// ===============================================================
// Helpers
// ===============================================================

function makeRow(label, value, valueClass) {
  const row = document.createElement("div");
  row.className = "result-row";

  const lbl = document.createElement("span");
  lbl.className   = "row-label";
  lbl.textContent = label;

  const val = document.createElement("span");
  val.className   = "row-val" + (valueClass ? " " + valueClass : "");
  val.textContent = value;

  row.appendChild(lbl);
  row.appendChild(val);
  return row;
}

function showRisk(prefix, level, score) {
  const bannerEl = document.getElementById(prefix + "Banner");
  const iconEl   = document.getElementById(prefix + "Icon");
  const labelEl  = document.getElementById(prefix + "Label");
  const subEl    = document.getElementById(prefix + "Sublabel");

  const map = {
    High:   { icon: "🚨", cls: "high",   sub: "Treat with caution" },
    Medium: { icon: "⚠️",  cls: "medium", sub: "Potentially suspicious" },
    Low:    { icon: "✅",  cls: "low",    sub: "No major signals detected" }
  };
  const info = map[level] || map.Low;

  bannerEl.className  = "risk-banner " + info.cls;
  iconEl.textContent  = info.icon;
  labelEl.className   = "risk-label " + info.cls;
  labelEl.textContent = level + " Risk";
  subEl.textContent   = "Score: " + score + " — " + info.sub;
}

function setSpinner(spinnerId, btnTextId, btnId, loading, loadingText, idleText) {
  const spinner = document.getElementById(spinnerId);
  const btnText = document.getElementById(btnTextId);
  const btn     = document.getElementById(btnId);
  spinner.style.display = loading ? "block" : "none";
  btnText.textContent   = loading ? loadingText : idleText;
  btn.disabled          = loading;
}

function showInfo(id, msg, isErr) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className   = "info-line" + (isErr ? " err" : "");
}

function clearRows(elId) {
  const el = document.getElementById(elId);
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

// ===============================================================
// Tab switching
// ===============================================================
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
  });
});

// ===============================================================
// Settings button
// ===============================================================
document.getElementById("settingsBtn").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});
document.getElementById("goSettings")?.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

// Show API warning if no key configured
chrome.storage.local.get("vtApiKey", (data) => {
  if (!data.vtApiKey) {
    document.getElementById("apiWarning").style.display = "block";
  }
});

// ===============================================================
// EMAIL SCAN
// ===============================================================
document.getElementById("scanBtn").addEventListener("click", async () => {
  showInfo("scanInfo", "");
  document.getElementById("emailResult").classList.remove("visible");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab?.url || tab.url.startsWith("chrome://")) {
    showInfo("scanInfo", "Open Gmail and select an email first.", true);
    return;
  }
  if (!tab.url.includes("mail.google.com")) {
    showInfo("scanInfo", "This extension only works on Gmail.", true);
    return;
  }

  setSpinner("scanSpinner", "scanBtnText", "scanBtn", true, "Scanning...", "Scan Email");
  showInfo("scanInfo", "Reading email...");

  
  try {
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
  } catch { /* already injected via manifest — fine */ }

  
  let response = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    response = await new Promise((resolve) => {
      try {
        chrome.tabs.sendMessage(tab.id, { action: "scanEmail" }, (res) => {
          if (chrome.runtime.lastError) resolve(null);
          else resolve(res);
        });
      } catch { resolve(null); }
    });
    if (response !== null && response !== undefined) break;
    await new Promise(r => setTimeout(r, 600));
  }

  if (!response) {
    setSpinner("scanSpinner", "scanBtnText", "scanBtn", false, "", "Scan Email");
    showInfo("scanInfo", "Could not read the page. Reload Gmail and try again.", true);
    return;
  }

  if (response.noEmail) {
    setSpinner("scanSpinner", "scanBtnText", "scanBtn", false, "", "Scan Email");
    showInfo("scanInfo", "Open a Gmail conversation first, then scan.", true);
    return;
  }

  
  displayEmailResult(response, null, true /* vtPending */);
  setSpinner("scanSpinner", "scanBtnText", "scanBtn", false, "", "Scan Email");

  const urls = response.urls || [];

  if (urls.length === 0) {
    // No URLs — no VT call needed, finalize
    displayEmailResult(response, null, false);
    showInfo("scanInfo", "");
    return;
  }

  
  showInfo("scanInfo", `Checking ${Math.min(urls.length, 5)} URL(s) with VirusTotal… (may take ~30s on free tier)`);

  const vtResult = await Promise.race([
    new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: "checkURLs", urls }, (vt) => {
        if (chrome.runtime.lastError) resolve({ malicious: 0, error: "Extension error" });
        else resolve(vt);
      });
    }),
    new Promise((resolve) => setTimeout(() => resolve({ malicious: 0, timedOut: true }), 60000))
  ]);

  displayEmailResult(response, vtResult, false);
  showInfo("scanInfo", "");
});

function displayEmailResult(local, vt, vtPending) {
  showRisk("risk", local.level, local.score);

  const rowsEl = clearRows("emailRows");

  // Attachments row
  const attClass =
    local.attachmentInfo.toLowerCase().includes("high-risk") ? "danger" :
    local.attachmentInfo === "No attachments" ? "ok" : "warning";
  rowsEl.appendChild(makeRow("Attachments", local.attachmentInfo, attClass));

  // URLs found row
  const urlCount = (local.urls || []).length;
  rowsEl.appendChild(makeRow(
    "URLs found",
    urlCount > 0 ? urlCount + " link(s)" : "None",
    urlCount > 0 ? "warning" : "ok"
  ));

  // VirusTotal row — with all possible states handled
  let vtLabel, vtClass;
  if (vtPending) {
    vtLabel = "Checking VirusTotal…"; vtClass = "";
  } else if (vt?.timedOut) {
    vtLabel = "VT timed out (free tier slow) — local scan shown above"; vtClass = "warning";
  } else if (vt?.rateLimited) {
    vtLabel = "VT rate limit hit — wait 1 min, then scan again"; vtClass = "warning";
  } else if (vt?.error === "API key not configured") {
    vtLabel = "API key not set — go to Settings"; vtClass = "warning";
  } else if (!local.urls || local.urls.length === 0) {
    vtLabel = "No URLs to scan"; vtClass = "";
  } else if (vt?.malicious > 0) {
    vtLabel = vt.malicious + " engine(s) flagged a link 🚨"; vtClass = "danger";
  } else if (vt) {
    vtLabel = "All links clean ✓"; vtClass = "ok";
  } else {
    vtLabel = "Not checked"; vtClass = "";
  }
  rowsEl.appendChild(makeRow("VirusTotal", vtLabel, vtClass));

  // Detection reasons (collapsible)
  const reasons = local.reasons || [];
  if (reasons.length > 0) {
    const toggle = document.createElement("span");
    toggle.className   = "reasons-toggle";
    toggle.textContent = "Show " + reasons.length + " detection reason(s)";

    const list = document.createElement("ul");
    list.className = "reasons-list";
    reasons.forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      list.appendChild(li);
    });

    toggle.addEventListener("click", () => {
      list.classList.toggle("open");
      toggle.textContent = list.classList.contains("open")
        ? "Hide reasons"
        : "Show " + reasons.length + " detection reason(s)";
    });

    rowsEl.appendChild(toggle);
    rowsEl.appendChild(list);
  }

  document.getElementById("emailResult").classList.add("visible");
}

// ===============================================================
// HEADER SCAN
// ===============================================================
document.getElementById("advancedBtn").addEventListener("click", () => {
  const text = document.getElementById("headersInput").value.trim().toLowerCase();

  document.getElementById("headerResult").classList.remove("visible");
  showInfo("headerInfo", "");

  if (!text) {
    showInfo("headerInfo", "Paste email headers above first.", true);
    return;
  }

  let score = 0;
  const reasons = [];

  if (/received-spf\s*:\s*fail/i.test(text) || /spf=fail/i.test(text)) {
    score += 30; reasons.push("SPF: FAIL");
  } else if (/spf=softfail/i.test(text)) {
    score += 15; reasons.push("SPF: SOFTFAIL");
  } else if (/spf=pass/i.test(text)) {
    reasons.push("SPF: pass ✓");
  }

  if (/dkim=fail/i.test(text))       { score += 25; reasons.push("DKIM: FAIL"); }
  else if (/dkim=pass/i.test(text))  { reasons.push("DKIM: pass ✓"); }

  if (/dmarc=fail/i.test(text))      { score += 25; reasons.push("DMARC: FAIL"); }
  else if (/dmarc=pass/i.test(text)) { reasons.push("DMARC: pass ✓"); }

  if (/disposition=quarantine/i.test(text)) { score += 10; reasons.push("DMARC disposition: quarantine"); }
  if (/disposition=reject/i.test(text))     { score += 20; reasons.push("DMARC disposition: reject"); }

  const level = score >= 55 ? "High" : score >= 25 ? "Medium" : "Low";
  showRisk("hRisk", level, score);

  const rowsEl = clearRows("headerRows");
  reasons.forEach(r => {
    const isBad = r.includes("FAIL") || r.includes("quarantine") || r.includes("reject");
    rowsEl.appendChild(makeRow("", r, isBad ? "danger" : "ok"));
  });
  if (reasons.length === 0) rowsEl.appendChild(makeRow("", "No authentication fields found", "warning"));

  document.getElementById("headerResult").classList.add("visible");
});

// ===============================================================
// FILE HASH SCAN
// ===============================================================
document.getElementById("fileScanBtn").addEventListener("click", async () => {
  const fileInput = document.getElementById("fileInput");
  document.getElementById("fileResult").classList.remove("visible");
  showInfo("fileInfo", "");

  if (!fileInput.files.length) {
    showInfo("fileInfo", "Select a file first.", true);
    return;
  }

  const file = fileInput.files[0];
  setSpinner("fileSpinner", "fileBtnText", "fileScanBtn", true, "Hashing...", "Scan File (Hash)");

  const hash = await getFileHash(file);
  showInfo("fileInfo", "Checking hash with VirusTotal...");

  const res = await Promise.race([
    new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: "checkFileHash", hash }, (r) => {
        if (chrome.runtime.lastError) resolve({ malicious: 0, unknown: true });
        else resolve(r);
      });
    }),
    new Promise((resolve) => setTimeout(() => resolve({ malicious: 0, timedOut: true }), 30000))
  ]);

  setSpinner("fileSpinner", "fileBtnText", "fileScanBtn", false, "", "Scan File (Hash)");
  showInfo("fileInfo", "");

  let vtLabel, vtClass;
  if (res?.timedOut)                         { vtLabel = "VT timed out — try again shortly"; vtClass = "warning"; }
  else if (res?.rateLimited)                 { vtLabel = "Rate limited — wait 1 min and retry"; vtClass = "warning"; }
  else if (res?.error === "API key not configured") { vtLabel = "API key not set — go to Settings"; vtClass = "warning"; }
  else if (res?.unknown)                     { vtLabel = "Unknown to VirusTotal (not necessarily safe)"; vtClass = "warning"; }
  else if (res?.malicious > 0)               { vtLabel = res.malicious + " engine(s) flagged this file 🚨"; vtClass = "danger"; }
  else                                       { vtLabel = "No known threat detected ✓"; vtClass = "ok"; }

  const level = (res?.malicious > 0) ? "High" : (res?.unknown || res?.timedOut) ? "Medium" : "Low";
  const score = res?.malicious ? res.malicious * 5 : 0;
  showRisk("fRisk", level, score);

  const rowsEl = clearRows("fileRows");
  rowsEl.appendChild(makeRow("File name", file.name, ""));
  rowsEl.appendChild(makeRow("Size", (file.size / 1024).toFixed(1) + " KB", ""));
  rowsEl.appendChild(makeRow("SHA-256", hash.slice(0, 16) + "…", ""));
  rowsEl.appendChild(makeRow("VirusTotal", vtLabel, vtClass));

  document.getElementById("fileResult").classList.add("visible");
});

async function getFileHash(file) {
  const buffer     = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
