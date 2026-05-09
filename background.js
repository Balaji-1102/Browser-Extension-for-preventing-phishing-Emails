// ============================================================
// SECURITY NOTE: Do NOT hardcode your API key here.
// Set it once after install via the extension's options page,
// or store it with: chrome.storage.local.set({ vtApiKey: "YOUR_KEY" })
// ============================================================

const VT_BASE = "https://www.virustotal.com/api/v3";

function getApiKey() {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get("vtApiKey", (data) => {
      if (data.vtApiKey) resolve(data.vtApiKey);
      else reject(new Error("API key not configured"));
    });
  });
}


async function pollAnalysis(analysisId, apiKey, attempts = 0) {
  if (attempts > 10) return { malicious: 0, status: "timeout" };

  const res  = await fetch(`${VT_BASE}/analyses/${analysisId}`, {
    headers: { "x-apikey": apiKey }
  });
  const data = await res.json();

  if (!data?.data) return { malicious: 0, status: "error" };

  const { status, stats } = data.data.attributes;

  if (status === "completed") {
    return { malicious: stats.malicious ?? 0, status: "completed" };
  }

  await new Promise(r => setTimeout(r, 3000));
  return pollAnalysis(analysisId, apiKey, attempts + 1);
}

// ================= MESSAGE LISTENER =================
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {

  // ---------- URL SCAN ----------
  if (req.action === "checkURLs") {
    (async () => {
      try {
        const apiKey = await getApiKey();

        // FIX: Deduplicate URLs and cap at 5 to avoid rate-limit hangs
        const seen = new Set();
        const urls = (req.urls || []).filter(u => {
          try { new URL(u); } catch { return false; }
          if (seen.has(u)) return false;
          seen.add(u);
          return true;
        }).slice(0, 5);

        let worstMalicious = 0;
        let worstUrl = "";

        for (const url of urls) {
          try {
            const submitRes = await fetch(`${VT_BASE}/urls`, {
              method: "POST",
              headers: {
                "x-apikey": apiKey,
                "Content-Type": "application/x-www-form-urlencoded"
              },
              body: "url=" + encodeURIComponent(url)
            });

            // FIX: Handle rate limiting (HTTP 429) gracefully
            if (submitRes.status === 429) {
              sendResponse({ malicious: worstMalicious, url: worstUrl, rateLimited: true });
              return;
            }

            const submitData = await submitRes.json();
            if (!submitData?.data?.id) continue;

            const result = await pollAnalysis(submitData.data.id, apiKey);

            if (result.malicious > worstMalicious) {
              worstMalicious = result.malicious;
              worstUrl = url;
            }

            
            await new Promise(r => setTimeout(r, 1000));

          } catch (urlErr) {
            // Skip this URL on error, continue with others
            console.warn("VT URL scan error:", urlErr);
          }
        }

        sendResponse({ malicious: worstMalicious, url: worstUrl });

      } catch (err) {
        sendResponse({ malicious: 0, error: err.message });
      }
    })();
    return true; // Keep message channel open for async response
  }

  // ---------- FILE HASH SCAN ----------
  if (req.action === "checkFileHash") {
    (async () => {
      try {
        const apiKey = await getApiKey();
        const res = await fetch(`${VT_BASE}/files/${req.hash}`, {
          headers: { "x-apikey": apiKey }
        });

        if (res.status === 404) {
          sendResponse({ malicious: 0, unknown: true });
          return;
        }

        if (res.status === 429) {
          sendResponse({ malicious: 0, unknown: true, rateLimited: true });
          return;
        }

        const data = await res.json();
        const stats = data?.data?.attributes?.last_analysis_stats;

        sendResponse({
          malicious: stats?.malicious ?? 0,
          unknown: false
        });
      } catch {
        sendResponse({ malicious: 0, unknown: true });
      }
    })();
    return true;
  }

  // ---------- SAVE API KEY ----------
  if (req.action === "saveApiKey") {
    chrome.storage.local.set({ vtApiKey: req.key }, () => {
      sendResponse({ ok: true });
    });
    return true;
  }
});
