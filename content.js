// Remove any previous listener from an earlier injection, then re-register fresh
if (window.__emailScannerHandler) {
  chrome.runtime.onMessage.removeListener(window.__emailScannerHandler);
}
window.__emailScannerHandler = null;

{
  window.__emailScannerHandler = (req, sender, sendResponse) => {

    if (req.action === "scanEmail") {

      // ---- FIX 1: Use multiple Gmail selectors (Gmail changes these over time) ----
      const messageContainer =
        document.querySelector("div[data-legacy-message-id]") ||
        document.querySelector("div[data-message-id]") ||
        document.querySelector(".a3s.aiL") ||
        document.querySelector(".ii.gt");

      if (!messageContainer) {
        // Not null — send a real response so popup knows no email is open
        sendResponse({ noEmail: true });
        return true;
      }

      // ---- FIX 2: Scan the message container text only (not entire page) ----
      const text = messageContainer.innerText.toLowerCase();
      let score = 0;
      const reasons = [];

      // ---- Phishing keyword scoring ----
      const highRiskPhrases = [
        "verify your account",
        "account suspended",
        "account has been limited",
        "confirm your identity",
        "unusual sign-in activity",
        "your password has expired",
        "click here to restore",
        "update your payment",
        "action required"
      ];

      const medRiskPhrases = [
        "verify",
        "urgent",
        "click here",
        "limited time",
        "dear customer",
        "dear user",
        "won a prize",
        "claim your reward",
        "log in immediately"
      ];

      highRiskPhrases.forEach(p => {
        if (text.includes(p)) {
          score += 25;
          reasons.push(`High-risk phrase: "${p}"`);
        }
      });

      medRiskPhrases.forEach(p => {
        if (text.includes(p)) {
          score += 10;
          reasons.push(`Suspicious phrase: "${p}"`);
        }
      });

      // ---- FIX 3: Extract URLs from <a> href tags (not just plain text regex) ----
      const anchorEls = messageContainer.querySelectorAll("a[href]");
      const validUrls = [];
      const seenUrls  = new Set();

      anchorEls.forEach(a => {
        const href = (a.getAttribute("href") || "").trim();
        // Skip mailto, tel, anchors, Google redirect wrappers that are empty
        if (!href || href.startsWith("mailto:") || href.startsWith("tel:") || href === "#") return;

        // Google wraps external links: https://www.google.com/url?q=REAL_URL
        let finalUrl = href;
        try {
          const parsed = new URL(href);
          if (parsed.hostname === "www.google.com" && parsed.pathname === "/url") {
            finalUrl = parsed.searchParams.get("q") || href;
          }
        } catch { return; }

        try {
          new URL(finalUrl);
          if (!seenUrls.has(finalUrl)) {
            seenUrls.add(finalUrl);
            validUrls.push(finalUrl);
          }
        } catch { /* skip malformed */ }
      });

      // Also catch plain-text URLs in the body (some emails use plain text)
      const rawMatches = text.match(/https?:\/\/[^\s"'<>)]+/g) || [];
      rawMatches.forEach(raw => {
        const cleaned = raw.replace(/[.,;:!?)]+$/, "");
        try {
          new URL(cleaned);
          if (!seenUrls.has(cleaned)) {
            seenUrls.add(cleaned);
            validUrls.push(cleaned);
          }
        } catch { /* skip */ }
      });

      if (validUrls.length > 0) {
        score += 15;
        reasons.push(`${validUrls.length} URL(s) detected`);
      }

      // ---- Attachment scanning ----
      // Gmail uses several selectors for attachments across versions
      const attachmentEls =
        document.querySelectorAll("span.aV3").length > 0
          ? document.querySelectorAll("span.aV3")
          : document.querySelectorAll("[data-tooltip][aria-label*='.']"); // fallback

      let attachmentInfo = "No attachments";

      if (attachmentEls.length > 0) {
        attachmentInfo = `${attachmentEls.length} attachment(s) detected`;

        const highRiskExts = [".exe", ".js", ".vbs", ".bat", ".cmd",
                              ".ps1", ".docm", ".xlsm", ".zip", ".rar",
                              ".7z", ".iso", ".scr", ".msi"];

        attachmentEls.forEach(el => {
          const name = el.innerText.toLowerCase().trim();
          const isHighRisk = highRiskExts.some(ext => name.endsWith(ext));
          if (isHighRisk) {
            attachmentInfo = `High-risk attachment: ${el.innerText.trim()}`;
            score += 30;
            reasons.push(`High-risk file type: ${name}`);
          }
        });
      }

      // ---- Sender domain mismatch ----
      const fromEls = document.querySelectorAll(".gD");
      if (fromEls.length > 0) {
        const fromEmail = (fromEls[0].getAttribute("email") || "").toLowerCase();
        const fromName  = (fromEls[0].innerText || "").toLowerCase();

        const knownBrands = ["paypal", "amazon", "google", "apple",
                             "microsoft", "netflix", "bank", "chase",
                             "wellsfargo", "citibank"];

        const nameMentionsBrand = knownBrands.some(b => fromName.includes(b));
        const emailMatchesBrand = knownBrands.some(b => fromEmail.includes(b));

        if (nameMentionsBrand && !emailMatchesBrand) {
          score += 40;
          reasons.push("Sender display name references a brand not matching email domain");
        }
      }

      const level =
        score >= 70 ? "High"   :
        score >= 40 ? "Medium" : "Low";

      sendResponse({
        level,
        score,
        reasons,
        urls: validUrls,
        attachmentInfo
      });

      return true;
    }
  };

  chrome.runtime.onMessage.addListener(window.__emailScannerHandler);
}
