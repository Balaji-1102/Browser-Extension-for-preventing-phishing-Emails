const input     = document.getElementById("apiKeyInput");
const saveBtn   = document.getElementById("saveBtn");
const toggleBtn = document.getElementById("toggleShow");
const status    = document.getElementById("status");

// Load existing key into the field on page open
chrome.storage.local.get("vtApiKey", (data) => {
  if (data.vtApiKey) {
    input.value = data.vtApiKey;
  }
});

// Show / Hide toggle
toggleBtn.addEventListener("click", () => {
  const isHidden = input.type === "password";
  input.type            = isHidden ? "text" : "password";
  toggleBtn.textContent = isHidden ? "Hide" : "Show";
});

// Save key directly to chrome.storage (no message needed)
saveBtn.addEventListener("click", () => {
  const key = input.value.trim();
  if (!key) {
    status.textContent = "Please enter a valid API key.";
    status.className   = "status err";
    return;
  }
  chrome.storage.local.set({ vtApiKey: key }, () => {
    status.textContent = "Key saved successfully.";
    status.className   = "status ok";
    setTimeout(() => { status.textContent = ""; }, 3000);
  });
});
