type WarningMessage = {
  type: 'PHISHING_WARNING';
  score: number;
};

const BANNER_ID = 'phishing-url-shield-warning-banner';

function removeBanner(): void {
  const existing = document.getElementById(BANNER_ID);
  if (existing) {
    existing.remove();
  }
}

function createBanner(score: number): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.id = BANNER_ID;
  wrapper.style.position = 'fixed';
  wrapper.style.top = '0';
  wrapper.style.left = '0';
  wrapper.style.right = '0';
  wrapper.style.zIndex = '2147483647';
  wrapper.style.background = '#FEF2F2';
  wrapper.style.borderBottom = '1px solid #FECACA';
  wrapper.style.color = '#7F1D1D';
  wrapper.style.fontFamily = 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif';
  wrapper.style.padding = '12px 16px';
  wrapper.style.display = 'flex';
  wrapper.style.justifyContent = 'space-between';
  wrapper.style.alignItems = 'center';
  wrapper.style.gap = '12px';

  const text = document.createElement('div');
  text.textContent = `Warning: this URL shows signs of a phishing link. Confidence: ${Math.round(score * 100)}%`;

  const actions = document.createElement('div');
  actions.style.display = 'flex';
  actions.style.gap = '8px';

  const proceed = document.createElement('button');
  proceed.textContent = 'Proceed anyway';
  proceed.style.border = '1px solid #991B1B';
  proceed.style.background = '#FFFFFF';
  proceed.style.color = '#991B1B';
  proceed.style.padding = '6px 10px';
  proceed.style.cursor = 'pointer';
  proceed.addEventListener('click', () => {
    chrome.storage.local.set({
      lastDismissedWarning: {
        url: window.location.href,
        action: 'proceed_anyway',
        timestamp: Date.now()
      }
    });
    removeBanner();
  });

  const goBack = document.createElement('button');
  goBack.textContent = 'Go back';
  goBack.style.border = '1px solid #7F1D1D';
  goBack.style.background = '#991B1B';
  goBack.style.color = '#FFFFFF';
  goBack.style.padding = '6px 10px';
  goBack.style.cursor = 'pointer';
  goBack.addEventListener('click', () => {
    window.history.back();
  });

  actions.appendChild(proceed);
  actions.appendChild(goBack);
  wrapper.appendChild(text);
  wrapper.appendChild(actions);

  return wrapper;
}

chrome.runtime.onMessage.addListener((message: WarningMessage) => {
  if (message.type !== 'PHISHING_WARNING') {
    return;
  }

  removeBanner();
  const banner = createBanner(message.score);
  document.documentElement.appendChild(banner);

  window.setTimeout(() => {
    if (document.getElementById(BANNER_ID)) {
      chrome.storage.local.set({
        lastDismissedWarning: {
          url: window.location.href,
          action: 'auto_dismiss',
          timestamp: Date.now()
        }
      });
      removeBanner();
    }
  }, 30000);
});
