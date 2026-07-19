import { extractFeatures, extractFeatureVector, isOfficialBrandDomain } from '../utils/feature-extractor';
import { parseUrl } from '../utils/url-parser';

let modelLoadFailed = false;
let creatingPromise: Promise<void> | null = null;

async function setupOffscreenDocument(): Promise<void> {
  const existingContexts = await chrome.runtime.getContexts({
    contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT]
  });
  if (existingContexts.length > 0) return;

  if (creatingPromise) {
    await creatingPromise;
    return;
  }

  creatingPromise = chrome.offscreen.createDocument({
    url: 'offscreen/offscreen.html',
    reasons: [chrome.offscreen.Reason.WORKERS || 'WORKERS' as any],
    justification: 'Run ONNX ML model'
  });
  
  await creatingPromise;
  creatingPromise = null;
}

function heuristicScore(url: string): number {
  const v = extractFeatureVector(url);
  let score = 0;
  score += v.brand_in_registered_domain * 0.40;
  score += v.brand_in_subdomain * 0.35;
  score += Math.min(v.suspicious_keyword_count / 3, 1) * 0.19;
  score += Math.min(Math.max(v.url_entropy - 3.5, 0) / 2, 1) * 0.15;
  score += Math.min(Math.max(v.hostname_entropy - 3.0, 0) / 2, 1) * 0.12;
  score += v.is_ip_address * 0.20;
  score += v.lookalike_char_detected * 0.15;
  score += v.encoded_url_in_path * 0.15;
  score += v.at_symbol_present * 0.15;
  score += v.double_slash_in_path * 0.10;
  score += v.tld_risk_score * 0.15;
  score += (1 - v.https_present) * 0.05;
  score += Math.min(Math.max(v.url_length - 60, 0) / 120, 1) * 0.05;
  score += Math.min(v.subdomain_depth / 4, 1) * 0.05;
  score += v.file_extension_suspicious * 0.10;
  score += Math.min(v.digit_ratio * 2, 1) * 0.05;
  return Math.min(Math.max(score, 0), 1);
}

async function classify(url: string): Promise<{ score: number; features: number[] }> {
  const v = extractFeatureVector(url);
  const features = extractFeatures(url);

  let rawScore = 0;
  let modelWorked = false;

  if (!modelLoadFailed) {
    try {
      await setupOffscreenDocument();
      
      // Call the offscreen document to do the ML inference
      const response = await chrome.runtime.sendMessage({
        type: 'OFFSCREEN_SCORE_URL',
        url: url
      });

      if (response && response.error) {
        await chrome.storage.session.set({ model_error: "Offscreen error: " + response.error });
      } else if (response && typeof response.score === 'number') {
        await chrome.storage.session.remove('model_error');
        rawScore = response.score;
        modelWorked = true;
      }
    } catch (err) {
      await chrome.storage.session.set({ model_error: String(err) });
    }
  }

  if (!modelWorked) {
    rawScore = heuristicScore(url);
  }

  let finalScore = rawScore;
  const parsed = parseUrl(url);
  const isOfficialBrand = isOfficialBrandDomain(parsed.registeredDomain) && v.tld_risk_score === 0;

  if (!isOfficialBrand) {
    // Boost score for critical phishing indicators that ML models often undervalue due to feature sparsity
    if (v.brand_in_registered_domain === 1) finalScore += 0.45;
    if (v.brand_in_subdomain === 1) finalScore += 0.40;
    if (v.lookalike_char_detected === 1) finalScore += 0.25;
    if (v.is_ip_address === 1) finalScore += 0.30;
    
    // Massive paths with high entropy are often Base64 encoded phishing payloads
    if (v.path_length > 100 && v.url_entropy > 4.5) {
      finalScore += 0.35;
    }

    if (v.suspicious_keyword_count > 0 && (v.brand_in_registered_domain === 1 || v.brand_in_subdomain === 1)) {
      finalScore += 0.20;
    }
  }
  
  finalScore = Math.min(Math.max(finalScore, 0), 1);
  return { score: finalScore, features };
}

function updateBadge(tabId: number, score: number): void {
  const color = score > 0.85 ? '#EF4444' : score > 0.5 ? '#F59E0B' : '#22C55E';
  const text = score > 0.5 ? Math.round(score * 100).toString() : 'OK';
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}

chrome.webNavigation.onCommitted.addListener(async ({ tabId, url }) => {
  if (!url || !url.startsWith('http')) {
    return;
  }
  try {
    const { score, features } = await classify(url);
    await chrome.storage.session.set({
      [tabId]: { score, features, url, timestamp: Date.now() }
    });
    updateBadge(tabId, score);
    if (score > 0.85) {
      chrome.tabs.sendMessage(tabId, { type: 'PHISHING_WARNING', score }).catch(() => {});
    }
  } catch {
    chrome.action.setBadgeText({ text: '?', tabId });
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'SCORE_URL' && message.url) {
    classify(message.url)
      .then(({ score, features }) => {
        if (message.tabId) {
          chrome.storage.session.set({
            [message.tabId]: { score, features, url: message.url, timestamp: Date.now() }
          });
          updateBadge(message.tabId, score);
        }
        sendResponse({ score, features });
      })
      .catch(() => sendResponse(null));
    return true; 
  }
});

chrome.runtime.onInstalled.addListener(() => {
  setupOffscreenDocument().catch(() => {
    modelLoadFailed = true;
  });
});
