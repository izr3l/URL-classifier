import * as ort from 'onnxruntime-web';
import { extractFeatures, extractFeatureVector } from '../utils/feature-extractor';

let session: ort.InferenceSession | null = null;
let modelLoadFailed = false;

async function loadModel(): Promise<void> {
  ort.env.wasm.wasmPaths = chrome.runtime.getURL('');
  ort.env.wasm.numThreads = 1;
  ort.env.wasm.proxy = false;

  session = await ort.InferenceSession.create(
    chrome.runtime.getURL('model/phishing-classifier.onnx'),
    { executionProviders: ['wasm'] }
  );
}

/**
 * Heuristic scorer used when no trained ONNX model is available.
 * Uses the same 26 lexical features from the spec with manually tuned weights
 * derived from the feature importance breakdown in the spec.
 */
function heuristicScore(url: string): number {
  const v = extractFeatureVector(url);

  let score = 0;

  // --- High-weight signals (from spec feature importances) ---
  // Suspicious keyword count: max ~8 keywords, weight 0.19
  score += Math.min(v.suspicious_keyword_count / 3, 1) * 0.19;

  // URL entropy: typical legit ~3.5, phishing ~4.5+
  score += Math.min(Math.max(v.url_entropy - 3.5, 0) / 2, 1) * 0.15;

  // Hostname entropy: typical legit ~3.0, phishing ~4.0+
  score += Math.min(Math.max(v.hostname_entropy - 3.0, 0) / 2, 1) * 0.12;

  // IP as hostname: instant strong signal
  score += v.is_ip_address * 0.11;

  // Brand in subdomain: strong phishing signal
  score += v.brand_in_subdomain * 0.10;

  // Lookalike characters: e.g. paypa1.com
  score += v.lookalike_char_detected * 0.09;

  // Encoded URL in path: redirect embedding
  score += v.encoded_url_in_path * 0.08;

  // @ symbol in URL: very strong phishing signal
  score += v.at_symbol_present * 0.07;

  // Double slash in URL body
  score += v.double_slash_in_path * 0.05;

  // High-risk TLD
  score += v.tld_risk_score * 0.04;

  // --- Supplementary signals ---
  // No HTTPS is a weak signal
  score += (1 - v.https_present) * 0.04;

  // Very long URL (phishing URLs tend to be long)
  score += Math.min(Math.max(v.url_length - 60, 0) / 120, 1) * 0.03;

  // High subdomain depth
  score += Math.min(v.subdomain_depth / 4, 1) * 0.03;

  // Suspicious file extension
  score += v.file_extension_suspicious * 0.05;

  // High digit ratio
  score += Math.min(v.digit_ratio * 2, 1) * 0.02;

  return Math.min(Math.max(score, 0), 1);
}

async function classify(url: string): Promise<{ score: number; features: number[] }> {
  const features = extractFeatures(url);

  // If model loading previously failed or the model session is not set, use heuristic.
  if (modelLoadFailed) {
    return { score: heuristicScore(url), features };
  }

  // Try loading the ONNX model if not already loaded
  if (!session) {
    try {
      await loadModel();
    } catch {
      modelLoadFailed = true;
      return { score: heuristicScore(url), features };
    }
  }

  try {
    const tensor = new ort.Tensor('float32', Float32Array.from(features), [1, features.length]);
    const results = await session!.run({ float_input: tensor });

    const outputNames = Object.keys(results);
    for (const name of outputNames) {
      const tensor = results[name];
      if (tensor.data instanceof Float32Array && tensor.data.length >= 2) {
        return { score: tensor.data[1], features };
      }
    }
    // Fallback if we can't parse output
    return { score: heuristicScore(url), features };
  } catch {
    return { score: heuristicScore(url), features };
  }
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
      [tabId]: {
        score,
        features,
        url,
        timestamp: Date.now()
      }
    });

    updateBadge(tabId, score);

    if (score > 0.85) {
      chrome.tabs.sendMessage(tabId, { type: 'PHISHING_WARNING', score }).catch(() => {
        // Content script may not be ready yet; ignore.
      });
    }
  } catch {
    chrome.action.setBadgeText({ text: '?', tabId });
  }
});

// Handle on-demand scoring requests from the popup
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'SCORE_URL' && message.url) {
    classify(message.url)
      .then(({ score, features }) => {
        // Cache it so future popup opens are instant
        if (message.tabId) {
          chrome.storage.session.set({
            [message.tabId]: { score, features, url: message.url, timestamp: Date.now() }
          });
          updateBadge(message.tabId, score);
        }
        sendResponse({ score, features });
      })
      .catch(() => sendResponse(null));
    return true; // keep message channel open for async response
  }
});

// Warm up the model on install/reload
chrome.runtime.onInstalled.addListener(() => {
  loadModel().catch(() => {
    modelLoadFailed = true;
  });
});
