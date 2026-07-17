import React from 'react';
import { createRoot } from 'react-dom/client';
import { FEATURE_ORDER } from '../utils/feature-extractor';

type StoredTabState = {
  score: number;
  features?: number[];
  url: string;
  timestamp: number;
};

type Signal = {
  title: string;
  value: number;
};

const FEATURE_LABELS: Record<string, string> = {
  suspicious_keyword_count: 'Suspicious keyword in path or query',
  url_entropy: 'High URL entropy',
  hostname_entropy: 'High domain entropy',
  is_ip_address: 'IP address used as hostname',
  brand_in_subdomain: 'Brand name found in subdomain',
  lookalike_char_detected: 'Lookalike characters detected',
  encoded_url_in_path: 'Encoded URL/redirect pattern found',
  at_symbol_present: '@ symbol present in URL',
  double_slash_in_path: 'Double slash sequence in URL body',
  tld_risk_score: 'High-risk top-level domain',
  file_extension_suspicious: 'Suspicious file extension (.exe, .zip, .php)',
  is_ip_address_missing_https: 'No HTTPS on a potentially risky domain',
};

const IMPORTANCE_HINT: Record<string, number> = {
  suspicious_keyword_count: 0.19,
  url_entropy: 0.15,
  hostname_entropy: 0.12,
  is_ip_address: 0.11,
  brand_in_subdomain: 0.1,
  lookalike_char_detected: 0.09,
  encoded_url_in_path: 0.08,
  at_symbol_present: 0.07,
  double_slash_in_path: 0.05,
  tld_risk_score: 0.04,
  file_extension_suspicious: 0.05,
};

function riskLabel(score: number): string {
  if (score > 0.85) return 'Likely Phishing';
  if (score >= 0.5) return 'Suspicious';
  return 'Low Risk';
}

function riskClass(score: number): 'low' | 'mid' | 'high' {
  if (score > 0.85) return 'high';
  if (score >= 0.5) return 'mid';
  return 'low';
}

function buildSignals(features: number[]): Signal[] {
  return FEATURE_ORDER.map((name, index) => {
    const value = features[index] ?? 0;
    const weight = IMPORTANCE_HINT[name] ?? 0;
    return { key: name, title: FEATURE_LABELS[name] ?? name, score: Math.abs(value) * weight, value };
  })
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5)
    .map((entry) => ({ title: entry.title, value: entry.value }));
}

function Popup(): React.JSX.Element {
  const [tabState, setTabState] = React.useState<StoredTabState | null>(null);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      const tabId = tab?.id;
      const tabUrl = tab?.url;

      if (!tabId || !tabUrl || !tabUrl.startsWith('http')) {
        setLoading(false);
        return;
      }

      // First check if we already have a cached score for this tab
      chrome.storage.session.get([String(tabId)], (items) => {
        const cached = items[String(tabId)] as StoredTabState | undefined;
        if (cached) {
          setTabState(cached);
          setLoading(false);
        } else {
          // No score yet — ask the service worker to score the URL now
          chrome.runtime.sendMessage({ type: 'SCORE_URL', tabId, url: tabUrl }, (response) => {
            if (chrome.runtime.lastError) {
              // Service worker may not be ready, just stop loading
              setLoading(false);
              return;
            }
            if (response && typeof response.score === 'number') {
              setTabState({ score: response.score, features: response.features, url: tabUrl, timestamp: Date.now() });
            }
            setLoading(false);
          });
        }
      });
    });
  }, []);

  if (loading) {
    return (
      <div className="popup">
        <p className="label">Scanning…</p>
        <div className="url">Analysing the current URL, please wait.</div>
      </div>
    );
  }

  if (!tabState) {
    return (
      <div className="popup">
        <p className="label">Not applicable</p>
        <div className="url">Open a regular http/https webpage to get a risk score.</div>
      </div>
    );
  }

  const scorePercent = Math.round(tabState.score * 100);
  const signals = buildSignals(tabState.features ?? []);

  return (
    <div className="popup">
      <div className="header">
        <div className={`score-ring ${riskClass(tabState.score)}`}>{scorePercent}</div>
        <div>
          <p className="label">{riskLabel(tabState.score)}</p>
          <div className="url">{tabState.url}</div>
        </div>
      </div>

      <section className="section">
        <h3>Feature Breakdown</h3>
        <ul className="list">
          {signals.length === 0 ? <li>No strong risk signals detected.</li> : null}
          {signals.map((signal) => (
            <li key={signal.title}>{signal.title}</li>
          ))}
        </ul>
      </section>

      <section className="section actions">
        <a
          className="button"
          href="https://github.com/example/phishing-url-shield/issues/new?title=False%20Positive"
          target="_blank"
          rel="noreferrer"
        >
          Report false positive
        </a>
        <a
          className="button"
          href="https://github.com/example/phishing-url-shield/issues/new?title=False%20Negative"
          target="_blank"
          rel="noreferrer"
        >
          Report false negative
        </a>
        <div className="privacy">
          <a href="https://example.com/privacy" target="_blank" rel="noreferrer">
            Privacy policy: all inference runs locally in your browser
          </a>
        </div>
      </section>
    </div>
  );
}

const rootElement = document.getElementById('root');
if (rootElement) {
  createRoot(rootElement).render(<Popup />);
}
