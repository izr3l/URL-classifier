import * as ort from 'onnxruntime-web';
import { extractFeatures } from '../utils/feature-extractor';

let session: ort.InferenceSession | null = null;
let modelLoadPromise: Promise<void> | null = null;

async function loadModel() {
  ort.env.wasm.wasmPaths = chrome.runtime.getURL('');
  ort.env.wasm.numThreads = 1;
  ort.env.wasm.proxy = false;

  session = await ort.InferenceSession.create(chrome.runtime.getURL('model/phishing-classifier.onnx'), {
    executionProviders: ['wasm']
  });
}

async function ensureModelLoaded() {
  if (session) return;
  if (!modelLoadPromise) {
    modelLoadPromise = loadModel();
  }
  await modelLoadPromise;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'OFFSCREEN_SCORE_URL') {
    (async () => {
      try {
        await ensureModelLoaded();
        const features = extractFeatures(message.url);
        const tensor = new ort.Tensor('float32', Float32Array.from(features), [1, features.length]);
        const results = await session!.run({ float_input: tensor });

        for (const name of Object.keys(results)) {
          const t = results[name];
          if (t.data instanceof Float32Array && t.data.length >= 2) {
            sendResponse({ score: t.data[1], features });
            return;
          }
        }
        sendResponse({ error: "Failed to parse ONNX output" });
      } catch (err) {
        sendResponse({ error: String(err) });
      }
    })();
    return true; // keep channel open
  }
});
