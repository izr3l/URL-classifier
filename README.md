# URL Classifier (Privacy-First Phishing Detection)

A locally-executed, privacy-first phishing URL detection system built as a Chrome browser extension. 

Unlike traditional cloud-based web filters, **no URL ever leaves your device**. A machine learning model (XGBoost exported to ONNX), trained on lexical URL features, runs entirely in your browser using the ONNX Runtime Web engine. If a model hasn't been trained yet, it intelligently falls back to a weighted heuristic scanner using the same feature extraction logic.

## Features

- **Tier-1 Local Inference:** All features are derived from the URL string itself. No network requests are made during inference.
- **Privacy-First:** Your browsing history and active URLs remain strictly on your machine.
- **Dynamic Badge Updates:** The extension icon updates dynamically (Green/Amber/Red) with a risk score as you browse.
- **Heuristic Fallback:** If the trained machine learning model is missing or fails to load, it automatically falls back to a hand-tuned heuristic engine.
- **Explainability:** Click the extension badge to see a breakdown of the specific features that contributed to the URL's risk score (e.g., "High domain entropy", "Suspicious file extension").

## Tech Stack

- **Extension:** Chrome Manifest V3, TypeScript, React, esbuild
- **Inference Engine:** ONNX Runtime Web (WebAssembly)
- **Model Training:** Python, scikit-learn, XGBoost, pandas
- **Model Format:** ONNX (`skl2onnx`)

## Project Structure

```
├── .github/workflows/   # Automated retraining CI/CD pipelines
├── data/                # Dataset storage (PhishTank & Tranco) - Ignored in Git
├── extension/           # Browser extension source code
│   ├── background/      # Service worker & ONNX runtime integration
│   ├── content/         # Warning overlay injection logic
│   ├── popup/           # React UI for risk score display
│   ├── utils/           # Lexical feature extractor (TypeScript)
│   └── model/           # Exported ONNX model
└── training/            # Python ML pipeline
    ├── pull_data.py     # Script to automate downloading PhishTank & Tranco datasets
    ├── dataset.py       # Data parsing and labeling
    ├── train.py         # XGBoost model training and evaluation
    └── export_onnx.py   # Exports the trained XGBoost model to .onnx format
```

## Getting Started

### 1. Build the Browser Extension

You will need [Node.js](https://nodejs.org/) installed to build the extension.

```bash
cd extension
npm install
npm run build
```

This will bundle the React popup, background service worker, and content scripts into their respective JavaScript files, and automatically pull the required WebAssembly engine files from the ONNX runtime.

### 2. Load the Extension in Chrome

1. Open Google Chrome and navigate to `chrome://extensions`.
2. Toggle on **Developer mode** in the top right corner.
3. Click **Load unpacked** in the top left corner.
4. Select the `extension` folder located inside this repository.

The extension is now active. As you navigate the web, the URL Classifier badge will update with a live risk score.

### 3. (Optional) Train the Machine Learning Model

The extension works out of the box using a heuristic engine. If you want to train the actual ML model using live phishing data:

You will need [Python 3.10+](https://www.python.org/) installed.

```bash
cd training
pip install -r requirements.txt

# 1. Download the latest datasets from PhishTank and Tranco Top 1M
python pull_data.py

# 2. Train the XGBoost model
python train.py

# 3. Export the model to the extension folder
python export_onnx.py
```

Once exported, run `npm run build` inside the `extension` folder again, and reload the extension in Chrome. The service worker will now use the trained ONNX model for inference.
