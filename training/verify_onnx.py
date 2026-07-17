from __future__ import annotations

from pathlib import Path

import numpy as np
import onnxruntime as rt

from feature_extractor import FEATURE_ORDER


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    model_path = project_root / "extension" / "model" / "phishing-classifier.onnx"

    sess = rt.InferenceSession(str(model_path))
    test_input = np.random.rand(1, len(FEATURE_ORDER)).astype(np.float32)
    result = sess.run(None, {"float_input": test_input})
    print(result)


if __name__ == "__main__":
    main()
