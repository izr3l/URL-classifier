from __future__ import annotations

import json
from pathlib import Path

import joblib
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from skl2onnx import update_registered_converter
from xgboost import XGBClassifier

try:
    from onnxmltools.convert.xgboost.operator_converters.XGBoost import convert_xgboost
    from onnxmltools.convert.xgboost.shape_calculators.Classifier import (
        calculate_xgboost_classifier_output_shapes,
    )
except ImportError as exc:  # pragma: no cover - dependency issue is surfaced at runtime.
    raise ImportError(
        "onnxmltools is required to export the trained XGBoost pipeline to ONNX."
    ) from exc

from feature_extractor import FEATURE_ORDER


def _register_xgboost_converter() -> None:
    update_registered_converter(
        XGBClassifier,
        "XGBoostXGBClassifier",
        calculate_xgboost_classifier_output_shapes,
        convert_xgboost,
        options={"zipmap": [True, False], "nocl": [True, False]},
    )


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    artifacts_dir = project_root / "artifacts"
    extension_model_dir = project_root / "extension" / "model"
    extension_model_dir.mkdir(parents=True, exist_ok=True)

    pipeline = joblib.load(artifacts_dir / "model.joblib")
    _register_xgboost_converter()
    initial_type = [("float_input", FloatTensorType([None, len(FEATURE_ORDER)]))]

    options = {}
    model = getattr(pipeline, "named_steps", {}).get("model")
    if model is not None:
        options = {id(model): {"zipmap": False}}

    onnx_model = convert_sklearn(
        pipeline,
        initial_types=initial_type,
        options=options,
    )

    output_path = extension_model_dir / "phishing-classifier.onnx"
    with output_path.open("wb") as f:
        f.write(onnx_model.SerializeToString())

    metadata_path = artifacts_dir / "onnx_export.json"
    metadata = {
        "output_path": str(output_path),
        "feature_count": len(FEATURE_ORDER),
        "model_type": type(pipeline.named_steps["model"]).__name__
        if hasattr(pipeline, "named_steps") and "model" in pipeline.named_steps
        else type(pipeline).__name__,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Exported ONNX model to {output_path}")


if __name__ == "__main__":
    main()
