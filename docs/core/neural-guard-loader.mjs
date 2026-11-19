/**
 * Browser-local neural guard adapter for Colab-distilled Transformers.js / ONNX models
 * (`yakki-ad-guard-ja` & `kurogate-context-guard-ja`).
 * Zero network calls are initiated by default; users load local exported model bundles or
 * fuse calibrated neural probabilities with KUROGATE's deterministic regex/check-digit rules.
 */

export function parseDistilledModelManifest(configJson) {
  if (!configJson || typeof configJson !== "object") {
    throw new Error("Invalid model config.json object.");
  }
  const id2label = configJson.id2label;
  if (!id2label || typeof id2label !== "object" || Object.keys(id2label).length === 0) {
    throw new Error("Model config.json must define a non-empty id2label map.");
  }
  const labels = Object.keys(id2label)
    .sort((a, b) => Number(a) - Number(b))
    .map((key) => String(id2label[key]));

  return {
    architecture: Array.isArray(configJson.architectures) ? configJson.architectures[0] : "sequence-classifier",
    numLabels: labels.length,
    labels,
    onnxRelativePath: "onnx/model_quantized.onnx",
  };
}

export function softmaxLogits(logits) {
  if (!Array.isArray(logits) || logits.length === 0) {
    throw new Error("Logits array must be non-empty.");
  }
  const maxVal = Math.max(...logits);
  const exps = logits.map((v) => Math.exp(v - maxVal));
  const sumExp = exps.reduce((acc, v) => acc + v, 0);
  return exps.map((v) => v / sumExp);
}

export function fuseRuleAndNeuralScore({
  ruleRiskScore = 0,
  neuralProbs = [],
  labels = [],
  safeLabel = "safe_business",
  neuralWeight = 0.65,
} = {}) {
  const clampedRule = Math.max(0, Math.min(1, Number(ruleRiskScore) || 0));
  if (!Array.isArray(neuralProbs) || neuralProbs.length === 0) {
    return {
      combinedRisk: Number(clampedRule.toFixed(4)),
      predictedLabel: clampedRule >= 0.5 ? "rule_flagged" : safeLabel,
      neuralRisk: 0,
    };
  }

  let bestIdx = 0;
  for (let i = 1; i < neuralProbs.length; i += 1) {
    if (neuralProbs[i] > neuralProbs[bestIdx]) {
      bestIdx = i;
    }
  }
  const predictedLabel = labels[bestIdx] ?? `class_${bestIdx}`;
  const safeIdx = labels.indexOf(safeLabel);
  const neuralRisk =
    safeIdx >= 0
      ? Math.max(0, Math.min(1, 1 - Number(neuralProbs[safeIdx] || 0)))
      : Math.max(0, Math.min(1, 1 - Number(neuralProbs[0] || 0)));

  const combined = Math.max(
    clampedRule,
    (1 - neuralWeight) * clampedRule + neuralWeight * neuralRisk,
  );

  return {
    combinedRisk: Number(Math.min(1, combined).toFixed(4)),
    predictedLabel,
    neuralRisk: Number(neuralRisk.toFixed(4)),
  };
}
