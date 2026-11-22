"""Scorers. Both return a raw anomaly score (higher = more anomalous); LevelMap turns it into 0..3.

ThresholdRule is the static-threshold BASELINE (the kind of rule Splunk/Kotlaba use); IForestScorer is
the benign-only unsupervised model. Scoring runs asynchronously, so the measured 12.9 ms single-row
IsolationForest latency (own throwaway benchmark) is off the KDC request path.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from .features import FEATURES, vector

DEFAULT_THRESHOLDS = {"fail_n": 10, "spray_users": 10, "svc_distinct": 15, "rc4_n": 10}


class ThresholdRule:
    name = "threshold_rule"

    def __init__(self, thresholds: dict | None = None):
        self.thr = dict(thresholds or DEFAULT_THRESHOLDS)

    def raw(self, feat: dict) -> float:
        return max(min(feat[k] / t, 1.0) for k, t in self.thr.items())

    def alert(self, feat: dict) -> bool:
        return self.raw(feat) >= 1.0


class IForestScorer:
    name = "isolation_forest"

    def __init__(self, n_estimators: int = 100, seed: int = 0):
        self.model = IsolationForest(n_estimators=n_estimators, random_state=seed)

    def fit(self, feats: list) -> "IForestScorer":
        self.model.fit(np.array([vector(f) for f in feats]))
        return self

    def raw(self, feat: dict) -> float:
        return float(-self.model.score_samples(np.array([vector(feat)]))[0])

    def raw_many(self, feats: list) -> np.ndarray:
        return -self.model.score_samples(np.array([vector(f) for f in feats]))


class LevelMap:
    """Cut-offs are quantiles of the BENIGN validation score distribution, so the share of benign events
    that get restricted is set by construction (alphas = target false-restriction rates for level 1,2,3)."""

    def __init__(self, cuts: tuple, n_calib: int = 0, alphas: tuple = ()):
        self.cuts, self.n_calib, self.alphas = cuts, n_calib, alphas

    @property
    def underpowered(self) -> list:
        """Alphas that fewer than 10 calibration samples can resolve (cut-off is then effectively the max)."""
        return [a for a in self.alphas if self.n_calib * a < 10]

    @classmethod
    def calibrate(cls, benign_raw, alphas=(0.01, 0.001, 0.0001)) -> "LevelMap":
        arr = np.asarray(benign_raw, dtype=float)
        cuts = [float(np.quantile(arr, 1.0 - a)) for a in alphas]
        for i in range(1, len(cuts)):          # keep cut-offs non-decreasing
            cuts[i] = max(cuts[i], cuts[i - 1])
        return cls(tuple(cuts), len(arr), tuple(alphas))

    def level(self, raw: float) -> int:
        return sum(1 for c in self.cuts if raw > c)
