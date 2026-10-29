"""Predict a CVE's weakness type (CWE) and CVSS attack vector from its description.

For CVEs NVD hasn't analysed yet. Trained on NVD records that do have both, tested on the newest ones.
"""

import json
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import date

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier

TOP_CWES = 50
VECTOR_NAMES = {"NETWORK": "network", "ADJACENT_NETWORK": "adjacent", "LOCAL": "local", "PHYSICAL": "physical"}


def labels(rec: dict) -> tuple[str | None, str | None]:
    """The CWE and attack vector a record is labelled with, preferring NVD's analysis over the issuer's."""
    cwes = rec["cwe_nvd"] or rec["cwe_cna"]
    cvss = rec["cvss_nvd"] or rec["cvss_cna"]
    return (cwes[0] if cwes else None), (cvss or {}).get("attackVector")


class Head:
    """One prediction target (CWE or attack vector): a linear classifier over the shared text features."""

    def __init__(self):
        self.clf = SGDClassifier(loss="log_loss", alpha=2e-6, max_iter=20, tol=1e-3, random_state=0)

    def fit(self, X, y: list[str]) -> "Head":
        self.clf.fit(X, y)
        return self

    def top(self, X, k: int = 3) -> list[list[tuple[str, float]]]:
        probs = self.clf.predict_proba(X)
        order = np.argsort(-probs, axis=1)[:, :k]
        return [[(self.clf.classes_[j], float(probs[i, j])) for j in row] for i, row in enumerate(order)]

    def words(self, x_row, label: str, names: np.ndarray, k: int = 4) -> list[str]:
        idx = list(self.clf.classes_).index(label)
        coef = self.clf.coef_[idx] if self.clf.coef_.shape[0] > 1 else self.clf.coef_[0] * (1 if idx else -1)
        contrib = x_row.multiply(coef).tocsr()
        pairs = sorted(zip(contrib.indices, contrib.data), key=lambda p: -p[1])
        return [names[i] for i, v in pairs if v > 0][:k]


class DescriptionClassifier:
    def __init__(self, min_df: int = 5):
        self.tfidf = TfidfVectorizer(ngram_range=(1, 2), min_df=min_df, max_features=100000, sublinear_tf=True,
                                     stop_words="english")
        self.cwe = Head()
        self.vector = Head()

    def fit(self, records: list[dict]) -> "DescriptionClassifier":
        with_cwe = [(r, c) for r in records for c, _ in [labels(r)] if c]
        common = {c for c, _ in Counter(c for _, c in with_cwe).most_common(TOP_CWES)}
        self.cwes = sorted(common)
        X_all = self.tfidf.fit_transform([r["description"] for r in records])
        self.names = self.tfidf.get_feature_names_out()
        index = {r["cve"]: i for i, r in enumerate(records)}
        cwe_rows = [index[r["cve"]] for r, _ in with_cwe]
        self.cwe.fit(X_all[cwe_rows], [c if c in common else "other" for _, c in with_cwe])
        av = [(index[r["cve"]], v) for r in records for _, v in [labels(r)] if v]
        self.vector.fit(X_all[[i for i, _ in av]], [v for _, v in av])
        self.trained_on = len(records)
        return self

    def predict(self, descriptions: list[str]) -> list[dict]:
        X = self.tfidf.transform(descriptions)
        out = []
        for i, (cwes, vectors) in enumerate(zip(self.cwe.top(X), self.vector.top(X, k=1))):
            cwe, cwe_p = cwes[0]
            vector, vector_p = vectors[0]
            out.append({
                "cwe": cwe, "cwe_confidence": cwe_p, "cwe_alternatives": cwes[1:],
                "attack_vector": vector, "vector_confidence": vector_p,
                "cwe_words": self.cwe.words(X[i], cwe, self.names),
                "vector_words": self.vector.words(X[i], vector, self.names),
            })
        return out


def explain(p: dict) -> str:
    cwe = "an uncommon weakness type (not in the top 50)" if p["cwe"] == "other" else p["cwe"]
    alts = ", ".join(f"{c} {q:.0%}" for c, q in p["cwe_alternatives"])
    cwe_why = f' because the description mentions {", ".join(repr(w) for w in p["cwe_words"])}' if p["cwe_words"] else ""
    vec_why = f' ({", ".join(repr(w) for w in p["vector_words"])})' if p["vector_words"] else ""
    return (f"Predicted {cwe} ({p['cwe_confidence']:.0%}){cwe_why}; next most likely: {alts or 'none'}. "
            f"Attack vector predicted {VECTOR_NAMES.get(p['attack_vector'], p['attack_vector'])} "
            f"({p['vector_confidence']:.0%}){vec_why}.")


@dataclass
class Evaluation:
    cutoff: date
    train_size: int
    test_cwe: int
    test_vector: int
    cwe_top1: float
    cwe_top3: float
    cwe_baseline: tuple[str, float]
    vector_acc: float
    vector_baseline: tuple[str, float]
    vector_recall: dict[str, tuple[float, int]]

    def report(self) -> str:
        lines = [
            f"Trained on {self.train_size:,} CVEs published before {self.cutoff}; tested on those published since.",
            f"CWE ({self.test_cwe:,} test CVEs with a CWE):",
            f"  right first guess {self.cwe_top1:.1%}, right within the top 3 {self.cwe_top3:.1%}",
            f"  for comparison, always guessing {self.cwe_baseline[0]} is right {self.cwe_baseline[1]:.1%} of the time",
            f"Attack vector ({self.test_vector:,} test CVEs with a CVSS vector):",
            f"  right {self.vector_acc:.1%}; always guessing {VECTOR_NAMES.get(self.vector_baseline[0])} is right "
            f"{self.vector_baseline[1]:.1%}",
        ]
        for vector, (recall, n) in sorted(self.vector_recall.items(), key=lambda kv: -kv[1][1]):
            lines.append(f"    {VECTOR_NAMES.get(vector, vector):<9} {recall:.1%} of {n:,} found")
        lines.append("CWE labels in NVD are inconsistent (CWE-20 and similar broad types are often used where a "
                     "narrower one fits), so a 'wrong' first guess is sometimes a defensible one; the top-3 figure "
                     "is the more useful number.")
        return "\n".join(lines)


def evaluate(records: list[dict], cutoff: date, min_df: int = 5) -> Evaluation:
    cut = cutoff.isoformat()
    train = [r for r in records if r["published"] < cut]
    test = [r for r in records if r["published"] >= cut]
    model = DescriptionClassifier(min_df=min_df).fit(train)
    X = model.tfidf.transform([r["description"] for r in test])

    cwe_idx = [i for i, r in enumerate(test) if labels(r)[0]]
    truth = [labels(test[i])[0] if labels(test[i])[0] in model.cwes else "other" for i in cwe_idx]
    tops = model.cwe.top(X[cwe_idx])
    top1 = np.mean([t[0][0] == y for t, y in zip(tops, truth)])
    top3 = np.mean([y in [c for c, _ in t] for t, y in zip(tops, truth)])
    common_train = Counter(labels(r)[0] for r in train if labels(r)[0]).most_common(1)[0][0]

    av_idx = [i for i, r in enumerate(test) if labels(r)[1]]
    av_truth = [labels(test[i])[1] for i in av_idx]
    av_pred = [t[0][0] for t in model.vector.top(X[av_idx], k=1)]
    common_av = Counter(labels(r)[1] for r in train if labels(r)[1]).most_common(1)[0][0]
    recall = {}
    for vector in set(av_truth):
        hits = [p == vector for p, y in zip(av_pred, av_truth) if y == vector]
        recall[vector] = (float(np.mean(hits)), len(hits))
    return Evaluation(
        cutoff=cutoff, train_size=len(train), test_cwe=len(cwe_idx), test_vector=len(av_idx),
        cwe_top1=float(top1), cwe_top3=float(top3),
        cwe_baseline=(common_train, float(np.mean([y == common_train for y in truth]))),
        vector_acc=float(np.mean([p == y for p, y in zip(av_pred, av_truth)])),
        vector_baseline=(common_av, float(np.mean([y == common_av for y in av_truth]))),
        vector_recall=recall,
    )


def needs_prediction(conn: sqlite3.Connection) -> list[tuple[str, str | None]]:
    """Your CVEs that NVD hasn't given a CWE or attack vector, with whatever description is stored."""
    return [(r["cve"], r["description"]) for r in conn.execute(
        """SELECT DISTINCT fc.cve, c.description FROM finding_cves fc LEFT JOIN cves c ON c.cve = fc.cve
           WHERE c.cve IS NULL OR c.cwes IS NULL OR c.attack_vector IS NULL
              OR c.nvd_status IN ('Received', 'Awaiting Analysis', 'Undergoing Analysis', 'Deferred')
           ORDER BY fc.cve""")]


def predict_mine(conn: sqlite3.Connection, model: DescriptionClassifier, trained_at: str, now: str,
                 records: dict[str, dict]) -> tuple[list[dict], list[str]]:
    todo, missing = [], []
    for cve, description in needs_prediction(conn):
        text = description or (records.get(cve) or {}).get("description")
        (todo if text else missing).append((cve, text) if text else cve)
    preds = model.predict([t for _, t in todo]) if todo else []
    rows = [{"cve": cve, **p, "explanation": explain(p)} for (cve, _), p in zip(todo, preds)]
    with conn:
        conn.execute("DELETE FROM cve_predictions")
        conn.executemany(
            """INSERT INTO cve_predictions (cve, cwe, cwe_confidence, cwe_alternatives, attack_vector,
                                            vector_confidence, explanation, model_trained, predicted_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(r["cve"], r["cwe"], r["cwe_confidence"], json.dumps(r["cwe_alternatives"]), r["attack_vector"],
              r["vector_confidence"], r["explanation"], trained_at, now) for r in rows])
    return rows, missing
