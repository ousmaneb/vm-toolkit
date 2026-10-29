"""Mark findings as false positives (or confirmed real) and flag open findings that look like past false positives.

With few marks a similarity rule is used: same scanner rule as findings you marked, plus how alike
the scanner output is. With enough marks (see MODEL_MIN_FP) a logistic regression is trained instead.
Fixed findings count as weak "real" examples (half weight): they went away when patched, which
usually means they were real, but not always.
"""

import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher

from .config import Settings
from .db import utcnow

MODEL_MIN_FP = 30
FIXED_WEIGHT = 0.5


@dataclass
class Prediction:
    finding_id: int
    machine: str
    title: str
    probability: float
    method: str
    reason: str


def mark(conn: sqlite3.Connection, ids: list[int], real: bool, reason: str | None) -> list[str]:
    label = "real" if real else "false_positive"
    lines = []
    for fid in ids:
        row = conn.execute("SELECT f.id, f.title, a.name FROM findings f JOIN assets a ON a.id = f.asset_id "
                           "WHERE f.id = ?", (fid,)).fetchone()
        if row is None:
            lines.append(f"Finding {fid} doesn't exist.")
            continue
        conn.execute(
            """INSERT INTO fp_labels (finding_id, label, reason, labeled_at) VALUES (?, ?, ?, ?)
               ON CONFLICT(finding_id) DO UPDATE SET label = excluded.label, reason = excluded.reason,
                   labeled_at = excluded.labeled_at""",
            (fid, label, reason, utcnow()))
        lines.append(f"Finding {fid} ({row['title']} on {row['name']}) marked {label.replace('_', ' ')}.")
    conn.commit()
    return lines


def unmark(conn: sqlite3.Connection, ids: list[int]) -> list[str]:
    lines = []
    for fid in ids:
        cur = conn.execute("DELETE FROM fp_labels WHERE finding_id = ?", (fid,))
        lines.append(f"Finding {fid}: " + ("mark removed." if cur.rowcount else "had no mark."))
    conn.commit()
    return lines


def _rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT f.*, a.name AS machine, l.label,
                  (SELECT max(sh.credentialed) FROM observations o JOIN scans s ON s.id = o.scan_id
                   JOIN scan_hosts sh ON sh.scan_id = s.id AND sh.asset_id = f.asset_id
                   WHERE o.finding_id = f.id) AS credentialed
           FROM findings f JOIN assets a ON a.id = f.asset_id LEFT JOIN fp_labels l ON l.finding_id = f.id
           WHERE f.severity != 'info'"""
    ).fetchall()


def training_set(rows: list[sqlite3.Row]) -> tuple[list[sqlite3.Row], list[int], list[float]]:
    examples, labels, weights = [], [], []
    for r in rows:
        if r["label"]:
            examples.append(r)
            labels.append(1 if r["label"] == "false_positive" else 0)
            weights.append(1.0)
        elif r["status"] == "fixed":
            examples.append(r)
            labels.append(0)
            weights.append(FIXED_WEIGHT)
    return examples, labels, weights


def _alike(a: str | None, b: str | None) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:500], b[:500]).ratio()


def predict_similarity(rows: list[sqlite3.Row]) -> list[Prediction]:
    by_rule: dict[tuple, list[sqlite3.Row]] = defaultdict(list)
    for r in rows:
        if r["label"] or r["status"] == "fixed":
            by_rule[(r["scanner"], r["rule_id"])].append(r)
    out = []
    for r in rows:
        if r["label"] or r["status"] != "open":
            continue
        labelled = by_rule.get((r["scanner"], r["rule_id"]), [])
        fps = [x for x in labelled if x["label"] == "false_positive"]
        if not fps:
            continue
        fp_ids = {x["id"] for x in fps}
        real_w = sum(1.0 if x["label"] == "real" else FIXED_WEIGHT for x in labelled if x["id"] not in fp_ids)
        # Laplace-style smoothing so one mark doesn't mean certainty.
        prob = (len(fps) + 0.5) / (len(fps) + real_w + 1.0)
        closest = max(fps, key=lambda x: _alike(r["evidence"], x["evidence"]))
        alike = _alike(r["evidence"], closest["evidence"])
        alike_real = max((_alike(r["evidence"], x["evidence"]) for x in labelled if x["id"] not in fp_ids), default=0.0)
        # Output that matches a marked false positive better than any real one is extra evidence.
        if alike >= 0.8 and alike > alike_real:
            prob = min(0.99, prob + 0.1)
        machines = ", ".join(sorted({x["machine"] for x in fps})[:3])
        reason = (f"You marked {len(fps)} finding(s) from the same {r['scanner']} rule {r['rule_id']} as false "
                  f"positives (on {machines})")
        reason += f" and {real_w:g} as real or fixed" if real_w else " and none as real or fixed"
        if r["evidence"] and closest["evidence"]:
            reason += f"; its scanner output is {alike:.0%} alike to finding {closest['id']}'s"
        out.append(Prediction(r["id"], r["machine"], r["title"], round(prob, 3), "similarity", reason + "."))
    return out


def _features(r: sqlite3.Row) -> tuple[dict, str]:
    cats = {f"scanner={r['scanner']}": 1.0, f"rule={r['scanner']}:{r['rule_id']}": 1.0,
            f"severity={r['severity']}": 1.0, f"port={r['port']}/{r['protocol']}": 1.0,
            "credentialed=yes" if r["credentialed"] else "credentialed=no": 1.0}
    return cats, f"{r['title']} {r['evidence'] or ''}"


def _describe(name: str) -> str:
    if name.startswith("word:"):
        return f'title or output mentions "{name[5:]}"'
    key, _, value = name.partition("=")
    return {"rule": f"scanner rule {value}", "scanner": f"found by {value}", "severity": f"severity {value}",
            "port": f"port {value}", "credentialed": "credentialed scan" if value == "yes" else "uncredentialed scan"
            }.get(key, name)


def predict_model(rows: list[sqlite3.Row]) -> tuple[list[Prediction], str]:
    import numpy as np
    from scipy.sparse import hstack
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score, precision_score, recall_score
    from sklearn.model_selection import StratifiedKFold

    examples, labels, weights = training_set(rows)
    y, w = np.array(labels), np.array(weights)

    def matrix(rs, dv, tf, fit=False):
        cats, texts = zip(*(_features(r) for r in rs))
        if fit:
            return hstack([dv.fit_transform(cats), tf.fit_transform(texts)]).tocsr()
        return hstack([dv.transform(cats), tf.transform(texts)]).tocsr()

    def fit(rs, ys, ws):
        dv, tf = DictVectorizer(), TfidfVectorizer(min_df=2, max_features=5000, sublinear_tf=True)
        clf = LogisticRegression(max_iter=2000, class_weight="balanced")
        clf.fit(matrix(rs, dv, tf, fit=True), ys, sample_weight=ws)
        return dv, tf, clf

    # Cross-validation on explicit marks only: fixed findings are weak labels and would flatter the score.
    folds = StratifiedKFold(n_splits=min(5, int(y.sum())), shuffle=True, random_state=0)
    explicit = np.array([bool(r["label"]) for r in examples])
    truth, scores = [], []
    for train_idx, test_idx in folds.split(np.zeros(len(y)), y):
        dv, tf, clf = fit([examples[i] for i in train_idx], y[train_idx], w[train_idx])
        test_idx = [i for i in test_idx if explicit[i]]
        if test_idx:
            scores += list(clf.predict_proba(matrix([examples[i] for i in test_idx], dv, tf))[:, 1])
            truth += list(y[test_idx])
    truth, scores = np.array(truth), np.array(scores)
    n_fp = int(y[explicit].sum())
    quality = (f"Cross-validated on your {int(explicit.sum())} explicit marks ({n_fp} false positives): "
               f"precision {precision_score(truth, scores >= 0.5, zero_division=0):.0%}, "
               f"recall {recall_score(truth, scores >= 0.5, zero_division=0):.0%}, "
               f"average precision {average_precision_score(truth, scores):.2f}.")
    if n_fp < 100:
        quality += f" With only {n_fp} false-positive marks these numbers can swing a lot."

    dv, tf, clf = fit(examples, y, w)
    names = list(dv.get_feature_names_out()) + [f"word:{t}" for t in tf.get_feature_names_out()]
    candidates = [r for r in rows if not r["label"] and r["status"] == "open"]
    out = []
    if candidates:
        X = matrix(candidates, dv, tf)
        probs = clf.predict_proba(X)[:, 1]
        for i, (r, p) in enumerate(zip(candidates, probs)):
            contrib = X[i].multiply(clf.coef_[0]).tocsr()
            top = sorted(zip(contrib.indices, contrib.data), key=lambda t: -t[1])
            ups = [_describe(names[j]) for j, v in top if v > 0][:3]
            out.append(Prediction(r["id"], r["machine"], r["title"], round(float(p), 3), "model",
                                  f"Pushed toward false positive by: {', '.join(ups) or 'nothing notable'}."))
    return out, quality


def predict(conn: sqlite3.Connection, settings: Settings) -> tuple[list[Prediction], str]:
    rows = _rows(conn)
    n_fp = sum(1 for r in rows if r["label"] == "false_positive")
    if n_fp == 0:
        return [], "No findings are marked as false positives yet. Use `vmt fp mark <id>` first."
    if n_fp < MODEL_MIN_FP:
        preds = predict_similarity(rows)
        note = (f"{n_fp} false-positive marks so far (a model needs {MODEL_MIN_FP}), so findings are compared "
                "with the ones you marked by scanner rule and output.")
    else:
        preds, note = predict_model(rows)
    threshold = float(settings.section("fp").get("threshold", 0.5))
    flagged = sorted((p for p in preds if p.probability > threshold), key=lambda p: -p.probability)
    now = utcnow()
    with conn:
        conn.execute("DELETE FROM fp_predictions")
        conn.executemany(
            "INSERT INTO fp_predictions (finding_id, probability, method, reason, predicted_at) VALUES (?, ?, ?, ?, ?)",
            [(p.finding_id, p.probability, p.method, p.reason, now) for p in flagged])
    return flagged, note + f" Flagging open findings above {threshold:.0%}; nothing is hidden automatically."
