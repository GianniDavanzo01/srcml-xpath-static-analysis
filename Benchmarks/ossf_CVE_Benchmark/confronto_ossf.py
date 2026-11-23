"""
confronto_ossf.py
Stampa: (1) matrice TP/FN/FP/TN totale con recall, precisione, specificita';
        (2) tabella per CWE con TP/FN/FP/TN.
Considera solo le CVE presenti nel report. Richiede confronto_ossf_JS_v2.py nella stessa cartella.

  TP = vulnerabilita' segnalata nel file PRIMA della patch
  FN = non segnalata prima della patch
  FP = segnalata nel file DOPO la patch (file corretto)
  TN = non segnalata dopo la patch

Uso:
  python confronto_ossf.py --report report_ossf_js.json --manifest manifest_js.json [--tol 5]
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path
import re
import difflib


CWE_EQUIVALENCES = {
    "CWE-22":   {"CWE-23", "CWE-36", "CWE-73"},
    "CWE-78":   {"CWE-77", "CWE-88"},
    "CWE-79":   {"CWE-80"},
    "CWE-94":   {"CWE-95"},
    "CWE-259":  {"CWE-798"},
    "CWE-328":  {"CWE-327", "CWE-916"},
    "CWE-338":  {"CWE-330"},
    "CWE-400":  {"CWE-730"},
    "CWE-1333": {"CWE-400", "CWE-730"},
}

def norm_cwe(val):
    m = re.search(r"CWE[-_]?0*(\d+)", str(val), re.IGNORECASE)
    return f"CWE-{int(m.group(1))}" if m else None


def parse_line(val):
    if val is None:
        return None
    m = re.match(r"(\d+)", str(val).strip())
    return int(m.group(1)) if m else None


def norm_path(p):
    p = str(p).replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p

def read_lines(src_root, rel):
    p = Path(src_root) / rel
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8", errors="replace").splitlines()

def map_pre_to_post(pre_lines, post_lines):
    """riga pre (1-based) -> (lo, hi) righe post corrispondenti."""
    sm = difflib.SequenceMatcher(None, pre_lines, post_lines, autojunk=False)
    m = {}
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                m[i1 + k + 1] = (j1 + k + 1, j1 + k + 1)
        elif tag in ("replace", "delete"):
            for i in range(i1, i2):
                m[i + 1] = (j1 + 1, max(j2, j1 + 1))
    return m

def lookup(by_file, path, log):
    """(presente, findings). Match esatto; suffisso solo se univoco."""
    p = norm_path(path)
    if p in by_file:
        return True, by_file[p]
    cands = [k for k in by_file if k.endswith("/" + p) or p.endswith("/" + k)]
    if len(cands) == 1:
        log.append(f"match per suffisso: {p} -> {cands[0]}")
        return True, by_file[cands[0]]
    if len(cands) > 1:
        log.append(f"AMBIGUO ({len(cands)} candidati) per {p}: ignorato")
    return False, []


def expand(cwes, use_eq):
    out = set(cwes)
    if use_eq:
        for c in cwes:
            out |= CWE_EQUIVALENCES.get(c, set())
    return out

def extract_entries(raw):
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for k in ("details", "results", "files", "analyses", "report", "items", "data"):
            if isinstance(raw.get(k), list):
                return raw[k]
    return []

def load_report(report_path):
    files = sorted(report_path.rglob("*.json")) if report_path.is_dir() else [report_path]
    by_file = defaultdict(list)
    for jf in files:
        raw = json.loads(jf.read_text(encoding="utf-8"))
        for entry in extract_entries(raw):
            sf = norm_path(entry.get("source_file") or "")
            if not sf:
                continue
            for f in entry.get("findings") or []:
                cwes = {norm_cwe(v) for v in (f.get("vulnerabilities") or []) if norm_cwe(v)}
                by_file[sf].append({
                    "cwes": cwes,
                    "line": parse_line(f.get("line")),
                    "snippet": f.get("snippet", ""),
                    "rule_id": f.get("rule_id", ""),
                })
            by_file.setdefault(sf, by_file[sf])           # registra anche file senza finding
    return dict(by_file)



def ratio(num, den):
    return f"{num / den * 100:.1f}%" if den else "n/d"


def evaluate_cve(item, by_file, cfg, log):
    expected = expand({norm_cwe(c) for c in item["cwes"] if norm_cwe(c)}, False)
    tol, use_eq = cfg["tol"], cfg["eq"]

    def relevant(findings):
        return [f for f in findings if expand(f["cwes"], use_eq) & expected]

    res = {"cve": item["cve"], "primary": norm_cwe(item.get("primary_cwe") or item["cwes"][0]),
           "present": False, "pre_hit": False, "post_file": False, "post_line": None,
           "same_snippet": False, "line_checked": True, "n_pre": 0, "n_post": 0}

    pairs = []
    for fp in item["files"]:
        ok_pre, pre_f = lookup(by_file, fp["pre_path"], log)
        ok_post, post_f = lookup(by_file, fp["post_path"], log)
        if ok_pre and ok_post:
            pairs.append((fp, pre_f, post_f))
    if not pairs:
        return res
    res["present"] = True

    line_ok_all = True
    for fp, pre_f, post_f in pairs:
        targets = fp.get("lines") or []
        rel_pre, rel_post = relevant(pre_f), relevant(post_f)
        res["n_pre"] += len(rel_pre)
        res["n_post"] += len(rel_post)

        # --- PRE: CWE + riga ---
        matched_pre = []
        for f in rel_pre:
            if tol is None or not targets:
                matched_pre.append(f)
                if tol is not None:
                    res["line_checked"] = False      # tolleranza dichiarata ma non applicabile
            elif f["line"] is None:
                matched_pre.append(f)
                res["line_checked"] = False
            elif any(abs(f["line"] - t) <= tol for t in targets):
                matched_pre.append(f)
        if matched_pre:
            res["pre_hit"] = True

        # --- POST a livello di file ---
        if rel_post:
            res["post_file"] = True
        if matched_pre and {f["snippet"] for f in matched_pre} & {f["snippet"] for f in rel_post}:
            res["same_snippet"] = True               # lo stesso statement e' ancora segnalato

        # --- POST a livello di riga (con diff) ---
        if cfg["src_root"] and targets:
            a = read_lines(cfg["src_root"], fp["pre_path"])
            b = read_lines(cfg["src_root"], fp["post_path"])
            if a is not None and b is not None:
                mp = map_pre_to_post(a, b)
                ranges = [mp[t] for t in targets if t in mp] or [(1, len(b))]
                t2 = 0 if tol is None else tol
                hit = any(f["line"] is not None and any(lo - t2 <= f["line"] <= hi + t2 for lo, hi in ranges)
                          for f in rel_post)
                res["post_line"] = bool(res["post_line"]) or hit
                continue
        line_ok_all = False
    if not line_ok_all and res["post_line"] is None:
        res["post_line"] = None
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="report_ossf_js.json")
    ap.add_argument("--manifest", default="manifest_js.json")
    ap.add_argument("--tol", type=int, default=5)
    a = ap.parse_args()

    manifest = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
    by_file = load_report(Path(a.report))
    cfg = {"tol": a.tol, "eq": True, "src_root": None}

    results = [evaluate_cve(it, by_file, cfg, []) for it in manifest]
    results = [r for r in results if r["present"]]          # solo CVE analizzate

    per = defaultdict(lambda: {"TP": 0, "FN": 0, "FP": 0, "TN": 0})
    for r in results:
        d = per[r["primary"]]
        d["TP" if r["pre_hit"] else "FN"] += 1               # file prima della patch
        d["FP" if r["post_file"] else "TN"] += 1             # file dopo la patch

    t = {k: sum(d[k] for d in per.values()) for k in ("TP", "FN", "FP", "TN")}
    n = len(results)

    lines = [f"RISULTATO SU {n} CVE ANALIZZATE = {2 * n} FILE (tolleranza riga = {a.tol})", "",
             "                     | Segnalato | Non segnalato",
             "---------------------+-----------+--------------",
             f"File vulnerabile     | TP = {t['TP']:>4} | FN = {t['FN']:>4}",
             f"File corretto        | FP = {t['FP']:>4} | TN = {t['TN']:>4}", "",
             f"Recall       TP/(TP+FN) = {ratio(t['TP'], t['TP'] + t['FN'])}",
             f"Precisione   TP/(TP+FP) = {ratio(t['TP'], t['TP'] + t['FP'])}",
             f"Specificita' TN/(TN+FP) = {ratio(t['TN'], t['TN'] + t['FP'])}", "",
             "CWE     | CVE |  TP |  FN |  FP |  TN",
             "--------+-----+-----+-----+-----+----"]
    for cwe in sorted(per, key=lambda c: (-sum(per[c].values()) // 2, int(c.split('-')[1]))):
        d = per[cwe]
        lines.append(f"{cwe:<7} | {d['TP'] + d['FN']:>3} | {d['TP']:>3} | {d['FN']:>3} | {d['FP']:>3} | {d['TN']:>3}")
    lines.append("--------+-----+-----+-----+-----+----")
    lines.append(f"TOTALE  | {n:>3} | {t['TP']:>3} | {t['FN']:>3} | {t['FP']:>3} | {t['TN']:>3}")

    txt = "\n".join(lines)
    print(txt)
    Path("risultati_semplici.txt").write_text(txt, encoding="utf-8")


if __name__ == "__main__":
    main()