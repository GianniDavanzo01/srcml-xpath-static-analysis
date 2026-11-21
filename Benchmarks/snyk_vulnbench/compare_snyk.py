#!/usr/bin/env python3
"""Valuta il motore srcML su UN progetto di Snyk VulnBench 2.0.
TP/FN: per vulnerabilita', classe compatibile + sink entro --tol righe.
Report non abbinati: esclude endpoint secondari dello stesso flusso GT, raggruppa per (file, classe).
Uso: python compare_snyk.py --gt flask-bones/findings-attacker-reachable.json --report report.json"""
import argparse, json, re
from collections import Counter
from pathlib import Path

# Tutte le 14 classi ufficiali di Snyk VulnBench 2.0 con alias CWE
CLS = {
    "xss": {"CWE-79", "CWE-80", "CWE-81", "CWE-83"},
    "path-traversal": {"CWE-22", "CWE-23", "CWE-36"},
    "command-injection": {"CWE-78", "CWE-77"},
    "sql-injection": {"CWE-89", "CWE-564"},
    "open-redirect": {"CWE-601"},
    "ssrf": {"CWE-918"},
    "prototype-pollution": {"CWE-1321"},
    "insecure-deserialization": {"CWE-502"},
    "code-injection": {"CWE-94", "CWE-95"},
    "template-injection": {"CWE-1336"},
    "redos": {"CWE-1333"},
    "improper-type-validation": {"CWE-1287", "CWE-843"},
    "mass-assignment": {"CWE-915"},
    "idor": {"CWE-639", "CWE-284"},
}

# Classi attualmente implementate nel motore (usato solo per nota diagnostica)
SUPPORTED = {
    "xss", "path-traversal", "command-injection", "sql-injection",
    "open-redirect", "ssrf", "insecure-deserialization", "code-injection", "redos"
}

NONE, OTHER = "NONE", "OTHER"

norm = lambda s: re.sub(r"[^a-z0-9]+", "", s.lower())
cls_of = lambda cwe: next((c for c, s in CLS.items() if cwe in s), cwe)

def same_file(a: str, b: str) -> bool:
    na = a.replace("\\", "/").lstrip("./")
    nb = b.replace("\\", "/").lstrip("./")
    return na == nb or na.endswith("/" + nb) or nb.endswith("/" + na)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gt", required=True, help="findings-attacker-reachable.json (o cartella che lo contiene)")
    ap.add_argument("--report", required=True, help="report JSON del motore per questo progetto")
    ap.add_argument("--tol", type=int, default=2)
    a = ap.parse_args()
    p = Path(a.gt)
    p = p / "findings-attacker-reachable.json" if p.is_dir() else p

    gt = []  # (classe, [(file, riga) dei sink], [(file, riga) di tutto il flusso])
    for v in json.load(open(p, encoding="utf-8"))["vulnerabilities"]:
        names = [norm(v["type"])] + [norm(x) for x in v.get("typeAliases", [])]
        c = next((k for k in CLS if norm(k) in names), norm(v["type"]))
        fr = v["filesRelated"]
        sinks = [e for e in fr if e.get("type") == "sink"] or [fr[-1]]
        all_locs = [(e["file"], e["line"]) for e in fr]
        gt.append((c, [(e["file"], e["line"]) for e in sinks], all_locs))

    rep = []  # finding distinti (file, riga, classe)
    for d in json.load(open(a.report, encoding="utf-8"))["details"]:
        for f in d["findings"]:
            for cwe in f["vulnerabilities"]:
                t = (f["source_file"], int(str(f["line"]).split(":")[0]), cls_of(cwe))
                if t not in rep:
                    rep.append(t)

    dist = lambda locs, r: min((abs(r[1] - l) for f, l in locs if same_file(r[0], f)), default=None)
    cand = sorted(
        (r[2] != c, dist(s, r), i, j)
        for i, (c, s, _) in enumerate(gt)
        for j, r in enumerate(rep)
        if dist(s, r) is not None and dist(s, r) <= a.tol and r[2] in CLS
    )
    pred, used = {}, set()
    for wrong, _, i, j in cand:
        if i not in pred and j not in used:
            pred[i], used = (rep[j][2], j), used | {j}

    cm, detail = Counter(), []
    unsupported_fn = []
    for i, (c, s, _) in enumerate(gt):
        where = " ".join(f"{f}:{l}" for f, l in s)
        if i in pred:
            pc, j = pred[i]
            cm[(c, pc)] += 1
            detail.append(("TP" if pc == c else f"CONFUSA->{pc}", c, f"{where}  <- riga {rep[j][1]}"))
        else:
            cm[(c, NONE)] += 1
            tag_fn = "FN" if c in SUPPORTED else "FN (no regola)"
            if c not in SUPPORTED:
                unsupported_fn.append(c)
            detail.append((tag_fn, c, where))

    # Controlla se un finding non abbinato appartiene al flusso (es. source) di una GT gia' trovata
    is_flow_dup = lambda r: any(
        c == r[2] and dist(all_locs, r) is not None and dist(all_locs, r) <= a.tol
        for i, (c, _, all_locs) in enumerate(gt) if i in pred
    )

    groups, flow_dups = {}, []
    for j, r in enumerate(rep):
        if j not in used:
            if is_flow_dup(r):
                flow_dups.append(r)
            else:
                groups.setdefault((r[0], r[2]), []).append(r[1])

    gt_has = lambda f, c: any(cc == c and any(same_file(f, sf) for sf, _ in s) for cc, s, _ in gt)
    for (f, c) in groups:
        cm[(NONE, c if c in CLS else OTHER)] += 1

    print(f"Progetto: {p.parent.name} | vulnerabilita' GT: {len(gt)} | finding distinti nel report: {len(rep)} | tol+-{a.tol}\n")
    for st, c, w in detail:
        print(f"  {st:20} {c:24} {w}")
    if flow_dups:
        print("\nEndpoint secondari di flussi GT gia' abbinati (esclusi da FP):")
        for f, l, c in flow_dups:
            print(f"  {'duplicato flusso':24} {c:24} {f} riga {l}")
    print("\nReport non abbinati, raggruppati per (file, classe):")
    for (f, c), ls in sorted(groups.items()):
        tag = "fuori tassonomia" if c not in CLS else ("stessa classe/file di GT" if gt_has(f, c) else "non abbinato")
        print(f"  {tag:24} {c:24} {f} righe {','.join(map(str, sorted(ls)))}")
    oot = Counter(c for (f, c) in groups if c not in CLS)
    print("\nCWE fuori tassonomia (file in cui scattano): " + (", ".join(f"{k} x{v}" for k, v in sorted(oot.items())) or "nessuna"))

    classes = sorted({k[0] for k in cm if k[0] != NONE} | {k[1] for k in cm if k[1] not in (NONE, OTHER)})
    cols, rows = classes + [NONE, OTHER], classes + [NONE]
    print("\nMatrice (righe = vero, colonne = predetto)\n" + " " * 26 + "".join(f"{c[:10]:>11}" for c in cols))
    for r in rows:
        print(f"{r:26}" + "".join(f"{cm[(r, c)] or '.':>11}" for c in cols))
    TP = sum(cm[(c, c)] for c in classes)
    FN = sum(cm[(c, x)] for c in classes for x in cols) - TP
    FP = sum(cm[(r, c)] for r in rows for c in classes) - TP
    print(f"\nTP={TP} FN={FN} FP={FP} TN=n/d | recall={100*TP/max(TP+FN,1):.1f}% "
          f"precision(lower bound)={100*TP/max(TP+FP,1):.1f}% | fuori tassonomia={sum(oot.values())}")
    if unsupported_fn:
        supp_den = max(TP + FN - len(unsupported_fn), 1)
        print(f"Nota: {len(unsupported_fn)} FN su classi senza regola nel motore ({unsupported_fn}) "
              f"-> recall su classi supportate = {100*TP/supp_den:.1f}% ({TP}/{supp_den})")

if __name__ == "__main__":
    main()