#!/usr/bin/env python3
"""
---------------------
Calcola TP / FN / Recall per CWE a partire dai report JSON prodotti da
srcml_engine.py, usando come ground truth il CWE presente nel path del file
(es. SecurityEval: ".../CWE-918/codeql_1.py").

Per ogni campione:
  - CWE atteso  -> estratto dal path (cartella nella forma 'CWE-NNN').
  - CWE rilevato -> letto da 'vulnerabilities_summary' dell'entry.

Due criteri di match, entrambi riportati in tabella:
  - strict:    il CWE atteso compare esattamente tra quelli rilevati.
  - hierarchy: il CWE atteso è un "genitore" (vedi HIERARCHY sotto) e tra i
               rilevati compare uno dei suoi "figli" accettati.

Se passi --ruleset (ruleset_abstract.json), ogni CWE viene marcato come
'covered' o 'not_covered' in base alle regole esistenti (esatto o tramite
HIERARCHY), e il recall aggregato (micro/macro) viene calcolato solo sui
CWE covered.

In aggiunta alla tabella aggregata per CWE (.txt), viene scritto anche un CSV
con il dettaglio per singolo file analizzato: CWE atteso, CWE/i rilevato/i,
esito (TP_strict / TP_hierarchy / FN) e, in caso di match gerarchico, quale
CWE figlio ha prodotto il match.

USO
---
    python compare_security_eval.py --results report.json --output recall_table.txt
    python compare_security_eval.py --results report1.json report2.json \\
        --ruleset ruleset_abstract.json \\
        --output recall_table.txt --csv-output per_file_results.csv
"""

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path

CWE_PREFIX = "CWE-"
_CWE_NUM_RE = re.compile(r"(\d+)")


def normalize_cwe(cwe) -> str:
    """Forma canonica 'CWE-N' (senza zeri iniziali), qualunque sia la
    formattazione di partenza ('CWE-79', 'CWE-079', 'cwe_79', 79, ...).
    Ritorna il valore originale (come stringa) se non contiene cifre."""
    if cwe is None:
        return cwe
    m = _CWE_NUM_RE.search(str(cwe))
    if not m:
        return str(cwe)
    return f"{CWE_PREFIX}{int(m.group(1))}"

# Mappa gerarchica hardcoded: CWE genitore -> CWE figli accettati come match
# equivalente (basata sulle relazioni ChildOf della tassonomia MITRE CWE,
# ristretta ai CWE che compaiono in SecurityEval / nel ruleset del motore).
# Modificare direttamente qui per aggiungere altre equivalenze.
_HIERARCHY_RAW = {
    "CWE-020": {  # Improper Input Validation
        "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-95",
        "CWE-113", "CWE-129", "CWE-134", "CWE-643", "CWE-943"
    },
    "CWE-327":{"CWE-328"},
    "CWE-693": {"CWE-326", "CWE-327"},  # Protection Mechanism Failure
    "CWE-798":{"CWE-259"}
}
# Normalizzata una sola volta all'avvio: così la mappa sopra puoi scriverla
# con 2 o 3 cifre indifferentemente, il lookup a runtime userà sempre la
# forma canonica (vedi normalize_cwe).
HIERARCHY = {
    normalize_cwe(parent): {normalize_cwe(child) for child in children}
    for parent, children in _HIERARCHY_RAW.items()
}


def extract_ground_truth_cwe(source_file: str):
    normalized = source_file.replace("\\", "/")
    for part in Path(normalized).parts:
        if not part.upper().startswith(CWE_PREFIX):
            continue
        head = part.upper().split("-")
        if len(head) >= 2 and head[1].isdigit():
            return normalize_cwe(head[1])   # 'CWE-079' -> 'CWE-79', non 'CWE-079'
    return None


def load_results(paths) -> list:
    entries = []
    for raw_p in paths:
        p = Path(raw_p)
        files = sorted(p.glob("*.json")) if p.is_dir() else [p]
        for f in files:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "details" in data:
                entries.extend(data["details"])
            elif isinstance(data, list):
                entries.extend(data)
            else:
                entries.append(data)
    return entries


def load_covered_cwes(ruleset_path) -> set:
    if not ruleset_path:
        return set()
    rules = json.loads(Path(ruleset_path).read_text(encoding="utf-8"))
    covered = set()
    for r in rules:
        langs = r.get("languages")
        if langs is not None and "python" not in [l.lower() for l in langs]:
            continue
        covered.update(normalize_cwe(v) for v in r.get("vulnerabilities", []))
    return covered


def classify_coverage(cwe: str, covered_cwes: set) -> str:
    if not covered_cwes:
        return "covered"
    if cwe in covered_cwes:
        return "covered"
    if HIERARCHY.get(cwe, set()) & covered_cwes:
        return "covered"
    return "not_covered"


def build_table(entries):
    """Calcola sia l'aggregato per CWE (per la tabella .txt) sia il dettaglio
    per singolo file (per il CSV): un solo giro sulle entry, nessuna logica
    duplicata tra i due output."""
    per_cwe = defaultdict(lambda: {"total": 0, "tp_strict": 0, "tp_hier": 0})
    file_rows = []
    skipped = 0

    for entry in entries:
        source_file = entry.get("source_file", "")
        gt = extract_ground_truth_cwe(source_file)
        if gt is None:
            skipped += 1
            continue

        detected = {normalize_cwe(v) for v in entry.get("vulnerabilities_summary", [])}
        rec = per_cwe[gt]
        rec["total"] += 1

        if gt in detected:
            match, matched_via = "TP_strict", gt
            rec["tp_strict"] += 1
            rec["tp_hier"] += 1
        else:
            hier_hits = detected & HIERARCHY.get(gt, set())
            if hier_hits:
                match, matched_via = "TP_hierarchy", ";".join(sorted(hier_hits))
                rec["tp_hier"] += 1
            else:
                match, matched_via = "FN", ""

        file_rows.append({
            "source_file": source_file,
            "cwe_expected": gt,
            "cwe_detected": ";".join(sorted(detected)) if detected else "",
            "match": match,
            "matched_via": matched_via,
        })

    return per_cwe, file_rows, skipped


def build_rows(per_cwe, covered_cwes):
    rows = []
    for cwe in sorted(per_cwe, key=lambda c: int(c.split("-")[1])):
        rec = per_cwe[cwe]
        total, tp_s, tp_h = rec["total"], rec["tp_strict"], rec["tp_hier"]
        rows.append({
            "CWE": cwe, "n": total,
            "tp_s": tp_s, "fn_s": total - tp_s,
            "recall_s": tp_s / total if total else 0.0,
            "tp_h": tp_h, "fn_h": total - tp_h,
            "recall_h": tp_h / total if total else 0.0,
            "coverage": classify_coverage(cwe, covered_cwes),
        })
    return rows


def summarize(rows):
    applicable = [r for r in rows if r["coverage"] == "covered"]

    def _agg(tp_key):
        samples = sum(r["n"] for r in applicable)
        tp = sum(r[tp_key] for r in applicable)
        micro = tp / samples if samples else 0.0
        macro = (sum(r[tp_key] / r["n"] for r in applicable if r["n"]) / len(applicable)
                 if applicable else 0.0)
        return micro, macro

    micro_s, macro_s = _agg("tp_s")
    micro_h, macro_h = _agg("tp_h")
    return applicable, micro_s, macro_s, micro_h, macro_h


def render_txt(rows, skipped):
    applicable, micro_s, macro_s, micro_h, macro_h = summarize(rows)

    header = f"{'CWE':<10}{'N':>4}{'TP_s':>6}{'FN_s':>6}{'Rec_s':>7}{'TP_h':>6}{'FN_h':>6}{'Rec_h':>7}  {'coverage'}"
    sep = "-" * len(header)
    lines = [header, sep]
    for r in rows:
        lines.append(
            f"{r['CWE']:<10}{r['n']:>4}{r['tp_s']:>6}{r['fn_s']:>6}{r['recall_s']:>7.3f}"
            f"{r['tp_h']:>6}{r['fn_h']:>6}{r['recall_h']:>7.3f}  {r['coverage']}"
        )
    lines.append(sep)
    lines.append(f"CWE totali nel dataset: {len(rows)}   CWE applicabili (coverage=covered): {len(applicable)}")
    lines.append(f"Recall STRICT    -> micro: {micro_s:.3f}   macro: {macro_s:.3f}")
    lines.append(f"Recall HIERARCHY -> micro: {micro_h:.3f}   macro: {macro_h:.3f}")
    if skipped:
        lines.append(f"[ATTENZIONE] {skipped} entry senza un CWE riconoscibile nel path, escluse.")
    return "\n".join(lines)


def write_csv(file_rows, output_path):
    fieldnames = ["source_file", "cwe_expected", "cwe_detected", "match", "matched_via"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(file_rows)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", nargs="+", required=True,
                     help="File JSON (o cartelle con più JSON) prodotti da srcml_engine.py")
    ap.add_argument("--ruleset",
                     help="ruleset_abstract.json, per marcare i CWE coperti dal motore")
    ap.add_argument("--output", default="recall_table.txt", help="File .txt di output (tabella aggregata)")
    ap.add_argument("--csv-output", default="per_file_results.csv",
                     help="File .csv di output (dettaglio TP/FN per singolo file)")
    args = ap.parse_args()

    entries = load_results(args.results)
    covered_cwes = load_covered_cwes(args.ruleset)
    per_cwe, file_rows, skipped = build_table(entries)
    rows = build_rows(per_cwe, covered_cwes)

    text = render_txt(rows, skipped)
    Path(args.output).write_text(text + "\n", encoding="utf-8")
    write_csv(file_rows, args.csv_output)

    print(text)
    print(f"\nTabella aggregata scritta in: {args.output}")
    print(f"Dettaglio per file scritto in: {args.csv_output}")


if __name__ == "__main__":
    main()