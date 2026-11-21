"""
evaluate_benchproctor.py
-------------------------
Confronta il report JSON prodotto da srcml_engine.py con il ground truth dei
CSV BenchProctor e calcola matrice di confusione e metriche per categoria, per framework e globali.

Definizione di predizione (per ogni test del CSV)
-------------------------------------------------
  --mode cwe  (default, stile OWASP Benchmark)
      Il test è predetto "vulnerabile" se il motore produce almeno un finding
      il cui CWE coincide con il CWE del test (colonna 'CWE' del CSV). I
      finding di altri CWE sullo stesso file NON contano come positivi
      (vengono solo segnalati come "off-target").
  --mode any
      Il test è predetto "vulnerabile" se il motore produce QUALSIASI finding
      sul file, indipendentemente dal CWE (più severo: penalizza il rumore).

Esito per test (ground truth = colonna 'real vulnerability'):
      truth=true  & predetto=true   -> TP
      truth=true  & predetto=false  -> FN
      truth=false & predetto=true   -> FP
      truth=false & predetto=false  -> TN

Esempi
------
  python evaluate_benchproctor.py --report report.json --csv expectedresults.csv
  python evaluate_benchproctor.py --report report.json --csv expectedresults.csv --details-csv out.csv
"""

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path



def norm_test_id(s: str) -> str:
    """Identificatore canonico di un test: minuscolo, senza estensione e
    senza alcun carattere non alfanumerico.

        'BenchmarkTest00001'       -> 'benchmarktest00001'
        'benchmark_test_00001.py'  -> 'benchmarktest00001'
    """
    return re.sub(r"[^a-z0-9]", "", Path(s).stem.lower())


def parse_benchproctor_csv_lines(lines) -> tuple:
    """Ritorna (meta: dict, header: list[str], rows: list[dict]) da un
    iterabile di righe di testo (senza terminatori)."""
    meta = {}
    header_line = None
    data_lines = []

    for line in lines:
        line = line.rstrip("\r\n")
        if line.startswith("#"):
            content = line.lstrip("#").strip()
            if "=" in content:
                for part in content.split():
                    if "=" in part:
                        k, _, v = part.partition("=")
                        meta[k] = v
            elif header_line is None and "test name" in content:
                header_line = content
            continue
        if line:
            data_lines.append(line)

    if header_line is None:
        raise ValueError("Header non trovato nei commenti del CSV")

    header = [h.strip() for h in header_line.split(",")]
    reader = csv.DictReader(data_lines, fieldnames=header)
    rows = list(reader)
    return meta, header, rows


def parse_benchproctor_csv(csv_path: Path) -> tuple:
    """Wrapper su file locale."""
    with csv_path.open(encoding="utf-8") as f:
        return parse_benchproctor_csv_lines(f)

def _columns(header: list[str]) -> tuple[str, str, str, str]:
    cwe_col = next(c for c in header if c.lower() == "cwe")
    name_col = next(c for c in header if "test name" in c.lower())
    label_col = next(c for c in header if "vulnerability" in c.lower())
    cat_col = next(c for c in header if c.lower() == "category")
    return cwe_col, name_col, label_col, cat_col


_TEST_ID_RE = re.compile(r"benchmark[a-z]*\d+")


# --------------------------------------------------------------------- #
# Utilità
# --------------------------------------------------------------------- #
def _cwe_nums(values) -> set[str]:
    """['CWE-89', 'CWE-416'] -> {'89', '416'}"""
    out = set()
    for v in values:
        out.update(re.findall(r"\d+", str(v)))
    return out


def test_id_from_path(path: str) -> str | None:
    """Id normalizzato del test a partire dal path del file analizzato.
    Gestisce file singolo (.../benchmark_test_00001.py) e cartella-per-test
    (.../benchmark_test_00001/app.py), con separatori / o \\."""
    parts = path.replace("\\", "/").split("/")
    for part in reversed(parts):
        k = norm_test_id(part)
        if _TEST_ID_RE.fullmatch(k):
            return k
    return None


def _tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", s.lower()) if t}


# --------------------------------------------------------------------- #
# Caricamento ground truth
# --------------------------------------------------------------------- #
def collect_csvs(paths) -> list[Path]:
    out, seen = [], set()
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            found = sorted(p.rglob("expectedresults-*.csv"))
            if not found:
                sys.exit(f"[ERRORE] nessun 'expectedresults-*.csv' sotto {p}")
        elif p.is_file():
            found = [p]
        else:
            sys.exit(f"[ERRORE] percorso inesistente: {p}")
        for f in found:
            if f.resolve() not in seen:
                seen.add(f.resolve())
                out.append(f)
    return out


def load_truth(csv_paths) -> dict:
    """{framework_label: {"language": str, "tests": {test_id: {...}}}}"""
    truth = {}
    for p in csv_paths:
        meta, header, rows = parse_benchproctor_csv(p)
        cwe_col, name_col, label_col, cat_col = _columns(header)
        label = (meta.get("framework") or p.parent.name).lower()
        entry = truth.setdefault(
            label, {"language": (meta.get("language") or "").lower(), "tests": {}})
        for r in rows:
            tid = norm_test_id(r[name_col])
            entry["tests"][tid] = {
                "name": r[name_col].strip(),
                "category": r[cat_col].strip(),
                "cwe": r[cwe_col].strip(),
                "vulnerable": r[label_col].strip().lower() == "true",
            }
    return truth


# --------------------------------------------------------------------- #
# Caricamento report del motore
# --------------------------------------------------------------------- #
def attribute_label(source_file: str, xml_source: str, labels, strict: bool):
    toks = _tokens(source_file) | _tokens(Path(xml_source or "").stem)
    hits = [l for l in labels if l in toks]
    if hits:
        return hits[0]
    if len(labels) == 1 and not strict:
        return next(iter(labels))
    return None


def load_reports(report_paths, labels, strict: bool):
    """Ritorna (analyzed, stats).
    analyzed: {(label, test_id): [(rule_id, frozenset(cwe), line), ...]}
    Un test compare in `analyzed` anche con zero finding (file analizzato e
    pulito): è ciò che distingue 'nessun finding' da 'file non analizzato'."""
    analyzed: dict = {}
    stats = {"units": 0, "no_test_id": 0, "unattributed": 0, "engine_errors": 0}

    for rp in report_paths:
        try:
            report = json.loads(Path(rp).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            sys.exit(f"[ERRORE] report non leggibile {rp}: {e}")

        stats["engine_errors"] += len(report.get("errors", []))

        for d in report.get("details", []):
            stats["units"] += 1
            sf = d.get("source_file") or ""
            tid = test_id_from_path(sf)
            if tid is None:
                stats["no_test_id"] += 1
                continue
            label = attribute_label(sf, d.get("xml_source", ""), labels, strict)
            if label is None:
                stats["unattributed"] += 1
                continue
            bucket = analyzed.setdefault((label, tid), [])
            for f in d.get("findings", []):
                bucket.append((f.get("rule_id", "?"),
                               frozenset(_cwe_nums(f.get("vulnerabilities", []))),
                               f.get("line", "?")))
    return analyzed, stats


# --------------------------------------------------------------------- #
# Valutazione
# --------------------------------------------------------------------- #
def evaluate(truth, analyzed, mode):
    """Ritorna (per_test: list[dict], not_analyzed: {label: [nomi]})."""
    per_test = []
    not_analyzed = defaultdict(list)

    for label, entry in truth.items():
        for tid, t in entry["tests"].items():
            findings = analyzed.get((label, tid))
            if findings is None:
                not_analyzed[label].append(t["name"])
                continue

            target = {t["cwe"]}
            if mode == "any":
                matched, other = list(findings), []
            else:
                matched = [f for f in findings if f[1] & target]
                other = [f for f in findings if not (f[1] & target)]

            predicted = bool(matched)
            truth_pos = t["vulnerable"]
            outcome = ("TP" if predicted else "FN") if truth_pos else ("FP" if predicted else "TN")

            per_test.append({
                "framework": label, "test": t["name"], "category": t["category"],
                "cwe": t["cwe"], "truth": truth_pos, "predicted": predicted,
                "outcome": outcome,
                "matched_rules": sorted({f[0] for f in matched}),
                "other_rules": sorted({f[0] for f in other}),
                "lines": sorted({str(f[2]) for f in matched}),
            })
    return per_test, not_analyzed


def metrics(c: dict) -> dict:
    tp, fp, tn, fn = c["TP"], c["FP"], c["TN"], c["FN"]
    n = tp + fp + tn + fn
    tpr = tp / (tp + fn) if tp + fn else None
    prec = tp / (tp + fp) if tp + fp else None
    f1 = (2 * prec * tpr / (prec + tpr)
          if prec is not None and tpr is not None and prec + tpr > 0 else None)
    return {"N": n, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "TPR": tpr, "precision": prec, "F1": f1}


def _empty():
    return {"TP": 0, "FP": 0, "TN": 0, "FN": 0}


def _macro(cat_metrics: list) -> dict:
    def avg(key):
        vals = [m[key] for m in cat_metrics if m[key] is not None]
        return sum(vals) / len(vals) if vals else None
    return {k: avg(k) for k in ("TPR", "precision", "F1")}


# --------------------------------------------------------------------- #
# Stampa
# --------------------------------------------------------------------- #
def _f(x):
    return "   -  " if x is None else f"{x:6.3f}"


def _cells(m):
    return f"{_f(m['precision'])} {_f(m['TPR'])} {_f(m['F1'])}"


def _row(name, cwe, m):
    return (f"{name:<19}{cwe:>5} {m['N']:>5} {m['TP']:>5} {m['FN']:>5} "
            f"{m['FP']:>5} {m['TN']:>5} {_cells(m)}")


def _header():
    return (f"{'categoria':<19}{'CWE':>5} {'N':>5} {'TP':>5} {'FN':>5} "
            f"{'FP':>5} {'TN':>5} {'prec':>6} {'recall':>6} {'F1':>6}")


def build_results(per_test, truth):
    """Aggrega per_test in: {label: {categories:{cat:{cwe, **metrics}},
    total, macro}}, più global."""
    by_cat = defaultdict(_empty)
    cat_cwe = {}
    by_fw = defaultdict(_empty)
    glob = _empty()
    offtarget = defaultdict(int)

    for r in per_test:
        by_cat[(r["framework"], r["category"])][r["outcome"]] += 1
        cat_cwe[(r["framework"], r["category"])] = r["cwe"]
        by_fw[r["framework"]][r["outcome"]] += 1
        glob[r["outcome"]] += 1
        if r["other_rules"]:
            offtarget[r["framework"]] += 1

    results = {}
    for label in sorted(by_fw):
        cats = {}
        for (fw, cat), c in sorted(by_cat.items()):
            if fw != label:
                continue
            m = metrics(c)
            m["cwe"] = cat_cwe[(fw, cat)]
            cats[cat] = m
        results[label] = {
            "categories": cats,
            "total_micro": metrics(by_fw[label]),
            "macro_avg": _macro(list(cats.values())),
            "tests_with_offtarget_findings": offtarget[label],
        }
    return results, metrics(glob)


def print_report(results, global_m, truth, not_analyzed, stats, mode, n_labels):
    for label, res in results.items():
        lang = truth[label]["language"] or "?"
        total_in_csv = len(truth[label]["tests"])
        n_eval = res["total_micro"]["N"]
        print(f"\n=== {label} (language={lang}) | mode={mode} | "
              f"valutati {n_eval}/{total_in_csv} test ===")
        hdr = _header()
        print(hdr)
        print("-" * len(hdr))
        for cat, m in res["categories"].items():
            print(_row(cat, m["cwe"], m))
        print("-" * len(hdr))
        print(_row("TOTALE (micro)", "", res["total_micro"]))
        mac = res["macro_avg"]
        print(f"{'MEDIA (macro)':<19}{'':>5} {'':>5} {'':>5} {'':>5} {'':>5} {'':>5} "
              f"{_cells(mac)}")
        if res["tests_with_offtarget_findings"]:
            print(f"  [INFO] {res['tests_with_offtarget_findings']} test con finding di CWE "
                  f"diverso da quello atteso (ignorati in mode=cwe)")
        if not_analyzed.get(label):
            na = not_analyzed[label]
            print(f"  [ATTENZIONE] {len(na)} test del CSV senza file analizzato "
                  f"(esclusi dalla matrice). Primi: {na[:5]}")

    if n_labels > 1:
        print("\n=== GLOBALE (tutti i framework, micro) ===")
        hdr = _header()
        print(hdr)
        print("-" * len(hdr))
        print(_row("TOTALE", "", global_m))

    if stats["no_test_id"] or stats["unattributed"] or stats["engine_errors"]:
        print(f"\n[INFO] report: {stats['units']} unità; "
              f"{stats['no_test_id']} senza id test riconoscibile, "
              f"{stats['unattributed']} non attribuibili a un framework, "
              f"{stats['engine_errors']} errori del motore")


def write_details_csv(path: Path, per_test):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["framework", "test", "category", "cwe", "truth", "predicted",
                    "outcome", "matched_rules", "other_rules", "lines"])
        for r in sorted(per_test, key=lambda x: (x["framework"], x["category"], x["test"])):
            w.writerow([r["framework"], r["test"], r["category"], r["cwe"],
                        str(r["truth"]).lower(), str(r["predicted"]).lower(),
                        r["outcome"], ";".join(r["matched_rules"]),
                        ";".join(r["other_rules"]), ";".join(r["lines"])])


# --------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", nargs="+", required=True, type=Path,
                    help="uno o più report JSON di srcml_engine.py")
    ap.add_argument("--csv", nargs="+", required=True,
                    help="CSV expectedresults-*.csv oppure cartelle")
    ap.add_argument("--mode", choices=["cwe", "any"], default="cwe",
                    help="cwe: conta solo finding del CWE atteso (default); any: qualsiasi finding")
    ap.add_argument("--strict-framework", action="store_true",
                    help="un'unità è attribuita a un CSV solo se il framework compare nel path/xml")
    ap.add_argument("--json-out", type=Path, default=None, help="salva le metriche in JSON")
    ap.add_argument("--details-csv", type=Path, default=None,
                    help="salva l'esito di ogni test ")
    args = ap.parse_args()

    truth = load_truth(collect_csvs(args.csv))
    analyzed, stats = load_reports(args.report, set(truth), args.strict_framework)

    if not analyzed:
        sys.exit("[ERRORE] nessuna unità del report è stata abbinata a un test dei CSV. "
                 "Controlla 'source_file' nel report e il nome dei file (benchmark_test_N).")

    per_test, not_analyzed = evaluate(truth, analyzed, args.mode)
    if not per_test:
        sys.exit("[ERRORE] nessun test valutabile.")

    results, global_m = build_results(per_test, truth)
    print_report(results, global_m, truth, not_analyzed, stats, args.mode, len(results))

    if args.json_out:
        payload = {"mode": args.mode,
                   "frameworks": results, "global_micro": global_m,
                   "not_analyzed": {k: len(v) for k, v in not_analyzed.items()},
                   "report_stats": stats}
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                                 encoding="utf-8")
        print(f"\nMetriche scritte in {args.json_out}")
    if args.details_csv:
        write_details_csv(args.details_csv, per_test)
        print(f"Esiti per test scritti in {args.details_csv}")


if __name__ == "__main__":
    main()