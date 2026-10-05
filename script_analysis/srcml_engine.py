"""
srcml_engine.py
----------------
Motore di analisi statica per srcML.
Architettura "Source-Sink-Sanitizer" con predicati tipizzati e componibili
per sink e safe-context.
"""
import time, sys

import argparse
import json
from pathlib import Path
from lxml import etree
from collections import Counter


from common import NS, load_rules, check_required_imports, compile_rules, reset_caches
from taint_engine import run_taint_rule
from structural_engine import run_structural_rule, run_forbidden_functions_indexed 
from unit_context import UnitContext

from language_adapter import get_adapter

from RuleCompiler import RuleCompiler

from validator_rules import validate_or_exit


_COMPILED_RULESETS_CACHE = {} # language -> (compiled, catalog_obj)

def collect_xml_files(xml_args: list[str] | None, xml_dir: str | None) -> list[Path]:
    """
    Raccoglie i file .xml da analizzare, preservando l'ordine di specifica:
    prima quelli passati singolarmente con --xml (nell'ordine dato),
    poi quelli trovati in --xml-dir (ordinati alfabeticamente).
    Deduplica mantenendo la prima occorrenza.
    """
    ordered: list[Path] = []
    seen: set[Path] = set()

    for raw in (xml_args or []):
        p = Path(raw)
        if p not in seen:
            seen.add(p)
            ordered.append(p)

    if xml_dir:
        for p in sorted(Path(xml_dir).glob("*.xml")):
            if p not in seen:
                seen.add(p)
                ordered.append(p)

    return ordered


def get_units(tree) -> list:
    """
    Ritorna la lista dei nodi src:unit che rappresentano un singolo file
    sorgente (quelli con attributo @filename), nell'ordine in cui compaiono
    nel documento.
    """
    root = tree.getroot() if hasattr(tree, "getroot") else tree
    if root.get("filename"):
        return [root]
    return root.xpath(".//src:unit[@filename]", namespaces=NS)

DEFAULT_CATALOG_DIR = Path(__file__).resolve().parent

def _get_compiled_ruleset(adapter, raw_rules, catalog_dir):
    lang = adapter.name.lower()
    cached = _COMPILED_RULESETS_CACHE.get(lang)
    if cached is None:
        catalog_path = Path(catalog_dir) / f"{lang}_catalog.json"
        if not catalog_path.exists():
            raise FileNotFoundError(f"Catalogo mancante per '{lang}': {catalog_path}")
        compiler = RuleCompiler(str(catalog_path))
        translated = [compiler.compile(r) for r in raw_rules]
        compiled = compile_rules(translated, adapter)
        validate_or_exit(compiled.rules, lang, extra_errors=compiler.errors)
        for w in compiler.warnings:
            print(f"[AVVISO] [{lang}] {w}", file=sys.stderr)

        cached = (compiled, compiler.catalog)
        _COMPILED_RULESETS_CACHE[lang] = cached
    return cached


def analyze_unit(unit_node, raw_rules: list, xml_source: str, source_file: str | None = None, catalog_dir: Path = DEFAULT_CATALOG_DIR) -> dict:
    reset_caches()
    adapter = get_adapter(unit_node)
    imports = adapter.resolve_imports(unit_node, NS)
    compiled, catalog_obj = _get_compiled_ruleset(adapter, raw_rules, catalog_dir)

    ctx = UnitContext(unit_node, adapter, catalog=catalog_obj)
    findings = []

    run_forbidden_functions_indexed(ctx, compiled, findings, adapter, imports)

    for rule in compiled.rules:
        if not check_required_imports(rule, imports):
            continue
        rule_type = rule.get("type")
        if rule_type == "taint":
            findings.extend(run_taint_rule(unit_node, rule, adapter, imports, ctx=ctx))
        elif rule_type == "structural":
            findings.extend(run_structural_rule(unit_node, rule, adapter, imports, ctx=ctx))

    return {
        "source_file": source_file or unit_node.get("filename", "Sconosciuto"),
        "xml_source": xml_source,
        "vulnerable": len(findings) > 0,
        "rules_summary": sorted({f.get("rule_id", "UNKNOWN") for f in findings}),
        "vulnerabilities_summary": sorted({v for f in findings for v in f.get("vulnerabilities", [])}),
        "findings_count": len(findings),
        "findings": findings,
    }


def analyze_file(xml_file, raw_rules, catalog_dir: Path = DEFAULT_CATALOG_DIR):
    tree = etree.parse(str(xml_file))
    units = get_units(tree) or [tree.getroot()]
    results = []
    for u in units:
        try:
            results.append(analyze_unit(
                u, raw_rules, xml_source=xml_file.name,
                source_file=None if u.get("filename") else xml_file.name,
                catalog_dir=catalog_dir))
        except (FileNotFoundError, NotImplementedError, ValueError) as e:
            results.append({
                "source_file": u.get("filename") or xml_file.name,
                "xml_source": xml_file.name,
                "vulnerable": False,
                "error": str(e),
                "findings_count": 0,
                "findings": [],
            })
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xml", nargs="+", help="Uno o più file .xml generati da srcML")
    ap.add_argument("--xml-dir", help="Directory contenente più file .xml da analizzare in batch")
    ap.add_argument("--rules", required=True, help="File JSON con le regole, oppure cartella con più file .json")
    ap.add_argument("--catalog-dir",help="Cartella con i cataloghi <linguaggio>_catalog.json ""(default: cartella dello script)")
    ap.add_argument("-o", "--output", help="File JSON di output (default: stdout)")
    args = ap.parse_args()

    if not args.xml and not args.xml_dir:
        ap.error("Specificare almeno uno tra --xml e --xml-dir")

    catalog_dir = Path(args.catalog_dir) if args.catalog_dir else DEFAULT_CATALOG_DIR
    if not catalog_dir.is_dir():
        ap.error(f"--catalog-dir non è una cartella valida: {catalog_dir}")

    rules_path = Path(args.rules)
    if rules_path.is_dir() and rules_path.resolve() == catalog_dir.resolve():
        ap.error("La cartella delle regole e quella dei cataloghi devono essere diverse: "
                "i file *_catalog.json verrebbero letti come regole.")

    try:
        raw_rules = load_rules(rules_path)
    except ValueError as e:
        ap.error(str(e))

    # raw_rules = load_rules(Path(args.rules))
    xml_files = collect_xml_files(args.xml, args.xml_dir)

    if not xml_files:
        ap.error("Nessun file .xml trovato da analizzare")



    t0 = time.perf_counter() #TEMPO PER VERIFICARE PERFORMANCE


    report = []
    errors = []
    for xml in xml_files:
        try:
            report.extend(analyze_file(xml, raw_rules, catalog_dir))
        except (FileNotFoundError, NotImplementedError, ValueError) as e:
            print(f"[ERRORE] {xml.name}: {e}", file=sys.stderr)
            errors.append({"xml_source": xml.name, "error": str(e)})
    
    
    elapsed = time.perf_counter() - t0               #TEMPO PER VERIFICARE PERFORMANCE

    category_counter = Counter()
    total_findings = 0
    vulnerable_files_count = 0

    failed = [r for r in report if "error" in r]
    ok = [r for r in report if "error" not in r]

    for file_report in ok:
        if file_report.get("vulnerable"):
            vulnerable_files_count += 1
            
        total_findings += file_report.get("findings_count", 0)
        
        for finding in file_report.get("findings", []):
            for vuln_category in finding.get("vulnerabilities", []):
                category_counter[vuln_category] += 1

    final_output = {
        "summary": {
            "units_analyzed": len(ok),
            "units_failed": len(failed), 
            "files_failed": len(errors),
            "vulnerable_files": vulnerable_files_count,
            "total_findings": total_findings,
            "categories_count": dict(category_counter),
        },
        "errors": errors + [
        {"xml_source": r["xml_source"], "source_file": r["source_file"], "error": r["error"]}
        for r in failed
    ],
        "details": ok, 
    }

    output_text = json.dumps(final_output, indent=2, ensure_ascii=False)
    
    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Report scritto in {args.output}")
    else:
        print(output_text)

    print(f"[TIMING] Analisi di {len(xml_files)} file in {elapsed:.2f} s", file=sys.stderr) #TEMPO PER VERIFICARE PERFORMANCE

if __name__ == "__main__":
    main()