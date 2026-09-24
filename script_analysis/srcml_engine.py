"""
srcml_engine.py
----------------
Motore di analisi statica per srcML.
Architettura "Source-Sink-Sanitizer" con predicati tipizzati e componibili
per sink e safe-context.
"""

import argparse
import json
from pathlib import Path
from lxml import etree
from collections import Counter

# from common import NS, load_rules, check_required_imports
# from taint_engine import run_taint_rule
# from structural_engine import run_structural_rule

from common import NS, load_rules, check_required_imports, compile_rules, CompiledRuleset
from taint_engine import run_taint_rule
from structural_engine import run_structural_rule, run_forbidden_functions_indexed, run_forbidden_names_indexed
from unit_context import UnitContext

from language_adapter import get_adapter

from RuleCompiler import RuleCompiler


_COMPILED_RULESETS_CACHE = {}

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


def _get_compiled_ruleset(language_name: str, raw_rules: list) -> "CompiledRuleset":
    """Compila (traduce i tag del catalogo) le regole per un linguaggio, una sola volta, con cache."""
    if language_name not in _COMPILED_RULESETS_CACHE:
        catalog_path = Path(f"{language_name}_catalog.json")
        if catalog_path.exists():
            compiler = RuleCompiler(str(catalog_path))
            translated_rules = [compiler.compile(r) for r in raw_rules]
        else:
            translated_rules = raw_rules
        _COMPILED_RULESETS_CACHE[language_name] = compile_rules(translated_rules)
    return _COMPILED_RULESETS_CACHE[language_name]


def analyze_unit(unit_node, raw_rules: list, xml_source: str) -> dict:
    adapter = get_adapter(unit_node)
    imports = adapter.resolve_imports(unit_node, NS)
    language_name = getattr(adapter, 'name', 'python').lower()

    compiled = _get_compiled_ruleset(language_name, raw_rules)

    catalog_obj = {}
    catalog_path = Path(f"{language_name}_catalog.json")
    if catalog_path.exists():
        with open(catalog_path, 'r', encoding='utf-8') as f:
            catalog_obj = json.load(f)

    ctx = UnitContext(unit_node, adapter, catalog=catalog_obj)
    findings = []

    run_forbidden_functions_indexed(ctx, compiled, findings, adapter, imports)
    run_forbidden_names_indexed(ctx, compiled, findings, adapter, imports)

    for rule in compiled.rules:
        if not check_required_imports(unit_node, rule, NS, imports=imports):
            continue
        rule_type = rule.get("type")
        if rule_type == "taint":
            findings.extend(run_taint_rule(unit_node, rule, adapter, imports, ctx=ctx))
        elif rule_type == "structural":
            findings.extend(run_structural_rule(unit_node, rule, adapter, imports, ctx=ctx))

    return {
        "source_file": unit_node.get("filename", "Sconosciuto"),
        "xml_source": xml_source,
        "vulnerable": len(findings) > 0,
        "rules_summary": sorted({f.get("rule_id", "UNKNOWN") for f in findings}),
        "vulnerabilities_summary": sorted({v for f in findings for v in f.get("vulnerabilities", [])}),
        "findings_count": len(findings),
        "findings": findings,
    }


def analyze_file(xml_file: Path, raw_rules: list) -> list:
    tree = etree.parse(str(xml_file))
    units = get_units(tree)

    if not units:
        root = tree.getroot() if hasattr(tree, "getroot") else tree
        adapter = get_adapter(root)
        imports = adapter.resolve_imports(root, NS)
        language_name = getattr(adapter, 'name', 'python').lower()

        compiled = _get_compiled_ruleset(language_name, raw_rules)   # <-- ora compila anche qui

        findings = []
        for rule in compiled.rules:
            if not check_required_imports(tree, rule, NS, imports):
                continue
            rule_type = rule.get("type")
            if rule_type == "taint":
                findings.extend(run_taint_rule(tree, rule, adapter, imports))
            elif rule_type == "structural":
                findings.extend(run_structural_rule(tree, rule, adapter, imports))
        return [{
            "source_file": xml_file.name,
            "xml_source": xml_file.name,
            "vulnerable": len(findings) > 0,
            "rules_summary": sorted({f.get("rule_id", "UNKNOWN") for f in findings}),
            "vulnerabilities_summary": sorted({v for f in findings for v in f.get("vulnerabilities", [])}),
            "findings_count": len(findings),
            "findings": findings,
        }]

    return [analyze_unit(u, raw_rules, xml_source=xml_file.name) for u in units]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xml", nargs="+", help="Uno o più file .xml generati da srcML")
    ap.add_argument("--xml-dir", help="Directory contenente più file .xml da analizzare in batch")
    ap.add_argument("--rules", required=True, help="File JSON con le regole, oppure cartella con più file .json")
    ap.add_argument("-o", "--output", help="File JSON di output (default: stdout)")
    args = ap.parse_args()

    if not args.xml and not args.xml_dir:
        ap.error("Specificare almeno uno tra --xml e --xml-dir")

    # rules = load_rules(Path(args.rules))
    raw_rules = load_rules(Path(args.rules))
    # compiled = compile_rules(rules)
    xml_files = collect_xml_files(args.xml, args.xml_dir)

    if not xml_files:
        ap.error("Nessun file .xml trovato da analizzare")

    report = []
    for xml in xml_files:
        # report.extend(analyze_file(xml, compiled))
        report.extend(analyze_file(xml, raw_rules))

    category_counter = Counter()
    total_findings = 0
    vulnerable_files_count = 0

    for file_report in report:
        if file_report.get("vulnerable"):
            vulnerable_files_count += 1
            
        total_findings += file_report.get("findings_count", 0)
        
        for finding in file_report.get("findings", []):
            for vuln_category in finding.get("vulnerabilities", []):
                category_counter[vuln_category] += 1

    final_output = {
        "summary": {
            "total_files_analyzed": len(report),
            "vulnerable_files": vulnerable_files_count,
            "total_findings": total_findings,
            "categories_count": dict(category_counter) 
        },
        "details": report  
    }

    output_text = json.dumps(final_output, indent=2, ensure_ascii=False)
    
    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Report scritto in {args.output}")
    else:
        print(output_text)



if __name__ == "__main__":
    main()