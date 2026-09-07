#!/usr/bin/env python3
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

from common import NS, load_rules, check_required_imports
from taint_engine import run_taint_rule
from structural_engine import run_structural_rule


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


def analyze_unit(unit_node, rules: list, xml_source: str) -> dict:
    findings = []
    for rule in rules:
        if not check_required_imports(unit_node, rule, NS):
            continue  

        rule_type = rule.get("type")
        if rule_type == "taint":
            findings.extend(run_taint_rule(unit_node, rule))
        elif rule_type == "structural":
            findings.extend(run_structural_rule(unit_node, rule))

    return {
        "source_file": unit_node.get("filename", "Sconosciuto"),
        "xml_source": xml_source,
        "vulnerable": len(findings) > 0,
        "rules_summary": sorted({f.get("rule_id", "UNKNOWN") for f in findings}),
        "vulnerabilities_summary": sorted({v for f in findings for v in f.get("vulnerabilities", [])}),
        "findings_count": len(findings),
        "findings": findings,
    }


def analyze_file(xml_file: Path, rules: list) -> list:
    """
    Analizza un file .xml prodotto da srcML. Ritorna una lista di
    risultati (un elemento per ciascun file sorgente individuato).
    """
    tree = etree.parse(str(xml_file))
    units = get_units(tree)

    if not units:
        findings = []
        for rule in rules:
            rule_type = rule.get("type")
            if rule_type == "taint":
                findings.extend(run_taint_rule(tree, rule))
            elif rule_type == "structural":
                findings.extend(run_structural_rule(tree, rule))
        return [{
            "source_file": xml_file.name,
            "xml_source": xml_file.name,
            "vulnerable": len(findings) > 0,
            "rules_summary": sorted({f.get("rule_id", "UNKNOWN") for f in findings}),
            "vulnerabilities_summary": sorted({v for f in findings for v in f.get("vulnerabilities", [])}),
            "findings_count": len(findings),
            "findings": findings,
        }]

    return [analyze_unit(u, rules, xml_source=xml_file.name) for u in units]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xml", nargs="+", help="Uno o più file .xml generati da srcML")
    ap.add_argument("--xml-dir", help="Directory contenente più file .xml da analizzare in batch")
    ap.add_argument("--rules", required=True, help="File JSON con le regole, oppure cartella con più file .json")
    ap.add_argument("-o", "--output", help="File JSON di output (default: stdout)")
    args = ap.parse_args()

    if not args.xml and not args.xml_dir:
        ap.error("Specificare almeno uno tra --xml e --xml-dir")

    rules = load_rules(Path(args.rules))
    xml_files = collect_xml_files(args.xml, args.xml_dir)

    if not xml_files:
        ap.error("Nessun file .xml trovato da analizzare")

    report = []
    for xml in xml_files:
        report.extend(analyze_file(xml, rules))

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