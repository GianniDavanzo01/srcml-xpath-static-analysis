import json

class RuleCompiler:
    def __init__(self, catalog_path: str):
        self.catalog_path = catalog_path
        with open(catalog_path, 'r') as f:
            self.catalog = json.load(f)

    def _expand_tags(self, items_list: list, catalog_section: str) -> list:
        expanded = []
        for item in items_list:
            if isinstance(item, dict) and "tag" in item:
                tag_name = item["tag"]
                values = self.catalog.get(catalog_section, {}).get(tag_name)
                if values is None:
                    print(f"[ATTENZIONE] tag '{tag_name}' non trovato nella sezione '{catalog_section}' del catalogo {self.catalog_path}")
                    values = []
                expanded.extend(values)
            else:
                expanded.append(item)
        return expanded

    def compile(self, abstract_rule):
        """Traduce la regola astratta (o una lista di regole) nel formato leggibile dal motore."""
        # Se riceve una lista di regole, le compila ricorsivamente una per una
        if isinstance(abstract_rule, list):
            return [self.compile(r) for r in abstract_rule]

        concrete_rule = abstract_rule.copy()

        # --- NUOVA LOGICA: Espansione dei pattern generici ---
        if "patterns" in concrete_rule:
            for item in concrete_rule.pop("patterns"):
                if isinstance(item, dict) and "tag" in item:
                    tag_name = item["tag"]
                    # Recupera l'intero blocco dal catalogo (es. il dict con xpath_rules e forbidden_calls)
                    pattern_data = self.catalog.get("patterns", {}).get(tag_name, {})
                    
                    # Fonde le chiavi del catalogo dentro la regola concreta
                    for engine_key, engine_values in pattern_data.items():
                        if engine_key not in concrete_rule:
                            concrete_rule[engine_key] = []
                        if isinstance(engine_values, list):
                            concrete_rule[engine_key].extend(engine_values)
        
        # Mappatura delle chiavi della regola JSON alle sezioni del Catalogo
        mapping = {
            "sources": "sources",
            "sinks": "sinks",
            "forbidden_functions": "forbidden_functions",
            "sanitizers": "sanitizers",
            "safe_contexts": "safe_contexts"
        }

        for rule_key, catalog_section in mapping.items():
            if rule_key in abstract_rule:
                concrete_rule[rule_key] = self._expand_tags(
                    abstract_rule[rule_key], 
                    catalog_section
                )

        return concrete_rule