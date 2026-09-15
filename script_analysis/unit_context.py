from common import NS

class UnitContext:
    __slots__ = (
        "unit", "calls", "names", "strings", "imports_nodes",
        "assignments", "conditions", "_itertext_cache",
    )

    def __init__(self, unit, adapter):
        self.unit = unit
        self.calls = unit.xpath(".//src:call", namespaces=NS)
        self.names = unit.xpath(".//src:name", namespaces=NS)
        self.strings = unit.xpath(".//src:literal[@type='string']", namespaces=NS)
        self.imports_nodes = unit.xpath(".//src:import", namespaces=NS)
        self.conditions = unit.xpath(".//src:if_stmt//src:condition", namespaces=NS)

        self.assignments = [
            stmt for stmt in unit.xpath(".//src:expr_stmt | .//src:decl_stmt", namespaces=NS)
            if adapter.is_assignment(stmt, NS)
        ]
        
        self._itertext_cache = {}

    def text_of(self, node) -> str:
        key = id(node)
        cached = self._itertext_cache.get(key)
        if cached is None:
            cached = "".join(node.itertext())
            self._itertext_cache[key] = cached
        return cached