from collections import namedtuple
from common import NS, name_text

AssignInfo = namedtuple("AssignInfo", "stmt lhs rhs var scope rhs_all")


def build_assign_infos(assignments, adapter, unit):
    """Calcola UNA volta lhs/rhs/scope/rhs_all di ogni assegnazione con LHS <name>."""
    infos = []
    for stmt in assignments:
        lhs, rhs = adapter.get_assignment_lhs_rhs(stmt, NS)
        if lhs is None or not lhs.tag.endswith("name"):
            continue
        parent_func = stmt.xpath("ancestor::src:function[1]", namespaces=NS)
        scope = parent_func[0] if parent_func else unit
        rhs_all = rhs.xpath("self::* | following-sibling::*", namespaces=NS) if rhs is not None else []
        # infos.append(AssignInfo(stmt, lhs, rhs, "".join(lhs.itertext()).strip(), scope, rhs_all))
        infos.append(AssignInfo(stmt, lhs, rhs, name_text(lhs), scope, rhs_all))
    return infos


class UnitContext:
    __slots__ = (
        "unit", "calls", "names", "strings", "imports_nodes",
        "assignments", "conditions", "_itertext_cache", "catalog",
        "assign_infos", "assign_by_stmt",
    )

    def __init__(self, unit, adapter, catalog=None):
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
        self.assign_infos = build_assign_infos(self.assignments, adapter, unit)
        self.assign_by_stmt = {i.stmt: i for i in self.assign_infos}

        self._itertext_cache = {}
        self.catalog = catalog or {}

    def text_of(self, node) -> str:
        key = id(node)
        cached = self._itertext_cache.get(key)
        if cached is None:
            cached = "".join(node.itertext())
            self._itertext_cache[key] = cached
        return cached