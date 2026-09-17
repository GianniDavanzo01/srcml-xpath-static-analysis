#!/usr/bin/env python3
"""
language_adapter.py
--------------------

Il motore generico (taint_engine.py, structural_engine.py,
safe_context_matchers.py, sink_matchers.py) NON deve più contenere stringhe
hardcoded per un linguaggio, ma Deve invece interrogare un LanguageAdapter:

    adapter.is_assignment(node)
    adapter.resolve_call_name(call_node, imports)
    adapter.is_interpolated_string(text)
    ...

Aggiungere un linguaggio (Java, C#, ...) significa scrivere una nuova classe
che implementa LanguageAdapter. In modo da lasciare il motore sempre uguale
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ImportBinding:
    """Rappresenta un binding di import risolto a un nome canonico.

    Esempio Python:  'import os as sys'      -> local_name='sys',  canonical_name='os'
    Esempio Python:  'from os import system as run' -> local_name='run', canonical_name='os.system'
    """
    local_name: str
    canonical_name: str
    is_module: bool = True  # False se il binding punta a una funzione/simbolo, non a un modulo intero


class LanguageAdapter(ABC):

    name: str  # "python", "java", ...

    # ------------------------------------------------------------------ #
    # Riconoscimento strutturale (sostituisce i confronti testuali sparsi)
    # ------------------------------------------------------------------ #

    @abstractmethod
    def is_assignment(self, node, ns) -> bool:
        """True se `node` (tipicamente <src:expr_stmt> o <src:expr>) è
        un'assegnazione semplice (LHS = RHS)."""

    @abstractmethod
    def get_assignment_lhs_rhs(self, node, ns) -> tuple:
        """Ritorna (lhs_node, rhs_first_node) o (None, None). Isola il fatto
        che in Python il separatore è '=', in altri linguaggi la struttura
        AST prodotta da srcML può differire (es. dichiarazioni tipizzate)."""

    @abstractmethod
    def is_kwarg(self, argument_node, ns) -> bool:
        """True se l'argomento usa la sintassi nome=valore. In Java/C non
        esiste: l'adapter per quei linguaggi ritorna sempre False."""

    @abstractmethod
    def string_concat_operators(self) -> list:
        """Operatori che contano come concatenazione/formattazione stringhe.
        Python: ['+', '%']. Java/C#: ['+']. Da estendere per fstring-like."""

    @abstractmethod
    def is_interpolated_string(self, literal_text: str) -> bool:
        """f-string Python, template string JS, text block Java, ecc."""

    @abstractmethod
    def is_none_literal(self, text: str) -> bool:
        """'None' in Python, 'null' in Java/C#/JS, 'nil' in Ruby."""

    @abstractmethod
    def parse_numeric_literal(self, text: str):
        """Gestisce le notazioni numeriche language-specific (0o755 ottale
        Python, 0x.. esadecimale, underscore come separatori, ecc). Ritorna
        un int o None se non interpretabile."""

    @abstractmethod
    def normalize_string_literal(self, text: str) -> str:
        """Normalizza apici/prefissi (f/r/b in Python) per confronti safe."""

    # ------------------------------------------------------------------ #
    # Import e risoluzione dei nomi (punto 7: 'os.system' vs 'qualsiasi.system')
    # ------------------------------------------------------------------ #

    @abstractmethod
    def resolve_imports(self, unit_node, ns) -> list:
        """Analizza tutte le direttive di import del file e ritorna una
        lista di ImportBinding, gestendo alias (import x as y), import
        parziali (from x import y), wildcard, ecc."""

    @abstractmethod
    def resolve_call_name(self, call_node, ns, imports: list) -> str:
        """Ritorna il nome CANONICO e completo della funzione invocata,
        risolvendo gli import. Es: con `import os as sys`, la chiamata
        `sys.system(...)` deve risolvere a 'os.system', non a 'sys.system'.
        Se non risolvibile, fallback sul nome letterale (comportamento
        attuale di get_call_name in common.py)."""


    @abstractmethod
    def get_interpolated_variables(self, literal_text: str) -> list[str]:
        """Estrae l'elenco dei nomi di variabili usate dentro una stringa interpolata."""

    @abstractmethod
    def string_formatting_operator_roles(self) -> dict:
        """Mappa RUOLO SEMANTICO -> operatore, per i costrutti che il motore
        deve distinguere esplicitamente (concatenazione vs formattazione
        printf-style). Un linguaggio che non ha un certo ruolo (es. Java non ha
        l'equivalente di '%' per le stringhe) semplicemente non lo include nel
        dict, e la regola corrispondente resta inattiva senza bisogno di
        toccare il motore."""

    # language_adapter.py, nel contratto astratto
    @abstractmethod
    def negation_operator(self) -> str:
        """Operatore di negazione booleana. Python: 'not' (parola chiave,
        separata da spazio dall'operando). C/Java/C#: '!' (prefisso, attaccato)."""

    @abstractmethod
    def is_boolean_literal(self, text: str) -> bool:
        """"""

    @abstractmethod
    def reference_comparison_operators(self) -> list:
        """Operatori di confronto per identità/riferimento. Python: ['is', 'is not'].
        Java/C/C#: lista vuota (l'identità si confronta con '==', già coperto da
        altre regole/sink, quindi questa categoria di regola resta inattiva)."""


    @abstractmethod
    def assignment_operator_token(self) -> str:
        """Il token letterale dell'operatore di assegnazione semplice, per i
        pochi punti del motore che devono costruirlo dentro una query XPath
        dinamica invece di passare da is_assignment/get_assignment_lhs_rhs
        (es. pattern kwarg-like 'nome = valore' senza uno statement completo
        a disposizione). Python: '='."""

    @abstractmethod
    def equality_operator(self) -> str:
        """Operatore testuale usato per il confronto di uguaglianza (es. '==')."""

    @abstractmethod
    def get_parameter_name_and_type(self, param_node, namespaces):
            """Estrae nome e tipo da un parametro (<src:parameter>) in Python."""

    @abstractmethod
    def member_access_operator(self) -> str:
        """Operatore usato per accedere a metodi e attributi.
        Python/Java/C#: '.'  -  PHP: '->'"""


    @abstractmethod
    def taint_block_functions(self) -> list:
        """Nomi di funzioni/metodi built-in del linguaggio il cui valore di
        ritorno non può più contenere il contenuto originale di una stringa
        taintata (es. len, hash, bool in Python restituiscono un tipo
        completamente diverso dall'input). Un argomento taintato passato a
        una di queste NON propaga il taint attraverso quella chiamata."""

# ---------------------------------------------------------------------- #
# Implementazione Python
# ---------------------------------------------------------------------- #

class PythonAdapter(LanguageAdapter):
    name = "python"

    OCTAL_RE = re.compile(r"^0[oO][0-7]+$")
    HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
    BIN_RE = re.compile(r"^0[bB][01]+$")

    def is_assignment(self, node, ns) -> bool:
        return bool(node.xpath(".//src:operator[text()='='][1]", namespaces=ns)) \
            if not node.tag.endswith("}operator") else False

    def get_assignment_lhs_rhs(self, node, ns):
        op = node.xpath(".//src:operator[text()='='][1]", namespaces=ns)
        if not op:
            return None, None
        op = op[0]
        lhs_nodes = op.xpath("./preceding-sibling::*[not(self::src:annotation)]", namespaces=ns)
        rhs_nodes = op.xpath("./following-sibling::*", namespaces=ns)
        lhs = lhs_nodes[-1] if lhs_nodes else None
        rhs = rhs_nodes[0] if rhs_nodes else None
        return lhs, rhs

    def is_kwarg(self, argument_node, ns) -> bool:
        # Cerca il nome del parametro
        name_nodes = argument_node.xpath("./src:name[1]", namespaces=ns)
        if not name_nodes:
            return False
            
        # Caso 1: srcML lo incapsula in un tag <operator> (comportamento standard)
        if argument_node.xpath("./src:operator[1][text()='=']", namespaces=ns):
            return True
            
        # Caso 2: srcML lo lascia come testo "libero" subito dopo il tag <name>
        tail_text = name_nodes[0].tail
        if tail_text and "=" in tail_text:
            return True
            
        return False

    def string_concat_operators(self) -> list:
        return ["+", "%"]  

    def is_interpolated_string(self, literal_text: str) -> bool:
        t = literal_text.strip()
        return t.startswith(("f'", 'f"', "F'", 'F"', "rf'", 'rf"', "fr'", 'fr"'))

    def is_none_literal(self, text: str) -> bool:
        return text.strip() == "None"

    def parse_numeric_literal(self, text: str):
        t = text.strip().replace("_", "")
        try:
            if self.OCTAL_RE.match(t):
                return int(t, 8)
            if self.HEX_RE.match(t):
                return int(t, 16)
            if self.BIN_RE.match(t):
                return int(t, 2)
            return int(t)
        except ValueError:
            try:
                return int(float(t))
            except ValueError:
                return None

    def normalize_string_literal(self, text: str) -> str:
        t = text.strip()
        # rimuove prefissi f/r/b/u in qualsiasi combinazione e uniforma gli apici
        t = re.sub(r"^[fFrRbBuU]{1,2}(?=['\"])", "", t)
        if len(t) >= 2 and t[0] in "'\"" and t[-1] == t[0]:
            t = t[1:-1]
        return t

    def resolve_imports(self, unit_node, ns) -> list:
        
        bindings = []
 
        for imp in unit_node.xpath(".//src:import", namespaces=ns):
            from_nodes = imp.xpath("./src:from", namespaces=ns)
 
            if from_nodes:
                # from MODULO import simbolo [as alias], simbolo2 [as alias2], ...
                module_name_nodes = from_nodes[0].xpath("./src:name", namespaces=ns)
                module = "".join(module_name_nodes[0].itertext()).strip() if module_name_nodes else ""
 
                imported_names = imp.xpath(
                    "./src:name[not(ancestor::src:from) and not(ancestor::src:alias)]",
                    namespaces=ns,
                )
                for n in imported_names:
                    symbol = "".join(n.itertext()).strip()
                    if not symbol:
                        continue
                    canonical = f"{module}.{symbol}" if module else symbol
                    alias_nodes = n.xpath("following-sibling::src:alias[1]//src:name", namespaces=ns)
                    local = "".join(alias_nodes[0].itertext()).strip() if alias_nodes else symbol
                    bindings.append(ImportBinding(local_name=local, canonical_name=canonical, is_module=False))
 
            else:
                # import MODULO [as alias] [, MODULO2 [as alias2]]
                names = imp.xpath("./src:name[not(ancestor::src:alias)]", namespaces=ns)
                for n in names:
                    canonical = "".join(n.itertext()).strip()
                    if not canonical:
                        continue
                    alias_nodes = n.xpath("following-sibling::src:alias[1]//src:name", namespaces=ns)
                    local = "".join(alias_nodes[0].itertext()).strip() if alias_nodes else canonical.split(".")[0]
                    bindings.append(ImportBinding(local_name=local, canonical_name=canonical))
 
        return bindings

    def resolve_call_name(self, call_node, ns, imports: list) -> str:
        name_nodes = call_node.xpath("./src:name", namespaces=ns)
        if not name_nodes:
            return None
        raw = "".join(name_nodes[0].itertext()).strip()
        if not raw:
            return None

        # PREVENZIONE DOPPIO PREFISSO: se è già qualificato con un modulo noto, ritornalo così com'è
        for binding in imports:
            if raw == binding.canonical_name or raw.startswith(f"{binding.canonical_name}."):
                return raw

        head, _, rest = raw.partition(".")
        for binding in imports:
            if binding.local_name == head:
                if binding.is_module:
                    return f"{binding.canonical_name}.{rest}" if rest else binding.canonical_name
                if not rest:
                    return binding.canonical_name
                    
        return raw 


    def get_interpolated_variables(self, literal_text: str) -> list[str]:
        # Cerca tutto quello che c'è tra { e } ignorando eventuali specificatori di formato
        matches = re.findall(r"\{([a-zA-Z0-9_]+)[^}]*\}", literal_text)
        return matches

    def string_formatting_operator_roles(self) -> dict:
        return {"concat": "+", "percent_format": "%"}

    def negation_operator(self) -> str:
        return "not"


    def is_boolean_literal(self, text: str) -> bool:
        return text.strip() in ("True", "False")

    def reference_comparison_operators(self) -> list:
        return ["is", "is not"]

    def assignment_operator_token(self) -> str:
        return "="

    def equality_operator(self) -> str:
        return "=="

    def get_parameter_name_and_type(self, param_node, namespaces):
        """Estrae nome e tipo da un parametro (<src:parameter>) in Python."""
        # In Python il tipo è dentro l'annotazione
        type_nodes = param_node.xpath("./src:annotation/src:expr", namespaces=namespaces)
        type_text = "".join(type_nodes[0].itertext()).strip() if type_nodes else ""
        
        
        name_nodes = param_node.xpath("./src:name[1]", namespaces=namespaces)
        name_text = "".join(name_nodes[0].itertext()).strip() if name_nodes else ""
        
        return name_text, type_text


    def member_access_operator(self) -> str:
        return "."


    def taint_block_functions(self) -> list:
        return ["len", "hash", "bool", "isinstance", "id", "type", "int","float"]

# ---------------------------------------------------------------------- #
# Implementazione Java
# ---------------------------------------------------------------------- #

class JavaAdapter(LanguageAdapter):
    name = "java"

    def is_assignment(self, node, ns) -> bool:
        # Java usa expr_stmt per riassegnazioni (x = 10;) e decl_stmt per dichiarazioni (int x = 5;)
        if node.tag.endswith("expr_stmt"):
            return bool(node.xpath(".//src:operator[text()='='][1]", namespaces=ns))
        if node.tag.endswith("decl_stmt"):
            return bool(node.xpath(".//src:init", namespaces=ns))
        return False

    def get_assignment_lhs_rhs(self, node, ns):
        if node.tag.endswith("expr_stmt"):
            op = node.xpath(".//src:operator[text()='='][1]", namespaces=ns)
            if not op:
                return None, None
            lhs_nodes = op[0].xpath("./preceding-sibling::*", namespaces=ns)
            rhs_nodes = op[0].xpath("./following-sibling::*", namespaces=ns)
            return (lhs_nodes[-1] if lhs_nodes else None, rhs_nodes[0] if rhs_nodes else None)
            
        if node.tag.endswith("decl_stmt"):
            decl = node.xpath(".//src:decl[1]", namespaces=ns)
            if not decl:
                return None, None
            # In Java: <decl> <type>int</type> <name>x</name> <init>= <expr>5</expr></init> </decl>
            lhs = decl[0].xpath("./src:name", namespaces=ns)
            rhs = decl[0].xpath("./src:init/src:expr | ./src:init/src:decl", namespaces=ns)
            return (lhs[0] if lhs else None, rhs[0] if rhs else None)
            
        return None, None

    def is_kwarg(self, argument_node, ns) -> bool:
        # Java NON supporta i keyword arguments nelle chiamate a funzione
        return False

    def string_concat_operators(self) -> list:
        return ["+"]

    def is_interpolated_string(self, literal_text: str) -> bool:
        # Supporto per String Templates (es. STR."Hello \{name}")
        t = literal_text.strip()
        return t.startswith("STR.") or "\\{" in t

    def get_interpolated_variables(self, literal_text: str) -> list[str]:
        # Cattura le variabili dentro i blocchi \{ ... }
        return re.findall(r"\\\{([a-zA-Z0-9_]+)[^}]*\}", literal_text)

    def is_none_literal(self, text: str) -> bool:
        return text.strip() == "null"

    def parse_numeric_literal(self, text: str):
        t = text.strip().replace("_", "").lower()
        # Rimuove i suffissi di tipo di Java (float, long, double)
        if t.endswith(('f', 'l', 'd')):
            t = t[:-1]
            
        try:
            if t.startswith("0x"):
                return int(t, 16)
            if t.startswith("0b"):
                return int(t, 2)
            # In Java i numeri che iniziano per 0 (es: 0755) sono ottali!
            if t.startswith("0") and len(t) > 1 and t[1].isdigit():
                return int(t, 8)
            return int(t)
        except ValueError:
            try:
                return int(float(t))
            except ValueError:
                return None

    def normalize_string_literal(self, text: str) -> str:
        t = text.strip()
        if t.startswith("STR."):
            t = t[4:]
        if len(t) >= 2 and t[0] == '"' and t[-1] == '"':
            t = t[1:-1]
        return t

    def resolve_imports(self, unit_node, ns) -> list:
        bindings = []
        for imp in unit_node.xpath(".//src:import", namespaces=ns):
            name_nodes = imp.xpath("./src:name", namespaces=ns)
            if not name_nodes:
                continue
                
            full_name = "".join(name_nodes[0].itertext()).strip()
            if not full_name:
                continue

            # Gestione wildcard: import java.util.*;
            if full_name.endswith(".*"):
                bindings.append(ImportBinding(
                    local_name="*", 
                    canonical_name=full_name[:-2], 
                    is_module=True
                ))
            else:
                # import java.util.List; -> local: List, canonical: java.util.List
                local_name = full_name.split(".")[-1]
                bindings.append(ImportBinding(
                    local_name=local_name, 
                    canonical_name=full_name, 
                    is_module=False
                ))
                
        return bindings

    def resolve_call_name(self, call_node, ns, imports) -> str:
            name_nodes = call_node.xpath("./src:name", namespaces=ns)
            if not name_nodes:
                return None
                
            raw_name = "".join(name_nodes[0].itertext()).strip()
            
            parts = name_nodes[0].xpath("./src:name", namespaces=ns)
            ops = name_nodes[0].xpath("./src:operator[text()='.']", namespaces=ns)
            
            if len(parts) >= 2 and ops:
                var_name = "".join(parts[0].itertext()).strip()
                method_name = "".join(parts[-1].itertext()).strip()
                
                # Cerca il nodo di scope più vicino (blocco, funzione, classe o l'intero file unit)
                # e cerca al suo interno la dichiarazione della variabile
                xpath_query = (
                    f"ancestor::*[self::src:block or self::src:function or self::src:class or self::src:unit][1]"
                    f"//src:decl[src:name[text()='{var_name}']]"
                )
                decls = call_node.xpath(xpath_query, namespaces=ns)
                    
                if decls:
                    # Estrae il tipo dal nodo <type><name>
                    type_nodes = decls[-1].xpath("./src:type//src:name", namespaces=ns)
                    if type_nodes:
                        var_type = "".join(type_nodes[0].itertext()).strip()
                        
                        #  restituisce "ScriptEngine.eval"
                        return f"{var_type}.{method_name}"
                        
            return raw_name

    def string_formatting_operator_roles(self) -> dict:
        return {"concat": "+"}

    def negation_operator(self) -> str:
        return "!"

    def assignment_operator_token(self) -> str:
        return "="

    def reference_comparison_operators(self) -> list:
        # In Java == e != confrontano il reference in memoria degli oggetti
        return ["==", "!="]

    def is_boolean_literal(self, text: str) -> bool:
        return text.strip() in ("true", "false")

    def equality_operator(self) -> str:
        return "=="

    def get_parameter_name_and_type(self, param_node, namespaces):
        decl = param_node.xpath("./src:decl[1]", namespaces=namespaces)
        if not decl:
            return None, None
        type_nodes = decl[0].xpath("./src:type[1]", namespaces=namespaces)
        type_text = "".join(type_nodes[0].itertext()).strip() if type_nodes else ""
        name_nodes = decl[0].xpath("./src:name[1]", namespaces=namespaces)
        name_text = "".join(name_nodes[0].itertext()).strip() if name_nodes else ""
        return name_text, type_text


    def member_access_operator(self) -> str:
        return "."


    def taint_block_functions(self) -> list:
        return ["length", "hashCode", "isEmpty", "equals", "compareTo"]



# ---------------------------------------------------------------------- #
# Registro / dispatch
# ---------------------------------------------------------------------- #

ADAPTERS = {
    "python": PythonAdapter(),
    "java": JavaAdapter(),
}


def get_adapter(unit_node) -> LanguageAdapter:
    """Sceglie l'adapter leggendo l'attributo language="..." che srcML scrive
    su ogni <unit> (es. language="Python", language="Java", language="C++").
    """
    lang = (unit_node.get("language") or "python").lower()
    adapter = ADAPTERS.get(lang)
    if adapter is None:
        raise NotImplementedError(
            f"Nessun LanguageAdapter registrato per '{lang}'. "
            f"Linguaggi disponibili: {sorted(ADAPTERS)}"
        )
    return adapter