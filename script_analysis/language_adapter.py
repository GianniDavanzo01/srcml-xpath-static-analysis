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

    @abstractmethod
    def negation_operator(self) -> str:
        """Operatore di negazione booleana. Python: 'not' (parola chiave,
        separata da spazio dall'operando). C/Java/C#: '!' (prefisso, attaccato)."""

    @abstractmethod
    def is_boolean_literal(self, text: str) -> bool:
        """Scrittura dei letterali booleani del relativo linguaggio"""

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
            """Estrae nome e tipo da un parametro (<src:parameter>)."""

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

    @abstractmethod
    def taint_propagating_calls(self) -> dict:
        """Mappa nome_funzione -> indice dell'argomento di OUTPUT (scritto per
        side-effect, non tramite valore di ritorno). Se un qualsiasi altro
        argomento della call e' taintato, l'argomento a quell'indice diventa
        taintato a sua volta. Es. C: sprintf(buf, fmt, tainted) -> buf
        (indice 0) diventa taintato. Linguaggi senza questo pattern (Python,
        Java) ritornano un dict vuoto."""


    @abstractmethod
    def extract_membership_relations(self, condition_node, ns) -> list[dict]:
        """Estrae i nodi LHS, RHS e lo stato di negazione per le condizioni di appartenenza 
        (es. 'x in y' in Python, 'y.contains(x)' in Java).
        Ritorna una lista di dict: [{"lhs": node, "rhs": node, "is_negated": bool}]"""

    @abstractmethod
    def is_collection_assignment(self, assignment_node, ns) -> bool:
        """True se il lato destro dell'assegnazione inizializza una collezione
        nativa (lista, array, dizionario, set).
        Python: [1,2,3], {1,2,3}. Java/C: {1,2,3}."""

    @abstractmethod
    def find_exception_bindings(self, tree, ns) -> list:
        """Ritorna una lista di tuple (nome_variabile, scope_node) - una per
        ogni blocco except/catch che lega l'eccezione catturata a un nome.
        Lo scope_node e' il blocco di codice del catch, cosi' la variabile
        viene considerata taintata SOLO li' dentro, non in tutta la funzione."""


    @abstractmethod
    def requires_pointer_type_for_reference_comparison(self) -> bool:
        """True se reference_comparison_operators() è ambiguo senza conoscere
            il tipo degli operandi (C: '==' vale sia per interi sia per puntatori).
            Python/Java: False, l'operatore da solo è già inequivocabile."""

    @abstractmethod
    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        """Cerca la dichiarazione (locale o parametro) di var_name nello scope
    di name_node e ritorna il tipo dichiarato (es. 'char *'), o None se non
    trovato. Usato solo dai linguaggi con requires_pointer_type_for_reference_comparison() = True."""




    @abstractmethod
    def null_comparison_operators(self) -> dict:
        """
        Restituisce gli operatori usati per i confronti col null divisi per semantica.
        - 'falsy': verificano che la variabile SIA nulla (es. ==, is)
        - 'truthy': verificano che la variabile NON SIA nulla (es. !=, is not)
        """
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

    def taint_propagating_calls(self) -> dict:
        # Le stringhe Python sono immutabili: nessuna funzione scrive su un
        # argomento passato per riferimento come farebbe sprintf in C.
        return {}


    def extract_membership_relations(self, condition_node, ns) -> list[dict]:
        relations = []
        # srcML raggruppa nativamente sia 'in' che 'not in' in un singolo nodo <operator>
        membership_ops = condition_node.xpath(".//src:operator[text()='in' or text()='not in']", namespaces=ns)
        
        for op_node in membership_ops:
            op_text = "".join(op_node.itertext()).strip()
            is_negated = (op_text == "not in")
            
            # LHS: Il nodo precedente (tipicamente un <name> o un <expr>)
            prev_nodes = op_node.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=ns)
            if not prev_nodes:
                continue
            lhs_node = prev_nodes[-1]
            
            # RHS: Il nodo successivo (es. un <name>, <array>, o <tuple>)
            rhs_nodes = op_node.xpath("./following-sibling::*[not(self::src:comment)]", namespaces=ns)
            if not rhs_nodes:
                continue
            rhs_node = rhs_nodes[0]
            
            relations.append({
                "lhs": lhs_node,
                "rhs": rhs_node,
                "is_negated": is_negated
            })
            
        return relations

    def is_collection_assignment(self, assignment_node, ns) -> bool:
        op = assignment_node.xpath(".//src:operator[text()='='][1]", namespaces=ns)
        if not op:
            return False
            
        rhs = op[0].xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=ns)
        if not rhs:
            return False
            
        rhs_node = rhs[0]
        # Adattato ai tag reali di srcML per Python: <array> e <dictionary>
        tag = rhs_node.tag.split('}')[-1] if '}' in rhs_node.tag else rhs_node.tag
        return tag in ("array", "dictionary", "set")


    def find_exception_bindings(self, tree, ns) -> list:
        bindings = []
        for catch in tree.xpath(".//src:catch", namespaces=ns):
            alias_names = catch.xpath("./src:alias//src:name", namespaces=ns)
            if not alias_names:
                continue   # 'except Exception:' senza 'as e' -> nessuna variabile da tracciare
            var_name = "".join(alias_names[0].itertext()).strip()
            block = catch.xpath("./src:block[1]", namespaces=ns)
            if block:
                bindings.append((var_name, block[0]))
        return bindings

    def requires_pointer_type_for_reference_comparison(self) -> bool:
        return False

    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        return None

    def null_comparison_operators(self) -> dict:
        return {
            "falsy": ["==", "is"],
            "truthy": ["!=", "is not"]
        }

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
        t = text.strip().replace("_", "")
        is_hex = t.lower().startswith("0x")
        is_bin = t.lower().startswith("0b")

        if is_hex or is_bin:
            # In Java l'unico suffisso valido su hex/bin e' 'L' (long); mai
            # una cifra esadecimale, quindi rimovibile senza ambiguita'.
            core = re.sub(r'[lL]+$', '', t)
            try:
                return int(core, 16 if is_hex else 2)
            except ValueError:
                return None

        core = t
        if core.lower().endswith(('f', 'l', 'd')):
            core = core[:-1]
        try:
            # In Java i numeri che iniziano per 0 (es: 0755) sono ottali!
            if core.startswith("0") and len(core) > 1 and core[1:].isdigit():
                return int(core, 8)
            return int(core)
        except ValueError:
            try:
                return int(float(core))
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

            xpath_query_local = (
                f"ancestor::*[self::src:function or self::src:class or self::src:unit][1]"   # <-- 'src:block' tolto
                f"//src:decl[src:name[text()='{var_name}']]"
            )
            decls = call_node.xpath(xpath_query_local, namespaces=ns)

            # --- 2. Fallback sui Parametri (Se la variabile non è nel blocco) ---
            if not decls:
                xpath_query_param = (
                    f"ancestor::src:function[1]//src:parameter_list"
                    f"//src:decl[src:name[text()='{var_name}']]"
                )
                decls = call_node.xpath(xpath_query_param, namespaces=ns)

            if decls:
                decl_node = decls[-1]
                var_type = None
                seen = set()

                # Risale attraverso <type ref="prev"/> nelle dichiarazioni multiple
                # a tipo condiviso (es. 'ScriptEngine a, b, c = ...') finché non
                # trova il <decl> che possiede davvero il <type>.
                while decl_node is not None and id(decl_node) not in seen:
                    seen.add(id(decl_node))

                    type_nodes = decl_node.xpath("./src:type//src:name", namespaces=ns)
                    if type_nodes:
                        var_type = "".join(type_nodes[0].itertext()).strip()
                        break

                    type_node = decl_node.xpath("./src:type", namespaces=ns)
                    if type_node and type_node[0].get("ref") == "prev":
                        prev_decl = decl_node.xpath("preceding-sibling::src:decl[1]", namespaces=ns)
                        decl_node = prev_decl[0] if prev_decl else None
                    else:
                        decl_node = None

                if var_type:
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

    def taint_propagating_calls(self) -> dict:
        # Le String Java sono immutabili; StringBuilder/StringBuffer si
        # aggiornano tramite valore di ritorno (append restituisce this),
        # gia' coperto dalla propagazione via assegnazione/metodo standard.
        return {}

    def extract_membership_relations(self, condition_node, ns) -> list[dict]:
        relations = []
        contains_calls = condition_node.xpath(".//src:call[.//src:name[last()][text()='contains']]", namespaces=ns)
        
        for call_node in contains_calls:
            # RHS (es. 'lista' in lista.contains)
            rhs_nodes = call_node.xpath("./src:name/src:name[1]", namespaces=ns)
            
            # LHS (es. 'x' passato come argomento)
            lhs_nodes = call_node.xpath("./src:argument_list/src:argument/src:expr/*[1]", namespaces=ns)
            
            if not rhs_nodes or not lhs_nodes:
                continue
                
            # Identifica l'operatore '!' che si trova prima della <call>
            is_negated = False
            prev_sibling = call_node.xpath("preceding-sibling::src:operator[1]", namespaces=ns)
            if prev_sibling and "".join(prev_sibling[0].itertext()).strip() == "!":
                is_negated = True
                
            relations.append({
                "lhs": lhs_nodes[0],
                "rhs": rhs_nodes[0],
                "is_negated": is_negated
            })
            
        return relations

    def is_collection_assignment(self, assignment_node, ns) -> bool:
        # Array initializer (es. int[] arr = {1, 2, 3};) -> srcML usa <block>
        init_block = assignment_node.xpath(".//src:init/src:expr/src:block", namespaces=ns)
        if init_block:
            return True
            
        # Inizializzazioni tramite 'new' (es. new ArrayList<>(Arrays.asList(...)))
        new_obj = assignment_node.xpath(".//src:init/src:expr/src:call[.//src:name[text()='new']]", namespaces=ns)
        if new_obj:
            text = "".join(new_obj[0].itertext()).strip()
            if "List" in text or "Set" in text or "Collection" in text or "Array" in text:
                return True
                
        return False


    def find_exception_bindings(self, tree, ns) -> list:
        bindings = []
        for catch in tree.xpath(".//src:catch", namespaces=ns):
            param_names = catch.xpath("./src:parameter_list/src:parameter/src:decl/src:name[1]", namespaces=ns)
            if not param_names:
                continue
            var_name = "".join(param_names[0].itertext()).strip()
            block = catch.xpath("./src:block[1]", namespaces=ns)
            if block:
                bindings.append((var_name, block[0]))
        return bindings

    def requires_pointer_type_for_reference_comparison(self) -> bool:
        return False

    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        return None


    def null_comparison_operators(self) -> dict:
        return {
            "falsy": ["=="],
            "truthy": ["!="]
        }

# ---------------------------------------------------------------------- #
# Implementazione C
# ---------------------------------------------------------------------- #

class CAdapter(LanguageAdapter):
    name = "c"

    def is_assignment(self, node, ns) -> bool:
        # Gestisce sia riassegnazioni (expr_stmt) che inizializzazioni (decl_stmt)
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
            lhs = decl[0].xpath("./src:name", namespaces=ns)
            rhs = decl[0].xpath("./src:init/src:expr | ./src:init/src:decl", namespaces=ns)
            return (lhs[0] if lhs else None, rhs[0] if rhs else None)
            
        return None, None

    def is_kwarg(self, argument_node, ns) -> bool:
        # Il linguaggio C non supporta keyword arguments
        return False

    def string_concat_operators(self) -> list:
        # In C l'operatore '+' su char* esegue aritmetica dei puntatori, non concatenazione
        return []

    def is_interpolated_string(self, literal_text: str) -> bool:
        # Il C non ha stringhe interpolate native (si usa sprintf/snprintf)
        return False

    def get_interpolated_variables(self, literal_text: str) -> list[str]:
        return []

    def is_none_literal(self, text: str) -> bool:
        # In C si usa NULL per i puntatori
        return text.strip() == "NULL"

    def parse_numeric_literal(self, text: str):
        t = text.strip()
        is_hex = t.lower().startswith("0x")
        is_bin = t.lower().startswith("0b")

        if is_hex or is_bin:
            # Solo u/l sono suffissi validi qui: mai cifre esadecimali,
            # quindi rimovibili senza ambiguita' con 'e'/'f'.
            core = re.sub(r'[ulUL]+$', '', t)
            try:
                return int(core, 16 if is_hex else 2)
            except ValueError:
                return None

        core = re.sub(r'[ulfeULFE]+$', '', t)
        try:
            if core.startswith("0") and len(core) > 1 and core[1:].isdigit():
                return int(core, 8)
            return int(core)
        except ValueError:
            try:
                return int(float(core))
            except ValueError:
                return None

    def normalize_string_literal(self, text: str) -> str:
        t = text.strip()
        # Rimuove prefissi wide-char o utf (L, u8, u, U)
        t = re.sub(r'^(L|u8|u|U)', '', t)
        if len(t) >= 2 and t[0] == '"' and t[-1] == '"':
            t = t[1:-1]
        return t

    def resolve_imports(self, unit_node, ns) -> list:
        bindings = []
        # Per C, srcML usa il namespace cpp per le direttive del preprocessore
        cpp_ns = {"cpp": "http://www.srcML.org/srcML/cpp"}
        
        for inc in unit_node.xpath(".//cpp:include", namespaces=cpp_ns):
            file_nodes = inc.xpath("./cpp:file", namespaces=cpp_ns)
            if file_nodes:
                file_text = "".join(file_nodes[0].itertext()).strip()
                # Rimuove < > o " " dal nome del file incluso
                clean_name = file_text.strip('<>"')
                
                # In C non ci sono alias, il file importato mappa se stesso globalmente
                bindings.append(ImportBinding(
                    local_name=clean_name, 
                    canonical_name=clean_name, 
                    is_module=True
                ))
        return bindings

    def resolve_call_name(self, call_node, ns, imports) -> str:
        name_nodes = call_node.xpath("./src:name", namespaces=ns)
        if not name_nodes:
            return None

        raw_name = "".join(name_nodes[0].itertext()).strip()

        parts = name_nodes[0].xpath("./src:name", namespaces=ns)
        ops = name_nodes[0].xpath("./src:operator[text()='.' or text()='->']", namespaces=ns)

        if len(parts) >= 2 and ops:
            var_name = "".join(parts[0].itertext()).strip()
            method_name = "".join(parts[-1].itertext()).strip()

            xpath_query_local = (
                f"ancestor::*[self::src:function or self::src:unit][1]"
                f"//src:decl[src:name[text()='{var_name}']]"
            )
            decls = call_node.xpath(xpath_query_local, namespaces=ns)

            if not decls:
                xpath_query_param = (
                    f"ancestor::src:function[1]//src:parameter_list"
                    f"//src:decl[src:name[text()='{var_name}']]"
                )
                decls = call_node.xpath(xpath_query_param, namespaces=ns)

            if decls:
                decl_node = decls[-1]
                var_type = None
                seen = set()

                while decl_node is not None and id(decl_node) not in seen:
                    seen.add(id(decl_node))

                    type_nodes = decl_node.xpath("./src:type//src:name", namespaces=ns)
                    if type_nodes:
                        var_type = "".join(type_nodes[0].itertext()).strip()
                        break

                    type_node = decl_node.xpath("./src:type", namespaces=ns)
                    if type_node and type_node[0].get("ref") == "prev":
                        prev_decl = decl_node.xpath("preceding-sibling::src:decl[1]", namespaces=ns)
                        decl_node = prev_decl[0] if prev_decl else None
                    else:
                        decl_node = None

                if var_type:
                    return f"{var_type}.{method_name}"

        return raw_name

    def string_formatting_operator_roles(self) -> dict:
        # Non ci sono operatori di formato nativi inline (si usano funzioni di libreria)
        return {}

    def negation_operator(self) -> str:
        return "!"

    def assignment_operator_token(self) -> str:
        return "="

    def reference_comparison_operators(self) -> list:
        # In C, == e != confrontano i valori diretti, che per i puntatori sono gli indirizzi di memoria
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
        # Unisce il nome del tipo (es: char) con eventuali modificatori (es: *)
        type_text = "".join(type_nodes[0].itertext()).strip() if type_nodes else ""
        type_text = re.sub(r'\s+', ' ', type_text) # Pulisce spazi extra
        
        name_nodes = decl[0].xpath("./src:name[1]", namespaces=namespaces)
        name_text = "".join(name_nodes[0].itertext()).strip() if name_nodes else ""
        
        return name_text, type_text

    def member_access_operator(self) -> str:
        # Operatore base per l'accesso ai membri. L'adapter gestisce esplicitamente 
        # anche '->' in resolve_call_name.
        return "."

    def taint_block_functions(self) -> list:
        # Funzioni C che restituiscono numeri o bool analizzando buffer/stringhe,
        # interrompendo la propagazione del taint come stringa.
        return ["strlen", "sizeof", "atoi", "atol", "atof", "strcmp", "strncmp"]

    def taint_propagating_calls(self) -> dict:
        # Funzioni libc che scrivono il risultato in un buffer passato come
        # argomento (side-effect), non tramite valore di ritorno: se un
        # qualsiasi altro argomento e' taintato, il buffer di output lo
        # diventa a sua volta. Indice = posizione dell'argomento di output.
        return {
            "sprintf": 0, "snprintf": 0,
            "strcpy": 0, "strncpy": 0,
            "strcat": 0, "strncat": 0,
            "memcpy": 0,
        }

    def extract_membership_relations(self, condition_node, ns) -> list[dict]:
        # Il linguaggio C non ha un costrutto 'in' o un metodo '.contains()' nativo.
        # L'analisi di membership richiede funzioni custom (es. strchr per stringhe)
        # o iterazioni su array. Riconoscerlo in una singola condizione non è fattibile in modo generico.
        return []

    def is_collection_assignment(self, assignment_node, ns) -> bool:
        # Inizializzazione di array statici (es. int arr[] = {1, 2, 3};)
        init_block = assignment_node.xpath(".//src:init/src:expr/src:block", namespaces=ns)
        if init_block:
            return True
        return False

    def find_exception_bindings(self, tree, ns) -> list:
        return []   # il C non ha un meccanismo di eccezioni: CWE-209 in questa forma
                # (variabile d'eccezione -> risposta HTTP) non è applicabile


    def requires_pointer_type_for_reference_comparison(self) -> bool:
        return True   # == in C è ambiguo (numerico vs puntatore) senza sapere il tipo

    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        """Cerca la dichiarazione (locale o parametro) di var_name e ritorna
        il suo tipo dichiarato, es. 'char *'."""
        xpath_query_local = (
            f"ancestor::*[self::src:function or self::src:unit][1]"
            f"//src:decl[src:name[text()='{var_name}']]"
        )
        decls = name_node.xpath(xpath_query_local, namespaces=ns)
        if not decls:
            xpath_query_param = (
                f"ancestor::src:function[1]//src:parameter_list//src:decl[src:name[text()='{var_name}']]"
            )
            decls = name_node.xpath(xpath_query_param, namespaces=ns)
        if not decls:
            return None

        decl_node = decls[-1]
        seen = set()
        while decl_node is not None and id(decl_node) not in seen:
            seen.add(id(decl_node))
            type_nodes = decl_node.xpath("./src:type", namespaces=ns)
            if type_nodes and type_nodes[0].get("ref") != "prev":
                return "".join(type_nodes[0].itertext()).strip()
            prev_decl = decl_node.xpath("preceding-sibling::src:decl[1]", namespaces=ns)
            decl_node = prev_decl[0] if prev_decl else None
        return None


    def null_comparison_operators(self) -> dict:
        return {
            "falsy": ["=="],
            "truthy": ["!="]
        }


# ---------------------------------------------------------------------- #
# Registro / dispatch
# ---------------------------------------------------------------------- #

ADAPTERS = {
    "python": PythonAdapter(),
    "java": JavaAdapter(),
    "c": CAdapter(),
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