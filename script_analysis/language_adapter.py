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
from dataclasses import dataclass

from lxml import etree

from common import macro_map, expand_macro_name, _pos_key, find_assignments, enclosing_scope, name_text, get_decl_index, get_class_field_index


_MACRO_ALIAS_RE = re.compile(r"^\s*\(?\s*([A-Za-z_]\w*)\s*\)?\s*$")  # #define FOPEN fopen
_MACRO_FWD_RE   = re.compile(r"^\s*([A-Za-z_]\w*)\s*\(")             # #define F(p) fopen(p,"r")
_C_STRING_VALUE_RE = re.compile(r'^\(?\s*(?:(?:L|u8|u|U)?"(?:[^"\\\n]|\\.)*"\s*)+\)?$')  #Verificare che la define sia costante: #define PASSWORD "ABCD1234!"


_SRC_NS = {"src": "http://www.srcML.org/srcML/src"}
_JS_PARAM_NAME_XP = etree.XPath("./src:decl/src:name[1]", namespaces=_SRC_NS)


@dataclass
class ImportBinding:
    """Rappresenta un binding di import risolto a un nome canonico.

    Esempio Python:  'import os as sys'      -> local_name='sys',  canonical_name='os'
    Esempio Python:  'from os import system as run' -> local_name='run', canonical_name='os.system'
    """
    local_name: str
    canonical_name: str
    node: etree._Element = None
    is_macro: bool = False 

class LanguageAdapter(ABC):

    name: str  # "python", "java", ...

    @abstractmethod
    def potential_assignment_xpath(self) -> str:
        """Potenziale statement di assegnazione"""
    
    @abstractmethod
    def is_assignment(self, node, ns) -> bool:
        """True se `node` (tipicamente <src:expr_stmt> o <src:expr>) è
        un'assegnazione semplice (LHS = RHS)."""

    @abstractmethod
    def get_assignment_lhs_rhs(self, node, ns) -> tuple:
        """Ritorna (lhs_node, rhs_first_node) o (None, None). """

    @abstractmethod
    def is_kwarg(self, argument_node, ns) -> bool:
        """True se l'argomento usa la sintassi nome=valore. In Java/C non
        esiste: l'adapter per quei linguaggi ritorna sempre False."""

    @abstractmethod
    def string_concat_operators(self) -> list:
        """Operatori che contano come concatenazione/formattazione stringhe.
        Python: ['+', '%']. Java/C#: ['+']."""

    @abstractmethod
    def is_interpolated_string(self, literal_text: str) -> bool:
        """f-string Python, template string JS, text block Java, ecc."""

    @abstractmethod
    def is_none_literal(self, text: str) -> bool:
        """'None' in Python, 'null' in Java/C#/JS."""

    @abstractmethod
    def parse_numeric_literal(self, text: str):
        """Gestisce le notazioni numeriche language-specific (0o755 ottale
        Python, 0x.. esadecimale, underscore come separatori, ecc). Ritorna
        un int o None se non interpretabile."""

    @abstractmethod
    def normalize_string_literal(self, text: str) -> str:
        """Normalizza apici/prefissi (f/r/b in Python) per confronti safe."""


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
    def negation_operator(self) -> str:
        """Operatore di negazione booleana. Python: 'not' (parola chiave,
        separata da spazio dall'operando). C/Java/C#: '!' (prefisso, attaccato)."""

    @abstractmethod
    def is_boolean_literal(self, text: str) -> bool:
        """Scrittura dei letterali booleani del relativo linguaggio"""

    @abstractmethod
    def reference_comparison_operators(self) -> list:
        """Operatori di confronto per identità/riferimento. Python: ['is', 'is not'].
        Java/C/C#: l'identità si confronta con '=='."""


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
    def logical_and_operator(self) -> list:
        """Operatori logici AND. Python: ['and']. C/Java: ['&&']."""

    @abstractmethod
    def logical_or_operator(self) -> list:
        """Operatori logici OR. Python: ['or']. C/Java: ['||']."""

    @abstractmethod
    def get_parameter_name_and_type(self, param_node, namespaces):
            """Estrae nome e tipo da un parametro (<src:parameter>)."""

    @abstractmethod
    def member_access_operator(self) -> list:
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
    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        """Cerca la dichiarazione (locale o parametro) di var_name nello scope
        di name_node e ritorna il tipo dichiarato (es. 'char *'), o None se non
        trovato."""


    @abstractmethod
    def null_comparison_operators(self) -> dict:
        """
        Restituisce gli operatori usati per i confronti col null divisi per semantica.
        - 'falsy': verificano che la variabile SIA nulla (es. ==, is)
        - 'truthy': verificano che la variabile NON SIA nulla (es. !=, is not)
        """


    @abstractmethod
    def taint_source_output_args(self) -> dict:
        """Mappa nome_funzione -> spec degli argomenti che la funzione RIEMPIE con
        dati esterni (source per side-effect, non per valore di ritorno).
        spec = {
            "indices": [int, ...],       # argomenti di output fissi
            "variadic_from": int,        # (opz.) tutti gli argomenti da questo indice in poi
            "return_tainted": bool,      # (opz., default False) il valore di ritorno e' anch'esso source
        }
        Linguaggi senza questo pattern ritornano {}."""


    @abstractmethod
    def get_parameter_name_node(self, param_node, ns):
        """Nodo <name> dell'identificatore del parametro, o None."""

    @abstractmethod
    def function_tags(self) -> list:
        """Tag srcML che definiscono uno scope di funzione (es. ['function'])."""

    @abstractmethod
    def lambda_tags(self) -> list:
        """Tag srcML delle funzioni anonime: confine di flusso, non scope di taint."""

    @abstractmethod
    def flow_exit_tags(self) -> list:
        """Tag srcML che interrompono il flusso (return, throw, ...)."""

    @abstractmethod
    def flow_exit_calls(self) -> list:
        """Nomi di chiamate che terminano il flusso (exit, abort, ...)."""

    @abstractmethod
    def noop_statement_tags(self) -> list:
        """Tag srcML di statement che non hanno effetto (es. 'pass' in Python)."""

    @abstractmethod
    def class_tags(self) -> list:
        """Tag srcML che definiscono un tipo/classe (es. ['class']). Lista vuota se il
        linguaggio non ha classi (C)."""


    def scope_axis(self, extra=()) -> str:
        """Asse XPath verso la funzione/costruttore che racchiude il nodo,
        con eventuali tag di ripiego (es. 'class', 'unit')."""
        tags = list(self.function_tags()) + list(extra)
        return "ancestor::*[" + " or ".join(f"self::src:{t}" for t in tags) + "][1]"

    def source_call_args_propagate_to_return(self) -> bool:
        """True se 'x = source(args...)' propaga il taint degli argomenti al
        valore di ritorno. False per linguaggi con source per side-effect (C)."""
        return True

    def taint_opaque_tags(self) -> list:
        """Tag srcML il cui contenuto non trasporta taint verso l'espressione
        che li racchiude (es. sizeof in C: il risultato dipende dal tipo, non
        dal contenuto). Default: nessuno."""
        return []

    def resolve_operand_type(self, node, ns):
        """Tipo dichiarato di un operando che sia un semplice identificatore, altrimenti None."""
        if node is None or not node.tag.endswith("}name"):
            return None
        text = "".join(node.itertext()).strip()
        if not text.isidentifier():
            return None
        return self.resolve_variable_type(node, text, ns)


    def is_cast_type_name(self, name_node) -> bool:
        """True se <name> fa parte del tipo di un cast. Default: nessun cast sintattico
        riconoscibile (Python, Java: il cast è un nodo a parte o non esiste)."""
        return False

    def extract_output_buffer_name(self, arg_node, ns) -> str | None:
        """Nome della variabile in un <src:argument>, ignorando tipi, indici,
        costrutti opachi (taint_opaque_tags) e cast."""      
        skip = ["ancestor::src:index", "ancestor::src:type"]
        skip += [f"ancestor::src:{t}" for t in self.taint_opaque_tags()]
        skip_xpath = " | ".join(skip)

        for n in arg_node.xpath(".//src:name[not(src:name)]", namespaces=ns):
            if n.xpath(skip_xpath, namespaces=ns):
                continue
            if self.is_cast_type_name(n):
                continue
            txt = name_text(n)
            if txt:
                return txt
        return None

    def is_reference_comparison(self, lhs_type, rhs_type) -> bool:
        """True se il confronto va segnalato. Default: nel dubbio segnala."""
        return True


    def resolve_name_text(self, text: str, imports: list, node=None) -> str:
        """Nome puntato (non call) -> nome canonico. Default: invariato."""
        return text


    _CR_XP = {}

    def _chain_receiver(self, call_node, ns):
        xp = LanguageAdapter._CR_XP.get(self.name)
        if xp is None:
            ops = " or ".join(f"text()='{o}'" for o in self.member_access_operator())
            xp = LanguageAdapter._CR_XP[self.name] = etree.XPath(
                f"preceding-sibling::*[1][self::src:operator and ({ops})]"
                f"/preceding-sibling::*[1][self::src:call]", namespaces=ns)
        r = xp(call_node)
        return r[0] if r else None

    def _chain_next(self, call_node, ns):
        """Call successiva nella catena: a.b(x).c() -> da b(x) ritorna c()."""
        ops = " or ".join(f"text()='{o}'" for o in self.member_access_operator())
        op = call_node.xpath(
            f"following-sibling::*[1][self::src:operator and ({ops})]", namespaces=ns)
        if not op:
            return None
        nxt = op[0].xpath("following-sibling::*[1][self::src:call]", namespaces=ns)
        return nxt[0] if nxt else None


    def normalize_member_access(self, name: str) -> str:
        """Riporta gli accessi a membro alla forma canonica '.' (C: s->fn == s.fn)."""
        for op in self.member_access_operator():
            if op != ".":
                name = name.replace(op, ".")
        return name

    def is_async_function(self, func_node, ns) -> bool:
        """True se la funzione è dichiarata async. Default: False (C, Java)."""
        return False

    def is_true_constant(self, text: str) -> bool:
        """True se il letterale è una costante sempre vera (while(true))."""
        t = text.strip()
        return self.is_boolean_literal(t) and t.lower() == "true"

    def is_false_constant(self, text: str) -> bool:
        t = text.strip()
        return self.is_boolean_literal(t) and t.lower() == "false"


    def loop_update_operators(self) -> dict:
        """Operatori che modificano la variabile di un ciclo.
        compound: 'x op= n'; unary: 'x++' / '--x'."""
        return {
            "compound": ["+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^="],
            "unary": ["++", "--"],
        }

    def is_identifier(self, text: str) -> bool:
        """True se `text` è un identificatore semplice (non un accesso a membro)."""
        return bool(re.match(r"^[A-Za-z_$][\w$]*$", text))

    def comparison_operators(self) -> list:
        return ["<", "<=", ">", ">=", "!=", "=="]

    def loop_exit_tags(self) -> list:
        """Tag che possono far uscire dal ciclo che li racchiude (come flow_exit_tags, senza 'continue')."""
        return [t for t in self.flow_exit_tags() if t != "continue"]

    def break_target_tags(self) -> list:
        """Costrutti che catturano un 'break' (un break dentro un loop annidato o uno switch
        non esce dal ciclo esterno)."""
        return ["while", "do", "for", "switch"]

    def canonical_literal(self, text: str) -> str:
        """Forma canonica per confrontare valori letterali (True/true -> true, None/null -> null)."""
        t = text.strip()
        if self.is_boolean_literal(t):
            return t.lower()
        if self.is_none_literal(t):
            return "null"
        return self.normalize_string_literal(t)



    def is_in_macro_definition(self, node) -> bool:
        """True se `node` sta dentro la definizione di una macro del preprocessore.
        Default: False (Python, Java non hanno macro)."""
        return False


    def call_receiver_name(self, call_node, ns) -> str | None:
        """Nome della variabile su cui e' invocato il metodo ('x' in x.add(...)).
        Solo per la forma semplice 'var.metodo(...)'; altrimenti None."""
        nm = call_node.xpath("./src:name", namespaces=ns)
        if not nm:
            return None
        parts = nm[0].xpath("./src:name", namespaces=ns)
        ops = nm[0].xpath("./src:operator", namespaces=ns)
        if len(parts) != 2 or len(ops) != 1:
            return None
        if "".join(ops[0].itertext()).strip() not in self.member_access_operator():
            return None
        return name_text(parts[0]) or None


    def parameter_annotation_names(self, param_node, ns) -> list:
        """Nomi (semplici) delle annotazioni/decoratori di un parametro. Default: nessuno."""
        return []

    def is_implicit_receiver_param(self, param_node, ns) -> bool:
        """True se il parametro è il ricevente implicito (self/cls): non è input esterno."""
        return False


    def is_numeric_type(self, type_text) -> bool:
        """True se il tipo dichiarato non può trasportare una stringa arbitraria
        (interi, float, booleani). Default: False (nel dubbio, resta taintato)."""
        return False

    def get_parameter_type(self, param_node, ns) -> str:
        return self.get_parameter_name_and_type(param_node, ns)[1] or ""



    def chain_ops_xpath(self, rhs, ns) -> str:
        """XPath (relativo a `rhs`) degli operatori '=' di una catena 'a = b = c'.
        Forma 'init': l'RHS è l'<expr> intera e gli '=' sono suoi figli diretti.
        Forma piatta: gli '=' sono i fratelli che seguono l'RHS."""
        tok = self.assignment_operator_token()
        if rhs.tag.endswith("}expr"):
            return f"./src:operator[text()='{tok}']"
        return f"./following-sibling::src:operator[text()='{tok}']"

    def _chain_rhs(self, op, ns):
        """RHS di un anello della catena: primo fratello non-commento dopo l''='."""
        r = op.xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=ns)
        return r[0] if r else None

    def get_assignment_chain(self, node, ns) -> list:
        """[(lhs, rhs), ...] per 'a = b = c'. Ogni anello della catena condivide
        l'RHS finale: 'a = b = src' -> (a, src), (b, src). Così l'RHS di 'a' non
        contiene 'b' (che viene sovrascritta), evitando falsi positivi nella
        sanificazione e nel kill-by-reassign."""
        lhs, rhs = self.get_assignment_lhs_rhs(node, ns)
        if lhs is None or rhs is None:
            return []
        chain = [(lhs, rhs)]

        if node.tag.endswith("}control"):      # binding di iterazione: nessuna catena
            return chain

        for op in rhs.xpath(self.chain_ops_xpath(rhs, ns), namespaces=ns):
            l = op.xpath("./preceding-sibling::*[not(self::src:comment)][1]", namespaces=ns)
            r = self._chain_rhs(op, ns)
            if l and l[0].tag.endswith("}name") and r is not None:
                chain.append((l[0], r))
        if len(chain) > 1:
            final_rhs = chain[-1][1]
            chain = [(l, final_rhs) for l, _ in chain]
        return chain



    def receiver_is_local_instance(self, call_node, recv_name, ns) -> bool:
        """True se `recv_name` è un oggetto creato nello scope della call
        (contenitore di dati) e non un collaboratore ricevuto dall'esterno
        (parametro, campo, ritorno di factory). Default: False, cioè la
        propagazione strutturale sul ricevente resta inattiva."""
        return False

    def constant_string_definitions(self, unit, ns) -> list:
        """[(nodo_definizione, nodo_name)] di costanti stringa dichiarate a
        livello di preprocessore/modulo. Default: nessuna."""
        return []


    def parameters_xpath(self) -> str:
        return "./src:parameter_list/src:parameter"

    def get_parameter_name_nodes(self, param_node, ns) -> list:
        n = self.get_parameter_name_node(param_node, ns)
        return [n] if n is not None else []

    def equality_operators(self) -> list:
        return [self.equality_operator()]   

    def source_name_prefixes(self) -> bool:
        return False

    def structural_only_assignment_tags(self) -> tuple:
        return ()

    def compound_assignment_operators(self) -> list:
        """Operatori 'x op= y' che propagano il taint di y su x ma NON lo cancellano.
        Default: nessuno (comportamento invariato)."""
        return []

    def _compound_op(self, node, ns):
        ops = self.compound_assignment_operators()
        if not ops or not node.tag.endswith("}expr_stmt"):
            return None
        cond = " or ".join(f"text()='{o}'" for o in ops)
        op = node.xpath(f"./src:expr/src:operator[{cond}][1]", namespaces=ns)
        return op[0] if op else None

    def is_compound_assignment(self, node, ns) -> bool:
        return self._compound_op(node, ns) is not None

    def get_compound_assignment_lhs_rhs(self, node, ns):
        op = self._compound_op(node, ns)
        if op is None:
            return None, None
        lhs = op.xpath("./preceding-sibling::*[not(self::src:comment)][1]", namespaces=ns)
        rhs = op.xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=ns)
        return (lhs[0] if lhs else None, rhs[0] if rhs else None)

    def call_keyword_args(self, call_node, ns) -> dict:
        """{nome: valore normalizzato} degli argomenti nominati di una call."""
        out = {}
        for arg in call_node.xpath("./src:argument_list/src:argument", namespaces=ns):
            if self.is_kwarg(arg, ns):
                k = arg.xpath("./src:name[1]", namespaces=ns)
                v = arg.xpath("./src:expr[1] | ./src:literal[1]", namespaces=ns)
                if k and v:
                    out[name_text(k[0])] = self.normalize_string_literal("".join(v[0].itertext()).strip())
        return out


    def callback_param_flow(self) -> dict:
        """pattern call -> indice del parametro della callback che riceve i dati del receiver."""
        return {}

    def callback_receiver_flow(self) -> bool:
        """True se i parametri di una funzione passata come argomento a un metodo
        il cui receiver è taintato ricevono taint (qualunque metodo, qualunque
        posizione). Nessun nome di API: è una regola di flusso dati."""
        return False

    def callback_arg_xpath(self) -> str:
        """XPath (relativo alla call) che trova le funzioni passate come argomento.
        Default: solo argomento diretto."""
        cond = " or ".join(f"self::src:{t}" for t in
                        set(self.lambda_tags()) | set(self.function_tags()))
        return f"./src:argument_list/src:argument/src:expr/*[{cond}]"


    
# ---------------------------------------------------------------------- #
# Implementazione Python
# ---------------------------------------------------------------------- #

class PythonAdapter(LanguageAdapter):
    name = "python"

    OCTAL_RE = re.compile(r"^0[oO][0-7]+$")
    HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
    BIN_RE = re.compile(r"^0[bB][01]+$")

    def potential_assignment_xpath(self) -> str:
        return ".//src:expr_stmt | .//src:control[parent::src:for]"

    def is_assignment(self, node, ns) -> bool:
        if node.tag.endswith("expr_stmt"):
            return bool(node.xpath(".//src:operator[text()='='][1]", namespaces=ns))
            
        # Supporto per iterazione Python: cerca il tag <range>
        if node.tag.endswith("control") and node.getparent() is not None and node.getparent().tag.endswith("for"):
            return bool(node.xpath(".//src:range", namespaces=ns))
            
        return False

    def get_assignment_lhs_rhs(self, node, ns):
        if node.tag.endswith("expr_stmt"):
            op = node.xpath(".//src:operator[text()='='][1]", namespaces=ns)
            if not op:
                return None, None
            op = op[0]
            lhs_nodes = op.xpath("./preceding-sibling::*[not(self::src:annotation)]", namespaces=ns)
            rhs_nodes = op.xpath("./following-sibling::*", namespaces=ns)
            lhs = lhs_nodes[-1] if lhs_nodes else None
            rhs = rhs_nodes[0] if rhs_nodes else None
            return (lhs, rhs)

        # Estrazione LHS e RHS per i loop: for x in y:
        if node.tag.endswith("control"):
            lhs_expr = node.xpath("./src:expr[1]", namespaces=ns)
            range_expr = node.xpath(".//src:range/src:expr[1]", namespaces=ns)
            
            if not lhs_expr or not range_expr:
                return None, None
            
            # Estrae il nome della variabile. Nell'unpacking, per ora prenderà solo la prima.
            lhs_name = lhs_expr[0].xpath(".//src:name[1]", namespaces=ns)
            lhs = lhs_name[0] if lhs_name else None
            rhs = range_expr[0]
            
            return (lhs, rhs)

        return None, None

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
        if tail_text:
            t = tail_text.strip()
            if t.startswith("=") and not t.startswith("=="):
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
                    bindings.append(ImportBinding(local_name=local, canonical_name=canonical, node=imp))
 
            else:
                # # import MODULO [as alias] [, MODULO2 [as alias2]]
                names = imp.xpath("./src:name[not(ancestor::src:alias)]", namespaces=ns)
                for n in names:
                    canonical = "".join(n.itertext()).strip()
                    if not canonical:
                        continue
                    alias_nodes = n.xpath("following-sibling::src:alias[1]//src:name", namespaces=ns)
                    head = canonical.split(".")[0]

                    if alias_nodes:
                        local = "".join(alias_nodes[0].itertext()).strip()
                        bindings.append(ImportBinding(local_name=local, canonical_name=canonical, node=imp))
                    else:
                        # 'import os.path' rende disponibile 'os', non 'os.path'
                        bindings.append(ImportBinding(local_name=head, canonical_name=head, node=imp))
                        if canonical != head:   # serve a required_imports
                            bindings.append(ImportBinding(local_name=canonical, canonical_name=canonical, node=imp))
 
        return bindings


    _MAX_RESOLVE_DEPTH = 5 #Guardia per evitare ricorsione infinita di catene eccessivamente lunghe all'interno di resolve_call_name
    
    # Funzioni factory built-in (non richiedono import) i cui oggetti restituiti
    # hanno metodi tracciati nel catalogo (es. f = open(...); f.read() -> 'open.read').
    _BUILTIN_FACTORIES = {"open"}

    def resolve_call_name(self, call_node, ns, imports: list, _depth: int = 0) -> str:
        if _depth > self._MAX_RESOLVE_DEPTH:
            return None

        name_nodes = call_node.xpath("./src:name", namespaces=ns)
        if not name_nodes:
            return None
        raw = "".join(name_nodes[0].itertext()).strip()
        if not raw:
            return None

        # 0. call concatenata: 'a.b().c()'
        if "." not in raw:
            recv = self._chain_receiver(call_node, ns)
            if recv is not None:
                recv_name = self.resolve_call_name(recv, ns, imports, _depth + 1)
                if recv_name:
                    return f"{recv_name}.{raw}"

        # 1. prevenzione doppio prefisso
        for binding in imports:
            if raw == binding.canonical_name or raw.startswith(f"{binding.canonical_name}."):
                return raw

        head, _, rest = raw.partition(".")

        # 2. moduli importati
        for binding in imports:
            if binding.local_name == head:
                return f"{binding.canonical_name}.{rest}" if rest else binding.canonical_name

        # 3. instance tracking con risalita lessicale
        if rest:
            rhs = self._reaching_rhs(call_node, head, ns)
            if rhs is not None:
                first_call = rhs.xpath("descendant-or-self::src:call[1]", namespaces=ns)
                chain = self._call_chain_names(rhs, ns)
                if first_call and chain:
                    resolved = self.resolve_call_name(first_call[0], ns, imports, _depth + 1) or chain[0]
                    if len(chain) > 1:
                        resolved += "." + ".".join(chain[1:])
                    # Sostituisce il receiver solo se l'RHS risolve a un nome qualificato,
                    # a un modulo importato o a una factory built-in, evitando che helper
                    # locali (es. conn = get_db()) sovrascrivano 'conn.execute' in 'get_db.execute'.
                    if (
                        "." in resolved
                        or resolved in self._BUILTIN_FACTORIES
                        or any(
                            resolved == b.canonical_name or resolved.startswith(f"{b.canonical_name}.")
                            for b in imports
                        )
                    ):
                        return f"{resolved}.{rest}"

        return raw
                

    def get_interpolated_variables(self, literal_text: str) -> list[str]:
        # Cerca tutto quello che c'è tra { e } ignorando eventuali specificatori di formato
        matches = re.findall(r"\{([a-zA-Z0-9_]+)[^}]*\}", literal_text)
        return matches

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

    def logical_and_operator(self) -> list:
        return ["and"]

    def logical_or_operator(self) -> list:
        return ["or"]

    def get_parameter_name_and_type(self, param_node, namespaces):
        """Estrae nome e tipo da un parametro (<src:parameter>) in Python."""
        # In Python il tipo è dentro l'annotazione
        type_nodes = param_node.xpath("./src:annotation/src:expr", namespaces=namespaces)
        type_text = "".join(type_nodes[0].itertext()).strip() if type_nodes else ""
        
        
        name_nodes = param_node.xpath("./src:name[1]", namespaces=namespaces)
        pname = "".join(name_nodes[0].itertext()).strip() if name_nodes else ""
        
        return pname, type_text


    def member_access_operator(self) -> list:
        return ["."]


    def taint_block_functions(self) -> list:
        return ["len", "hash", "bool", "isinstance", "id", "type", "int","float"]

    def taint_propagating_calls(self) -> dict:
        recv = {"out_receiver": True}
        return {"*.append": recv, "*.extend": recv, "*.insert": recv,
                "*.add": recv, "*.update": recv, "*.setdefault": recv}


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

    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        return None

    def null_comparison_operators(self) -> dict:
        return {
            "falsy": ["==", "is"],
            "truthy": ["!=", "is not"]
        }

    def taint_source_output_args(self) -> dict:
        return {}

    def get_parameter_name_node(self, param_node, ns):
        n = param_node.xpath("./src:name[1]", namespaces=ns)
        return n[0] if n else None

    def function_tags(self):   return ["function"]
    def lambda_tags(self):     return ["lambda"]
    def flow_exit_tags(self):  return ["return", "throw", "continue", "break"]
    def flow_exit_calls(self): return ["sys.exit", "exit", "quit", "os._exit"]
    def noop_statement_tags(self): return ["pass"]
    def class_tags(self): return ["class"]


    def resolve_name_text(self, text, imports, node=None):
        if not text or not imports:
            return text
        # già canonico: 'os.environ' con 'import os' (evita il doppio prefisso)
        for b in imports:
            if b.is_macro:
                continue
            if text == b.canonical_name or text.startswith(b.canonical_name + "."):
                return text
        head, _, rest = text.partition(".")
        for b in imports:
            if not b.is_macro and b.local_name == head:
                return f"{b.canonical_name}.{rest}" if rest else b.canonical_name
        return text

    #HELPER PER call concatenate
    def _call_chain_names(self, rhs, ns):
        """Nomi delle call concatenate a destra di '=': a.b().c().d() -> ['a.b', 'c', 'd']."""
        start = rhs.xpath("descendant-or-self::src:call[1]", namespaces=ns)
        if not start:
            return None
        node = start[0]
        first = node.xpath("./src:name", namespaces=ns)
        if not first:
            return None
        names = ["".join(first[0].itertext()).strip()]
        while True:
            op = node.xpath("following-sibling::*[1][self::src:operator and text()='.']", namespaces=ns)
            if not op:
                break
            nxt = op[0].xpath("following-sibling::*[1][self::src:call]", namespaces=ns)
            if not nxt:
                break
            nm = nxt[0].xpath("./src:name", namespaces=ns)
            if not nm:
                break
            names.append("".join(nm[0].itertext()).strip())
            node = nxt[0]
        return names

    def _reaching_rhs(self, call_node, head, ns):
        """RHS dell'assegnazione di `head` che raggiunge `call_node`, cercando dallo
        scope più interno verso l'esterno (funzioni annidate -> funzione -> modulo).
        Ritorna None se non c'è, o se `head` è un parametro (shadowing)."""
        

        call_key = _pos_key(call_node)
        call_ancestors = set(call_node.iterancestors())     
        fn_cond = " or ".join(f"self::src:{t}" for t in self.function_tags())

        funcs = call_node.xpath(f"ancestor::*[{fn_cond}]", namespaces=ns)
        unit = call_node.xpath("ancestor::src:unit[1]", namespaces=ns)
        scopes = list(reversed(funcs)) + unit

        for scope_node in scopes:
            is_unit = scope_node.tag.endswith("}unit")

            if not is_unit:
                for p in scope_node.xpath("./src:parameter_list/src:parameter", namespaces=ns):
                    n = self.get_parameter_name_node(p, ns)
                    if n is not None and "".join(n.itertext()).strip() == head:
                        return None

            prior = []
            for stmt, lhs, rhs in find_assignments(scope_node, self, head):
                if rhs is None or _pos_key(stmt) >= call_key:
                    continue
                if stmt in call_ancestors:                  
                    continue
                owner = enclosing_scope(stmt, self)
                if (owner is None) if is_unit else (owner is scope_node):
                    prior.append((stmt, rhs))

            if prior:
                return max(prior, key=lambda t: _pos_key(t[0]))[1]

        return None


    def is_async_function(self, func_node, ns) -> bool:
        return bool(func_node.xpath("./src:specifier[text()='async']", namespaces=ns))


    def is_true_constant(self, text: str) -> bool:
        '''anche 1 è una condizione sempre vera, quindi esegue l'override'''
        return text.strip() == "1" or super().is_true_constant(text)

    def is_false_constant(self, text: str) -> bool:
        return text.strip() == "0" or super().is_false_constant(text)


    def loop_update_operators(self) -> dict:
        return {
            "compound": ["+=", "-=", "*=", "/=", "//=", "%=", "**=", "<<=", ">>=", "&=", "|=", "^="],
            "unary": [],
        }

    def is_identifier(self, text: str) -> bool:
        return text.isidentifier()


    def is_implicit_receiver_param(self, param_node, ns) -> bool:
        if param_node.get("type") in ("args", "kwargs"):
            return False                      # *args / **kwargs sono input veri
        plist = param_node.getparent()
        first = plist.xpath("./src:parameter[1]", namespaces=ns)
        if not first or first[0] is not param_node:
            return False                      # solo il primo parametro
        func = plist.getparent()
        owner = func.xpath("ancestor::*[self::src:class or self::src:function][1]", namespaces=ns)
        if not owner or not owner[0].tag.endswith("}class"):
            return False                      # non è un metodo
        # @staticmethod: il primo parametro è un argomento vero
        return not func.xpath("./src:attribute//src:name[text()='staticmethod']", namespaces=ns)

    def is_numeric_type(self, type_text) -> bool:
        return (type_text or "").strip() in ("int", "float", "bool", "complex")


    def receiver_is_local_instance(self, call_node, recv_name, ns) -> bool:
        scope = enclosing_scope(call_node, self)
        if scope is None:
            scope = call_node.xpath("ancestor::src:unit[1]", namespaces=ns)[0]
        key = _pos_key(call_node)
        prior = [(s, r) for s, _, r in find_assignments(scope, self, recv_name)
                if r is not None and _pos_key(s) < key]
        if not prior:
            return False                      # parametro, globale, non risolto
        stmt, rhs = max(prior, key=lambda t: _pos_key(t[0]))
        if self.is_collection_assignment(stmt, ns):
            return True
        call = rhs.xpath("self::src:call | descendant-or-self::src:call[1]", namespaces=ns)
        if not call:
            return False
        nm = call[0].xpath("./src:name", namespaces=ns)
        cname = name_text(nm[0]) if nm else ""
        unit = call_node.xpath("ancestor::src:unit[1]", namespaces=ns)[0]
        classes = {name_text(n) for n in unit.xpath(".//src:class/src:name", namespaces=ns)}
        return cname in classes


# ---------------------------------------------------------------------- #
# Implementazione Java
# ---------------------------------------------------------------------- #


class JavaAdapter(LanguageAdapter):
    name = "java"


    _SCOPE_CLASS_UNIT_XP = etree.XPath(
        "ancestor::*[self::src:function or self::src:constructor or self::src:class or self::src:unit][1]",
        namespaces={"src": "http://www.srcML.org/srcML/src"},
    )
    _ANC_CLASS_XP = etree.XPath(
        "ancestor::src:class[1]",
        namespaces={"src": "http://www.srcML.org/srcML/src"},
    )

    _GENERIC_FREE_TEXT_XP = etree.XPath(
        ".//text()[not(ancestor::src:argument_list[@type='generic'])]",
        namespaces={"src": "http://www.srcML.org/srcML/src"},
    )

    _J_NAME  = etree.XPath("./src:name", namespaces={"src": "http://www.srcML.org/srcML/src"})
    _J_DOT   = etree.XPath("./src:operator[text()='.']", namespaces={"src": "http://www.srcML.org/srcML/src"})

    def _find_decls(self, node, var_name: str, include_fields: bool = False) -> list:
        # 1. Scope locale + parametri (function/constructor/class/unit)
        containers = self._SCOPE_CLASS_UNIT_XP(node)
        if containers:
            decls = get_decl_index(containers[0]).get(var_name)
            if decls:
                return decls
        # 2. Fallback sui campi della classe che racchiude il metodo
        if include_fields:
            classes = self._ANC_CLASS_XP(node)
            if classes:
                decls = get_class_field_index(classes[0]).get(var_name)
                if decls:
                    return decls
        return []

    def _canonicalize(self, name, imports):
        head, _, rest = name.partition(".")
        for b in imports or []:
            if b.is_macro or b.local_name != head:
                continue
            return f"{b.canonical_name}.{rest}" if rest else b.canonical_name
        return name

    def potential_assignment_xpath(self) -> str:
        return ".//src:expr_stmt | .//src:decl_stmt | .//src:control[parent::src:for]"

    def is_assignment(self, node, ns) -> bool:
        if node.tag.endswith("expr_stmt"):
            return bool(node.xpath(".//src:operator[text()='='][1]", namespaces=ns))
        if node.tag.endswith("decl_stmt"):
            return bool(node.xpath(".//src:init", namespaces=ns))
            
        # Supporto nativo per i cicli for-each in Java
        if node.tag.endswith("control") and node.getparent() is not None and node.getparent().tag.endswith("for"):
            return bool(node.xpath(".//src:range", namespaces=ns))
            
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
            
        # Estrazione LHS e RHS per i cicli for-each
        if node.tag.endswith("control"):
            decl = node.xpath(".//src:init/src:decl[1]", namespaces=ns)
            range_expr = node.xpath(".//src:range/src:expr[1]", namespaces=ns)
            
            if not decl or not range_expr:
                return None, None
            
            lhs = decl[0].xpath("./src:name", namespaces=ns)
            rhs = range_expr[0]
            
            return (lhs[0] if lhs else None, rhs)

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
                   
                    node=imp
                ))
            else:
                # import java.util.List; -> local: List, canonical: java.util.List
                local_name = full_name.split(".")[-1]
                bindings.append(ImportBinding(
                    local_name=local_name, 
                    canonical_name=full_name, 
                    
                    node=imp
                ))
                
        return bindings


    _MAX_RESOLVE_DEPTH = 5

    def resolve_call_name(self, call_node, ns, imports, _depth: int = 0) -> str:
        if _depth > self._MAX_RESOLVE_DEPTH:
            return None

        name_nodes = self._J_NAME(call_node)
        if not name_nodes:
            return None

        raw_name = "".join(self._GENERIC_FREE_TEXT_XP(name_nodes[0])).strip()

        if not self._J_NAME(name_nodes[0]):
            recv = self._chain_receiver(call_node, ns)
            if recv is not None:
                recv_name = self.resolve_call_name(recv, ns, imports, _depth + 1)
                if recv_name:
                    return f"{recv_name}.{raw_name}"

        parts = name_nodes[0].xpath("./src:name", namespaces=ns)
        ops = self._J_DOT(name_nodes[0])

        if len(parts) >= 2 and ops:
            var_name = "".join(parts[0].itertext()).strip()
            method_name = "".join(parts[-1].itertext()).strip()
            

            decls = self._find_decls(call_node, var_name, include_fields=True)
    
            if decls:
                decl_node = decls[-1]
                var_type = None
                seen = set()

                # Risale attraverso <type ref="prev"/> nelle dichiarazioni multiple
                # a tipo condiviso (es. 'ScriptEngine a, b, c = ...') finché non
                # trova il <decl> che possiede davvero il <type>.
                while decl_node is not None and id(decl_node) not in seen:
                    seen.add(id(decl_node))

                    type_nodes = decl_node.xpath(
                        "./src:type//src:name[not(ancestor::src:annotation)]", namespaces=ns
                    )
                    if type_nodes:
                        var_type = "".join(type_nodes[0].itertext()).strip()
                        # Tronca la stringa alla prima parentesi angolare evita di considerare: Map<String<String>
                        var_type = var_type.split('<')[0].strip()
                        break

                    type_node = decl_node.xpath("./src:type", namespaces=ns)
                    if type_node and type_node[0].get("ref") == "prev":
                        prev_decl = decl_node.xpath("preceding-sibling::src:decl[1]", namespaces=ns)
                        decl_node = prev_decl[0] if prev_decl else None
                    else:
                        decl_node = None

                # Gestione 'var' (Java 10+): il tipo non è esplicito, si risale alla call nell'<init>
                # (es. 'var writer = response.getWriter()' -> 'HttpServletResponse.getWriter').
                if var_type == "var":
                    init_call = decls[-1].xpath("./src:init//src:call[1]", namespaces=ns)
                    if init_call:
                        var_type = self.resolve_call_name(init_call[0], ns, imports, _depth + 1)
                    else:
                        var_type = None

                if var_type:
                    return self._canonicalize(f"{var_type}.{method_name}", imports)
                
        return self._canonicalize(raw_name, imports)


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

    def logical_and_operator(self) -> list:
        return ["&&"]

    def logical_or_operator(self) -> list:
        return ["||"]

    def get_parameter_name_and_type(self, param_node, namespaces):
        decl = param_node.xpath("./src:decl[1]", namespaces=namespaces)
        if not decl:
            return None, None
        type_nodes = decl[0].xpath("./src:type[1]", namespaces=namespaces)
        type_text = "".join(type_nodes[0].itertext()).strip() if type_nodes else ""
        name_nodes = decl[0].xpath("./src:name[1]", namespaces=namespaces)
        pname = "".join(name_nodes[0].itertext()).strip() if name_nodes else ""
        return pname, type_text


    def member_access_operator(self) -> list:
        return ["."]


    def taint_block_functions(self) -> list:
        return ["*.length", "*.hashCode", "*.isEmpty", "*.equals", "*.compareTo"]

    def taint_propagating_calls(self) -> dict:
        # Metodi che modificano il RICEVENTE: x.add(tainted) rende taintato x.
        recv = {"out_receiver": True}
        return {"*.add": recv, "*.addAll": recv, "*.put": recv, "*.putAll": recv,
                "*.append": recv, "*.push": recv, "*.offer": recv}

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
        new_call = assignment_node.xpath(
            ".//src:init/src:expr[src:operator[text()='new']]/src:call/src:name", namespaces=ns)
        if new_call:
            text = "".join(new_call[0].itertext()).strip()
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



    def null_comparison_operators(self) -> dict:
        return {
            "falsy": ["=="],
            "truthy": ["!="]
        }

    def taint_source_output_args(self) -> dict:
        return {}

    def get_parameter_name_node(self, param_node, ns):
        n = param_node.xpath("./src:decl/src:name[1]", namespaces=ns)
        return n[0] if n else None


    def function_tags(self):   return ["function", "constructor"]
    def lambda_tags(self):     return ["lambda"]
    def flow_exit_tags(self):  return ["return", "throw", "continue", "break"]
    def flow_exit_calls(self): return ["System.exit"]
    def noop_statement_tags(self): return ["empty_stmt"]
    def class_tags(self): return ["class"]


    def resolve_name_text(self, text, imports, node=None):
        return self._canonicalize(text, imports) if text else text

    # CWE-595: distinguere confronto di riferimenti da confronto di valori
    # ------------------------------------------------------------------ #
    # In Java '==' ha due significati: tra primitivi confronta i valori
    # (int == int), tra oggetti confronta gli indirizzi (String == String).
    # Dall'AST la forma è identica ('a == b'), quindi serve il TIPO DICHIARATO
    # degli operandi. Questa sezione fornisce al motore generico tre cose,
    # senza che structural_engine.py conosca nulla di Java:
    #   - resolve_operand_type():     tipo di un operando (identificatore o letterale stringa)
    #   - resolve_variable_type():    ricerca della dichiarazione locale/parametro/campo
    #   - is_reference_comparison():  decisione finale "segnalare o no"

    # Limiti noti: enum ('st == State.READY' è corretto ma resta segnalato),
    # operandi che sono call ('a.size() == b.size()'), tipi definiti in altri file.


    _PRIMS = {"byte", "short", "int", "long", "float", "double", "char", "boolean"}

    def _is_primitive(self, t: str) -> bool:
        t = re.sub(r"\b(final|static)\b", "", t).split("<")[0].strip()
        return t in self._PRIMS          # "int[]" non è primitivo: confronto di riferimenti

    def resolve_operand_type(self, node, ns):
        if node is not None and node.tag.endswith("}literal") and node.get("type") == "string":
            return "String"
        return super().resolve_operand_type(node, ns)

    def resolve_variable_type(self, name_node, var_name, ns):

        decls = self._find_decls(name_node, var_name, include_fields=False)
        if not decls:
            return None
        key = _pos_key(name_node)
        before = [d for d in decls if _pos_key(d) <= key]
        decl = (before or decls)[-1]          # dichiarazione più vicina che precede l'uso

        seen = set()
        while decl is not None and id(decl) not in seen:
            seen.add(id(decl))
            t = decl.xpath("./src:type", namespaces=ns)
            if t and t[0].get("ref") != "prev":
                # Esclude eventuali annotazioni (es. @RequestParam("id") int -> int)
                texts = t[0].xpath(".//text()[not(ancestor::src:annotation)]", namespaces=ns)
                return "".join(texts).strip()
            prev = decl.xpath("preceding-sibling::src:decl[1]", namespaces=ns)
            decl = prev[0] if prev else None
        return None

    def is_reference_comparison(self, lhs_type, rhs_type) -> bool:
        known = [t for t in (lhs_type, rhs_type) if t and t != "var"]
        if not known:
            return False                      # nessuna evidenza -> non segnalo
        return not any(self._is_primitive(t) for t in known)


    #FINE SEZIONE CWE 595-----------------------------------------------------------------------------


    def parameter_annotation_names(self, param_node, ns) -> list:
        out = []
        for n in param_node.xpath("./src:decl/src:type/src:annotation/src:name[1]", namespaces=ns):
            full = name_text(n)
            if full:
                out.append(full.split(".")[-1])    # org.x.RequestParam -> RequestParam
        return out

    
    _NUMERIC_TYPES = {
    "byte","short","int","long","float","double","boolean",
    "Byte","Short","Integer","Long","Float","Double","Boolean",
    "BigInteger","BigDecimal",
    }

    def get_parameter_type(self, param_node, ns) -> str:
        t = param_node.xpath("./src:decl/src:type[1]", namespaces=ns)
        if not t:
            return ""
        texts = t[0].xpath(".//text()[not(ancestor::src:annotation)]", namespaces=ns)
        return "".join(texts).strip()

    def is_numeric_type(self, type_text) -> bool:
        if not type_text:
            return False
        t = re.sub(r"\b(final|static)\b", "", type_text).strip()
        return t in self._NUMERIC_TYPES      # "Long[]" e "List<Long>" restano non numerici


    def receiver_is_local_instance(self, call_node, recv_name, ns) -> bool:
        decls = self._find_decls(call_node, recv_name, include_fields=False)
        if not decls:
            return False                      # campo, statico o non risolto: collaboratore
        key = _pos_key(call_node)
        before = [d for d in decls if _pos_key(d) <= key]
        decl = (before or decls)[-1]          # dichiarazione più vicina che precede la call
        return bool(decl.xpath(
            "./src:init/src:expr/src:operator[text()='new']", namespaces=ns))


# ---------------------------------------------------------------------- #
# Helper per l'adapter C (cast)
# ---------------------------------------------------------------------- #

C_TYPE_WORDS = {
    "char", "int", "long", "short", "unsigned", "signed", "void",
    "float", "double", "struct", "union", "enum", "const", "volatile",
    "size_t", "ssize_t", "wchar_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
}

def _lname(n): return n.tag.split('}')[-1]
def _ntxt(n):  return "".join(n.itertext()).strip()

def _skip_leading_casts(nodes):
    """Scarta i cast C iniziali '(' name+ '*'* ')' dalla lista di fratelli."""
    i = 0
    while i < len(nodes):
        if not (_lname(nodes[i]) == "operator" and _ntxt(nodes[i]) == "("):
            break
        j, names, stars = i + 1, [], 0
        while j < len(nodes) and _lname(nodes[j]) == "name":
            names.append(_ntxt(nodes[j])); j += 1
        while j < len(nodes) and _lname(nodes[j]) == "operator" and _ntxt(nodes[j]) and set(_ntxt(nodes[j])) == {"*"}:
            stars += 1; j += 1
        closed = j < len(nodes) and _lname(nodes[j]) == "operator" and _ntxt(nodes[j]) == ")"
        is_type = bool(names) and (stars > 0 or any(n in C_TYPE_WORDS for n in names))
        if not (closed and is_type):
            break
        i = j + 1
    return nodes[i:]

# ---------------------------------------------------------------------- #
# Implementazione C
# ---------------------------------------------------------------------- #

class CAdapter(LanguageAdapter):
    name = "c"

    _SCOPE_UNIT_XP = etree.XPath(
        "ancestor::*[self::src:function or self::src:unit][1]",
        namespaces={"src": "http://www.srcML.org/srcML/src"},
    )

    def _find_decls(self, node, var_name: str) -> list:
        containers = self._SCOPE_UNIT_XP(node)
        if containers:
            decls = get_decl_index(containers[0]).get(var_name)
            if decls:
                return decls
        return []


    def potential_assignment_xpath(self) -> str:
        return ".//src:expr_stmt | .//src:decl_stmt"
    
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
            rhs_nodes = _skip_leading_casts(op[0].xpath("./following-sibling::*", namespaces=ns))
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
            # Per hex/bin, SOLO u/l sono suffissi validi: mai f/d/z, che
            # collidono con cifre esadecimali reali (A-F).
            core = re.sub(r'[uUlL]+$', '', t)
            try:
                return int(core, 16 if is_hex else 2)
            except ValueError:
                return None

        # Per i letterali decimali, la classe più ampia è sicura: nessuna
        # cifra decimale (0-9) è mai in [uUlLfFdDzZ].
        core = re.sub(r'[uUlLfFdDzZ]+$', '', t)
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
                    
                    node=inc
                ))

        full_ns = {**ns, **cpp_ns}
        for d in unit_node.xpath(".//cpp:define", namespaces=full_ns):
            name_n = d.xpath("./cpp:macro/src:name[1]", namespaces=full_ns)
            val_n = d.xpath("./cpp:value[1]", namespaces=full_ns)
            if not name_n or not val_n:
                continue   # es. include guard: #define FOO_H

            local = "".join(name_n[0].itertext()).strip()
            value = "".join(val_n[0].itertext()).strip()
            is_fn_like = bool(d.xpath("./cpp:macro/src:parameter_list", namespaces=full_ns))

            m = (_MACRO_FWD_RE if is_fn_like else _MACRO_ALIAS_RE).match(value)
            if not m or m.group(1) == local:
                continue

            bindings.append(ImportBinding(
                local_name=local, canonical_name=m.group(1),
                 node=d, is_macro=True))
            
        return bindings


    def resolve_call_name(self, call_node, ns, imports) -> str:
        name_nodes = call_node.xpath("./src:name", namespaces=ns)
        if not name_nodes:
            return None

        raw_name = "".join(name_nodes[0].itertext()).strip()

        raw_name = expand_macro_name(raw_name, macro_map(imports))

        parts = name_nodes[0].xpath("./src:name", namespaces=ns)
        ops = name_nodes[0].xpath("./src:operator[text()='.' or text()='->']", namespaces=ns)

        if len(parts) >= 2 and ops:
            var_name = "".join(parts[0].itertext()).strip()
            method_name = "".join(parts[-1].itertext()).strip()

            decls = self._find_decls(call_node, var_name)

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

    def logical_and_operator(self) -> list:
        return ["&&"]

    def logical_or_operator(self) -> list:
        return ["||", "or"]

    def get_parameter_name_and_type(self, param_node, namespaces):
        decl = param_node.xpath("./src:decl[1]", namespaces=namespaces)
        if not decl:
            return None, None
            
        type_nodes = decl[0].xpath("./src:type[1]", namespaces=namespaces)
        # Unisce il nome del tipo (es: char) con eventuali modificatori (es: *)
        type_text = "".join(type_nodes[0].itertext()).strip() if type_nodes else ""
        type_text = re.sub(r'\s+', ' ', type_text) # Pulisce spazi extra
        
        name_nodes = decl[0].xpath("./src:name[1]", namespaces=namespaces)
        pname = "".join(name_nodes[0].itertext()).strip() if name_nodes else ""
        
        return pname, type_text

    def member_access_operator(self) -> list:
        # Operatore base per l'accesso ai membri. L'adapter gestisce esplicitamente 
        return [".", "->"]

    def taint_block_functions(self) -> list:
        # Funzioni C che restituiscono numeri o bool analizzando buffer/stringhe,
        # interrompendo la propagazione del taint come stringa.
        return ["strlen", "atoi", "atol", "atof", "strcmp", "strncmp"]

    def taint_propagating_calls(self) -> dict:
        # Funzioni libc che scrivono il risultato in un buffer passato come
        # argomento (side-effect), non tramite valore di ritorno: se un
        # qualsiasi altro argomento e' taintato, il buffer di output lo
        # diventa a sua volta. Indice = posizione dell'argomento di output.
        return {
            "sprintf": 0, "snprintf": 0,
            "strcpy": 0, "strncpy": 0,
            "strcat": 0, "strncat": 0,
            "memcpy": 0,  "_snprintf": 0,
            "sscanf": {"in": [0], "out_variadic_from": 2},
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

    def resolve_variable_type(self, name_node, var_name, ns) -> str | None:
        """Cerca la dichiarazione (locale o parametro) di var_name e ritorna
        il suo tipo dichiarato, es. 'char *'."""

        decls = self._find_decls(name_node, var_name)

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


    def taint_source_output_args(self) -> dict:
        return {
            "recv":     {"indices": [1]},
            "recvfrom": {"indices": [1]},
            "recvmsg":  {"indices": [1]},
            "read":     {"indices": [1]},
            "pread":    {"indices": [1]},
            "fread":    {"indices": [0]},
            "fgets":    {"indices": [0], "return_tainted": True},
            "gets":     {"indices": [0], "return_tainted": True},
            "getline":  {"indices": [0]},
            "scanf":    {"variadic_from": 1},
            "fscanf":   {"variadic_from": 2},
            "sscanf":   {"variadic_from": 2},
            "WSARecv":     {"indices": [1], "return_tainted": False},
            "WSARecvFrom": {"indices": [1], "return_tainted": False},
        }

    def get_parameter_name_node(self, param_node, ns):
        n = param_node.xpath(
            "./src:decl/src:name[1] | ./src:function_decl/src:name[1]", namespaces=ns)
        return n[0] if n else None


    def function_tags(self):   return ["function"]
    def lambda_tags(self):     return []
    def flow_exit_tags(self):  return ["return", "goto", "continue", "break"]
    def flow_exit_calls(self): return ["exit", "abort", "_exit", "_Exit"]
    def noop_statement_tags(self): return ["empty_stmt"]
    def class_tags(self): return []


    def source_call_args_propagate_to_return(self) -> bool:
        return False

    def taint_opaque_tags(self) -> list:
        return ["sizeof"]


    def is_reference_comparison(self, lhs_type, rhs_type) -> bool:
        return bool(lhs_type and rhs_type and "*" in lhs_type and "*" in rhs_type)


    def is_cast_type_name(self, name_node) -> bool:
        """'(char*)x', '(struct foo *)x': sequenza piatta '(' name+ '*'* ')'."""
        if _ntxt(name_node) in C_TYPE_WORDS:
            return True

        prev = name_node.getprevious()
        while prev is not None and _lname(prev) == "name":
            prev = prev.getprevious()
        if prev is None or _lname(prev) != "operator" or _ntxt(prev) != "(":
            return False

        nxt = name_node.getnext()
        while nxt is not None and _lname(nxt) == "name":
            nxt = nxt.getnext()
        stars = 0
        while nxt is not None and _lname(nxt) == "operator" and _ntxt(nxt) == "*":
            stars += 1
            nxt = nxt.getnext()

        # serve almeno un '*' (altrimenti '(buf)' sembrerebbe un cast) e la ')' finale
        return stars > 0 and nxt is not None and _lname(nxt) == "operator" and _ntxt(nxt) == ")"


    def is_true_constant(self, text: str) -> bool:
        '''anche 1 è una condizione sempre vera, quindi esegue l'override'''
        return text.strip() == "1" or super().is_true_constant(text)

    def is_false_constant(self, text: str) -> bool:
        return text.strip() == "0" or super().is_false_constant(text)


    _C_NUMERIC_WORDS = {"char","int","long","short","unsigned","signed","float","double",
                        "size_t","ssize_t","uint8_t","uint16_t","uint32_t","uint64_t",
                        "int8_t","int16_t","int32_t","int64_t","const","bool"}

    def is_numeric_type(self, type_text) -> bool:
        if not type_text or "*" in type_text or "[" in type_text:
            return False
        words = type_text.split()
        # 'char' da solo è un tipo scalare, ma 'char *' o 'char[]' no (già esclusi sopra)
        return bool(words) and all(w in self._C_NUMERIC_WORDS for w in words)

    def _chain_rhs(self, op, ns):
        nodes = _skip_leading_casts(op.xpath("./following-sibling::*", namespaces=ns))
        return nodes[0] if nodes else None


    _CPP_NS = {"cpp": "http://www.srcML.org/srcML/cpp"}
    def is_in_macro_definition(self, node) -> bool:
        return bool(node.xpath("ancestor::cpp:define", namespaces=self._CPP_NS))


    def constant_string_definitions(self, unit, ns) -> list:
        full = {**ns, **self._CPP_NS}
        out = []
        # solo macro-oggetto (senza parametri): #define NAME "..."
        for d in unit.xpath(".//cpp:define[not(cpp:macro/src:parameter_list)]", namespaces=full):
            n = d.xpath("./cpp:macro/src:name[1]", namespaces=full)
            v = d.xpath("./cpp:value[1]", namespaces=full)
            if n and v and _C_STRING_VALUE_RE.match("".join(v[0].itertext()).strip()):
                out.append((d, n[0]))
        return out


#---------------------------------------------------
#Implementazione Adapter Javascritpt
#---------------------------------------------------
_JS_KEYWORDS = {
    "true", "false", "null", "undefined", "typeof", "new", "await", "yield",
    "void", "delete", "in", "of", "instanceof", "function", "return", "if",
    "else", "async",
}
 
# nome puntato (anche con '?.'), non preceduto da '.', da parola o da '$'
_JS_CHAIN_RE = re.compile(
    r"(?<![\w$.])[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*"
)
_JS_PREFIX_OPS = ("await", "new", "yield")


_JS_FN_QTAGS = ("{http://www.srcML.org/srcML/src}lambda",
                "{http://www.srcML.org/srcML/src}function")
 
 
class JavaScriptAdapter(LanguageAdapter):
    name = "javascript"
 
    HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
    OCT_RE = re.compile(r"^0[oO][0-7]+$")
    BIN_RE = re.compile(r"^0[bB][01]+$")
    LEGACY_OCT_RE = re.compile(r"^0[0-7]+$")
 
    # ------------------------------------------------------------------ #
    # Helper interni: prefissi (await / new / yield)
    # ------------------------------------------------------------------ #
    # srcML e' incoerente su 'new': <operator>new</operator> dentro un <init>,
    # <name>new</name> a inizio statement. 'await' e' sempre <operator>.

    def _chain_receiver(self, call_node, ns):
        # 1. Verifica se esiste un operatore membro precedente
        ops = " or ".join(f"normalize-space()='{o}'" for o in self.member_access_operator())
        op = call_node.xpath(
            f"preceding-sibling::*[not(self::src:comment)][1][self::src:operator and ({ops})]",
            namespaces=ns
        )
        if not op:
            return None

        # 2. Caso fratello nello stesso <expr> (riga singola o indentazione canonica)
        prev = op[0].xpath(
            "preceding-sibling::*[not(self::src:comment)][1][self::src:call]",
            namespaces=ns
        )
        if prev:
            return prev[0]

        # 3. Caso multilinea srcML per JS (ASI split tra due <expr_stmt>)
        parent_stmt = call_node.xpath("ancestor::src:expr_stmt[1]", namespaces=ns)
        if parent_stmt:
            prev_stmt = parent_stmt[0].xpath(
                "preceding-sibling::*[not(self::src:comment)][1][self::src:expr_stmt]",
                namespaces=ns
            )
            if prev_stmt:
                # last_call = prev_stmt[0].xpath(".//src:call[last()]", namespaces=ns)
                last_call =  prev_stmt[0].xpath("./src:expr/src:call[last()]", namespaces=ns)
                if last_call:
                    return last_call[0]

        return None
 
    def _is_prefix(self, n) -> bool:
        t, txt = _lname(n), _ntxt(n)
        if t == "operator" and txt in _JS_PREFIX_OPS:
            return True
        return t == "name" and txt == "new"
 
    def _skip_prefix(self, nodes):
        i = 0
        while i < len(nodes) and self._is_prefix(nodes[i]):
            i += 1
        return nodes[i:]
 
    # ------------------------------------------------------------------ #
    # Assegnazioni
    # ------------------------------------------------------------------ #
 
    def potential_assignment_xpath(self) -> str:
        # for (i = 0; ...): <init><expr>i = 0</expr></init> (verificato su XML)
        return (
            ".//src:expr_stmt | .//src:decl_stmt | .//src:control[parent::src:for]"
            " | .//src:init[parent::src:control]/src:decl[not(src:range)]"
            " | .//src:init[parent::src:control]/src:expr"
            " | .//src:object/src:property")
 
    def is_assignment(self, node, ns) -> bool:
        tag = _lname(node)
        if tag == "property":
            return bool(node.xpath("./src:decl/src:init", namespaces=ns))
        if tag == "expr":                      # for (i = 0; ...)
            return bool(node.xpath("./src:operator[text()='='][1]", namespaces=ns))
        if tag == "expr_stmt":
            # solo l''=' figlio diretto dell'expr: './/' catturerebbe quelli
            # delle callback annidate (app.get(..., (req,res) => { x = 1 }))
            return bool(node.xpath("./src:expr/src:operator[text()='='][1]", namespaces=ns))
        if tag == "decl_stmt":
            return bool(node.xpath("./src:decl/src:init", namespaces=ns))
        if tag == "decl":
            return bool(node.xpath("./src:init", namespaces=ns))
        if tag == "control":
            return bool(node.xpath("./src:init/src:decl/src:range", namespaces=ns))
        return False
 
    def _lhs_head(self, op, ns):
        """LHS dell''=': se il nome e' spezzato da un index non terminale
        (a[0].b = x -> name(a[0]) . name(b)) risale fino alla testa della catena,
        cosi' la variabile taintata e' la radice ('a') e non 'b'."""
        prev = op.xpath("./preceding-sibling::*[not(self::src:comment)]", namespaces=ns)
        if not prev:
            return None
        i = len(prev) - 1
        node = prev[i]
        if not node.tag.endswith("}name"):
            return node
        member_ops = self.member_access_operator()
        while (i >= 2 and _lname(prev[i - 1]) == "operator"
               and _ntxt(prev[i - 1]) in member_ops
               and _lname(prev[i - 2]) == "name"):
            node = prev[i - 2]
            i -= 2
        return node
 
    def _decl_bound_names(self, decl, ns) -> list:
        """<name> delle variabili legate da un <decl>: nome diretto, oppure
        (destructuring) i nomi dei <decl> annidati.
        Verificato su XML: rest ({a, ...rest}) e pattern annidati ({a: {b}})."""
        direct = decl.xpath("./src:name[1]", namespaces=ns)
        if direct:
            return [direct[0]]
        out = []
        for d in decl.xpath("./src:decl", namespaces=ns):
            out.extend(self._decl_bound_names(d, ns))
        return out
 
    def _decl_pairs(self, decl, ns) -> list:
        """[(lhs_name, rhs_expr)] per un <decl>. Nel destructuring tutte le
        variabili condividono l'init del decl ESTERNO (i default 'b = 5'
        annidati sono ignorati; la chiave del rename 'a: renamed' e' un <expr>,
        non una variabile)."""
        init = decl.xpath("./src:init/src:expr[1]", namespaces=ns)
        if not init:
            return []
        return [(n, init[0]) for n in self._decl_bound_names(decl, ns)]
 
    def _control_pairs(self, control, ns) -> list:
        decl = control.xpath("./src:init/src:decl[src:range][1]", namespaces=ns)
        if not decl:
            return []
        rhs = decl[0].xpath("./src:range/src:expr[1]", namespaces=ns)
        if not rhs:
            return []
        # for (x of y), (const {id} of r), (const [a,b] of x): <decl> con <range> (verificato su XML).
        return [(n, rhs[0]) for n in self._decl_bound_names(decl[0], ns)]
 
    def get_assignment_lhs_rhs(self, node, ns):
        tag = _lname(node)
        if tag == "property":
            decl = node.xpath("./src:decl[1]", namespaces=ns)
            if decl:
                lhs = decl[0].xpath("./src:name[1]", namespaces=ns)
                rhs = decl[0].xpath("./src:init/src:expr[1]", namespaces=ns)
                return (lhs[0] if lhs else None, rhs[0] if rhs else None)
        if tag in ("expr_stmt", "expr"):
            op = node.xpath(("./src:expr" if tag == "expr_stmt" else ".")
                            + "/src:operator[text()='='][1]", namespaces=ns)
            if not op:
                return None, None
            lhs = self._lhs_head(op[0], ns)
            rhs_nodes = self._skip_prefix(
                op[0].xpath("./following-sibling::*[not(self::src:comment)]", namespaces=ns))
            if lhs is None or not rhs_nodes:
                return None, None
            return lhs, rhs_nodes[0]
        pairs = self.get_assignment_chain(node, ns)
        return pairs[0] if pairs else (None, None)
 
    def get_assignment_chain(self, node, ns) -> list:
        tag = _lname(node)
        if tag == "decl_stmt":
            out = []
            for d in node.xpath("./src:decl", namespaces=ns):   # const z = a, w = b
                out.extend(self._decl_pairs(d, ns))
            return out
        if tag == "decl":
            return self._decl_pairs(node, ns)
        if tag == "control":
            return self._control_pairs(node, ns)
        return super().get_assignment_chain(node, ns)
 
    def _chain_rhs(self, op, ns):
        nodes = self._skip_prefix(
            op.xpath("./following-sibling::*[not(self::src:comment)]", namespaces=ns))
        return nodes[0] if nodes else None
 
    def is_kwarg(self, argument_node, ns) -> bool:
        # JS non ha keyword argument. L'equivalente e' l'object literal
        # passato come ultimo argomento ({ secure: true }).
        # le opzioni in object literal sono lette da call_keyword_args().
        return False
 
    # ------------------------------------------------------------------ #
    # Stringhe, letterali, numeri
    # ------------------------------------------------------------------ #
 
    def call_keyword_args(self, call_node, ns) -> dict:
        """JS non ha keyword argument: l'equivalente e' l'object literal passato come
        ultimo argomento. Gli object annidati vengono appiattiti con chiavi puntate:
        session({cookie: {secure: false}}) -> {"cookie": "{...}", "cookie.secure": "false"}."""
        out = {}
        args = call_node.xpath("./src:argument_list/src:argument", namespaces=ns)
        if not args:
            return out
        for obj in args[-1].xpath("./src:expr/src:object | ./src:object", namespaces=ns):
            self._flatten_object(obj, "", out, ns, depth=0)
        return out

    _MAX_OBJECT_DEPTH = 4

    def _flatten_object(self, obj, prefix, out, ns, depth):
        if depth > self._MAX_OBJECT_DEPTH:
            return
        for prop in obj.xpath("./src:property", namespaces=ns):
            decl = prop.xpath("./src:decl[1]", namespaces=ns)
            if not decl:
                continue                      # spread, shorthand senza decl, ecc.
            # chiave: identificatore oppure letterale stringa ('secure': ...)
            k = decl[0].xpath("./src:name[1]", namespaces=ns)
            if k:
                key = name_text(k[0])
            else:
                lit = decl[0].xpath("./src:literal[@type='string'][1]", namespaces=ns)
                if not lit:
                    continue                  # chiave calcolata ([Op.like]): ignorata
                key = self.normalize_string_literal("".join(lit[0].itertext()))
            if not key:
                continue
            full = f"{prefix}.{key}" if prefix else key

            v = decl[0].xpath("./src:init/src:expr[1]", namespaces=ns)
            if not v:
                continue                      # shorthand {secure}: nessun valore letterale
            # il valore intero resta disponibile (retrocompatibilita')
            out[full] = self.normalize_string_literal("".join(v[0].itertext()).strip())
            # se il valore e' a sua volta un object literal, scendi
            nested = v[0].xpath("./src:object[count(../*)=1]", namespaces=ns)
            if nested:
                self._flatten_object(nested[0], full, out, ns, depth + 1)

    def string_concat_operators(self) -> list:
        return ["+"]
 
    def is_interpolated_string(self, literal_text: str) -> bool:
        t = literal_text.strip()
        return t.startswith("`") and "${" in t
 
    def get_interpolated_variables(self, literal_text: str) -> list:
        """Nomi usati dentro i ${...} di un template literal, con graffe e
        template annidati. Per un nome puntato restituisce anche i prefissi:
        ${req.query.id} -> req.query.id, req.query, req."""
        return list(dict.fromkeys(self._template_names(literal_text.strip())))
 
    def _skip_quoted(self, s, j):
        q = s[j]
        j += 1
        while j < len(s):
            if s[j] == "\\":
                j += 2
                continue
            if s[j] == q:
                return j + 1
            j += 1
        return j
 
    def _skip_template(self, s, j):
        j += 1
        while j < len(s):
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c == "`":
                return j + 1
            if c == "$" and s[j + 1:j + 2] == "{":
                j, _ = self._read_template_expr(s, j + 2)
                continue
            j += 1
        return j
 
    def _read_template_expr(self, s, i):
        """s[i] e' il primo carattere dopo '${'. Ritorna (indice dopo '}', espressione)."""
        depth, j, n = 1, i, len(s)
        while j < n:
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c in "'\"":
                j = self._skip_quoted(s, j)
                continue
            if c == "`":
                j = self._skip_template(s, j)
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return j + 1, s[i:j]
            j += 1
        return n, s[i:]
 
    def _template_names(self, s) -> list:
        out, i, n = [], 0, len(s)
        while i < n:
            c = s[i]
            if c == "\\":
                i += 2
                continue
            if c == "$" and s[i + 1:i + 2] == "{":
                i, expr = self._read_template_expr(s, i + 2)
                out.extend(self._expr_names(expr))
                continue
            i += 1
        return out
 
    def _expr_names(self, expr) -> list:
        out, buf, j = [], [], 0
        while j < len(expr):
            c = expr[j]
            if c == "`":                      # template annidato: ricorsione
                k = self._skip_template(expr, j)
                out.extend(self._template_names(expr[j:k]))
                buf.append(" ")
                j = k
                continue
            if c in "'\"":                    # contenuto di stringa: non e' codice
                buf.append(" ")
                j = self._skip_quoted(expr, j)
                continue
            buf.append(c)
            j += 1
        for m in _JS_CHAIN_RE.finditer("".join(buf)):
            parts = re.sub(r"\s*\??\.\s*", ".", m.group(0)).split(".")
            if parts[0] in _JS_KEYWORDS:
                continue
            for k in range(len(parts), 0, -1):
                out.append(".".join(parts[:k]))
        return out
 
    def is_none_literal(self, text: str) -> bool:
        return text.strip() in ("null", "undefined")
 
    def is_boolean_literal(self, text: str) -> bool:
        return text.strip() in ("true", "false")
 
    def parse_numeric_literal(self, text: str):
        t = text.strip().replace("_", "")
        if t[-1:] in ("n", "N"):             # BigInt: 10n
            t = t[:-1]
        try:
            if self.HEX_RE.match(t):
                return int(t, 16)
            if self.OCT_RE.match(t):
                return int(t[2:], 8)
            if self.BIN_RE.match(t):
                return int(t[2:], 2)
            if self.LEGACY_OCT_RE.match(t):  # 0755 (ottale legacy)
                return int(t, 8)
            return int(t)
        except ValueError:
            try:
                return int(float(t))
            except ValueError:
                return None
 
    def normalize_string_literal(self, text: str) -> str:
        t = text.strip()
        if len(t) >= 2 and t[0] in "'\"`" and t[-1] == t[0]:
            t = t[1:-1]
        return t
 
    def is_true_constant(self, text: str) -> bool:
        return text.strip() == "1" or super().is_true_constant(text)
 
    def is_false_constant(self, text: str) -> bool:
        return text.strip() == "0" or super().is_false_constant(text)
 
    # ------------------------------------------------------------------ #
    # Import / require
    # ------------------------------------------------------------------ #
 
    def _module_name(self, module: str) -> str:
        return module[5:] if module.startswith("node:") else module
 
    def _require_target(self, nodes, ns):
        """Nome canonico del modulo se i fratelli `nodes` (dentro un <expr>) sono
        [await] require("m") | import("m"), seguiti da . nome  ( require("m").y ->
        'm.y'). None se l'argomento non e' un letterale o la forma e' altra."""
        nodes = [n for n in nodes if isinstance(n.tag, str)]
        while nodes and _lname(nodes[0]) == "operator" and _ntxt(nodes[0]) == "await":
            nodes = nodes[1:]
        if not nodes or _lname(nodes[0]) != "call":
            return None
        call = nodes[0]
        nm = call.xpath("./src:name", namespaces=ns)
        if not nm or name_text(nm[0]) not in ("require", "import"):
            return None
        lit = call.xpath("./src:argument_list/src:argument[1]/src:expr/src:literal[@type='string']",
                         namespaces=ns)
        if not lit:
            return None
        module = self._module_name(self.normalize_string_literal("".join(lit[0].itertext())))
        rest, parts, i = nodes[1:], [], 0
        ops = self.member_access_operator()
        while (i + 1 < len(rest) and _lname(rest[i]) == "operator" and _ntxt(rest[i]) in ops
               and _lname(rest[i + 1]) == "name"):
            parts.append(name_text(rest[i + 1]))
            i += 2
        if i != len(rest):
            return None
        return ".".join([module] + parts)
 
    def resolve_imports(self, unit_node, ns) -> list:
        bindings = []
 
        # --- import ES ---------------------------------------------------
        for imp in unit_node.xpath(".//src:import", namespaces=ns):
            lit = imp.xpath("./src:from/src:literal[@type='string'][1]", namespaces=ns)
            if not lit:
                continue                       # import "side-effect"
            module = self._module_name(self.normalize_string_literal("".join(lit[0].itertext())))
            for n in imp.xpath("./src:name", namespaces=ns):   # default / namespace
                sym = name_text(n)
                if sym == "*":
                    al = n.xpath("following-sibling::src:alias[1]//src:name", namespaces=ns)
                    if al:
                        bindings.append(ImportBinding(name_text(al[0]), module, imp))
                elif sym:
                    bindings.append(ImportBinding(sym, module, imp))
            for n in imp.xpath("./src:name_list/src:name", namespaces=ns):   # { a, b as c }
                sym = name_text(n)
                al = n.xpath("following-sibling::src:alias[1]//src:name", namespaces=ns)
                local = name_text(al[0]) if al else sym
                if sym:
                    bindings.append(ImportBinding(local, f"{module}.{sym}", imp))
 
        # --- const x = require("m") / const { a, b: c } = require("m") / await import("m")
        for d in unit_node.xpath(".//src:decl[src:init/src:expr][not(parent::src:decl)]",
                                 namespaces=ns):
            expr = d.xpath("./src:init/src:expr[1]", namespaces=ns)[0]
            target = self._require_target(list(expr), ns)
            if not target:
                continue
            direct = d.xpath("./src:name[1]", namespaces=ns)
            if direct:
                bindings.append(ImportBinding(name_text(direct[0]), target, d))
                continue
            for nd in d.xpath("./src:decl", namespaces=ns):
                nm = nd.xpath("./src:name[1]", namespaces=ns)
                if not nm:
                    continue
                local = name_text(nm[0])
                prev = nd.xpath("preceding-sibling::*[1][self::src:expr]", namespaces=ns)
                key_nm = prev[0].xpath(".//src:name[1]", namespaces=ns) if prev else []
                key = name_text(key_nm[0]) if key_nm else local   # { exec: run } -> exec
                bindings.append(ImportBinding(local, f"{target}.{key}", d))
 
        # --- x = require("m")  (assegnazione semplice)
        for expr in unit_node.xpath(".//src:expr_stmt/src:expr[src:operator[text()='=']]",
                                    namespaces=ns):
            op = expr.xpath("./src:operator[text()='='][1]", namespaces=ns)[0]
            lhs = op.xpath("./preceding-sibling::*[1][self::src:name][not(src:operator)]",
                           namespaces=ns)
            if not lhs:
                continue
            target = self._require_target(
                op.xpath("./following-sibling::*", namespaces=ns), ns)
            if target:
                bindings.append(ImportBinding(name_text(lhs[0]), target, expr))

        return bindings
 
    def _canonicalize(self, name, imports):
        head, _, rest = name.partition(".")
        for b in imports or []:
            if b.is_macro or b.local_name != head:
                continue
            return f"{b.canonical_name}.{rest}" if rest else b.canonical_name
        return name
 
    def resolve_name_text(self, text, imports, node=None):
        if not text:
            return text
        text = text.replace("?.", ".")
        if node is not None:
            head, _, rest = text.partition(".")
            role = self.role_of_name(head, node)
            if role:
                return f"{role}.{rest}" if rest else role
        return self._canonicalize(text, imports)
 
    # ------------------------------------------------------------------ #
    # Nomi e chiamate
    # ------------------------------------------------------------------ #
 
    def _const_key(self, node):
        """Chiave letterale stringa di un subscript/computed: obj["m"] -> 'm'."""
        lit = node.xpath("./src:expr[count(*)=1]/src:literal[@type='string']",
                         namespaces={"src": "http://www.srcML.org/srcML/src"})
        if not lit:
            return None
        key = self.normalize_string_literal("".join(lit[0].itertext()))
        return key if self.is_identifier(key) else None
 
    def _dotted(self, name_node) -> str:
        """Nome puntato di un <name> (semplice o composto) senza gli index, ma
        con i subscript a chiave letterale trattati come membri: obj["m"] -> obj.m"""
        parts = []
        own = (name_node.text or "").strip()
        if own:
            parts.append(own)
        for c in name_node:
            if not isinstance(c.tag, str):
                continue
            t = _lname(c)
            if t == "name":
                if c.get("type") == "computed":
                    k = self._const_key(c)
                    if k:
                        parts.append(k)
                else:
                    sub = self._dotted(c)
                    if sub:
                        parts.append(sub)
            elif t == "index":
                k = self._const_key(c)
                if k:
                    parts.append(k)
        return ".".join(parts)
 
    _MAX_RESOLVE_DEPTH = 5

    _FLUENT = frozenset({
        "status", "set", "header", "type", "contentType", "cookie",
        "append", "vary", "location", "code", "links"
    })

    _REQ_MEMBERS = frozenset({"url", "headers", "query", "body", "params",
                              "cookies", "originalUrl"})
    _RES_MEMBERS = frozenset({"send", "write", "end", "writeHead", "setHeader",
                              "redirect", "render", "json", "sendFile"}) | _FLUENT

    def _used_members(self, fn_node, var, ns) -> set:
        """Membri a cui `var` accede nel corpo: var.NOME -> {'NOME'}."""
        return {name_text(n) for n in fn_node.xpath(
            ".//src:name[src:name[1][text()=$v]]/src:name[2]", namespaces=ns, v=var)}

    def _infer_http_roles(self, fn_node, ns) -> dict:
        params = fn_node.xpath(self.parameters_xpath(), namespaces=ns)
        if len(params) < 2:
            return {}
        names = []
        for p in params[:2]:
            n = self.get_parameter_name_node(p, ns)
            names.append(name_text(n) if n is not None else "")
        req, res = names
        if not req or not res:
            return {}
        if (self._used_members(fn_node, req, ns) & self._REQ_MEMBERS
                and self._used_members(fn_node, res, ns) & self._RES_MEMBERS):
            return {req: "Express.Request", res: "Express.Response"}
        return {}

    def get_express_route_bindings(self, fn_node, ns) -> dict[str, str]:
        """
        Riconosce se fn_node è una callback di un router Express (_ROUTER_METHODS)
        e mappa i nomi effettivi dei parametri ai tipi logici:
        - Express.Request
        - Express.Response
        """
        if self._route_call_of(fn_node, ns) is None:
            return self._infer_http_roles(fn_node, ns)
        params = fn_node.xpath(self.parameters_xpath(), namespaces=ns)
        if len(params) < 2:                 # (ctx) di Koa e simili: nessun ruolo
            return {}
        # (req, res, next) -> 0,1 ; error middleware (err, req, res, next) -> 1,2
        req_idx, res_idx = (1, 2) if len(params) == 4 else (0, 1)

        bindings = {}
        for idx, role in [(req_idx, "Express.Request"), (res_idx, "Express.Response")]:
            name_nodes = params[idx].xpath(".//src:decl/src:name | .//src:name", namespaces=ns)
            if name_nodes:
                local_name = "".join(name_nodes[0].itertext()).strip()
                if local_name:
                    bindings[local_name] = role
        return bindings

    def _call_require_module(self, call_node, ns) -> str | None:
        """Estrae il modulo se call_node è require("mod") o import("mod")."""
        nm = call_node.xpath("./src:name", namespaces=ns)
        if not nm or name_text(nm[0]) not in ("require", "import"):
            return None
        lit = call_node.xpath(
            "./src:argument_list/src:argument[1]//src:literal[@type='string']",
            namespaces=ns,
        )
        if not lit:
            return None
        return self._module_name(self.normalize_string_literal("".join(lit[0].itertext())))
 
    def resolve_call_name(self, call_node, ns, imports, _depth: int = 0) -> str:
        if _depth > self._MAX_RESOLVE_DEPTH:
            return None
        name_nodes = call_node.xpath("./src:name", namespaces=ns)
        if not name_nodes:
            return None
        raw = self._dotted(name_nodes[0])
        if not raw:
            return None

        # 0. Chiamata concatenata (risoluzione require inline, promises e strip catene fluenti)
        recv = self._chain_receiver(call_node, ns)
        if recv is not None:
            recv_name = (self._call_require_module(recv, ns)
                         or self.resolve_call_name(recv, ns, imports, _depth + 1))
            if recv_name:
                parts = recv_name.split(".")
                # base = quanti segmenti formano il "ricevente di risposta" da preservare
                if parts[:2] == ["Express", "Response"]:
                    base = 2
                elif parts[0] == "reply":              # Fastify: reply.code(200).send(x)
                    base = 1
                else:
                    base = None                        # cache.set(k, v).get(k) resta intatta
                if base:
                    while len(parts) > base and parts[-1] in self._FLUENT:
                        parts.pop()
                raw = f"{'.'.join(parts)}.{raw}"

        # Normalizzazione semantica parametri Express
        head, _, rest = raw.partition(".")
        role = self.role_of_name(head, call_node)
        if role:
            return f"{role}.{rest}" if rest else role

        # 1. Già canonico (evita doppio prefisso)
        for b in imports:
            if raw == b.canonical_name or raw.startswith(f"{b.canonical_name}."):
                return raw

        head, _, rest = raw.partition(".")

        # 2. Modulo o simbolo importato
        for b in imports:
            if b.local_name == head:
                return f"{b.canonical_name}.{rest}" if rest else b.canonical_name

        # 3. Instance tracking
        if rest:
            rhs = self._reaching_rhs(call_node, head, ns)
            if rhs is not None and not rhs.xpath(
                    "self::src:expr/*[1][self::src:lambda or self::src:function]", namespaces=ns):
                
                # Riconoscimento letterali Regex
                # Se l'RHS è o contiene un letterale regex (/.../)
                if rhs.xpath("self::src:literal[@type='regex'] | .//src:literal[@type='regex']", namespaces=ns):
                    return f"RegExp.{rest}"
                
                first_call = rhs.xpath("descendant-or-self::src:call[1]", namespaces=ns)
                chain = self._call_chain_names(rhs, ns)
                if first_call and chain:
                    resolved = self.resolve_call_name(first_call[0], ns, imports, _depth + 1) or chain[0]
                    if len(chain) > 1:
                        resolved += "." + ".".join(chain[1:])
                    if (
                        "." in resolved
                        or self._is_instance_expr(rhs, ns)  
                        or any(resolved == b.canonical_name or resolved.startswith(f"{b.canonical_name}.")
                            for b in imports)
                    ):
                        return f"{resolved}.{rest}"
        return raw
 
    def _call_chain_names(self, rhs, ns):
        """Nomi delle call concatenate a destra di '=': a.b().c().d() -> ['a.b', 'c', 'd']."""
        start = rhs.xpath("descendant-or-self::src:call[1]", namespaces=ns)
        if not start:
            return None
        node = start[0]
        first = node.xpath("./src:name", namespaces=ns)
        if not first:
            return None
        names = [self._dotted(first[0])]
        ops = " or ".join(f"text()='{o}'" for o in self.member_access_operator())
        while True:
            op = node.xpath(f"following-sibling::*[1][self::src:operator and ({ops})]", namespaces=ns)
            if not op:
                break
            nxt = op[0].xpath("following-sibling::*[1][self::src:call]", namespaces=ns)
            if not nxt:
                break
            nm = nxt[0].xpath("./src:name", namespaces=ns)
            if not nm:
                break
            names.append(self._dotted(nm[0]))
            node = nxt[0]
        return names
 
    def _reaching_rhs(self, call_node, head, ns):
        """RHS dell'assegnazione di `head` che raggiunge `call_node` (dallo scope piu'
        interno verso l'esterno). None se non c'e' o se `head` e' un parametro."""
        call_key = _pos_key(call_node)
        call_ancestors = set(call_node.iterancestors())
        fn_cond = " or ".join(f"self::src:{t}" for t in self.function_tags())
        funcs = call_node.xpath(f"ancestor::*[{fn_cond}]", namespaces=ns)
        unit = call_node.xpath("ancestor::src:unit[1]", namespaces=ns)
        for scope_node in list(reversed(funcs)) + unit:
            is_unit = scope_node.tag.endswith("}unit")
            if not is_unit:
                for p in scope_node.xpath(self.parameters_xpath(), namespaces=ns):
                    if any(name_text(n) == head for n in self.get_parameter_name_nodes(p, ns)):
                        return None
            prior = []
            for stmt, lhs, rhs in find_assignments(scope_node, self, head):
                if rhs is None or _pos_key(stmt) >= call_key or stmt in call_ancestors:
                    continue
                owner = enclosing_scope(stmt, self)
                if (owner is None) if is_unit else (owner is scope_node):
                    prior.append((stmt, rhs))
            if prior:
                return max(prior, key=lambda t: _pos_key(t[0]))[1]
        return None
 
    def member_access_operator(self) -> list:
        # il primo elemento e' usato dal motore per ricomporre i nomi: deve restare '.'
        return [".", "?."]

    _IMPORTS_CACHE = {}   # id(unit) -> (unit, bindings); una sola unit in cache

    def _unit_imports(self, unit, ns):
        """resolve_imports() una volta per unit (stesso schema di _UNIT_PARAMS_CACHE)."""
        ent = self._IMPORTS_CACHE.get(id(unit))
        if ent is not None and ent[0] is unit:
            return ent[1]
        bindings = self.resolve_imports(unit, ns)
        self._IMPORTS_CACHE.clear()
        self._IMPORTS_CACHE[id(unit)] = (unit, bindings)
        return bindings
 
    def receiver_is_local_instance(self, call_node, recv_name, ns) -> bool:
        # Se il ricevente è un modulo importato/require (es. fs, child_process, path), NON è un'istanza mutabile!
        unit = call_node.xpath("ancestor::src:unit[1]", namespaces=ns)
        if unit:
            # Esclude immediatamente i moduli da require/import
            imports = self._unit_imports(unit[0], ns)
            if any(b.local_name == recv_name for b in imports):
                return False

        scope = enclosing_scope(call_node, self)
        if scope is None:
            scope = unit[0] if unit else call_node
        key = _pos_key(call_node)
        prior = [(s, r) for s, _, r in find_assignments(scope, self, recv_name)
                 if r is not None and _pos_key(s) < key]
        if not prior:
            return False
        _, rhs = max(prior, key=lambda t: _pos_key(t[0]))
        return self._is_instance_expr(rhs, ns)
 
    def _is_instance_expr(self, rhs, ns) -> bool:
        if rhs.xpath("self::src:array | self::src:object"
                     " | self::src:expr[count(*)=1]/src:array"
                     " | self::src:expr[count(*)=1]/src:object", namespaces=ns):
            return True
        if rhs.xpath("./src:operator[text()='new'] | ./src:name[text()='new']", namespaces=ns):
            return True                       # forma <init>/<expr>
        prev = rhs.xpath("preceding-sibling::*[not(self::src:comment)][1]", namespaces=ns)
        return bool(prev) and self._is_prefix(prev[0]) and _ntxt(prev[0]) == "new"
 
    # ------------------------------------------------------------------ #
    # Operatori e condizioni
    # ------------------------------------------------------------------ #
 
    def negation_operator(self) -> str:
        return "!"
 
    def assignment_operator_token(self) -> str:
        return "="
 
    def equality_operator(self) -> str:
        return "==="
 
    def equality_operators(self) -> list:
        return ["===", "=="]
 
    def logical_and_operator(self) -> list:
        return ["&&"]
 
    def logical_or_operator(self) -> list:
        return ["||", "??"]
 
    def comparison_operators(self) -> list:
        return ["<", "<=", ">", ">=", "!=", "==", "!==", "==="]
 
    def reference_comparison_operators(self) -> list:
        # Nessun tipo dichiarato in JS: CWE-595 non e' applicabile (regola spenta).
        return []
 
    def null_comparison_operators(self) -> dict:
        return {"falsy": ["==", "==="], "truthy": ["!=", "!=="]}
 
    def loop_update_operators(self) -> dict:
        # verificato su XML: '**=', '>>>=', '&&=', '||=' sono un solo <operator>.
        return {
            "compound": ["+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=",
                         "&=", "|=", "^=", "&&=", "||=", "??="],
            "unary": ["++", "--"],
        }
 
    # ------------------------------------------------------------------ #
    # Parametri, funzioni, scope
    # ------------------------------------------------------------------ #
 
    def parameters_xpath(self) -> str:
        # `a => ...`: <parameter> figlio diretto della <lambda>, senza parameter_list
        return "./src:parameter_list/src:parameter | ./src:parameter"
 
    def get_parameter_name_node(self, param_node, ns):
        n = _JS_PARAM_NAME_XP(param_node)
        return n[0] if n else None
 
    def get_parameter_name_nodes(self, param_node, ns) -> list:
        direct = self.get_parameter_name_node(param_node, ns)   # semplice, default, rest
        if direct is not None:
            return [direct]

        def in_default(n):
            """True se `n` sta in un <init> (valore di default) interno al parametro.
            Un <init> esterno ('const g = ({a}) => ...') non conta."""
            return any(param_node in i.iterancestors()
                       for i in n.xpath("ancestor::src:init", namespaces=ns))

        out = []
        # {a} | {a = 1} | {a: b}: srcML modella tutto come property/decl/(name, init).
        # Con ':' la variabile legata e' la destinazione 'b' (nell'init), non la chiave 'a'.
        for prop in param_node.xpath("./src:decl/src:object//src:property", namespaces=ns):
            d = prop.xpath("./src:decl[1]", namespaces=ns)
            if not d:
                out += prop.xpath("./src:expr[src:operator[text()='...']]/src:name[1]", namespaces=ns)
                continue
            init = d[0].xpath("./src:init[1]", namespaces=ns)
            if init and "".join(init[0].itertext()).lstrip().startswith(":"):
                out += init[0].xpath("./src:expr[1]//src:name[not(src:name)]", namespaces=ns)
            else:
                n = d[0].xpath("./src:name[1]", namespaces=ns)
                if n:
                    out.append(n[0])
        out += param_node.xpath("./src:decl/src:object/src:decl/src:name[1]", namespaces=ns)
        out += [n for n in param_node.xpath("./src:decl/src:array//src:name", namespaces=ns)
                if not in_default(n)]
        return out
    def get_parameter_name_and_type(self, param_node, namespaces):
        n = self.get_parameter_name_node(param_node, namespaces)
        return (name_text(n) if n is not None else ""), ""     # JS: nessun tipo dichiarato
 
    def is_async_function(self, func_node, ns) -> bool:
        return bool(func_node.xpath("./src:specifier[text()='async']", namespaces=ns))
 
    def function_tags(self):
        # 'lambda' e' uno scope: in Express quasi tutto il codice sta in callback
        # (req, res) => {...}; senza questo ogni handler condividerebbe lo scope del file.
        return ["function", "constructor", "lambda"]
 
    def lambda_tags(self):     return ["lambda"]
    def class_tags(self):      return ["class"]
 
    # throw/break(etichetta)/empty_stmt verificati su XML.
    def flow_exit_tags(self):  return ["return", "throw", "continue", "break"]
    def flow_exit_calls(self): return ["process.exit", "process.abort"]
    def noop_statement_tags(self): return ["empty_stmt"]
 
    def resolve_variable_type(self, name_node, var_name, ns):
        return None                            # JS non ha tipi dichiarati
 
    def is_numeric_type(self, type_text) -> bool:
        return False
 
    # ------------------------------------------------------------------ #
    # Taint
    # ------------------------------------------------------------------ #
 
    def taint_block_functions(self) -> list:
        return ["parseInt", "parseFloat", "Number", "Boolean", "isNaN", "isFinite",
        "Array.isArray", "*.includes", "*.startsWith", "*.endsWith",
        "*.hasOwnProperty", "*.test",
        "*.indexOf", "*.lastIndexOf", "*.charCodeAt", "*.codePointAt", "*.localeCompare",
        "Math.max", "Math.min", "Math.abs"]
 
    def taint_propagating_calls(self) -> dict:
        # push/unshift/splice modificano sempre il ricevente. add/set/append sono
        # "structural": propagano solo se il ricevente e' un'istanza creata nello scope
        # (evita FP tipo res.set(h, v) -> 'res' taintato).
        recv = {"out_receiver": True}
        local = {"out_receiver": True, "structural": True}
        return {"*.push": recv, "*.unshift": recv, "*.splice": recv,
                "*.add": local, "*.set": local, "*.append": local,
                "Object.assign": {"out": [0]}}

    def taint_source_output_args(self) -> dict:
        return {}                              # nessuna source per side-effect in JS
 
    _COLLECTION_CTORS = {"Set", "Map", "Array", "WeakSet", "WeakMap"}

    def is_collection_assignment(self, assignment_node, ns) -> bool:
        _, rhs = self.get_assignment_lhs_rhs(assignment_node, ns)
        if rhs is None:
            return False
        if rhs.xpath("self::src:array | self::src:object"
                     " | self::src:expr[count(*)=1]/src:array"
                     " | self::src:expr[count(*)=1]/src:object", namespaces=ns):
            return True
        call = None
        if _lname(rhs) == "call":            # forma piatta: 'new' e' il fratello precedente
            prev = rhs.xpath("preceding-sibling::*[not(self::src:comment)][1]", namespaces=ns)
            if prev and self._is_prefix(prev[0]) and _ntxt(prev[0]) == "new":
                call = rhs
        elif _lname(rhs) == "expr":          # forma <init>: <expr>new <call/></expr>
            kids = [c for c in rhs if isinstance(c.tag, str)]
            if len(kids) >= 2 and self._is_prefix(kids[0]) and _ntxt(kids[0]) == "new" \
               and _lname(kids[1]) == "call":
                call = kids[1]
        if call is None:
            return False
        nm = call.xpath("./src:name", namespaces=ns)
        return bool(nm) and self._dotted(nm[0]) in self._COLLECTION_CTORS

    def extract_membership_relations(self, condition_node, ns) -> list:
        """a.includes(x) / a.has(x) / a.indexOf(x) <cmp> n / 'k' in obj (anche negati)."""
        rel = []

        def negated_by_prefix(node):
            p = node.xpath("preceding-sibling::*[not(self::src:comment)][1]", namespaces=ns)
            return bool(p) and _lname(p[0]) == "operator" and _ntxt(p[0]) == "!"

        for call in condition_node.xpath(
                ".//src:call[src:name/src:name[last()][text()='includes' or text()='has'"
                " or text()='indexOf']]", namespaces=ns):
            method = name_text(call.xpath("./src:name/src:name[last()]", namespaces=ns)[0])
            recv = call.xpath("./src:name/src:name[last()-1]", namespaces=ns)
            arg = call.xpath("./src:argument_list/src:argument[1]/src:expr/*[1]", namespaces=ns)
            if not recv or not arg:
                continue
            neg = negated_by_prefix(call)
            if method == "indexOf":
                # srcML spezza '-1' in <operator>-</operator><literal>1</literal>
                f = call.xpath("following-sibling::*[not(self::src:comment)][position()<=3]", namespaces=ns)
                if not f or _lname(f[0]) != "operator":
                    continue
                op = _ntxt(f[0])
                val = _ntxt(f[1]) if len(f) > 1 else ""
                if val == "-" and len(f) > 2:
                    val = "-" + _ntxt(f[2])
                if (op in ("!==", "!=") and val == "-1") or (op == ">=" and val == "0") \
                   or (op == ">" and val == "-1"):
                    neg = False
                elif (op in ("===", "==") and val == "-1") or (op == "<" and val == "0"):
                    neg = True
                else:
                    continue
            rel.append({"lhs": arg[0], "rhs": recv[0], "is_negated": neg})

        for op in condition_node.xpath(".//src:operator[text()='in']", namespaces=ns):
            b = op.xpath("./preceding-sibling::*[not(self::src:comment)][1]", namespaces=ns)
            a = op.xpath("./following-sibling::*[not(self::src:comment)][1]", namespaces=ns)
            if a and b:
                rel.append({"lhs": b[0], "rhs": a[0], "is_negated": False})
        return rel

    def find_exception_bindings(self, tree, ns) -> list:
        bindings = []
        # try { } catch (e) { } / catch ({ message }) { }
        for catch in tree.xpath(".//src:catch", namespaces=ns):
            block = catch.xpath("./src:block[1]", namespaces=ns)
            if not block:
                continue
            for p in catch.xpath("./src:parameter_list/src:parameter", namespaces=ns):
                for n in self.get_parameter_name_nodes(p, ns):
                    bindings.append((name_text(n), block[0]))
        # promise.catch(err => ...): primo parametro della callback; scope = la callback
        for call in tree.xpath(".//src:call[src:name]", namespaces=ns):
            nm = call.xpath("./src:name", namespaces=ns)[0]
            if self._dotted(nm).split(".")[-1] != "catch":
                continue
            for fn in call.xpath(
                    "./src:argument_list/src:argument[1]/src:expr/*[self::src:lambda or self::src:function][1]",
                    namespaces=ns):
                params = fn.xpath(self.parameters_xpath(), namespaces=ns)
                if params:
                    for n in self.get_parameter_name_nodes(params[0], ns)[:1]:
                        bindings.append((name_text(n), fn))
        return bindings

    def source_name_prefixes(self) -> bool:
        return True

    def structural_only_assignment_tags(self) -> tuple:
        return ("property",)

    def compound_assignment_operators(self) -> list:
        return ["+=", "||=", "&&=", "??="]

    _ROUTER_METHODS = frozenset({
        "get", "post", "put", "delete", "patch", "options", "head", "use", "all"
    })

    def _route_call_of(self, fn_node, ns):
        """La call-route di cui fn_node è la callback, o None se non ha forma di route."""
        parent_call = fn_node.xpath(
            "parent::src:expr/parent::src:argument/parent::src:argument_list/parent::src:call",
            namespaces=ns)
        if not parent_call:
            return None
        call = parent_call[0]
        nm = call.xpath("./src:name", namespaces=ns)
        if not nm:
            return None
        method = self._dotted(nm[0]).split(".")[-1]
        if method not in self._ROUTER_METHODS:
            return None

        first = call.xpath("./src:argument_list/src:argument[1]/src:expr/*[1]", namespaces=ns)
        if not first:
            return None
        node = first[0]
        tag = node.tag.rsplit("}", 1)[-1]
        if tag in ("lambda", "function"):
            return call if method == "use" else None      # app.use((req, res, next) => ...)
        if tag == "array":
            return call                                    # app.get(['/a', '/b'], ...)
        if tag == "literal":                               # stringa, template o regex
            txt = self.normalize_string_literal("".join(node.itertext()).strip())
            return call if txt.startswith(("/", "*")) else None
        return None

    def is_implicit_receiver_param(self, param_node, ns) -> bool:
        fn = param_node.xpath("ancestor::*[self::src:lambda or self::src:function][1]", namespaces=ns)
        if not fn:
            return False
        fn_node = fn[0]

        # handler riconosciuto (route registrata o ruoli inferiti dall'uso):
        # gli input arrivano da Express.Request.* nel catalogo, nessun parametro va seminato
        if self._fn_roles(fn_node, ns):
            return True

        is_arg = fn_node.xpath(
            "parent::src:expr/parent::src:argument/parent::src:argument_list/parent::src:call",
            namespaces=ns)
        if not is_arg:
            return False                      # funzione top-level senza ruoli: input valido

        # callback di db/fs/timer: non è input; route senza ruoli (Koa, 1 parametro): lo seminiamo
        return self._route_call_of(fn_node, ns) is None


    _SRC = {"src": "http://www.srcML.org/srcML/src"}
    _FN_ANC = "ancestor::*[self::src:lambda or self::src:function]"
    _FN_ANC_XP = etree.XPath(_FN_ANC, namespaces=_SRC)
    _ROLES_CACHE = {}          # id(fn) -> (fn, roles)
    _ROLE_CACHE = {}

    def _fn_roles(self, fn, ns):
        ent = self._ROLES_CACHE.get(id(fn))
        if ent is not None and ent[0] is fn:
            return ent[1]
        if len(self._ROLES_CACHE) > 4096:      # limite di sicurezza tra unit diverse
            self._ROLES_CACHE.clear()
        roles = self.get_express_route_bindings(fn, ns)
        self._ROLES_CACHE[id(fn)] = (fn, roles)
        return roles


    def role_of_name(self, head, node, ns=_SRC):
        inner = next(node.iterancestors(*_JS_FN_QTAGS), None)
        if inner is None:
            return None
        key = (id(inner), head)
        ent = self._ROLE_CACHE.get(key)
        if ent is not None and ent[0] is inner:
            return ent[1]
        fns = self._FN_ANC_XP(node)
        if not fns:
            return None
        inner = fns[-1]
        key = (id(inner), head)
        ent = self._ROLE_CACHE.get(key)
        if ent is not None and ent[0] is inner:
            return ent[1]
        if len(self._ROLE_CACHE) > 20000:
            self._ROLE_CACHE.clear()
        result = None
        for fn in reversed(fns):
            roles = self._fn_roles(fn, ns)
            if head in roles:
                local = [d for d in get_decl_index(fn).get(head, [])
                        if not d.xpath("ancestor::src:parameter", namespaces=ns)
                        and enclosing_scope(d, self) is fn]
                result = None if local else roles[head]
                break
            if any(name_text(n) == head
                for p in fn.xpath(self.parameters_xpath(), namespaces=ns)
                for n in self.get_parameter_name_nodes(p, ns)):
                result = None
                break
        self._ROLE_CACHE[key] = (inner, result)
        return result
    
    def callback_param_flow(self) -> dict:
        return {"*.forEach": 0, "*.map": 0, "*.filter": 0, "*.some": 0,
                "*.every": 0, "*.flatMap": 0, "*.then": 0, "*.reduce": 1}

    def callback_receiver_flow(self) -> bool:
        return True


    def callback_arg_xpath(self) -> str:
        cond = " or ".join(f"self::src:{t}" for t in
                        set(self.lambda_tags()) | set(self.function_tags()))
        return f"./src:argument_list//*[{cond}]"

# ---------------------------------------------------------------------- #
# Registro / dispatch
# ---------------------------------------------------------------------- #

ADAPTERS = {
    "python": PythonAdapter(),
    "java": JavaAdapter(),
    "c": CAdapter(),
    "javascript": JavaScriptAdapter(),
}

def get_adapter(unit_node) -> LanguageAdapter:
    """Sceglie l'adapter leggendo l'attributo language="..." che srcML scrive
    su ogni <unit> (es. language="Python", language="Java", language="C").
    """
    raw = unit_node.get("language")
    if not raw:
        raise ValueError(f"<unit> senza attributo language (file: {unit_node.get('filename')}). "
                         "Rigenera l'XML con srcML indicando --language.")
    adapter = ADAPTERS.get(raw.lower())
    if adapter is None:
        raise NotImplementedError(f"Nessun adapter per '{raw}'. Disponibili: {sorted(ADAPTERS)}")
    return adapter