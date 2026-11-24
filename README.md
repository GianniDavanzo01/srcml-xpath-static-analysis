## Struttura del Progetto

* **`script_analysis/`**: Script Python del motore di analisi statica e dell'orchestrazione (Engine, Adapter di linguaggio e Context).
* **`cataloghi/`**: File JSON dei cataloghi (`java_catalog.json`, `python_catalog.json`, `c_catalog.json`,`javascript_catalog.json`). Sono dizionari di traduzione che mappano i concetti astratti di sicurezza (sorgenti, sink, sanitizer, safe-context) sulle funzioni e librerie dei singoli linguaggi. Nome file obbligatorio: `<linguaggio>_catalog.json`.
* **`regole/`**: Ruleset semantico e astratto (CWE), indipendente dal linguaggio (es. `ruleset_abstract.json`). Può contenere uno o più file `.json`, ciascuno con un array di regole.
* **`Testset/`**: Dataset e snippet di codice sorgente usati per validare il motore.
* **`Benchmarks/`**: Materiale della valutazione sperimentale. Per ciascun benchmark contiene i codici di test analizzati, i report di analisi in JSON, gli script di confronto con la ground truth, i risultati per categoria in forma tabellare.
* **`xml_archivi/`**: Rappresentazioni AST in XML generate da srcML a partire dal codice sorgente originale.
* **`Result/`**: Report finali generati dal motore, in JSON strutturato.

> ⚠️ **Se `--rules` punta a una cartella**, questa non deve contenere i cataloghi:
> il motore carica tutti i `*.json` che trova aspettandosi array di regole, e un catalogo (oggetto JSON) provocherebbe un errore. Con `--rules` su un singolo file non c'è alcun vincolo. Per tenere l'ordine, è comunque consigliato separare regole/` e `cataloghi/`.

## Come eseguire il motore di analisi

```bash
python srcml_engine.py \
    --xml <percorso/al/file.xml> \
    --rules <file_regole.json | cartella_regole/> \
    --catalog-dir <cartella_cataloghi/> \
    -o <percorso/output.json>
```

| Opzione | Descrizione |
|---|---|
| `--xml` | Uno o più file `.xml` generati da srcML |
| `--xml-dir` | Cartella con più file `.xml` da analizzare in batch |
| `--rules` | Singolo file JSON di regole **oppure** cartella con più file `.json` |
| `--catalog-dir` | Cartella dei cataloghi `<linguaggio>_catalog.json`. Se omessa, usa la cartella dello script. Se --rules è una cartella, deve essere diversa da questa |
| `-o`, `--output` | File JSON di output (default: stdout) |


## Dataset e Fonti di Test

Per l'esecuzione dei test del motore di analisi, le regole sono state validate su snippet di codice estratti da dataset e progetti open-source. 

I casi di test presenti nella cartella `Testset/` derivano dalle seguenti repository:

* **[DeVAIC](https://github.com/dessertlab/DeVAIC/tree/main)**
* **[PoisonPy](https://github.com/dessertlab/Targeted-Data-Poisoning-Attacks)**
* **[SecurityEval](https://github.com/s2e-lab/SecurityEval)**
* **[juliet-test-suite-c](https://github.com/arichardson/juliet-test-suite-c/tree/master)**
* **[juliet-java-test-suite](https://github.com/UnitTestBot/juliet-java-test-suite)**
* **[JavascriptObfuscationSAST](https://github.com/X3no21/JavascriptObfuscationSAST)**

### Benchmark della valutazione sperimentale
La valutazione descritta usa i seguenti benchmark, i cui campioni, report e risultati si trovano nella cartella `Benchmarks/`:
| Benchmark | Linguaggi | Cartella | Fonte |
|---|---|---|---|
| BenchProctor | C, Java, Python, JavaScript | `Benchmarks/BenchProctor` | [TheAuditorTool/BenchProctor](https://github.com/TheAuditorTool/BenchProctor) |
| Juliet Test Suite | C, Java | `Benchmarks/Juliet_suite` | [juliet-test-suite-c](https://github.com/arichardson/juliet-test-suite-c), [juliet-java-test-suite](https://github.com/UnitTestBot/juliet-java-test-suite) |
| Snyk VulnBench | Java, Python | `Benchmarks/snyk_vulnbench` | [snyk-labs/snyk-vulnbench](https://github.com/snyk-labs/snyk-vulnbench) |
| OpenSSF CVE Benchmark | JavaScript | `Benchmarks/ossf_CVE_Benchmark` | [ossf-cve-benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark) |
| SecurityEval | Python | `Benchmarks/Security_Eval` | [s2e-lab/SecurityEval](https://github.com/s2e-lab/SecurityEval) |
| Java Vulnerability Dataset (Ananbeh et al.) | Java | `Benchmarks/Java_Vulnerability_Dataset` | [figshare](https://figshare.com/s/e07242d5b0538be41a4c?file=46912750) |

L'estrazione casuale da Juliet Test Suite e OpenSSF CVE Benchmark non è stata eseguita con un seed fissato: la riproducibilità si basa sull'elenco dei campioni già selezionati presente nelle rispettive cartelle.

