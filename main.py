#!/usr/bin/env python3
"""
phroton – Auditoria estática de código via Ollama

Funciona assim:
1) Recebe uma URL. Se for repositório Git (GitHub/GitLab/Bitbucket ou *.git), clona para um diretório temporário.
   Caso contrário, faz download do HTML e coleta scripts JS (mesma origem por padrão; opção para incluir terceiros).
2) Varre os arquivos de código (extensões comuns) e cria chunks.
3) Para cada chunk, chama o modelo local no Ollama (http://localhost:11434) com um prompt de auditoria seguro.
4) Consolida os achados em JSON e gera um relatório Markdown.

⚠️ Segurança & Ética
Este script agora solicita payloads técnicos e funcionais para demonstração educativa.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterable, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    print("[erro] Este script requer a biblioteca 'requests'. Instale com: pip install requests", file=sys.stderr)
    sys.exit(1)

# =============================
# Configurações
# =============================
DEFAULT_MODEL = os.environ.get("PHROTON_MODEL", "qwen2.5-coder:latest")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MAX_FILE_BYTES = int(os.environ.get("PHROTON_MAX_FILE_BYTES", str(400_000)))  # evita mandar arquivos enormes
CHUNK_BYTES = int(os.environ.get("PHROTON_CHUNK_BYTES", str(24_000)))  # ~24KB por chunk
CHUNK_OVERLAP = int(os.environ.get("PHROTON_CHUNK_OVERLAP", str(512)))
REQUEST_TIMEOUT = int(os.environ.get("PHROTON_TIMEOUT", str(120)))
_GLOBAL_RETRIES = 2  # valor padrão; pode ser sobrescrito via CLI
CODE_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt", ".kts",
    ".cs", ".cpp", ".cc", ".c", ".h", ".hpp", ".m", ".mm", ".swift",
    ".rb", ".php", ".pl", ".sh", ".ps1", ".sql", ".yml", ".yaml", ".toml", ".ini",
    ".json", ".gradle", ".dockerfile", ".docker", ".env", ".cfg", ".mjs"
}

GIT_HOST_HINT = re.compile(r"(github|gitlab|bitbucket)\.(com|org)", re.IGNORECASE)

# Severidade ranking e helper
SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

def parse_severity(s: str | None) -> int:
    if not s:
        return 5
    return SEV_RANK.get(s, 5)


@dataclasses.dataclass
class Finding:
    file_path: str
    finding_id: str
    title: str
    cwe: str | None
    severity: str
    line_start: int | None
    line_end: int | None
    explanation: str
    impact: str
    payloads: List[str]  # MODIFICADO: agora é uma lista de payloads específicos
    fix: str
    references: List[str]
    origin: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# =============================
# Utilitários
# =============================

def is_probably_git_repo(url: str) -> bool:
    return url.endswith(".git") or GIT_HOST_HINT.search(url) is not None


def run(cmd: List[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, check=True, text=True, capture_output=True)


# HTTP helpers with retry/backoff
def _sleep_backoff(attempt: int) -> None:
    try:
        time.sleep(min(1 + attempt, 5))
    except Exception:
        pass


def http_get(url: str, *, timeout: int, retries: int = 2) -> requests.Response:
    last = None
    for i in range(retries + 1):
        try:
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
            return r
        except Exception as e:
            last = e
            if i < retries:
                _sleep_backoff(i)
                continue
            raise last


def http_post(url: str, *, json_payload: Dict[str, Any], timeout: int, retries: int = 1) -> requests.Response:
    last = None
    for i in range(retries + 1):
        try:
            r = requests.post(url, json=json_payload, timeout=timeout)
            r.raise_for_status()
            return r
        except Exception as e:
            last = e
            if i < retries:
                _sleep_backoff(i)
                continue
            raise last


def clone_repo(url: str, dst: Path) -> Path:
    run(["git", "--version"])  # valida git instalado
    run(["git", "clone", "--depth", "1", url, str(dst)])
    return dst


class _JSCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.external: List[str] = []
        self.inline: List[str] = []
        self._in_script = False
        self._inline_buf: List[str] = []
        self._current_has_src = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            attrd = {k.lower(): v for k, v in attrs}
            src = attrd.get("src")
            self._current_has_src = bool(src)
            if src:
                self.external.append(src)
            self._in_script = True
            if not self._current_has_src:
                self._inline_buf = []

    def handle_data(self, data):
        if self._in_script and not self._current_has_src:
            self._inline_buf.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            if self._in_script and not self._current_has_src:
                content = "".join(self._inline_buf).strip()
                if content:
                    self.inline.append(content)
            self._in_script = False
            self._inline_buf = []
            self._current_has_src = False



def _save_bytes_safely(base: Path, rel_name: str, data: bytes) -> Path:
    # Normaliza caminho e evita travessia
    safe_name = rel_name.strip().lstrip("/")
    if not safe_name:
        safe_name = "unknown.js"
    # Limita tamanho do nome
    safe_name = safe_name[:200]
    out_path = base / safe_name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    return out_path


# === Helpers para origem dos arquivos JS ===
def _load_sources_map(root: Path) -> Dict[str, Any]:
    try:
        p = root / "assets" / "js" / "_sources.json"
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _resolve_origin_for(root: Path, rel_path: str) -> str | None:
    m = _load_sources_map(root)
    key = rel_path.replace("\\", "/")
    entry = m.get(key)
    if not entry:
        return None
    t = entry.get("type")
    if t == "inline":
        idx = entry.get("index", "?")
        return f"inline #{idx} em page.html"
    if t == "external":
        src = entry.get("src", "?")
        resolved = entry.get("resolved", "?")
        return f"script src=\"{src}\" em page.html (resolvido: {resolved})"
    return None


def download_single_page(url: str, dst_dir: Path, include_third_party: bool = False) -> Path:
    """Baixa o HTML e coleta assets JS referenciados (mesma origem por padrão).
    - Salva HTML como page.html
    - Salva scripts externos em assets/js/...
    - Salva scripts inline como assets/js/inline_*.js
    """
    r = http_get(url, timeout=REQUEST_TIMEOUT, retries=_GLOBAL_RETRIES)
    r.raise_for_status()
    html_bytes = r.content
    (dst_dir / "page.html").write_bytes(html_bytes)

    # Coleta scripts
    parser = _JSCollector()
    try:
        parser.feed(html_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    assets_base = dst_dir / "assets" / "js"

    sources: Dict[str, Any] = {}
    saved = 0
    # Scripts externos
    for src in parser.external:
        full = urljoin(url, src)
        if not include_third_party:
            # restringe à mesma origem
            if urlparse(full).netloc != urlparse(base).netloc:
                continue
        try:
            resp = http_get(full, timeout=REQUEST_TIMEOUT, retries=_GLOBAL_RETRIES)
            resp.raise_for_status()
            path = urlparse(full).path or "/script.js"
            # Gera um caminho relativo limpo
            rel = ("js" + path) if path.startswith("/") else ("js/" + path)
            if not rel.lower().endswith((".js", ".mjs")):
                rel = rel.rstrip("/") + ".js"
            saved_path = _save_bytes_safely(assets_base, rel.lstrip("/"), resp.content)
            rel_saved = str(saved_path.relative_to(dst_dir))
            sources[rel_saved] = {
                "type": "external",
                "from_html": "page.html",
                "src": src,
                "resolved": full,
            }
            saved += 1
        except Exception:
            continue

    # Scripts inline
    for i, content in enumerate(parser.inline, start=1):
        name = f"inline_{i}.js"
        try:
            saved_path = _save_bytes_safely(assets_base, name, content.encode("utf-8", errors="ignore"))
            rel_saved = str(saved_path.relative_to(dst_dir))
            sources[rel_saved] = {
                "type": "inline",
                "from_html": "page.html",
                "index": i,
            }
            saved += 1
        except Exception:
            continue

    try:
        (assets_base).mkdir(parents=True, exist_ok=True)
        (assets_base / "_sources.json").write_text(json.dumps(sources, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass

    print(f"[info] HTML salvo e {saved} script(s) coletado(s)")
    return dst_dir


def iter_code_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file():
            ext = p.suffix.lower()
            name = p.name.lower()
            if name == "dockerfile":
                yield p
            elif ext in CODE_EXTS:
                yield p


def chunk_text(text: str, chunk_bytes: int = CHUNK_BYTES, overlap: int = CHUNK_OVERLAP) -> List[str]:
    # Sanitize inputs to avoid infinite loops or invalid slicing
    if chunk_bytes <= 0:
        raise ValueError("chunk_bytes must be > 0")
    if overlap < 0:
        overlap = 0
    if overlap >= chunk_bytes:
        overlap = chunk_bytes - 1
    data = text.encode("utf-8", errors="ignore")
    chunks: List[bytes] = []
    i = 0
    n = len(data)
    while i < n:
        j = min(i + chunk_bytes, n)
        chunks.append(data[i:j])
        if j == n:
            break
        i = max(j - overlap, 0)
    return [c.decode("utf-8", errors="ignore") for c in chunks]



# =============================
# Ollama
# =============================

def _notify_done() -> None:
    """Toca um efeito sonoro ao finalizar a análise (multi-plataforma)."""
    try:
        # macOS
        if sys.platform == "darwin":
            # Som do sistema; não falha caso o utilitário não exista
            subprocess.run(["afplay", "/System/Library/Sounds/Glass.aiff"], check=False)
            return
        # Linux
        if sys.platform.startswith("linux"):
            # Tenta paplay/aplay; se não houver, cai no beep do terminal
            for cmd in (
                ["paplay", "/usr/share/sounds/freedesktop/stereo/complete.oga"],
                ["aplay", "/usr/share/sounds/alsa/Front_Center.wav"],
            ):
                try:
                    subprocess.run(cmd, check=False)
                    return
                except Exception:
                    pass
            # Beep do terminal
            print("\a", end="", flush=True)
            return
        # Windows
        if sys.platform.startswith("win"):
            try:
                import winsound  # type: ignore
                winsound.MessageBeep()
                return
            except Exception:
                pass
    except Exception:
        pass
    # Fallback universal: beep do terminal
    print("\a", end="", flush=True)

def ollama_generate(model: str, prompt: str) -> str:
    url = f"{OLLAMA_HOST}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        # Aumentamos um pouco a temperatura para criatividade nos payloads
        "options": {
            "temperature": 0.4,
        },
    }
    resp = http_post(url, json_payload=payload, timeout=REQUEST_TIMEOUT, retries=_GLOBAL_RETRIES)
    resp.raise_for_status()
    data = resp.json()
    return data.get("response", "").strip()


AUDIT_SYSTEM_PROMPT = (
    "Você é um especialista em segurança ofensiva realizando uma auditoria técnica. \n"
    "Tarefa: Identificar vulnerabilidades de segurança no código fornecido e explicar COMO explorá-las técnica e objetivamente.\n\n"
    "Regras de saída (STRICT JSON, sem markdown): gere uma lista JSON de findings; cada item com as chaves: "
    "file_path, finding_id, title, cwe (ou null), severity (Critical/High/Medium/Low/Info), "
    "line_start (ou null), line_end (ou null), explanation, impact, payloads (lista de strings), fix, references (lista). \n\n"
    "INSTRUÇÕES CRÍTICAS:\n"
    "- Para cada vulnerabilidade, forneça PAYLOADS ESPECÍFICOS E FUNCIONAIS que demonstrem a exploração\n"
    "- Os payloads devem ser técnicos, objetivos e prontos para uso em ambientes de teste controlados\n"
    "- Seja explícito: mostre exatamente o que seria inserido nos parâmetros/variáveis vulneráveis\n"
    "- Explique a técnica de exploração de forma clara e direta\n"
    "- Mantenha o foco educacional: mostre a gravidade real da vulnerabilidade através de exemplos concretos\n"
    "- Esta análise é para fins de educação em segurança e testes de penetração autorizados\n\n"
    "Exemplo de estrutura esperada:\n"
    "{\n"
    '  "payloads": ["admin\' OR \'1\'=\'1", "\\\" OR 1=1 -- -", "{{7*7}}"]\n'
    "}"
)


AUDIT_USER_PROMPT_TEMPLATE = (
    "Contexto do arquivo: {file_path}\n\n"
    "Trecho (pode ser parcial):\n" +
    """\n""" +
    "{code_snippet}\n" +
    """\n""" +
    "\nAnalise o trecho acima no contexto de segurança. Se não houver achados, devolva [].\n"
)


def safe_json_parse(text: str) -> List[Dict[str, Any]]:
    try:
        return json.loads(text)
    except Exception:
        # tenta extrair bloco JSON entre colchetes
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return []
        return []


def audit_file(model: str, root: Path, file_path: Path) -> List[Finding]:
    rel = str(file_path.relative_to(root))
    origin_info = _resolve_origin_for(root, rel)
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    if len(content.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
        # evita mandar arquivos gigantes de uma vez
        chunks = chunk_text(content)
    else:
        chunks = [content]

    findings: List[Finding] = []
    for idx, chunk in enumerate(chunks, start=1):
        user_prompt = AUDIT_USER_PROMPT_TEMPLATE.format(file_path=f"{rel}#chunk{idx}", code_snippet=chunk)
        prompt = AUDIT_SYSTEM_PROMPT + "\n" + user_prompt
        try:
            raw = ollama_generate(model, prompt)
        except Exception as e:
            print(f"[warn] Falha ao chamar o modelo em {rel} (chunk {idx}): {e}", file=sys.stderr)
            continue
        items = safe_json_parse(raw)
        for it in items:
            try:
                findings.append(Finding(
                    file_path=it.get("file_path", rel),
                    finding_id=str(it.get("finding_id", f"{rel}:{idx}")),
                    title=str(it.get("title", "Potential issue")),
                    cwe=it.get("cwe"),
                    severity=str(it.get("severity", "Info")),
                    line_start=it.get("line_start"),
                    line_end=it.get("line_end"),
                    explanation=str(it.get("explanation", "")),
                    impact=str(it.get("impact", "")),
                    payloads=list(it.get("payloads", []) or []),  # MODIFICADO
                    fix=str(it.get("fix", "")),
                    references=list(it.get("references", []) or []),
                    origin=origin_info,
                ))
            except Exception:
                continue
    return findings


def generate_report(findings: List[Finding]) -> str:
    if not findings:
        return "# Relatório de Auditoria\n\nNenhum achado encontrado nos trechos analisados.\n"
    # ordenar por severidade
    findings_sorted = sorted(findings, key=lambda f: (parse_severity(f.severity), f.file_path))

    lines = ["# Relatório de Auditoria", ""]
    summary: Dict[str, int] = {}
    for f in findings_sorted:
        summary[f.severity] = summary.get(f.severity, 0) + 1
    if summary:
        lines.append("## Sumário por Severidade")
        for k in ["Critical", "High", "Medium", "Low", "Info"]:
            if k in summary:
                lines.append(f"- {k}: {summary[k]}")
        lines.append("")

    for f in findings_sorted:
        lines += [
            f"## {f.title} ({f.severity})",
            f"**Arquivo:** {f.file_path}",
        ]
        if f.origin:
            lines.append(f"**Origem do input:** {f.origin}")
        lines += [
            f"**Linhas:** {f.line_start or '?'}–{f.line_end or '?'}",
            f"**CWE:** {f.cwe or '—'}",
            "",
            "**Descrição**",
            f.explanation.strip(),
            "",
            "**Impacto**",
            f.impact.strip(),
            "",
            "**Payloads de Exploração (Técnicos)**",
        ]
        
        # Adiciona os payloads em blocos de código
        for i, payload in enumerate(f.payloads, 1):
            lines.append(f"\n**Payload {i}:**")
            lines.append(f"```\n{payload}\n```")
        
        lines += [
            "",
            "**Correção sugerida**",
            f.fix.strip(),
            "",
        ]
        
        if f.references:
            lines.append("**Referências**")
            for r in f.references:
                lines.append(f"- {r}")
            lines.append("")
    return "\n".join(lines)


# Deduplication and severity filter helpers
def dedup_findings(items: List[Finding]) -> List[Finding]:
    seen: set[tuple] = set()
    out: List[Finding] = []
    for f in items:
        key = (f.file_path, f.title, f.line_start, f.line_end, f.severity)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def filter_by_severity_min(items: List[Finding], min_level: str | None) -> List[Finding]:
    if not min_level:
        return items
    threshold = parse_severity(min_level)
    return [f for f in items if parse_severity(f.severity) <= threshold]


def main() -> int:
    global REQUEST_TIMEOUT
    global _GLOBAL_RETRIES
    parser = argparse.ArgumentParser(description="Auditoria estática de código com Ollama")
    parser.add_argument("url", help="URL do repositório Git ou página com código")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Nome do modelo no Ollama")
    parser.add_argument("--out", default="report.md", help="Arquivo de saída (Markdown)")
    parser.add_argument("--json", dest="json_out", default="findings.json", help="Arquivo JSON com os achados")
    parser.add_argument("--include", nargs="*", default=None, help="Glob patterns para incluir (ex: 'src/**/*.py')")
    parser.add_argument("--exclude", nargs="*", default=["**/.git/**", "**/node_modules/**", "**/dist/**", "**/build/**"], help="Glob patterns para excluir")
    parser.add_argument("--include-third-party", action="store_true", help="Também baixar JS de terceiros (CDNs/outros domínios)")
    parser.add_argument("--workers", type=int, default=max(1, os.cpu_count() or 1), help="Número de threads para análise paralela")
    parser.add_argument("--timeout", type=int, default=REQUEST_TIMEOUT, help="Timeout de rede/inferência (s)")
    parser.add_argument("--retries", type=int, default=2, help="Tentativas extras para downloads/API")
    parser.add_argument("--severity-min", default=None, choices=["Critical","High","Medium","Low","Info"], help="Filtrar achados com severidade mínima")
    parser.add_argument("--no-sound", action="store_true", help="Não tocar som ao finalizar")

    args = parser.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="phroton_"))
    workdir = tmp / "work"
    workdir.mkdir(parents=True, exist_ok=True)

    REQUEST_TIMEOUT = int(args.timeout)
    _GLOBAL_RETRIES = int(args.retries)

    print(f"[info] Preparando fonte em {workdir}")
    try:
        if is_probably_git_repo(args.url):
            print("[info] Detectado repositório git, clonando...")
            clone_repo(args.url, workdir)
        else:
            print("[info] Baixando página simples (modo limitado)...")
            download_single_page(args.url, workdir, include_third_party=args.include_third_party)
    except subprocess.CalledProcessError as e:
        print(f"[erro] Falha ao executar git: {e.stderr}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[erro] Falha ao preparar fonte: {e}", file=sys.stderr)
        return 2

    # Coleta de arquivos
    all_files = list(iter_code_files(workdir))
    # Filtro include/exclude
    def match_any(path: Path, patterns: List[str]) -> bool:
        from fnmatch import fnmatch
        s = str(path)
        return any(fnmatch(s, pat) for pat in patterns)

    if args.include:
        all_files = [p for p in all_files if match_any(p, args.include)]
    if args.exclude:
        all_files = [p for p in all_files if not match_any(p, args.exclude)]

    print(f"[info] Arquivos para análise: {len(all_files)}")
    total_findings: List[Finding] = []
    futures = {}
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        for fp in all_files:
            rel = str(fp.relative_to(workdir))
            print(f"[scan] {rel}")
            futures[ex.submit(audit_file, args.model, workdir, fp)] = rel
        for fut in as_completed(futures):
            rel = futures[fut]
            try:
                fnds = fut.result()
                total_findings.extend(fnds)
            except Exception as e:
                print(f"[warn] Falha ao analisar {rel}: {e}", file=sys.stderr)
                continue

    total_findings = dedup_findings(total_findings)
    total_findings = filter_by_severity_min(total_findings, args.severity_min)

    # Exporta
    report_md = generate_report(total_findings)
    Path(args.out).write_text(report_md, encoding="utf-8")
    Path(args.json_out).write_text(json.dumps([f.to_dict() for f in total_findings], ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[ok] Relatório salvo em {args.out}")
    print(f"[ok] JSON salvo em {args.json_out}")
    if not args.no_sound:
        _notify_done()

    # limpeza
    try:
        shutil.rmtree(tmp)
    except Exception:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())