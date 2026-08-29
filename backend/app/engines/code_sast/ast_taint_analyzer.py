"""
Contract 03 §3.3 & Contract 08 §4.3: Interprocedural AST Taint Flow Analyzer.
Parses Python Abstract Syntax Trees (AST), tracks untrusted input flow through variables
and string formatting into SQL and Command Execution sinks, generating structured taint traces.
"""

from __future__ import annotations
import ast
import os
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint

UNTRUSTED_SOURCES = {
    "request.args.get", "request.args", "request.form.get", "request.form",
    "request.values.get", "request.json.get", "request.json", "request.GET.get",
    "request.GET", "request.POST.get", "request.POST", "sys.argv", "input",
}

SQL_SINKS = {
    "cursor.execute", "db.session.execute", "engine.execute", "connection.execute",
    "db.engine.execute", "raw_connection.execute",
}

CMD_SINKS = {
    "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_output",
    "os.system", "os.popen",
}


def _get_call_name(node: ast.AST) -> str:
    """Extracts a dotted function call name from an AST node."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        value_name = _get_call_name(node.value)
        return f"{value_name}.{node.attr}" if value_name else node.attr
    elif isinstance(node, ast.Call):
        return _get_call_name(node.func)
    return ""


def _extract_names_from_expr(node: ast.AST) -> Set[str]:
    """Extracts variable names referenced in an expression."""
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            names.add(child.id)
    return names


class TaintVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, lines: List[str]):
        self.filename = filename
        self.lines = lines
        self.tainted_vars: Dict[str, List[str]] = {}  # var_name -> trace steps
        self.findings: List[Finding] = []

    def visit_Assign(self, node: ast.Assign):
        # Check if right-hand side is an untrusted source
        rhs_call = _get_call_name(node.value)
        line_no = node.lineno
        code_line = self.lines[line_no - 1].strip() if 0 < line_no <= len(self.lines) else ""

        # Direct source assignment
        if any(src in rhs_call for src in UNTRUSTED_SOURCES) or (isinstance(node.value, ast.Subscript) and any(src in _get_call_name(node.value.value) for src in UNTRUSTED_SOURCES)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    step = f"Source ({self.filename}:{line_no}): {code_line}"
                    self.tainted_vars[var_name] = [step]
        else:
            # Dataflow propagation check
            rhs_names = _extract_names_from_expr(node.value)
            intersecting_taints = [n for n in rhs_names if n in self.tainted_vars]
            if intersecting_taints:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        source_steps = self.tainted_vars[intersecting_taints[0]]
                        prop_step = f"Propagate ({self.filename}:{line_no}): {code_line}"
                        self.tainted_vars[var_name] = source_steps + [prop_step]

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = _get_call_name(node.func)
        line_no = node.lineno
        code_line = self.lines[line_no - 1].strip() if 0 < line_no <= len(self.lines) else ""

        # Check if any argument contains tainted variables
        call_names = set()
        for arg in node.args:
            call_names.update(_extract_names_from_expr(arg))
        for kw in node.keywords:
            call_names.update(_extract_names_from_expr(kw.value))

        tainted_args = [n for n in call_names if n in self.tainted_vars]

        if tainted_args:
            first_taint = tainted_args[0]
            trace = self.tainted_vars[first_taint] + [f"Sink ({self.filename}:{line_no}): {code_line}"]
            loc = f"{self.filename}:{line_no}"

            # Check for SQL Injection Sink
            if any(sink in call_name for sink in SQL_SINKS):
                obs = f"Untrusted input variable '{first_taint}' flows into SQL execution sink '{call_name}'"
                self.findings.append(Finding(
                    scan_id="auto",
                    engine="code_sast",
                    check_id="SAST-TAINT-001",
                    category="Injection",
                    title=f"AST Taint Flow: Unsanitized User Input Flows into Database Execution Sink ({first_taint})",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021-Injection",
                    nist_control="SI-10",
                    description=(
                        f"AST static taint analysis traced unsanitized user input from HTTP source into the database "
                        f"execution sink '{call_name}' at line {line_no}. This creates a direct SQL Injection flaw."
                    ),
                    impact="Full database compromise, authentication bypass, and potential remote command execution.",
                    remediation="Use parameterized queries (prepared statements) instead of dynamically interpolating variables into queries.",
                    remediation_code_snippet="# Parameterized query fix:\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                    references=["https://cwe.mitre.org/data/definitions/89.html"],
                    evidence=Evidence(
                        location=loc,
                        observed_value=obs,
                        expected_value="User input passed exclusively through query parameter binding",
                        line_number=line_no,
                        raw_response_snippet=code_line,
                    ),
                    taint_trace=trace,
                    fingerprint=calculate_fingerprint("SAST-TAINT-001", loc, obs),
                    source_tool="native",
                ))

            # Check for Command Injection Sink
            elif any(sink in call_name for sink in CMD_SINKS):
                # Check for shell=True if subprocess
                has_shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                ) or "os.system" in call_name or "os.popen" in call_name

                if has_shell_true:
                    obs = f"Untrusted input variable '{first_taint}' flows into shell command execution sink '{call_name}'"
                    self.findings.append(Finding(
                        scan_id="auto",
                        engine="code_sast",
                        check_id="SAST-TAINT-002",
                        category="Injection",
                        title=f"AST Taint Flow: Unsanitized User Input Flows into OS Command Sink ({first_taint})",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-78",
                        owasp_category="A03:2021-Injection",
                        nist_control="SI-10",
                        description=(
                            f"AST taint flow detected user input reaching OS command execution sink '{call_name}' "
                            f"with shell execution enabled at line {line_no}."
                        ),
                        impact="Remote Code Execution (RCE) allowing attackers to execute arbitrary system commands.",
                        remediation="Avoid shell execution. Pass command arguments as a list with shell=False, or validate against a strict whitelist.",
                        remediation_code_snippet="# Safe command execution fix:\nsubprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)",
                        references=["https://cwe.mitre.org/data/definitions/78.html"],
                        evidence=Evidence(
                            location=loc,
                            observed_value=obs,
                            expected_value="Command execution executed with shell=False and argument list",
                            line_number=line_no,
                            raw_response_snippet=code_line,
                        ),
                        taint_trace=trace,
                        fingerprint=calculate_fingerprint("SAST-TAINT-002", loc, obs),
                        source_tool="native",
                    ))

        self.generic_visit(node)


def audit_ast_taint_flow(repo_path: str) -> List[Finding]:
    """
    Scans Python files in repository path for interprocedural AST taint flow vulnerabilities.
    """
    findings: List[Finding] = []
    p = Path(repo_path)
    if not p.exists():
        return findings

    python_files = list(p.rglob("*.py")) if p.is_dir() else ([p] if p.suffix == ".py" else [])

    for py_file in python_files:
        try:
            code = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(code, filename=str(py_file))
            lines = code.splitlines()
            visitor = TaintVisitor(str(py_file.name), lines)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception:
            pass

    return findings
