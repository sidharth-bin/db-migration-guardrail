# 🗄️ DB Migration Guardrail Analyzer

A zero-dependency DevSecOps static analysis engine that acts as a continuous integration pipeline gatekeeper for database migrations. 

By analyzing raw SQL pull requests before deployment, this tool prevents catastrophic production outages caused by table locks, accidental data wipes, and unbounded queries.

---

## 💡 System Blueprint: The Three Ws

### 1. WHEN to use this tool?
*   **Continuous Integration Checks (CI):** Integrate into GitHub Actions or GitLab CI to automatically block Pull Requests if a developer pushes a migration containing dangerous operations.
*   **Local Developer Hooks:** Bind this tool to Git `pre-commit` hooks so developers are warned about missing performance parameters before they even push their code.

### 2. WHERE does it run?
*   **Pipeline Agnostic:** Written in standard Python, this utility runs seamlessly on Ubuntu CI runners, Alpine Docker containers, or local developer workstations without requiring an actual database connection.

### 3. WHY use this over other solutions?
*   **Zero Infrastructure Overhead:** Most database linting tools require active connections to a shadow database, complex schema registries, or heavy third-party JVM dependencies. This tool uses lightning-fast AST regex parsing to identify logic flaws entirely offline.

---

## ✨ Architectural Differentiators (Why This Stands Out)

| Rule Enforced | Standard Behavior | Guardrail Protection |
| :--- | :--- | :--- |
| **Index Creation** | `CREATE INDEX` locks tables, causing API timeouts. | Blocks creation unless `CONCURRENTLY` is explicitly declared. |
| **Data Wipes** | `DROP/TRUNCATE` executes cleanly if syntax is correct. | Hard-blocks destructive operations requiring explicit DBA override. |
| **Unbounded Updates** | `UPDATE users SET status=1;` overwrites 10M rows. | Intercepts updates/deletes lacking a precise `WHERE` clause. |

---

## 📋 Prerequisites

*   **Runtime Core:** Standard Python 3.8 or higher.
*   **Dependencies:** None. Employs built-in core array modules (`re`, `json`, `sys`, `os`) to guarantee absolute pipeline portability.

---

## 🔧 Tailoring to Your Infrastructure

To enforce company-specific SQL standards, you can easily append custom Regex evaluation blocks inside the `analyzer.py` engine ruleset:

```python
# Example: Prevent usage of VARCHAR without length limits
{
    "code": "DB-005",
    "severity": "MEDIUM",
    "pattern": re.compile(r"(?i)\bVARCHAR\b(?!\()"),
    "desc": "Schema Risk: Unbounded VARCHAR detected. Specify a character limit."
}
