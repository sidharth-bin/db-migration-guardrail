#!/usr/bin/env python3
"""
Module Name:    analyzer.py
Description:    Static SQL Migration Guardrail & Database Lock Preventer
Author:         Sidharth (sidharth-bin)
Architecture:   Zero-dependency Regex AST analyzer for CI/CD database pipelines
"""

import re
import sys
import json
import os

class MigrationGuardrail:
    def __init__(self):
        """Initializes database safety rules designed to prevent production outages."""
        self.files_scanned = 0
        self.total_risks_flagged = 0
        
        # Core Rules Engine: Regex patterns targeting common catastrophic SQL mistakes
        self.rules = [
            {
                "code": "DB-001",
                "severity": "CRITICAL",
                "pattern": re.compile(r"(?i)\bDROP\s+TABLE\b"),
                "desc": "Destructive Operation: 'DROP TABLE' detected. This requires manual DBA override."
            },
            {
                "code": "DB-002",
                "severity": "CRITICAL",
                "pattern": re.compile(r"(?i)\bTRUNCATE\s+TABLE\b"),
                "desc": "Destructive Operation: 'TRUNCATE TABLE' wipes all data and resets identities."
            },
            {
                "code": "DB-003",
                "severity": "HIGH",
                # Matches CREATE INDEX but flags if CONCURRENTLY is missing (Postgres specific)
                "pattern": re.compile(r"(?i)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!.*CONCURRENTLY)"),
                "desc": "Performance Risk: 'CREATE INDEX' without 'CONCURRENTLY' will lock the entire production table."
            },
            {
                "code": "DB-004",
                "severity": "HIGH",
                # Matches UPDATE or DELETE statements missing a WHERE clause
                "pattern": re.compile(r"(?i)^(UPDATE|DELETE\s+FROM)\s+[a-zA-Z0-9_]+\s*(?!.*WHERE)"),
                "desc": "Data Integrity Risk: Unbounded UPDATE/DELETE detected. Missing a WHERE clause."
            }
        ]

    def analyze_sql_file(self, filename: str, sql_content: str) -> dict:
        """Parses a migration file line-by-line and evaluates it against safety boundaries."""
        self.files_scanned += 1
        findings = []
        
        # Strip comments to prevent false positives in documentation blocks
        clean_content = re.sub(r"--.*", "", sql_content)
        clean_content = re.sub(r"/\*.*?\*/", "", clean_content, flags=re.DOTALL)
        
        # Split into individual SQL statements
        statements = [stmt.strip() for stmt in clean_content.split(";") if stmt.strip()]
        
        for stmt_index, statement in enumerate(statements, start=1):
            # Condense spacing for accurate regex matching
            normalized_stmt = " ".join(statement.split())
            
            for rule in self.rules:
                if rule["pattern"].search(normalized_stmt):
                    findings.append({
                        "statement_index": stmt_index,
                        "rule_code": rule["code"],
                        "severity": rule["severity"],
                        "description": rule["desc"],
                        "query_snippet": normalized_stmt[:60] + "..."
                    })
                    self.total_risks_flagged += 1
                    
        return {
            "file": filename,
            "status": "REJECTED" if findings else "PASSED",
            "violation_count": len(findings),
            "violations": findings
        }

if __name__ == "__main__":
    print("=== DATABASE MIGRATION GUARDRAIL INITIALIZED ===")
    analyzer = MigrationGuardrail()
    
    # Simulating a developer's dangerous Pull Request migration file
    dangerous_migration_mock = """
    -- Migration V2.4: Add index for faster user lookups
    CREATE INDEX idx_user_email ON users (email);
    
    -- Cleanup old session table completely
    TRUNCATE TABLE active_sessions;
    
    -- Update status flags (DANGER: missing WHERE clause)
    UPDATE user_preferences SET theme = 'dark';
    """
    
    print("[INFO] Intercepting CI/CD SQL migration staging array...")
    report = analyzer.analyze_sql_file("V2.4__schema_updates.sql", dangerous_migration_mock)
    
    print("\n[STATIC ANALYSIS REPORT]:")
    print(json.dumps(report, indent=2))
    print("\n---------------------------------------------------------")
    print(f"Total Migration Files Scanned: {analyzer.files_scanned}")
    print(f"Critical/High Risks Intercepted: {analyzer.total_risks_flagged}")
    
    if analyzer.total_risks_flagged > 0:
        print("RESULT: PIPELINE BLOCKED. Unsafe database operations detected.")
        print("Please resolve violations or request DBA override before merging.")
        print("---------------------------------------------------------")
        sys.exit(1)
    else:
        print("RESULT: PIPELINE APPROVED. Migrations meet production safety standards.")
        print("---------------------------------------------------------")
        sys.exit(0)
