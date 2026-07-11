"""
demo/record_demo.py — Animated terminal demo for screen recording.

Run this script, then record your terminal window with Xbox Game Bar
(Win + G → Record) or OBS. Convert the resulting video to GIF at ezgif.com.

Usage:
    python demo/record_demo.py
"""

import sys
import time


def type_out(text, delay=0.045):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)


def print_line(text, delay=0.018):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()


def pause(seconds):
    time.sleep(seconds)


# ANSI colours
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
ORANGE = "\033[33m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
DIM    = "\033[2m"


def main():
    # Clear screen
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()
    pause(0.6)

    # Prompt + command
    sys.stdout.write(f"{GREEN}>{RESET}  {CYAN}secchecker_repo{RESET}  ")
    sys.stdout.flush()
    pause(0.3)
    type_out("secchecker demo/ --type all --verbose")
    pause(0.5)
    sys.stdout.write("\n")
    sys.stdout.flush()
    pause(0.4)

    # Scanning header
    print_line(f"{DIM}[*] Scanning: demo/{RESET}", 0.01)
    pause(0.1)
    print_line(f"{DIM}[*] Scan type: all{RESET}", 0.01)
    pause(0.1)
    print_line(f"{DIM}[*] Format: md{RESET}", 0.01)
    pause(0.8)
    print_line(f"{DIM}[*] 21 finding(s) across 3 file(s){RESET}", 0.01)
    pause(0.3)
    print_line(f"{GREEN}[+] Report: secchecker_report.md{RESET}", 0.01)
    pause(1.0)

    # Separator
    print_line("")

    # Report header
    print_line(f"{BOLD}# 🔍 Secret Scan Report{RESET}", 0.012)
    pause(0.3)
    print_line(f"{DIM}Generated: 2026-03-28  |  Tool: secchecker v0.3.0{RESET}", 0.008)
    pause(0.4)

    # Summary
    print_line("")
    print_line(f"{BOLD}## 📊 Summary{RESET}", 0.012)
    pause(0.2)
    print_line("- Files Scanned:      3", 0.01)
    print_line("- Secret Types Found: 21", 0.01)
    print_line("- Total Matches:      21", 0.01)
    pause(0.3)
    print_line("")
    print_line(f"{BOLD}### 🚨 Severity Breakdown{RESET}", 0.012)
    pause(0.15)
    print_line(f"{RED}  ● CRITICAL: 2{RESET}", 0.012)
    print_line(f"{ORANGE}  ● HIGH:     4{RESET}", 0.012)
    print_line(f"{YELLOW}  ● MEDIUM:   1{RESET}", 0.012)
    print_line(f"{GREEN}  ● LOW:      14{RESET}", 0.012)
    pause(0.8)

    # app.py findings
    print_line("")
    print_line(f"{BOLD}### 📄 app.py{RESET}", 0.015)
    pause(0.2)

    findings_app = [
        (RED,    "CRITICAL", "LLM - OpenAI API Key",              "sk-aBcDe...NoPqRsTuV",                  "LLM02:2025 · CWE-540"),
        (RED,    "CRITICAL", "LLM - Eval of LLM Output",          "eval(llm_response)",                    "LLM05:2025 · CWE-95"),
        (ORANGE, "HIGH",     "LLM - Prompt Injection via f-string","f'...{user_input}'",                    "LLM01:2025 · CWE-77"),
        (ORANGE, "HIGH",     "LLM - RAG DB Query in Context",     "rag_context = conn.execute(...)",        "LLM08:2025 · CWE-200"),
        (GREEN,  "LOW",      "AST - Hardcoded Secret Assignment",  "OPENAI_API_KEY = 'sk-...'",             "CWE-798"),
        (GREEN,  "LOW",      "AST - eval/exec Call",               "eval(llm_response)",                    "CWE-95"),
    ]

    for colour, sev, name, match, owasp in findings_app:
        badge = f"{colour}[{sev}]{RESET}"
        print_line(f"  {badge}  {BOLD}{name}{RESET}", 0.008)
        print_line(f"         {DIM}Match: {match}{RESET}", 0.006)
        print_line(f"         {DIM}OWASP: {owasp}{RESET}", 0.006)
        pause(0.25)

    # Dockerfile findings
    print_line("")
    print_line(f"{BOLD}### 📄 Dockerfile{RESET}", 0.015)
    pause(0.2)

    findings_docker = [
        (ORANGE, "HIGH", "Postgres URI",                "postgresql://admin:hunter2@db.internal:5432/prod", "A02:2021 · CWE-312"),
        (ORANGE, "HIGH", "Dockerfile - FROM latest tag","FROM python:latest",                               "A06:2021 · CWE-1104"),
        (GREEN,  "LOW",  "Dockerfile - curl pipe shell","curl -sSL ... | bash",                             "A08:2021 · CWE-829"),
    ]

    for colour, sev, name, match, owasp in findings_docker:
        badge = f"{colour}[{sev}]{RESET}"
        print_line(f"  {badge}  {BOLD}{name}{RESET}", 0.008)
        print_line(f"         {DIM}Match: {match}{RESET}", 0.006)
        print_line(f"         {DIM}OWASP: {owasp}{RESET}", 0.006)
        pause(0.25)

    # Terraform findings
    print_line("")
    print_line(f"{BOLD}### 📄 terraform/main.tf{RESET}", 0.015)
    pause(0.2)

    findings_tf = [
        (ORANGE, "HIGH",   "AWS Secret Key",                      "wJalrXUtnFEMI/K7MDENG/...",     "A02:2021 · CWE-312"),
        (YELLOW, "MEDIUM", "Password in Config",                  "password = 'supersecret123'",   "A05:2021 · CWE-259"),
        (GREEN,  "LOW",    "Terraform - Open security group",     "cidr_blocks = [\"0.0.0.0/0\"]","A05:2021 · CWE-732"),
        (GREEN,  "LOW",    "Terraform - S3 bucket public ACL",    "acl = \"public-read\"",         "A05:2021 · CWE-732"),
        (GREEN,  "LOW",    "Terraform - RDS publicly accessible", "publicly_accessible = true",    "A05:2021 · CWE-284"),
    ]

    for colour, sev, name, match, owasp in findings_tf:
        badge = f"{colour}[{sev}]{RESET}"
        print_line(f"  {badge}  {BOLD}{name}{RESET}", 0.008)
        print_line(f"         {DIM}Match: {match}{RESET}", 0.006)
        print_line(f"         {DIM}OWASP: {owasp}{RESET}", 0.006)
        pause(0.25)

    # Footer
    print_line("")
    print_line("─" * 62, 0.004)
    pause(0.3)
    print_line(f"  {RED}2 CRITICAL{RESET}  {ORANGE}4 HIGH{RESET}  {YELLOW}1 MEDIUM{RESET}  {GREEN}14 LOW{RESET}  across 3 files", 0.012)
    pause(0.4)
    print_line(f"  {DIM}Add --format sarif --output report.sarif to upload to{RESET}", 0.008)
    print_line(f"  {DIM}GitHub Security tab with full OWASP + CWE tags.{RESET}", 0.008)
    pause(1.5)
    print_line("")


if __name__ == "__main__":
    main()
