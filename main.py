#!/usr/bin/env python3
"""WebExpose Scanner - Main CLI Application."""

import asyncio
import sys

import typer

from scanner import ScanConfiguration, ScopeValidationError, WebExposureScanner

# CLI Application
app = typer.Typer(
    name="WebExpose Scanner",
    help="Professional web exposure assessment tool for authorized security testing",
    add_completion=False,
)


def print_banner():
    """Print application banner."""
    print("""
================================================================================
                    WebExpose Scanner v1.0.2
          Professional Web Exposure Assessment Tool
          Authorized Security Testing - Passive Discovery Only
================================================================================

Author: Christos Ploutarchou <cploutarchou@gmail.com>
GitHub: https://github.com/cploutarchou/webexpose-scanner
    """)


def print_authorized_warning():
    """Print authorized use warning."""
    print("""
[!] AUTHORIZED USE ONLY [!]

This tool should ONLY be used on systems you own or have explicit written
authorization to test. Use of this tool against unauthorized targets is illegal.

By continuing, you confirm that you have authorization to test the target.

Features:
- Passive discovery and reconnaissance
- File and document exposure detection
- Secret and credential pattern matching
- Security misconfiguration identification
- Historical data analysis

This tool does NOT:
- Perform active exploitation
- Bypass authentication
- Modify or delete data
- Perform denial-of-service testing
    """)


def print_summary(report, output_dir: str):
    """Print scan summary to terminal."""
    stats = report.statistics

    print(f"""
================================================================================
                              SCAN SUMMARY
================================================================================

Target:                     {report.target.base_url}
Scan Duration:              {stats.duration_seconds:.1f} seconds
Scan Version:              {report.scan_version}

================================================================================
                         DISCOVERY STATISTICS
================================================================================

URLs discovered:            {stats.urls_discovered}
URLs checked:               {stats.urls_checked}
Currently accessible:       {stats.currently_accessible}

Documents:                   {stats.documents}
Images:                      {stats.images}
Data files:                  {stats.data_files}
Potential sensitive files:   {stats.potential_sensitive_files}

================================================================================
                           SECURITY FINDINGS
================================================================================
""")

    # Severity indicators
    severity_symbols = {
        "CRITICAL": "[!]",
        "HIGH": "[*]",
        "MEDIUM": "[+]",
        "LOW": "[i]",
        "INFO": "[.]",
    }

    findings = [
        ("CRITICAL", stats.critical_count),
        ("HIGH", stats.high_count),
        ("MEDIUM", stats.medium_count),
        ("LOW", stats.low_count),
        ("INFO", stats.info_count),
    ]

    for severity, count in findings:
        symbol = severity_symbols[severity]
        print(f"{symbol} {severity.lower():12} {count:4}")

    print(f"\nSecrets detected:            {stats.total_secrets_found}")

    # Report files
    print("""
================================================================================
                              REPORT FILES
================================================================================
""")

    domain = report.target.hostname.replace(":", "_")
    report_files = []

    if report.configuration.markdown_output:
        md_path = f"{output_dir}/{domain}/report.md"
        report_files.append(("Markdown", md_path))

    if report.configuration.json_output:
        json_path = f"{output_dir}/{domain}/report.json"
        report_files.append(("JSON", json_path))

    if report.configuration.text_output:
        txt_path = f"{output_dir}/{domain}/urls.txt"
        report_files.append(("Text", txt_path))

    for format_name, path in report_files:
        print(f"{format_name:12} {path}")

    # Urgent findings alert
    if stats.critical_count > 0 or stats.high_count > 0:
        print("""
================================================================================
                        [!] IMMEDIATE ATTENTION REQUIRED
================================================================================
""")
        if stats.critical_count > 0:
            print(f"[!] {stats.critical_count} CRITICAL findings require immediate remediation")
        if stats.high_count > 0:
            print(f"[*] {stats.high_count} HIGH findings should be addressed urgently")

    print("""
================================================================================
                            NEXT STEPS
================================================================================

1. Review the generated reports for detailed findings
2. Prioritize remediation of CRITICAL and HIGH findings
3. Rotate any exposed credentials or API keys
4. Remove or restrict access to exposed sensitive files
5. Implement secure development practices going forward
""")


@app.command()
def audit(
    target_url: str = typer.Argument(..., help="Target URL to audit"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory"),
    max_pages: int = typer.Option(150, "--max-pages", help="Maximum pages to crawl"),
    max_depth: int = typer.Option(3, "--max-depth", help="Maximum crawl depth"),
    workers: int = typer.Option(5, "--workers", "-w", help="Number of concurrent workers"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout (seconds)"),
    rate_limit: float = typer.Option(0.3, "--rate-limit", help="Seconds between requests"),
    passive_only: bool = typer.Option(False, "--passive-only", help="Passive discovery only"),
    active: bool = typer.Option(True, "--active/--no-active", help="Enable active crawling"),
    include_subdomains: bool = typer.Option(False, "--include-subdomains", help="Include subdomains"),
    user_agent: str = typer.Option("Mozilla/5.0 (compatible; WebExposeScanner/1.0; authorized-recon)", "--user-agent", help="Custom User-Agent"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    json_output: bool = typer.Option(True, "--json/--no-json", help="Generate JSON report"),
    markdown_output: bool = typer.Option(True, "--markdown/--no-markdown", help="Generate Markdown report"),
    text_output: bool = typer.Option(False, "--text", help="Generate text summary"),
    common_paths_check: bool = typer.Option(True, "--common-paths/--no-common-paths", help="Check sensitive paths"),
    archive_check: bool = typer.Option(True, "--archive/--no-archive", help="Check web archives"),
    max_response_size: int = typer.Option(10 * 1024 * 1024, "--max-response-size", help="Maximum response size (bytes)"),
):
    """Run a web exposure audit against the target URL."""

    print_banner()
    print_authorized_warning()

    try:
        # Setup scan configuration
        configuration = ScanConfiguration(
            max_pages=max_pages,
            max_depth=max_depth,
            workers=workers,
            timeout=timeout,
            rate_limit=rate_limit,
            output_directory=output,
            passive_only=passive_only,
            active=active,
            include_subdomains=include_subdomains,
            user_agent=user_agent,
            verbose=verbose,
            max_response_size=max_response_size,
            json_output=json_output,
            markdown_output=markdown_output,
            text_output=text_output,
            common_paths_check=common_paths_check,
            archive_check=archive_check,
        )

        print(f"\n[*] Starting audit of: {target_url}")
        print(f"[*] Configuration: {max_pages} pages, {max_depth} depth, {workers} workers")
        print(f"[*] Output directory: {output}")
        print()

        # Run the scan
        scanner = WebExposureScanner(target_url, configuration)
        report = asyncio.run(scanner.run())

        # Show results
        print_summary(report, output)

    except ScopeValidationError as e:
        typer.echo(f"[!] Scope validation error: {e}", err=True)
        raise typer.Exit(1)
    except KeyboardInterrupt:
        typer.echo("\n\n[!] Scan interrupted by user", err=True)
        raise typer.Exit(130)
    except Exception as e:
        typer.echo(f"[!] Error during scan: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    print("WebExpose Scanner v1.0.2")
    print("Professional web exposure assessment tool for authorized security testing")
    print("Author: Christos Ploutarchou <cploutarchou@gmail.com>")
    print("GitHub: https://github.com/cploutarchou/webexpose-scanner")


def main():
    """Main entry point."""
    if len(sys.argv) == 1:
        print_banner()
        print_authorized_warning()
        app()
    else:
        app()


if __name__ == "__main__":
    main()