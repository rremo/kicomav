# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Report Generator

This module provides report generation in various formats:
- JSON: Machine-readable format for automation
- HTML: Human-readable format for viewing in browser

Usage:
    from kicomav.report import ReportGenerator, ScanSummary, ScanFileResult

    generator = ReportGenerator()
    summary = ScanSummary(...)

    # Generate JSON report
    json_report = generator.to_json(summary)

    # Generate HTML report
    html_report = generator.to_html(summary)
"""

import json
import html
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional


@dataclass
class ScanFileResult:
    """Result of scanning a single file."""

    filepath: str
    status: str  # "clean", "infected", "error"
    malware_name: Optional[str] = None
    error_message: Optional[str] = None
    scan_time_ms: int = 0
    sha256: Optional[str] = None
    file_size: Optional[int] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ScanSummary:
    """Summary of a scan operation."""

    scan_path: str
    scan_date: str = field(default_factory=lambda: datetime.now().isoformat())
    total_files: int = 0
    infected_files: int = 0
    clean_files: int = 0
    error_files: int = 0
    total_scan_time_ms: int = 0
    signature_count: int = 0
    signature_date: str = ""
    kicomav_version: str = ""
    results: List[ScanFileResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        data = asdict(self)
        data["results"] = [r.to_dict() if hasattr(r, "to_dict") else r for r in self.results]
        return data


class ReportGenerator:
    """Generate scan reports in various formats."""

    def __init__(self):
        pass

    def to_json(self, summary: ScanSummary, indent: int = 2) -> str:
        """Generate JSON report.

        Args:
            summary: Scan summary data
            indent: JSON indentation level

        Returns:
            JSON formatted string
        """
        return json.dumps(summary.to_dict(), indent=indent, ensure_ascii=False)

    def to_html(self, summary: ScanSummary) -> str:
        """Generate HTML report.

        Args:
            summary: Scan summary data

        Returns:
            HTML formatted string
        """

        # Escape helper
        def esc(text):
            return html.escape(str(text)) if text else ""

        # Build infected files table
        infected_rows = ""
        for result in summary.results:
            if result.status == "infected":
                infected_rows += f"""
                <tr class="infected">
                    <td>{esc(result.filepath)}</td>
                    <td class="malware">{esc(result.malware_name)}</td>
                    <td>{result.scan_time_ms}ms</td>
                </tr>"""

        # Build error files table
        error_rows = ""
        for result in summary.results:
            if result.status == "error":
                error_rows += f"""
                <tr class="error">
                    <td>{esc(result.filepath)}</td>
                    <td>{esc(result.error_message)}</td>
                </tr>"""

        # Build all files table
        all_files_rows = ""
        for result in summary.results:
            status_class = result.status
            status_text = {
                "clean": "Clean",
                "infected": f"Infected: {esc(result.malware_name)}",
                "error": f"Error: {esc(result.error_message)}",
            }.get(result.status, result.status)

            all_files_rows += f"""
                <tr class="{status_class}">
                    <td>{esc(result.filepath)}</td>
                    <td>{status_text}</td>
                    <td>{result.scan_time_ms}ms</td>
                </tr>"""

        # Calculate percentages for chart
        total = summary.total_files or 1
        clean_pct = (summary.clean_files / total) * 100
        infected_pct = (summary.infected_files / total) * 100
        error_pct = (summary.error_files / total) * 100

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KicomAV Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        header .meta {{
            opacity: 0.8;
            font-size: 0.9em;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .card h3 {{
            font-size: 0.9em;
            color: #666;
            margin-bottom: 5px;
        }}
        .card .value {{
            font-size: 2em;
            font-weight: bold;
        }}
        .card.infected .value {{
            color: #e74c3c;
        }}
        .card.clean .value {{
            color: #27ae60;
        }}
        .card.error .value {{
            color: #f39c12;
        }}
        .chart-container {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .bar-chart {{
            display: flex;
            height: 40px;
            border-radius: 5px;
            overflow: hidden;
            margin-top: 10px;
        }}
        .bar-clean {{
            background: #27ae60;
        }}
        .bar-infected {{
            background: #e74c3c;
        }}
        .bar-error {{
            background: #f39c12;
        }}
        .legend {{
            display: flex;
            gap: 20px;
            margin-top: 15px;
            flex-wrap: wrap;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .legend-color {{
            width: 15px;
            height: 15px;
            border-radius: 3px;
        }}
        section {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        section h2 {{
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
        }}
        tr.infected {{
            background: #fff5f5;
        }}
        tr.error {{
            background: #fffaf0;
        }}
        tr.clean:hover, tr.infected:hover, tr.error:hover {{
            background: #f0f0f0;
        }}
        .malware {{
            color: #e74c3c;
            font-weight: 600;
        }}
        .empty {{
            text-align: center;
            padding: 40px;
            color: #999;
        }}
        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        @media (max-width: 768px) {{
            .summary {{
                grid-template-columns: 1fr 1fr;
            }}
            table {{
                font-size: 0.9em;
            }}
            th, td {{
                padding: 8px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>KicomAV Scan Report</h1>
            <div class="meta">
                <div>Scan Path: {esc(summary.scan_path)}</div>
                <div>Date: {esc(summary.scan_date)}</div>
                <div>Version: {esc(summary.kicomav_version)} | Signatures: {summary.signature_count}</div>
            </div>
        </header>

        <div class="summary">
            <div class="card">
                <h3>Total Files</h3>
                <div class="value">{summary.total_files}</div>
            </div>
            <div class="card clean">
                <h3>Clean</h3>
                <div class="value">{summary.clean_files}</div>
            </div>
            <div class="card infected">
                <h3>Infected</h3>
                <div class="value">{summary.infected_files}</div>
            </div>
            <div class="card error">
                <h3>Errors</h3>
                <div class="value">{summary.error_files}</div>
            </div>
        </div>

        <div class="chart-container">
            <h3>Scan Results Distribution</h3>
            <div class="bar-chart">
                <div class="bar-clean" style="width: {clean_pct}%"></div>
                <div class="bar-infected" style="width: {infected_pct}%"></div>
                <div class="bar-error" style="width: {error_pct}%"></div>
            </div>
            <div class="legend">
                <div class="legend-item">
                    <div class="legend-color" style="background: #27ae60"></div>
                    <span>Clean ({summary.clean_files})</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #e74c3c"></div>
                    <span>Infected ({summary.infected_files})</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #f39c12"></div>
                    <span>Errors ({summary.error_files})</span>
                </div>
            </div>
        </div>

        {"" if not infected_rows else f'''
        <section>
            <h2>Infected Files ({summary.infected_files})</h2>
            <table>
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Malware Name</th>
                        <th>Scan Time</th>
                    </tr>
                </thead>
                <tbody>
                    {infected_rows}
                </tbody>
            </table>
        </section>
        '''}

        {"" if not error_rows else f'''
        <section>
            <h2>Errors ({summary.error_files})</h2>
            <table>
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody>
                    {error_rows}
                </tbody>
            </table>
        </section>
        '''}

        <section>
            <h2>All Scanned Files ({summary.total_files})</h2>
            {"<div class='empty'>No files scanned</div>" if not all_files_rows else f'''
            <table>
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Status</th>
                        <th>Scan Time</th>
                    </tr>
                </thead>
                <tbody>
                    {all_files_rows}
                </tbody>
            </table>
            '''}
        </section>

        <footer>
            Generated by KicomAV {esc(summary.kicomav_version)} |
            Total scan time: {summary.total_scan_time_ms}ms |
            Signature date: {esc(summary.signature_date)}
        </footer>
    </div>
</body>
</html>"""

        return html_content

    def save(self, summary: ScanSummary, filepath: str, format: str = "json") -> None:
        """Save report to file.

        Args:
            summary: Scan summary data
            filepath: Output file path
            format: Report format ("json" or "html")
        """
        if format == "json":
            content = self.to_json(summary)
        elif format == "html":
            content = self.to_html(summary)
        else:
            raise ValueError(f"Unsupported format: {format}")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)


def create_summary_from_results(
    scan_path: str,
    results: list,
    kicomav_version: str = "",
    signature_count: int = 0,
    signature_date: str = "",
    total_scan_time_ms: int = 0,
) -> ScanSummary:
    """Create ScanSummary from a list of scan results.

    Args:
        scan_path: Path that was scanned
        results: List of result dictionaries or ScanFileResult objects
        kicomav_version: KicomAV version string
        signature_count: Number of signatures
        signature_date: Signature update date
        total_scan_time_ms: Total scan time in milliseconds

    Returns:
        ScanSummary object
    """
    file_results = []
    infected = 0
    clean = 0
    errors = 0

    for r in results:
        if isinstance(r, ScanFileResult):
            result = r
        elif isinstance(r, dict):
            result = ScanFileResult(
                filepath=r.get("filepath", r.get("filename", "")),
                status=r.get("status", "unknown"),
                malware_name=r.get("malware_name", r.get("malware")),
                error_message=r.get("error_message", r.get("error")),
                scan_time_ms=r.get("scan_time_ms", 0),
                sha256=r.get("sha256"),
                file_size=r.get("file_size"),
            )
        else:
            continue

        file_results.append(result)

        if result.status == "infected":
            infected += 1
        elif result.status == "clean":
            clean += 1
        elif result.status == "error":
            errors += 1

    return ScanSummary(
        scan_path=scan_path,
        total_files=len(file_results),
        infected_files=infected,
        clean_files=clean,
        error_files=errors,
        total_scan_time_ms=total_scan_time_ms,
        signature_count=signature_count,
        signature_date=signature_date,
        kicomav_version=kicomav_version,
        results=file_results,
    )
