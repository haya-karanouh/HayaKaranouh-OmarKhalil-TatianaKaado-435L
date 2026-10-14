"""Capture real API, database, and command output as evidence screenshots."""

import html
import json
import re
import sqlite3
import time
from pathlib import Path
from urllib.parse import quote

import requests
from playwright.sync_api import Error as PlaywrightError, sync_playwright
from sqlalchemy.engine import make_url

from common.config import DATABASE_URL, PROJECT_ROOT


class EvidenceRecorder:
    def __init__(self, student_full_name):
        self.student_full_name = student_full_name
        folder_name = re.sub(r"[^A-Za-z0-9]+", "_", student_full_name.strip()).strip("_")
        self.output_dir = PROJECT_ROOT / "evidence" / folder_name
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.captions_path = self.output_dir / "captions.md"
        existing = [int(match.group(1)) for path in self.output_dir.glob("[0-9][0-9]_*.png")
                    if (match := re.match(r"(\d+)_", path.name))]
        self._next_number = max(existing, default=0) + 1

    def _render(self, caption, explanation, sections):
        number = self._next_number
        self._next_number += 1
        slug = re.sub(r"[^A-Za-z0-9]+", "_", caption).strip("_").lower()[:48] or "evidence"
        filename = f"{number:02d}_{slug}.png"
        prefix = f"{self.student_full_name} – "
        full_caption = caption if caption.startswith(prefix) else f"{prefix}{caption}"
        explanation_html = (
            f"<section><h2>Explanation</h2><pre>{html.escape(explanation)}</pre></section>"
            if explanation else ""
        )
        section_parts = []
        for label, content in sections:
            if label == "Rows" and isinstance(content, dict) and {"columns", "rows"} <= content.keys():
                columns = content["columns"]
                heading = "".join(f"<th>{html.escape(str(column))}</th>" for column in columns)
                body = "".join(
                    "<tr>" + "".join(
                        f"<td>{html.escape(str(row.get(column, '')))}</td>" for column in columns
                    ) + "</tr>"
                    for row in content["rows"]
                )
                if not body:
                    body = f"<tr><td colspan='{max(1, len(columns))}'>(no rows)</td></tr>"
                section_parts.append(
                    f"<section><h2>{html.escape(label)}</h2><table><thead><tr>{heading}</tr></thead><tbody>{body}</tbody></table></section>"
                )
            else:
                section_parts.append(
                    f"<section><h2>{html.escape(label)}</h2><pre>{html.escape(str(content))}</pre></section>"
                )
        section_html = explanation_html + "".join(section_parts)
        document = f"""<!doctype html><html><head><meta charset='utf-8'><style>
            * {{ box-sizing: border-box; }} body {{ margin: 0; padding: 38px; color: #17212b;
            background: #edf1f4; font: 15px/1.5 -apple-system, BlinkMacSystemFont, sans-serif; }}
            main {{ max-width: 1100px; margin: auto; background: white; border: 1px solid #cad2d9;
            box-shadow: 0 8px 26px #10203020; }} header {{ padding: 25px 30px; color: white;
            background: #173b4f; }} h1 {{ margin: 0; font-size: 23px; }} section {{ padding: 18px 30px;
            border-bottom: 1px solid #e0e5e9; }} h2 {{ margin: 0 0 9px; color: #345365; font-size: 13px;
            text-transform: uppercase; }} pre {{ margin: 0; white-space: pre-wrap; overflow-wrap: anywhere;
            font: 13px/1.55 ui-monospace, SFMono-Regular, monospace; }} table {{ width: 100%; border-collapse: collapse;
            font: 12px/1.45 ui-monospace, SFMono-Regular, monospace; }} th, td {{ padding: 8px; border: 1px solid #d7dfe5;
            text-align: left; vertical-align: top; overflow-wrap: anywhere; }} th {{ background: #eef3f6; }}
            </style></head><body><main><header><h1>{html.escape(full_caption)}</h1></header>
            {section_html}</main></body></html>"""
        image_path = self.output_dir / filename
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch()
            except PlaywrightError:
                browser = playwright.chromium.launch(channel="chrome")
            page = browser.new_page(viewport={"width": 1200, "height": 900}, device_scale_factor=1)
            page.set_content(document, wait_until="load")
            page.locator("body").screenshot(path=str(image_path), animations="disabled")
            browser.close()
        with self.captions_path.open("a", encoding="utf-8") as captions:
            captions.write(f"- **{filename}**: {full_caption}\n")
            if explanation:
                captions.write(f"  - {explanation}\n")
        return image_path

    def api(self, caption, method, url, token=None, json=None, params=None, explanation=""):
        """Send a live HTTP request and screenshot its request and response."""
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        started = time.perf_counter()
        response = requests.request(
            method.upper(), url, headers=headers, json=json, params=params, timeout=20,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        request_headers = dict(response.request.headers)
        if token:
            request_headers["Authorization"] = f"Bearer {token[:12]}…"
        try:
            response_payload = json_module_dumps(response.json())
        except (ValueError, requests.exceptions.JSONDecodeError):
            response_payload = response.text
        request_body = json_module_dumps(json) if json is not None else "(none)"
        self._render(caption, explanation, [
            ("Request", f"{method.upper()} {response.url}"),
            ("Headers", json_module_dumps(request_headers)),
            ("Request body", request_body),
            ("HTTP status", str(response.status_code)),
            ("Response time", f"{elapsed_ms:.2f} ms"),
            ("Response", response_payload),
        ])
        return response

    def db(self, caption, sql, params=(), explanation=""):
        """Run a parameterized, read-only query against the configured SQLite DB."""
        url = make_url(DATABASE_URL)
        if not url.drivername.startswith("sqlite"):
            raise ValueError("Evidence database capture currently requires SQLite")
        database_path = Path(url.database or "").expanduser().resolve()
        readonly_uri = f"file:{quote(database_path.as_posix(), safe='/')}?mode=ro"
        connection = sqlite3.connect(readonly_uri, uri=True)
        allowed_actions = {
            sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
            getattr(sqlite3, "SQLITE_RECURSIVE", -1),
        }
        connection.set_authorizer(
            lambda action, _arg1, _arg2, _database, _trigger:
            sqlite3.SQLITE_OK if action in allowed_actions else sqlite3.SQLITE_DENY
        )
        try:
            cursor = connection.execute(sql, tuple(params))
            headers = [column[0] for column in cursor.description or ()]
            rows = [dict(zip(headers, row)) for row in cursor.fetchall()]
        finally:
            connection.close()
        result = {"columns": headers, "rows": rows}
        self._render(caption, explanation, [("Read-only query", sql), ("Parameters", json_module_dumps(params)),
                                            ("Rows", result)])
        return rows

    def text(self, caption, content, explanation=""):
        """Render exact caller-supplied command output as a screenshot."""
        return self._render(caption, explanation, [("Output", str(content))])


def json_module_dumps(value):
    return json.dumps(value, indent=2, default=str, ensure_ascii=False)
