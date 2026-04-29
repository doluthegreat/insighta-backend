import os
import csv as csv_mod
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.table import Table
from rich import box

from insighta.api import api_request, API_URL
from insighta.credentials import load_credentials

console = Console()


# ─── Display helpers ──────────────────────────────────────────────────────────
def _fmt_date(iso: str) -> str:
    return iso.replace("T", " ").replace("Z", "") if iso else "-"


def _profiles_table(profiles: list) -> Table:
    table = Table(box=box.ROUNDED, show_lines=False)
    table.add_column("Name",        style="bold white",  no_wrap=True)
    table.add_column("Gender",      style="cyan",        no_wrap=True)
    table.add_column("Age",         justify="right")
    table.add_column("Age Group",   style="dim")
    table.add_column("Country",     style="green")
    table.add_column("Created At",  style="dim",         no_wrap=True)

    for p in profiles:
        table.add_row(
            p.get("name", "-"),
            p.get("gender", "-"),
            str(p.get("age", "-")),
            p.get("age_group", "-"),
            p.get("country_name") or p.get("country_id", "-"),
            _fmt_date(p.get("created_at")),
        )
    return table


def _pagination_line(res: dict):
    console.print(
        f"\n[dim]Page {res['page']} of {res['total_pages']}  |  "
        f"{len(res['data'])} of {res['total']} total[/]\n"
    )


def _profile_detail(p: dict):
    table = Table(box=box.ROUNDED, show_header=False)
    table.add_column(style="bold cyan")
    table.add_column()

    rows = [
        ("ID",                  p.get("id", "-")),
        ("Name",                p.get("name", "-")),
        ("Gender",              p.get("gender", "-")),
        ("Gender Probability",  str(p.get("gender_probability", "-"))),
        ("Age",                 str(p.get("age", "-"))),
        ("Age Group",           p.get("age_group", "-")),
        ("Country ID",          p.get("country_id", "-")),
        ("Country Name",        p.get("country_name", "-")),
        ("Country Probability", str(p.get("country_probability", "-"))),
        ("Created At",          _fmt_date(p.get("created_at"))),
    ]
    for label, val in rows:
        table.add_row(label, val)

    console.print()
    console.print(table)
    console.print()


# ─── Commands ─────────────────────────────────────────────────────────────────
def list_profiles(gender, age_group, country, min_age, max_age,
                  sort_by, order, page, limit):
    params = {}
    if gender:    params["gender"]    = gender
    if age_group: params["age_group"] = age_group
    if country:   params["country_id"] = country
    if min_age:   params["min_age"]   = min_age
    if max_age:   params["max_age"]   = max_age
    if sort_by:   params["sort_by"]   = sort_by
    if order:     params["order"]     = order
    if page:      params["page"]      = page
    if limit:     params["limit"]     = limit

    with console.status("Fetching profiles…"):
        res = api_request("GET", "/api/profiles", params=params)

    if not res["data"]:
        console.print("[yellow]No profiles found.[/]")
        return

    console.print(_profiles_table(res["data"]))
    _pagination_line(res)


def get_profile(profile_id: str):
    with console.status(f"Fetching profile {profile_id}…"):
        res = api_request("GET", f"/api/profiles/{profile_id}")
    _profile_detail(res["data"])


def search_profiles(query: str, page, limit):
    params = {"q": query}
    if page:  params["page"]  = page
    if limit: params["limit"] = limit

    with console.status("Searching…"):
        res = api_request("GET", "/api/profiles/search", params=params)

    if not res["data"]:
        console.print("[yellow]No results found.[/]")
        return

    console.print(_profiles_table(res["data"]))
    _pagination_line(res)


def create_profile(name: str):
    with console.status(f"Creating profile for '{name}'…"):
        res = api_request("POST", "/api/profiles", json={"name": name})
    console.print("[bold green]✔  Profile created.[/]")
    _profile_detail(res["data"])


def export_profiles(fmt, gender, country, age_group, sort_by, order):
    import requests as req_lib

    params = {"format": fmt}
    if gender:    params["gender"]    = gender
    if country:   params["country_id"] = country
    if age_group: params["age_group"] = age_group
    if sort_by:   params["sort_by"]   = sort_by
    if order:     params["order"]     = order

    with console.status("Exporting profiles…"):
        resp = api_request("GET", "/api/profiles/export", params=params, raw=True)

    if not resp.ok:
        msg = resp.json().get("message", resp.text) if resp.content else resp.reason
        raise click.ClickException(msg)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    filename  = f"profiles_{timestamp}.csv"
    dest      = os.path.join(os.getcwd(), filename)

    with open(dest, "w", newline="", encoding="utf-8") as f:
        f.write(resp.text)

    console.print(f"[bold green]✔  Exported to[/] [cyan]{dest}[/]")
