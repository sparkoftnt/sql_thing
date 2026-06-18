#!/usr/bin/env python3
"""
SQLite Netzwerk-Server mit REST-API, Web-UI, API-Key-Auth,
rollenbasierten + tabellenspezifischen Berechtigungen,
Logging und Suchfunktion.
"""

import json
import sqlite3
import os
import logging
from functools import wraps
from flask import Flask, request, jsonify, g, render_template

CONFIG_FILE = "config.json"

# ---------------------------------------------------------------------------
# Konfiguration laden
# ---------------------------------------------------------------------------
def load_config():
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"Konfigurationsdatei '{CONFIG_FILE}' nicht gefunden.")
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

config = load_config()
app = Flask(__name__)

# ---------------------------------------------------------------------------
# Logging einrichten
# ---------------------------------------------------------------------------
log_conf = config.get("logging", {})
log_level = getattr(logging, log_conf.get("level", "INFO").upper(), logging.INFO)
log_file = log_conf.get("file", "server.log")

logger = logging.getLogger("sqlite_server")
logger.setLevel(log_level)

# Format mit Zeitstempel, Level, Nachricht
formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Datei-Handler
file_handler = logging.FileHandler(log_file, encoding="utf-8")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Konsolen-Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def log_action(action, status="OK", details=""):
    """Strukturiertes Logging eines API-Zugriffs."""
    user = getattr(g, "user", None)
    user_name = user["name"] if user else "anonym"
    role = user["role"] if user else "-"
    ip = request.remote_addr
    logger.info(
        f"{status} | user={user_name} | role={role} | ip={ip} | "
        f"action={action} | {request.method} {request.path} | {details}"
    )


# ---------------------------------------------------------------------------
# Datenbankverbindung (pro Request)
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(config["database"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# Authentifizierung & Autorisierung
# ---------------------------------------------------------------------------
def get_api_key():
    key = request.headers.get("X-API-Key")
    if not key:
        key = request.args.get("api_key")
    if not key:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            key = auth[7:]
    return key


def authenticate():
    """Prüft API-Key und liefert User-Info inkl. Berechtigungen."""
    key = get_api_key()
    if not key:
        return None
    user = config["api_keys"].get(key)
    if not user:
        return None
    role = user.get("role")
    role_def = config["roles"].get(role, {})
    return {
        "name": user.get("name"),
        "role": role,
        "permissions": set(role_def.get("permissions", [])),
        "table_permissions": role_def.get("table_permissions", {}),
    }


def has_table_permission(user, table, permission):
    """
    Prüft, ob der Nutzer 'permission' auf 'table' ausführen darf.
    table_permissions == "*" -> alle Tabellen mit globalen Rechten.
    Sonst Dict pro Tabelle.
    """
    tp = user["table_permissions"]
    if tp == "*":
        return permission in user["permissions"]
    allowed = tp.get(table)
    if allowed is None:
        return False  # Tabelle nicht freigegeben
    return permission in allowed


def require_permission(permission, table_scoped=False):
    """
    Decorator für Authentifizierung + Berechtigungsprüfung.
    table_scoped=True -> zusätzlich tabellenspezifische Prüfung
    (erwartet ein 'table'-Argument in der Route).
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = authenticate()
            if user is None:
                log_action(func.__name__, status="DENIED", details="kein/ungültiger API-Key")
                return jsonify({"error": "Ungültiger oder fehlender API-Key"}), 401

            g.user = user

            # globale Berechtigung
            if permission not in user["permissions"]:
                log_action(func.__name__, status="FORBIDDEN",
                           details=f"fehlende globale Berechtigung '{permission}'")
                return jsonify({
                    "error": "Keine Berechtigung",
                    "benötigt": permission,
                    "rolle": user["role"]
                }), 403

            # tabellenspezifische Berechtigung
            if table_scoped:
                table = kwargs.get("table")
                if table and not has_table_permission(user, table, permission):
                    log_action(func.__name__, status="FORBIDDEN",
                               details=f"kein Zugriff auf Tabelle '{table}' ({permission})")
                    return jsonify({
                        "error": "Keine Berechtigung für diese Tabelle",
                        "tabelle": table,
                        "benötigt": permission
                    }), 403

            return func(*args, **kwargs)
        return wrapper
    return decorator


def accessible_tables(user, all_tables, permission="read"):
    """Filtert Tabellenliste nach Lese-Berechtigung des Nutzers."""
    if user["table_permissions"] == "*":
        return all_tables
    return [t for t in all_tables if has_table_permission(user, t, permission)]


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
def is_safe_identifier(name):
    return name.replace("_", "").isalnum()


def table_exists(db, table):
    cur = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    )
    return cur.fetchone() is not None


def get_column_names(db, table):
    cur = db.execute(f'PRAGMA table_info("{table}")')
    return [row["name"] for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# REST-API: Tabellen
# ---------------------------------------------------------------------------
@app.route("/api/tables", methods=["GET"])
@require_permission("read")
def list_tables():
    db = get_db()
    cur = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    all_tables = [row["name"] for row in cur.fetchall()]
    # Nur Tabellen zeigen, auf die der Nutzer Lesezugriff hat
    tables = accessible_tables(g.user, all_tables, "read")
    log_action("list_tables", details=f"{len(tables)} Tabellen sichtbar")
    return jsonify({"tables": tables})


@app.route("/api/tables/<table>/schema", methods=["GET"])
@require_permission("read", table_scoped=True)
def table_schema(table):
    if not is_safe_identifier(table):
        return jsonify({"error": "Ungültiger Tabellenname"}), 400
    db = get_db()
    if not table_exists(db, table):
        return jsonify({"error": "Tabelle nicht gefunden"}), 404
    cur = db.execute(f'PRAGMA table_info("{table}")')
    columns = [dict(row) for row in cur.fetchall()]
    log_action("table_schema", details=f"table={table}")
    return jsonify({"table": table, "columns": columns})


@app.route("/api/tables/<table>", methods=["POST"])
@require_permission("create_table", table_scoped=True)
def create_table(table):
    if not is_safe_identifier(table):
        return jsonify({"error": "Ungültiger Tabellenname"}), 400
    data = request.get_json(silent=True) or {}
    columns = data.get("columns")
    if not columns or not isinstance(columns, dict):
        return jsonify({"error": "Feld 'columns' (dict) erforderlich"}), 400

    col_defs = []
    for name, definition in columns.items():
        if not is_safe_identifier(name):
            return jsonify({"error": f"Ungültiger Spaltenname: {name}"}), 400
        col_defs.append(f'"{name}" {definition}')

    sql = f'CREATE TABLE "{table}" ({", ".join(col_defs)})'
    db = get_db()
    try:
        db.execute(sql)
        db.commit()
    except sqlite3.Error as e:
        log_action("create_table", status="ERROR", details=str(e))
        return jsonify({"error": str(e)}), 400
    log_action("create_table", details=f"table={table}")
    return jsonify({"status": "Tabelle erstellt", "table": table}), 201


@app.route("/api/tables/<table>", methods=["DELETE"])
@require_permission("drop_table", table_scoped=True)
def drop_table(table):
    if not is_safe_identifier(table):
        return jsonify({"error": "Ungültiger Tabellenname"}), 400
    db = get_db()
    if not table_exists(db, table):
        return jsonify({"error": "Tabelle nicht gefunden"}), 404
    db.execute(f'DROP TABLE "{table}"')
    db.commit()
    log_action("drop_table", status="WARN", details=f"table={table} gelöscht")
    return jsonify({"status": "Tabelle gelöscht", "table": table})


# ---------------------------------------------------------------------------
# REST-API: Datensätze (CRUD) + Suche
# ---------------------------------------------------------------------------
@app.route("/api/tables/<table>/rows", methods=["GET"])
@require_permission("read", table_scoped=True)
def get_rows(table):
    if not is_safe_identifier(table):
        return jsonify({"error": "Ungültiger Tabellenname"}), 400
    db = get_db()
    if not table_exists(db, table):
        return jsonify({"error": "Tabelle nicht gefunden"}), 404

    limit = max(1, min(request.args.get("limit", default=100, type=int), 1000))
    offset = request.args.get("offset", default=0, type=int)

    # ---- Suchfunktion ----
    search = request.args.get("search", "").strip()
    search_column = request.args.get("column", "").strip()

    base_sql = f'SELECT rowid AS _rowid, * FROM "{table}"'
    params = []
    where_clauses = []

    if search:
        columns = get_column_names(db, table)
        if search_column:
            # Suche in einer bestimmten Spalte
            if search_column not in columns:
                return jsonify({"error": f"Spalte '{search_column}' nicht vorhanden"}), 400
            where_clauses.append(f'CAST("{search_column}" AS TEXT) LIKE ?')
            params.append(f"%{search}%")
        else:
            # Suche über alle Spalten (OR-verknüpft)
            ors = [f'CAST("{c}" AS TEXT) LIKE ?' for c in columns]
            where_clauses.append("(" + " OR ".join(ors) + ")")
            params.extend([f"%{search}%"] * len(columns))

    if where_clauses:
        base_sql += " WHERE " + " AND ".join(where_clauses)

    base_sql += " LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    try:
        cur = db.execute(base_sql, params)
        rows = [dict(r) for r in cur.fetchall()]
    except sqlite3.Error as e:
        log_action("get_rows", status="ERROR", details=str(e))
        return jsonify({"error": str(e)}), 400

    log_action("get_rows",
               details=f"table={table} count={len(rows)} search='{search}' col='{search_column}'")
    return jsonify({
        "table": table,
        "count": len(rows),
        "search": search or None,
        "rows": rows
    })


@app.route("/api/tables/<table>/rows", methods=["POST"])
@require_permission("write", table_scoped=True)
def insert_row(table):
    if not is_safe_identifier(table):
        return jsonify({"error": "Ungültiger Tabellenname"}), 400
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "JSON-Objekt mit Spaltenwerten erforderlich"}), 400

    db = get_db()
    if not table_exists(db, table):
        return jsonify({"error": "Tabelle nicht gefunden"}), 404

    cols = list(data.keys())
    for c in cols:
        if not is_safe_identifier(c):
            return jsonify({"error": f"Ungültiger Spaltenname: {c}"}), 400

    placeholders = ", ".join(["?"] * len(cols))
    col_names = ", ".join(f'"{c}"' for c in cols)
    sql = f'INSERT INTO "{table}" ({col_names}) VALUES ({placeholders})'

    try:
        cur = db.execute(sql, list(data.values()))
        db.commit()
    except sqlite3.Error as e:
        log_action("insert_row", status="ERROR", details=str(e))
        return jsonify({"error": str(e)}), 400
    log_action("insert_row", details=f"table={table} id={cur.lastrowid}")
    return jsonify({"status": "eingefügt", "id": cur.lastrowid}), 201


@app.route("/api/tables/<table>/rows/<int:row_id>", methods=["PUT"])
@require_permission("write", table_scoped=True)
def update_row(table, row_id):
    if not is_safe_identifier(table):
        return jsonify({"error": "Ungültiger Tabellenname"}), 400
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "JSON-Objekt erforderlich"}), 400

    db = get_db()
    if not table_exists(db, table):
        return jsonify({"error": "Tabelle nicht gefunden"}), 404

    cols = list(data.keys())
    for c in cols:
        if not is_safe_identifier(c):
            return jsonify({"error": f"Ungültiger Spaltenname: {c}"}), 400

    set_clause = ", ".join(f'"{c}" = ?' for c in cols)
    sql = f'UPDATE "{table}" SET {set_clause} WHERE rowid = ?'
    params = list(data.values()) + [row_id]

    try:
        cur = db.execute(sql, params)
        db.commit()
    except sqlite3.Error as e:
        log_action("update_row", status="ERROR", details=str(e))
        return jsonify({"error": str(e)}), 400
    if cur.rowcount == 0:
        return jsonify({"error": "Datensatz nicht gefunden"}), 404
    log_action("update_row", details=f"table={table} rowid={row_id}")
    return jsonify({"status": "aktualisiert", "rowid": row_id})


@app.route("/api/tables/<table>/rows/<int:row_id>", methods=["DELETE"])
@require_permission("delete", table_scoped=True)
def delete_row(table, row_id):
    if not is_safe_identifier(table):
        return jsonify({"error": "Ungültiger Tabellenname"}), 400
    db = get_db()
    if not table_exists(db, table):
        return jsonify({"error": "Tabelle nicht gefunden"}), 404
    cur = db.execute(f'DELETE FROM "{table}" WHERE rowid = ?', (row_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "Datensatz nicht gefunden"}), 404
    log_action("delete_row", status="WARN", details=f"table={table} rowid={row_id}")
    return jsonify({"status": "gelöscht", "rowid": row_id})


# ---------------------------------------------------------------------------
# REST-API: Raw-SQL
# ---------------------------------------------------------------------------
@app.route("/api/query", methods=["POST"])
@require_permission("execute_raw")
def raw_query():
    data = request.get_json(silent=True) or {}
    sql = data.get("sql")
    params = data.get("params", [])
    if not sql:
        return jsonify({"error": "Feld 'sql' erforderlich"}), 400

    db = get_db()
    try:
        cur = db.execute(sql, params)
        if cur.description:
            rows = [dict(r) for r in cur.fetchall()]
            log_action("raw_query", details=f"SELECT -> {len(rows)} Zeilen")
            return jsonify({"rows": rows, "count": len(rows)})
        else:
            db.commit()
            log_action("raw_query", status="WARN",
                       details=f"Schreiboperation, rowcount={cur.rowcount}")
            return jsonify({"status": "ausgeführt", "rowcount": cur.rowcount})
    except sqlite3.Error as e:
        log_action("raw_query", status="ERROR", details=str(e))
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Info-Endpunkt
# ---------------------------------------------------------------------------
@app.route("/api/me", methods=["GET"])
def whoami():
    user = authenticate()
    if user is None:
        return jsonify({"error": "Ungültiger oder fehlender API-Key"}), 401
    g.user = user
    tp = user["table_permissions"]
    log_action("whoami")
    return jsonify({
        "name": user["name"],
        "role": user["role"],
        "permissions": sorted(user["permissions"]),
        "table_permissions": tp if tp == "*" else
            {t: sorted(p) for t, p in tp.items()},
    })


@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("=" * 50)
    logger.info(f"Server startet | DB={config['database']} | "
                f"Adresse={config['host']}:{config['port']}")
    logger.info("=" * 50)
    app.run(
        host=config.get("host", "0.0.0.0"),
        port=config.get("port", 5000),
        debug=False
    )