"""SQLite/PostgreSQL connection layer and idempotent baseline schema initializer."""
from contextlib import contextmanager
from backend.core.config import DATABASE_URL

class ConnectionAdapter:
    def __init__(self, raw, dialect): self.raw=raw; self.dialect=dialect
    def execute(self, sql, params=()):
        if self.dialect=='postgres': sql=sql.replace('?', '%s')
        return self.raw.execute(sql, params)
    def executescript(self, script):
        # Schema DDL contains no semicolons inside quoted strings.
        for statement in script.split(';'):
            if statement.strip(): self.execute(statement)
    def __getattr__(self,name): return getattr(self.raw,name)

@contextmanager
def connection():
    if DATABASE_URL.startswith('sqlite:///'):
        import sqlite3
        path=DATABASE_URL.removeprefix('sqlite:///')
        from pathlib import Path
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        raw=sqlite3.connect(path,timeout=30);raw.row_factory=sqlite3.Row
        raw.execute('PRAGMA foreign_keys=ON');raw.execute('PRAGMA journal_mode=WAL')
        adapter=ConnectionAdapter(raw,'sqlite')
    elif DATABASE_URL.startswith(('postgresql://','postgres://')):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc: raise RuntimeError('Install psycopg[binary] to use PostgreSQL') from exc
        raw=psycopg.connect(DATABASE_URL,row_factory=dict_row);adapter=ConnectionAdapter(raw,'postgres')
    else: raise RuntimeError('DATABASE_URL must be sqlite:///... or postgresql://...')
    try:
        yield adapter;raw.commit()
    except Exception:
        raw.rollback();raise
    finally:raw.close()

def initialize_schema():
    with connection() as c:
        schema="""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'analyst',active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('Website','Server')),classification TEXT NOT NULL DEFAULT 'Unknown',owner TEXT NOT NULL DEFAULT '',environment TEXT NOT NULL DEFAULT 'Unknown',criticality TEXT NOT NULL DEFAULT 'Medium',compliance INTEGER,status TEXT NOT NULL DEFAULT 'Active',waf TEXT,source TEXT NOT NULL DEFAULT 'manual',source_id TEXT,attributes TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(id),source TEXT NOT NULL DEFAULT 'manual',source_finding_id TEXT,title TEXT NOT NULL,cve TEXT,severity TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'Open',first_seen TEXT,last_seen TEXT,due_at TEXT,evidence TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(source,source_finding_id,asset_id));
        CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),action TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT,detail TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),expires_at TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sync_runs(id TEXT PRIMARY KEY,source TEXT NOT NULL,status TEXT NOT NULL,started_at TEXT NOT NULL,finished_at TEXT,records_read INTEGER NOT NULL DEFAULT 0,records_written INTEGER NOT NULL DEFAULT 0,error TEXT);
        CREATE TABLE IF NOT EXISTS exception_requests(id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(id),finding_id TEXT REFERENCES findings(id),requested_by INTEGER REFERENCES users(id),reason TEXT NOT NULL,expires_at TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Pending',reviewed_by INTEGER REFERENCES users(id),review_note TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS containment_actions(id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(id),action TEXT NOT NULL,status TEXT NOT NULL,impact TEXT NOT NULL,requested_by INTEGER REFERENCES users(id),approved_by INTEGER REFERENCES users(id),created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS workflow_requests(id TEXT PRIMARY KEY,kind TEXT NOT NULL,asset_id TEXT REFERENCES assets(id),finding_id TEXT REFERENCES findings(id),status TEXT NOT NULL DEFAULT 'Pending',payload TEXT NOT NULL DEFAULT '{}',requested_by INTEGER REFERENCES users(id),created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS zero_day_signals(id TEXT PRIMARY KEY,title TEXT NOT NULL,severity TEXT NOT NULL,confidence TEXT NOT NULL,status TEXT NOT NULL,source TEXT NOT NULL,evidence TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_assets_scope ON assets(kind,classification,status);
        CREATE INDEX IF NOT EXISTS idx_findings_scope ON findings(asset_id,state,severity,due_at);
        CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(created_at);
        CREATE INDEX IF NOT EXISTS idx_exception_state ON exception_requests(status,expires_at);
        """
        if c.dialect=='postgres':
            schema=schema.replace('id INTEGER PRIMARY KEY','id BIGSERIAL PRIMARY KEY')
            for column in ('user_id','requested_by','reviewed_by','approved_by'):
                schema=schema.replace(column+' INTEGER',column+' BIGINT')
        c.executescript(schema)
