PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE masks (
    id       INTEGER PRIMARY KEY,
    mask     TEXT NOT NULL,
    type     INTEGER NOT NULL,
    enabled  INTEGER NOT NULL,
    reason   TEXT,
    hits     INTEGER NOT NULL,
    last_hit INTEGER
);
CREATE TABLE changes (
    mask_id INTEGER NOT NULL,
    by_nick TEXT NOT NULL,
    by_oper TEXT,
    time    INTEGER NOT NULL,
    change  TEXT NOT NULL
);
CREATE TABLE reasons (
    key   TEXT NOT NULL,
    value TEXT NOT NULL
);
COMMIT;
