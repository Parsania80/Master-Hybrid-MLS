use crate::ds::config::StorageConfig;
use rusqlite::{params, Connection};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
pub enum MessageKind {
    Proposal,
    Commit,
    Other,
}

impl MessageKind {
    fn as_str(&self) -> &'static str {
        match self {
            MessageKind::Proposal => "proposal",
            MessageKind::Commit => "commit",
            MessageKind::Other => "other",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "proposal" => MessageKind::Proposal,
            "commit" => MessageKind::Commit,
            _ => MessageKind::Other,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub id: i64,
    pub group_id: String,
    pub kind: MessageKind,
    pub size: u64,
    pub created_at: i64,
    pub path: PathBuf,
}

#[derive(Debug)]
pub struct Storage {
    conn: Connection,
    root_dir: PathBuf,
    max_bytes: u64,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl Storage {
    pub fn open(config: StorageConfig) -> Result<Self, StorageError> {
        fs::create_dir_all(&config.root_dir)?;
        let conn = Connection::open(&config.db_path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id    TEXT NOT NULL,
                kind        TEXT NOT NULL,
                size        INTEGER NOT NULL,
                created_at  INTEGER NOT NULL,
                path        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS messages_group_idx ON messages(group_id);
            CREATE INDEX IF NOT EXISTS messages_created_idx ON messages(created_at);
            ",
        )?;

        Ok(Self {
            conn,
            root_dir: config.root_dir,
            max_bytes: config.max_bytes,
        })
    }

    pub fn store_message(
        &mut self,
        group_id: &str,
        kind: MessageKind,
        payload: &[u8],
    ) -> Result<StoredMessage, StorageError> {
        let now = now_unix();
        let size = payload.len() as u64;
        let root_dir = self.root_dir.clone();
        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO messages (group_id, kind, size, created_at, path) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![group_id, kind.as_str(), size as i64, now, ""],
        )?;
        let id = tx.last_insert_rowid();
        let path = message_path_from(&root_dir, group_id, id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, payload)?;
        tx.execute(
            "UPDATE messages SET path = ?1 WHERE id = ?2",
            params![path.to_string_lossy().as_ref(), id],
        )?;
        tx.commit()?;

        self.evict_if_needed()?;

        Ok(StoredMessage {
            id,
            group_id: group_id.to_string(),
            kind,
            size,
            created_at: now,
            path,
        })
    }

    pub fn load_message(&self, id: i64) -> Result<Option<Vec<u8>>, StorageError> {
        let mut stmt = self.conn.prepare("SELECT path FROM messages WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;
        let Some(row) = rows.next()? else { return Ok(None) };
        let path: String = row.get(0)?;
        let data = fs::read(path)?;
        Ok(Some(data))
    }

    pub fn list_group(
        &self,
        group_id: &str,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, group_id, kind, size, created_at, path
             FROM messages
             WHERE group_id = ?1
             ORDER BY created_at DESC, id DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![group_id, limit as i64], |row| {
            let kind_str: String = row.get(2)?;
            Ok(StoredMessage {
                id: row.get(0)?,
                group_id: row.get(1)?,
                kind: MessageKind::from_str(&kind_str),
                size: row.get::<_, i64>(3)? as u64,
                created_at: row.get(4)?,
                path: PathBuf::from(row.get::<_, String>(5)?),
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    fn evict_if_needed(&mut self) -> Result<(), StorageError> {
        let mut total = self.total_size()?;
        while total > self.max_bytes {
            if let Some((id, path, size)) = self.oldest_message()? {
                let _ = fs::remove_file(&path);
                self.conn.execute("DELETE FROM messages WHERE id = ?1", params![id])?;
                total = total.saturating_sub(size);
            } else {
                break;
            }
        }
        Ok(())
    }

    fn total_size(&self) -> Result<u64, StorageError> {
        let mut stmt = self.conn.prepare("SELECT COALESCE(SUM(size), 0) FROM messages")?;
        let total: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(total as u64)
    }

    fn oldest_message(&self) -> Result<Option<(i64, PathBuf, u64)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, path, size FROM messages
             ORDER BY created_at ASC, id ASC
             LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;
        let Some(row) = rows.next()? else { return Ok(None) };
        let id: i64 = row.get(0)?;
        let path: String = row.get(1)?;
        let size: i64 = row.get(2)?;
        Ok(Some((id, PathBuf::from(path), size as u64)))
    }

}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn message_path_from(root_dir: &PathBuf, group_id: &str, id: i64) -> PathBuf {
    root_dir.join(sanitize(group_id)).join(format!("{id}.bin"))
}
