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
    PathUpdate,
    Application,
    Other,
}

impl MessageKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageKind::Proposal => "proposal",
            MessageKind::Commit => "commit",
            MessageKind::PathUpdate => "path_update",
            MessageKind::Application => "application",
            MessageKind::Other => "other",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "proposal" => MessageKind::Proposal,
            "commit" => MessageKind::Commit,
            "path_update" => MessageKind::PathUpdate,
            "application" => MessageKind::Application,
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
            CREATE TABLE IF NOT EXISTS users (
                username    TEXT PRIMARY KEY,
                password_hash BLOB NOT NULL,
                salt        BLOB NOT NULL,
                classic_pub BLOB NOT NULL,
                pq_pub      BLOB NOT NULL,
                created_at  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token       TEXT PRIMARY KEY,
                username    TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(username);
            CREATE TABLE IF NOT EXISTS keypackages (
                username    TEXT PRIMARY KEY,
                payload     BLOB NOT NULL,
                created_at  INTEGER NOT NULL
            );
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
        self.list_group_kind(group_id, None, limit, None)
    }

    pub fn list_group_kind(
        &self,
        group_id: &str,
        kind: Option<MessageKind>,
        limit: usize,
        before_id: Option<i64>,
    ) -> Result<Vec<StoredMessage>, StorageError> {
        let mut out = Vec::new();
        match (kind, before_id) {
            (Some(kind), Some(before_id)) => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, group_id, kind, size, created_at, path
                     FROM messages
                     WHERE group_id = ?1 AND kind = ?2 AND id < ?3
                     ORDER BY created_at DESC, id DESC
                     LIMIT ?4",
                )?;
                let rows = stmt.query_map(
                    params![group_id, kind.as_str(), before_id, limit as i64],
                    |row| {
                        let kind_str: String = row.get(2)?;
                        Ok(StoredMessage {
                            id: row.get(0)?,
                            group_id: row.get(1)?,
                            kind: MessageKind::from_str(&kind_str),
                            size: row.get::<_, i64>(3)? as u64,
                            created_at: row.get(4)?,
                            path: PathBuf::from(row.get::<_, String>(5)?),
                        })
                    },
                )?;
                for row in rows {
                    out.push(row?);
                }
            }
            (Some(kind), None) => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, group_id, kind, size, created_at, path
                     FROM messages
                     WHERE group_id = ?1 AND kind = ?2
                     ORDER BY created_at DESC, id DESC
                     LIMIT ?3",
                )?;
                let rows = stmt.query_map(params![group_id, kind.as_str(), limit as i64], |row| {
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
                for row in rows {
                    out.push(row?);
                }
            }
            (None, Some(before_id)) => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, group_id, kind, size, created_at, path
                     FROM messages
                     WHERE group_id = ?1 AND id < ?2
                     ORDER BY created_at DESC, id DESC
                     LIMIT ?3",
                )?;
                let rows = stmt.query_map(params![group_id, before_id, limit as i64], |row| {
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
                for row in rows {
                    out.push(row?);
                }
            }
            (None, None) => {
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
                for row in rows {
                    out.push(row?);
                }
            }
        }
        Ok(out)
    }

    pub fn load_message_group_kind(
        &self,
        id: i64,
        group_id: &str,
        kind: MessageKind,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT path FROM messages WHERE id = ?1 AND group_id = ?2 AND kind = ?3",
        )?;
        let mut rows = stmt.query(params![id, group_id, kind.as_str()])?;
        let Some(row) = rows.next()? else { return Ok(None) };
        let path: String = row.get(0)?;
        let data = fs::read(path)?;
        Ok(Some(data))
    }

    pub fn load_message_group(
        &self,
        id: i64,
        group_id: &str,
    ) -> Result<Option<(MessageKind, Vec<u8>)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT kind, path FROM messages WHERE id = ?1 AND group_id = ?2",
        )?;
        let mut rows = stmt.query(params![id, group_id])?;
        let Some(row) = rows.next()? else { return Ok(None) };
        let kind_str: String = row.get(0)?;
        let path: String = row.get(1)?;
        let data = fs::read(path)?;
        Ok(Some((MessageKind::from_str(&kind_str), data)))
    }

    pub fn insert_user(
        &mut self,
        username: &str,
        password_hash: &[u8],
        salt: &[u8],
        classic_pub: &[u8],
        pq_pub: &[u8],
    ) -> Result<(), StorageError> {
        let now = now_unix();
        self.conn.execute(
            "INSERT INTO users (username, password_hash, salt, classic_pub, pq_pub, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![username, password_hash, salt, classic_pub, pq_pub, now],
        )?;
        Ok(())
    }

    pub fn get_user_keys(
        &self,
        username: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT classic_pub, pq_pub FROM users WHERE username = ?1",
        )?;
        let mut rows = stmt.query(params![username])?;
        let Some(row) = rows.next()? else { return Ok(None) };
        let classic: Vec<u8> = row.get(0)?;
        let pq: Vec<u8> = row.get(1)?;
        Ok(Some((classic, pq)))
    }

    pub fn get_user_auth(
        &self,
        username: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT password_hash, salt FROM users WHERE username = ?1",
        )?;
        let mut rows = stmt.query(params![username])?;
        let Some(row) = rows.next()? else { return Ok(None) };
        let password_hash: Vec<u8> = row.get(0)?;
        let salt: Vec<u8> = row.get(1)?;
        Ok(Some((password_hash, salt)))
    }

    pub fn insert_session(
        &mut self,
        token: &str,
        username: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![token, username, created_at, expires_at],
        )?;
        Ok(())
    }

    pub fn get_session(
        &self,
        token: &str,
    ) -> Result<Option<(String, i64)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT username, expires_at FROM sessions WHERE token = ?1",
        )?;
        let mut rows = stmt.query(params![token])?;
        let Some(row) = rows.next()? else { return Ok(None) };
        let username: String = row.get(0)?;
        let expires_at: i64 = row.get(1)?;
        Ok(Some((username, expires_at)))
    }

    pub fn delete_session(&mut self, token: &str) -> Result<(), StorageError> {
        self.conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])?;
        Ok(())
    }

    pub fn upsert_key_package(
        &mut self,
        username: &str,
        payload: &[u8],
    ) -> Result<(), StorageError> {
        let now = now_unix();
        self.conn.execute(
            "INSERT INTO keypackages (username, payload, created_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(username) DO UPDATE SET payload = excluded.payload, created_at = excluded.created_at",
            params![username, payload, now],
        )?;
        Ok(())
    }

    pub fn get_key_package(
        &self,
        username: &str,
    ) -> Result<Option<(Vec<u8>, i64)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT payload, created_at FROM keypackages WHERE username = ?1",
        )?;
        let mut rows = stmt.query(params![username])?;
        let Some(row) = rows.next()? else { return Ok(None) };
        let payload: Vec<u8> = row.get(0)?;
        let created_at: i64 = row.get(1)?;
        Ok(Some((payload, created_at)))
    }

    pub fn count_by_kind(
        &self,
        group_id: &str,
        kind: MessageKind,
    ) -> Result<u64, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT COALESCE(COUNT(*), 0) FROM messages WHERE group_id = ?1 AND kind = ?2",
        )?;
        let count: i64 = stmt.query_row(params![group_id, kind.as_str()], |row| row.get(0))?;
        Ok(count as u64)
    }

    pub fn delete_group_kind(
        &mut self,
        group_id: &str,
        kind: MessageKind,
    ) -> Result<u64, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, path, size FROM messages WHERE group_id = ?1 AND kind = ?2",
        )?;
        let rows = stmt.query_map(params![group_id, kind.as_str()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u64,
            ))
        })?;

        let mut deleted = 0u64;
        for row in rows {
            let (id, path, _size) = row?;
            let _ = fs::remove_file(path);
            self.conn.execute("DELETE FROM messages WHERE id = ?1", params![id])?;
            deleted += 1;
        }
        Ok(deleted)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    fn temp_config(label: &str, max_bytes: u64) -> (StorageConfig, PathBuf) {
        let base = std::env::temp_dir().join(format!("hybrid-mls-{label}-{}", random::<u64>()));
        let db_path = base.join("ds.sqlite");
        let mut config = StorageConfig::new(&base, &db_path);
        config.max_bytes = max_bytes;
        (config, base)
    }

    #[test]
    fn store_and_load_roundtrip() {
        let (config, base) = temp_config("store-load", 1024);
        let mut storage = Storage::open(config).expect("open storage");

        let payload = b"hello-world";
        let stored = storage
            .store_message("group-a", MessageKind::Proposal, payload)
            .expect("store message");

        let loaded = storage
            .load_message(stored.id)
            .expect("load message")
            .expect("missing message");
        assert_eq!(loaded, payload);

        let list = storage.list_group("group-a", 10).expect("list group");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].kind, MessageKind::Proposal);

        let count = storage
            .count_by_kind("group-a", MessageKind::Proposal)
            .expect("count");
        assert_eq!(count, 1);

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn eviction_removes_oldest() {
        let (config, base) = temp_config("evict", 10);
        let mut storage = Storage::open(config).expect("open storage");

        let first = storage
            .store_message("group-b", MessageKind::Proposal, b"12345678")
            .expect("store first");
        let second = storage
            .store_message("group-b", MessageKind::Proposal, b"ABCDEFGH")
            .expect("store second");

        let list = storage.list_group("group-b", 10).expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, second.id);

        let missing = storage.load_message(first.id).expect("load");
        assert!(missing.is_none());

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn delete_group_kind_clears_only_target() {
        let (config, base) = temp_config("delete-kind", 1024);
        let mut storage = Storage::open(config).expect("open storage");

        storage
            .store_message("group-c", MessageKind::Proposal, b"p1")
            .expect("store proposal");
        storage
            .store_message("group-c", MessageKind::Commit, b"c1")
            .expect("store commit");

        let deleted = storage
            .delete_group_kind("group-c", MessageKind::Proposal)
            .expect("delete");
        assert_eq!(deleted, 1);

        let proposals = storage
            .count_by_kind("group-c", MessageKind::Proposal)
            .expect("count proposal");
        let commits = storage
            .count_by_kind("group-c", MessageKind::Commit)
            .expect("count commit");
        assert_eq!(proposals, 0);
        assert_eq!(commits, 1);

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn user_and_session_roundtrip() {
        let (config, base) = temp_config("user-session", 1024);
        let mut storage = Storage::open(config).expect("open storage");

        let username = "alice";
        let password_hash = b"hash";
        let salt = b"salt";
        let classic = b"classic";
        let pq = b"pq";

        storage
            .insert_user(username, password_hash, salt, classic, pq)
            .expect("insert user");

        let keys = storage.get_user_keys(username).expect("get keys").unwrap();
        assert_eq!(keys.0, classic);
        assert_eq!(keys.1, pq);

        let auth = storage.get_user_auth(username).expect("get auth").unwrap();
        assert_eq!(auth.0, password_hash);
        assert_eq!(auth.1, salt);

        storage
            .insert_session("token1", username, 1, 2)
            .expect("insert session");
        let session = storage.get_session("token1").expect("get session").unwrap();
        assert_eq!(session.0, username);
        assert_eq!(session.1, 2);

        storage.delete_session("token1").expect("delete session");
        let missing = storage.get_session("token1").expect("get session");
        assert!(missing.is_none());

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn keypackage_upsert_and_fetch() {
        let (config, base) = temp_config("keypackage", 1024);
        let mut storage = Storage::open(config).expect("open storage");

        storage
            .upsert_key_package("alice", b"kp1")
            .expect("upsert keypackage");
        let first = storage
            .get_key_package("alice")
            .expect("get keypackage")
            .expect("missing keypackage");
        assert_eq!(first.0, b"kp1");

        storage
            .upsert_key_package("alice", b"kp2")
            .expect("upsert keypackage");
        let second = storage
            .get_key_package("alice")
            .expect("get keypackage")
            .expect("missing keypackage");
        assert_eq!(second.0, b"kp2");

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn list_and_load_group_kind() {
        let (config, base) = temp_config("group-kind", 1024);
        let mut storage = Storage::open(config).expect("open storage");

        let app_msg = storage
            .store_message("group-d", MessageKind::Application, b"app1")
            .expect("store app");
        storage
            .store_message("group-d", MessageKind::Proposal, b"prop1")
            .expect("store proposal");

        let app_only = storage
            .list_group_kind("group-d", Some(MessageKind::Application), 10, None)
            .expect("list app");
        assert_eq!(app_only.len(), 1);
        assert_eq!(app_only[0].id, app_msg.id);

        let loaded = storage
            .load_message_group_kind(app_msg.id, "group-d", MessageKind::Application)
            .expect("load app")
            .expect("missing app");
        assert_eq!(loaded, b"app1");

        let missing = storage
            .load_message_group_kind(app_msg.id, "group-d", MessageKind::Commit)
            .expect("load app");
        assert!(missing.is_none());

        let _ = std::fs::remove_dir_all(base);
    }
}
