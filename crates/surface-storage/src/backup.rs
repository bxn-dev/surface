use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use uuid::Uuid;

use super::{Error, MIGRATIONS, secure_database};

/// Creates an integrity-checked, atomic `SQLite` backup.
///
/// # Errors
///
/// Returns an error if the destination exists or SQLite/filesystem operations fail.
pub fn backup_database(database: &Path, output: &Path) -> Result<(), Error> {
    if output.exists() {
        return Err(Error::new("backup destination already exists"));
    }
    let temporary = sibling_temporary(output, "backup");
    remove_if_exists(&temporary)?;
    let connection = Connection::open(database)
        .map_err(|error| Error::with_source("could not open database for backup", error))?;
    connection
        .execute("VACUUM INTO ?1", [temporary.to_string_lossy().as_ref()])
        .map_err(|error| Error::with_source("could not create SQLite backup", error))?;
    secure_database(&temporary)?;
    verify_database(&temporary)?;
    std::fs::rename(&temporary, output)
        .map_err(|error| Error::with_source("could not publish database backup", error))?;
    Ok(())
}

/// Verifies `SQLite` integrity and supported migration version.
///
/// # Errors
///
/// Returns an error for corruption, unreadable files, or future schemas.
pub fn verify_database(path: &Path) -> Result<(), Error> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| Error::with_source("could not open database for verification", error))?;
    let integrity = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(|error| Error::with_source("could not run SQLite integrity check", error))?;
    if integrity != "ok" {
        return Err(Error::new(format!(
            "database integrity check failed: {integrity}"
        )));
    }
    let version = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM surface_schema_migrations",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| Error::with_source("could not inspect backup schema", error))?;
    let supported = MIGRATIONS.last().map_or(0, |(version, _)| *version);
    if version > supported {
        return Err(Error::new(format!(
            "database schema version {version} is newer than supported version {supported}"
        )));
    }
    Ok(())
}

/// Atomically restores a verified backup while preserving the current database until validation.
///
/// # Errors
///
/// Returns an error without replacing the destination when input validation or copying fails.
pub fn restore_database(database: &Path, input: &Path) -> Result<(), Error> {
    verify_database(input)?;
    let temporary = sibling_temporary(database, "restore");
    let previous = sibling_temporary(database, "previous");
    remove_if_exists(&temporary)?;
    remove_if_exists(&previous)?;
    let source = Connection::open_with_flags(input, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| Error::with_source("could not open backup for restore", error))?;
    source
        .execute("VACUUM INTO ?1", [temporary.to_string_lossy().as_ref()])
        .map_err(|error| Error::with_source("could not prepare restored database", error))?;
    secure_database(&temporary)?;
    verify_database(&temporary)?;
    if database.exists() {
        std::fs::rename(database, &previous)
            .map_err(|error| Error::with_source("could not preserve current database", error))?;
    }
    if let Err(error) = std::fs::rename(&temporary, database) {
        if previous.exists() {
            let _ = std::fs::rename(&previous, database);
        }
        return Err(Error::with_source(
            "could not install restored database",
            error,
        ));
    }
    if let Err(error) = verify_database(database) {
        let _ = std::fs::remove_file(database);
        if previous.exists() {
            let _ = std::fs::rename(&previous, database);
        }
        return Err(error);
    }
    remove_if_exists(&previous)?;
    Ok(())
}

fn sibling_temporary(path: &Path, label: &str) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("surface.db");
    path.with_file_name(format!(".{name}.{label}.{}", Uuid::new_v4()))
}
fn remove_if_exists(path: &Path) -> Result<(), Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::with_source(
            "could not remove temporary database",
            error,
        )),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{backup_database, restore_database, verify_database};
    use crate::Storage;

    #[test]
    fn backup_and_restore_are_integrity_checked() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let database = directory.path().join("surface.db");
        let backup = directory.path().join("surface.backup.db");
        drop(Storage::open(&database).unwrap_or_else(|error| panic!("{error}")));
        backup_database(&database, &backup).unwrap_or_else(|error| panic!("{error}"));
        verify_database(&backup).unwrap_or_else(|error| panic!("{error}"));
        restore_database(&database, &backup).unwrap_or_else(|error| panic!("{error}"));
        verify_database(&database).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn corrupt_restore_preserves_destination() {
        let directory = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let database = directory.path().join("surface.db");
        drop(Storage::open(&database).unwrap_or_else(|error| panic!("{error}")));
        let before = std::fs::read(&database).unwrap_or_default();
        let corrupt = directory.path().join("corrupt.db");
        std::fs::write(&corrupt, b"not sqlite").unwrap_or_else(|error| panic!("{error}"));
        assert!(restore_database(&database, &corrupt).is_err());
        assert_eq!(std::fs::read(&database).unwrap_or_default(), before);
    }
}
