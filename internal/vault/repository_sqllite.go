package vault

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type SqlLiteRepository struct {
	db *sql.DB
}

func (r *SqlLiteRepository) SaveCredential(creds EncryptedCredential) error {
	_, err := r.db.Exec(`
	INSERT INTO credentials (id, vault_id, name, ciphertext, updated_at)
	VALUES (?, ?, ?, ?, ?)
		`,
		creds.ID,
		creds.VaultID,
		creds.Name,
		creds.ciphertext,
		creds.UpdatedAt)

	if err != nil {
		return fmt.Errorf("saving credential %s: %w", creds.ID, err)
	}

	return nil
}

func (r *SqlLiteRepository) GetCredential(id CredentialID) (*EncryptedCredential, error) {
	var creds EncryptedCredential
	err := r.db.QueryRow(`
	SELECT id, vault_id, name, ciphertext, updated_at
	FROM credentials
	WHERE id = ?
	`,
		id).Scan(
		&creds.ID,
		&creds.VaultID,
		&creds.Name,
		&creds.ciphertext,
		&creds.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("credentials does not exists %s: %w", id, err)
	}
	if err != nil {
		return nil, fmt.Errorf("getting credentials %s: %w", id, err)
	}
	return &creds, nil
}

func (r *SqlLiteRepository) GetCredentialByName(name string) (*EncryptedCredential, error) {
	var creds EncryptedCredential
	err := r.db.QueryRow(`
	SELECT id, vault_id, name, ciphertext, updated_at
	FROM credentials
	WHERE name = ?
	`,
		name).Scan(
		&creds.ID,
		&creds.VaultID,
		&creds.Name,
		&creds.ciphertext,
		&creds.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("credentials does not exists %s: %w", name, err)
	}
	if err != nil {
		return nil, fmt.Errorf("getting credentials %s: %w", name, err)
	}
	return &creds, nil
}

func (r *SqlLiteRepository) SearchCredentials(pattern string) ([]string, error) {
	var query string
	args := []any{}

	if pattern != "" {
		query = `SELECT name FROM credentials WHERE name LIKE ? ORDER BY name`
		args = append(args, "%"+pattern+"%")
	} else {
		query = `SELECT name FROM credentials ORDER BY name`
	}

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("searching credentials: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scanning credential name: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating credentials: %w", err)
	}
	return names, nil
}

func (r *SqlLiteRepository) UpdateCredential(creds EncryptedCredential) error {
	result, err := r.db.Exec(`
	UPDATE credentials
	SET ciphertext = ?, updated_at = ?
	WHERE id = ?
	`,
		creds.ciphertext,
		creds.UpdatedAt,
		creds.ID)
	if err != nil {
		return fmt.Errorf("updating credential %s: %w", creds.ID, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("credential %s not found", creds.ID)
	}
	return nil
}

func (r *SqlLiteRepository) DeleteCredential(id CredentialID) error {
	result, err := r.db.Exec(`DELETE FROM credentials WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting credential %s: %w", id, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("credential %s not found", id)
	}
	return nil
}

func (r *SqlLiteRepository) SaveVault(vault LockedVault) error {
	_, err := r.db.Exec(`
	INSERT INTO vaults (id, wrapped_dek, salt, kdf_time, parallelism, memory) 
	VALUES (?, ?, ?, ?, ?, ?)
		`,
		vault.ID,
		vault.WrappedDEK,
		vault.KDFParams.Salt,
		vault.KDFParams.Time,
		vault.KDFParams.Parallelism,
		vault.KDFParams.Memory,
	)

	if err != nil {
		return fmt.Errorf("saving vault %s: %w", vault.ID, err)
	}

	return nil
}

func (r *SqlLiteRepository) Exists() (bool, error) {
	var numRows uint8
	err := r.db.QueryRow(`SELECT COUNT(*) FROM vaults LIMIT 1`).Scan(&numRows)

	if err != nil {
		return false, fmt.Errorf("getting vault %s", err)
	}

	return numRows > 0, nil
}

func (r *SqlLiteRepository) GetVault() (*LockedVault, error) {
	var v LockedVault
	err := r.db.QueryRow(`
	SELECT id, wrapped_dek, salt, kdf_time, parallelism, memory
	FROM vaults
	LIMIT 1
	`).Scan(
		&v.ID,
		&v.WrappedDEK,
		&v.KDFParams.Salt,
		&v.KDFParams.Time,
		&v.KDFParams.Parallelism,
		&v.KDFParams.Memory,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("vault does not exists %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("getting vault %w", err)
	}

	return &v, nil
}

func (r *SqlLiteRepository) DeleteVault() error {
	result, err := r.db.Exec(`DELETE FROM vaults`)
	if err != nil {
		return fmt.Errorf("deleting vault: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("no vault to delete")
	}
	return nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS vaults (
		id          TEXT PRIMARY KEY,
		wrapped_dek BLOB NOT NULL,
		salt        BLOB NOT NULL,
		kdf_time    INTEGER NOT NULL,
		parallelism INTEGER NOT NULL,
		memory      INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS credentials (
		id         TEXT PRIMARY KEY,
		vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
		name       TEXT NOT NULL UNIQUE,
		ciphertext BLOB NOT NULL,
		updated_at DATETIME NOT NULL
	);

	`)

	return err

}

func newDB(pathToDB string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)", pathToDB)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func NewSqlLiteRepository() (*SqlLiteRepository, error) {
	pathToDB, err := ResolvePath()
	if err != nil {
		return nil, err
	}

	db, err := newDB(pathToDB)
	if err != nil {
		return nil, err
	}

	err = migrate(db)
	if err != nil {
		db.Close()
		return nil, err
	}

	repo := SqlLiteRepository{db}
	return &repo, nil

}

func ResolvePath() (string, error) {
	home, err := os.UserHomeDir()

	if err != nil {
		return "", fmt.Errorf("resolving home dir: %w", err)
	}

	dir := filepath.Join(home, ".credman")
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	path := filepath.Join(dir, ".credman.db")
	return path, nil
}
