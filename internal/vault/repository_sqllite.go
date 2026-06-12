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
	INSERT INTO credentials (id, vault_id, ciphertext, updated_at) 
	VALUES (?, ?, ?, ?)
		`,
		creds.ID,
		creds.VaultID,
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
	SELECT id, vault_id, ciphertext, updated_at
	FROM credentials
	WHERE id = ?

	`,
		id).Scan(
		&creds.ID,
		&creds.VaultID,
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
	INSERT INTO vaults (id, wrapped_dek, salt, kdf_time, parallelism, memory, is_default) 
	VALUES (?, ?, ?, ?, ?, ?, 0)
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

func (r *SqlLiteRepository) GetVault(id VaultID) (*LockedVault, error) {
	var v LockedVault
	err := r.db.QueryRow(`
	SELECT id, wrapped_dek, salt, kdf_time, parallelism, memory
	FROM vaults
	WHERE id=?
	`, id).Scan(
		&v.ID,
		&v.WrappedDEK,
		&v.KDFParams.Salt,
		&v.KDFParams.Time,
		&v.KDFParams.Parallelism,
		&v.KDFParams.Memory,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("vault does not exists %s: %w", id, err)
	}
	if err != nil {
		return nil, fmt.Errorf("getting vault %s: %w", id, err)
	}

	return &v, nil
}

func (r *SqlLiteRepository) GetDefaultVault() (VaultID, error) {
	var id VaultID
	err := r.db.QueryRow(`SELECT id FROM vaults WHERE is_default = 1 LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return id, fmt.Errorf("no default vault: %w", err)
	}
	if err != nil {
		return id, fmt.Errorf("getting default vault: %w", err)
	}

	return id, nil
}

func (r *SqlLiteRepository) SetDefaultVault(id VaultID) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE vaults SET is_default = 0 WHERE is_default = 1`); err != nil {
		return fmt.Errorf("clearing previous default: %w", err)
	}

	result, err := tx.Exec(`UPDATE vaults SET is_default = 1 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("setting default vault %s: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("vault %s not found", id)
	}
	return tx.Commit()

}

func (r *SqlLiteRepository) DeleteVault(id VaultID) error {
	result, err := r.db.Exec(`DELETE FROM vaults WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting vault %s: %w", id, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("vault %s not found", id)
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
		memory      INTEGER NOT NULL,
		is_default 	INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS credentials (
		id         TEXT PRIMARY KEY,
		vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
		ciphertext BLOB NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_credentials_vault_id
		ON credentials(vault_id);

	CREATE UNIQUE INDEX IF NOT EXISTS one_default_vault
		ON vaults(is_default) WHERE is_default = 1;
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
	path := filepath.Join(home, ".credman", ".credman.db")
	return path, nil
}
