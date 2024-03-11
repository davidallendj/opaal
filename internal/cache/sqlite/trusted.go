package cache

import (
	"davidallendj/opaal/internal/oauth"
	"fmt"

	"github.com/jmoiron/sqlx"
)

func CreateTrustedIfNotExists(path string) (*sqlx.DB, error) {
	schema := `
	CREATE TABLE IF NOT EXISTS trusted_issuers (
		id 					TEXT NOT NULL,
		allow_any_subject 	NUMBER,
		expires_at 			NUMBER,
		issuer 				TEXT,
		public_key 			NUMBER,
		scope 				TEXT,
		subject 			TEXT,
		PRIMARY KEY (id)
	);
	`
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %v", err)
	}
	db.MustExec(schema)
	return db, nil
}

func InsertTrustedIssuer(path string, issuer *oauth.TrustedIssuer) error {
	// create database if it doesn't already exist
	db, err := CreateOAuthClientsIfNotExists(path)
	if err != nil {
		return err
	}

	// insert all probe states into db
	tx := db.MustBegin()
	sql := `INSERT OR REPLACE INTO trusted_issuers
	(
		id,
		allow_any_subject
		expires_at,
		issuer,
		public_key,
		scope,
		subject
	) 
	VALUES 
	(
		:id,
		:allow_any_subject,
		:expires_at,
		:issuer,
		:public_key,
		:scope,
		:subject
	);`
	_, err = tx.NamedExec(sql, &issuer)
	if err != nil {
		fmt.Printf("could not execute transaction: %v\n", err)
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("could not commit transaction: %v", err)
	}
	return nil
}

func GetTrustedIssuer(path string, issuer string) (*oauth.TrustedIssuer, error) {
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %v", err)
	}

	results := &oauth.TrustedIssuer{}
	err = db.Select(&results, "SELECT * FROM trusted_issuers ORDER BY host ASC, port ASC LIMIT 1;")
	if err != nil {
		return nil, fmt.Errorf("could not retrieve probes: %v", err)
	}
	return results, nil
}

func DeleteTrustedIssuer(path string, ids []string) error {
	if ids == nil {
		return fmt.Errorf("no probe results found")
	}
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return fmt.Errorf("could not open database: %v", err)
	}
	tx := db.MustBegin()
	for _, state := range ids {
		sql := `DELETE FROM identity_providers WHERE id = :id;`
		_, err := tx.NamedExec(sql, &state)
		if err != nil {
			fmt.Printf("could not execute transaction: %v\n", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("could not commit transaction: %v", err)
	}
	return nil
}
