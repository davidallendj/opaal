package cache

import (
	"davidallendj/opaal/internal/oauth"
	"fmt"

	"github.com/jmoiron/sqlx"
)

func CreateOAuthClientsIfNotExists(path string) (*sqlx.DB, error) {
	schema := `
	CREATE TABLE IF NOT EXISTS oauth_clients (
		id TEXT NOT NULL,
		secret TEXT NOT NULL,
		name TEXT,
		description TEXT,
		issuer TEXT,
		registration_access_token TEXT,
		redirect_uris TEXT,
		scope TEXT
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

func InsertOAuthClients(path string, clients *[]oauth.Client) error {
	if clients == nil {
		return fmt.Errorf("states == nil")
	}

	// create database if it doesn't already exist
	db, err := CreateOAuthClientsIfNotExists(path)
	if err != nil {
		return err
	}

	// insert all probe states into db
	tx := db.MustBegin()
	for _, state := range *clients {
		sql := `INSERT OR REPLACE INTO oauth_clients 
		(
			id,
			secret,
			name,
			description,
			issuer,
			registration_access_token,
			redirect_uris,
			scope
		) 
		VALUES 
		(
			:id,
			:secret,
			:name,
			:description,
			:issuer,
			:registration_access_token,
			:redirect_uris,
			:scope
		);`
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

func GetOAuthClient(path string, id string) (*oauth.Client, error) {
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %v", err)
	}

	results := &oauth.Client{}
	err = db.Select(&results, "SELECT * FROM oauth_clients ORDER BY host ASC, port ASC LIMIT 1;")
	if err != nil {
		return nil, fmt.Errorf("could not retrieve probes: %v", err)
	}
	return results, nil
}

func GetOAuthClients(path string) ([]oauth.Client, error) {
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %v", err)
	}

	results := []oauth.Client{}
	err = db.Select(&results, "SELECT * FROM oauth_clients;")
	if err != nil {
		return nil, fmt.Errorf("could not retrieve probes: %v", err)
	}
	return results, nil
}

func UpdateOAuthClient(path string, clients *[]oauth.Client) error {
	if clients == nil {
		return fmt.Errorf("clients is nil")
	}
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return fmt.Errorf("could not open database: %v", err)
	}
	tx := db.MustBegin()
	for _, state := range *clients {
		sql := `UPDATE FROM identity_providers WHERE client_id = :client_id;`
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

func DeleteOAuthClients(path string, clientIds []string) error {
	if clientIds == nil {
		return fmt.Errorf("no probe results found")
	}
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return fmt.Errorf("could not open database: %v", err)
	}
	tx := db.MustBegin()
	for _, state := range clientIds {
		sql := `DELETE FROM identity_providers WHERE client_id = :client_id;`
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
