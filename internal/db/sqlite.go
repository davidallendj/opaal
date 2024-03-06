package db

import (
	"davidallendj/opaal/internal/oidc"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

func CreateIdentityProvidersIfNotExists(path string) (*sqlx.DB, error) {
	schema := `
	CREATE TABLE IF NOT EXISTS identity_providers (
		issuer 									TEXT NOT NULL,
		authorization_endpoint 					TEXT,
		token_endpoint 							TEXT,
		revocation_endpoint 					TEXT,
		introspection_endpoint 					TEXT,
		userinfo_endpoint 						TEXT,
		jwks_uri 								TEXT,
		response_types_supported 				TEXT,
		response_modes_supported 				TEXT,
		grant_types_supported 					TEXT,
		token_endpoint_auth_methods_supported 	TEXT,
		subject_types_supported 				TEXT,
		id_token_signing_alg_values_supported 	TEXT,
		claim_types_supported 					TEXT,
		claims_supported 						TEXT,
		jwks 									TEXT,
		
		PRIMARY KEY (issuer)
	);
	`
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %v", err)
	}
	db.MustExec(schema)
	return db, nil
}

func InsertIdentityProviders(path string, providers *[]oidc.IdentityProvider) error {
	if providers == nil {
		return fmt.Errorf("states == nil")
	}

	// create database if it doesn't already exist
	db, err := CreateIdentityProvidersIfNotExists(path)
	if err != nil {
		return err
	}

	// insert all probe states into db
	tx := db.MustBegin()
	for _, state := range *providers {
		sql := `INSERT OR REPLACE INTO identity_providers 
		(
			issuer, 
			authorization_endpoint, 
			token_endpoint, 
			revocation_endpoint,
			introspection_endpoint,
			userinfo_endpoint,
			jwks_uri,
			response_types_supported,
			response_modes_supported,
			grant_types_supported,
			token_endpoint_auth_methods_supported,
			subject_types_supported,
			id_token_signing_alg_values_supported,
			claim_types_supported,
			claims_supported,
			jwks
		) 
		VALUES 
		(
			:issuer, 
			:authorization_endpoint, 
			:token_endpoint, 
			:revocation_endpoint,
			:introspection_endpoint,
			:userinfo_endpoint,
			:jwks_uri,
			:response_types_supported,
			:response_modes_supported,
			:grant_types_supported,
			:token_endpoint_auth_methods_supported,
			:subject_types_supported,
			:id_token_signing_alg_values_supported,
			:claim_types_supported,
			:claims_supported,
			:jwks
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

func GetIdentityProvider(path string, issuer string) (*oidc.IdentityProvider, error) {
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %v", err)
	}

	results := &oidc.IdentityProvider{}
	err = db.Select(&results, "SELECT * FROM magellan_scanned_ports ORDER BY host ASC, port ASC LIMIT 1;")
	if err != nil {
		return nil, fmt.Errorf("could not retrieve probes: %v", err)
	}
	return results, nil
}

func GetIdentityProviders(path string) ([]oidc.IdentityProvider, error) {
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %v", err)
	}

	results := []oidc.IdentityProvider{}
	err = db.Select(&results, "SELECT * FROM magellan_scanned_ports ORDER BY host ASC, port ASC;")
	if err != nil {
		return nil, fmt.Errorf("could not retrieve probes: %v", err)
	}
	return results, nil
}

func DeleteIdentityProviders(path string, results *[]oidc.IdentityProvider) error {
	if results == nil {
		return fmt.Errorf("no probe results found")
	}
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return fmt.Errorf("could not open database: %v", err)
	}
	tx := db.MustBegin()
	for _, state := range *results {
		sql := `DELETE FROM identity_providers WHERE host = :issuer;`
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
