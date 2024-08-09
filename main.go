package main

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := NewDB()
	if err != nil {
		panic(err)
	}
	var (
		id     int
		token  string
		expiry time.Time
	)
	row := db.QueryRow(`SELECT * FROM sessions WHERE user_id = 5`)
	if err := row.Scan(&id, &token, &expiry); err != nil {
		log.Println(err.Error())
	}
	log.Println(id, token, expiry)
	// fmt.Println("perfect")
}

func NewDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "forum.db")
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	log.Println("database created")
	return db, nil
}
