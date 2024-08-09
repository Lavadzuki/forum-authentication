package repository

import "database/sql"

type Repo interface {
	NewUserQuery() UserQuery
	NewSessionQuery() SessionQuery
	NewPostQuery() PostQuery
}
type repo struct {
	db *sql.DB
}

func (r repo) NewUserQuery() UserQuery {
	return &userQuery{db: r.db}
}

func (r repo) NewSessionQuery() SessionQuery {
	return &sessionQuery{db: r.db}
}

func (r repo) NewPostQuery() PostQuery {
	return &postQuery{r.db}
}

// db, err := repository.NewDB(cfg.Database)

// repo := repository.NewRepo(db)

func NewRepo(db *sql.DB) Repo {
	return &repo{db: db}
}
