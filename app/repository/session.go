package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"forum/app/models"
	"log"
)

type SessionQuery interface {
	CreateSession(service models.Session) error
	GetSessionByToken(token string) (models.Session, error)
	GetAllSessionsTime() ([]models.Session, error)
	DeleteSession(token string) error
	GetSessionByUserId(userId int) (models.Session, error)
	DeleteSessionByUserId(userId int) error
}

type sessionQuery struct {
	db *sql.DB
}

func (s sessionQuery) DeleteSessionByUserId(userId int) error {
	res, err := s.db.Exec("delete from sessions where user_id = ?", userId)
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("delete session was failed")
	}
	return nil
}
func (s sessionQuery) GetSessionByToken(token string) (models.Session, error) {
	row := s.db.QueryRow(`select user_id,token,expiry from sessions where token=?`, token)
	var session models.Session
	err := row.Scan(&session.UserID, &session.Token, &session.Expiry)
	if err != nil {
		return models.Session{}, err
	}
	return session, nil
}

func (s sessionQuery) GetAllSessionsTime() ([]models.Session, error) {
	rows, err := s.db.Query(`select expiry,token from sessions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []models.Session
	for rows.Next() {
		var session models.Session
		err := rows.Scan(&session.Expiry, &session.Token)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func (s sessionQuery) DeleteSession(token string) error {
	res, err := s.db.Exec("delete from sessions where token = ?", token)
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("delete session was failed")
	}
	return nil
}

func (s sessionQuery) GetSessionByUserId(userId int) (models.Session, error) {
	row := s.db.QueryRow(`select user_id,token,expiry from sessions where user_id=?`, userId)
	var session models.Session
	err := row.Scan(&session.UserID, &session.Token, &session.Expiry)
	if err != nil {
		log.Println(err)
		return models.Session{}, err
	}
	return session, nil
}

func (s sessionQuery) CreateSession(session models.Session) error {
	fmt.Println(session)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(`insert into sessions (user_id, token, expiry) values (?,?,?)`, session.UserID, session.Token, session.Expiry)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
