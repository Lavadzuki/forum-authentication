package session

import (
	"forum/app/models"
	"forum/app/repository"
)

type SessionService interface {
	CreateSession(session *models.Session) error
	GetSessionByToken(token string) (models.Session, error)
	GetSessionByUserID(userId int) (models.Session, error)
	GetAllSessionsTime() ([]models.Session, error)
	DeleteSession(token string) error
}

type sessionService struct {
	repository.SessionQuery
}

func NewSessionService(repo repository.Repo) SessionService {
	return &sessionService{repo.NewSessionQuery()}
}
