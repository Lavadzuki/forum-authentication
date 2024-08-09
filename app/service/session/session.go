package session

import (
	"forum/app/models"
)

func (s *sessionService) CreateSession(session *models.Session) error {
	err := s.SessionQuery.CreateSession(*session)
	if err != nil {
		return err
	}
	return nil
}

func (s *sessionService) GetSessionByToken(token string) (models.Session, error) {
	session, err := s.SessionQuery.GetSessionByToken(token)
	if err != nil {
		return models.Session{}, err
	}
	return session, nil
}

func (s sessionService) GetSessionByUserID(userId int) (models.Session, error) {
	session, err := s.SessionQuery.GetSessionByUserId(userId)
	if err != nil {
		return models.Session{}, err
	}
	return session, nil
}

func (s sessionService) GetAllSessionsTime() ([]models.Session, error) {
	return s.SessionQuery.GetAllSessionsTime()
}

func (s sessionService) DeleteSession(token string) error {
	return s.SessionQuery.DeleteSession(token)
}
