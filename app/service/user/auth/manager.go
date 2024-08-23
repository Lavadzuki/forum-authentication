package auth

import (
	"forum/app/models"
	"forum/app/repository"
)

type AuthService interface {
	Login(user *models.User) (models.Session, error)
	Register(user *models.User) error
	Logout(token string) error
	GoogleAuth(user models.OAuthUser) (models.Session, error)
	UpdateUser(user *models.User) error
}
type authService struct {
	sessionQuery repository.SessionQuery
	userQuery    repository.UserQuery
}

func NewAuthService(repo repository.Repo) AuthService {
	return &authService{
		sessionQuery: repo.NewSessionQuery(),
		userQuery:    repo.NewUserQuery(),
	}
}
