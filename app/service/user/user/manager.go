package user

import (
	"forum/app/models"
	"forum/app/repository"
)

type UserService interface {
	GetUserByToken(token string) (models.User, error)
	GetUserByEmail(email string) (models.User, error)
}

type userService struct {
	repository repository.UserQuery
}

func NewUserService(repo repository.Repo) UserService {
	return &userService{repo.NewUserQuery()}
}
