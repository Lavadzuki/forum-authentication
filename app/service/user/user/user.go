package user

import (
	"forum/app/models"
)

func (u *userService) GetUserByToken(token string) (models.User, error) {
	userId, err := u.repository.GetUserIdByToken(token)
	if err != nil {
		return models.User{}, err
	}
	user, err := u.repository.GetUserByUserId(userId)
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (u userService) GetUserByEmail(email string) (models.User, error) {
	return u.repository.GetUserByEmail(email)
}
