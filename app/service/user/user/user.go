package user

import (
	"fmt"
	"forum/app/models"
)

func (u *userService) GetUserByToken(token string) (models.User, error) {
	userId, err := u.repository.GetUserIdByToken(token)
	if err != nil {
		return models.User{}, err
	}
	user, err := u.repository.GetUserByUserId(int64(userId))
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (u userService) GetUserByEmail(email string) (models.User, error) {
	return models.User{}, nil
}

func (u *userService) GetUserByIdOrEmail(id int64, email string) models.User {

	user1, err := u.repository.GetUserByEmail(email)
	if err != nil {
		return models.User{}
	}
	if user1.Email == "" {
		user2, err := u.repository.GetUserByUserId(id)
		if err != nil {
			fmt.Println(1)
			return models.User{}
		}
		return user2
	}
	return user1
}
