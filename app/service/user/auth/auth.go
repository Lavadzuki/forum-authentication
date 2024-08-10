package auth

import (
	"errors"
	"fmt"
	"forum/app/models"
	"log"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (a authService) Login(user *models.User) (models.Session, error) {
	userDB, err := a.userQuery.GetUserByEmail(user.Email)
	if err != nil {
		log.Printf("user %s sign in was failed", user.Email)
		return models.Session{}, errors.New("wrong password or email")
	}
	err = bcrypt.CompareHashAndPassword([]byte(userDB.Password), []byte(user.Password))
	if err != nil {
		log.Printf("user %s sing in was failed", user.Email)
		return models.Session{}, errors.New("wrong password or email")
	}

	sessionToken := uuid.NewString()
	expiry := time.Now().Add(10 * time.Minute)
	session := models.Session{
		UserID: userDB.ID,
		Token:  sessionToken,
		Expiry: expiry,
	}

	sessionDB, err := a.sessionQuery.GetSessionByUserId(int(userDB.ID))
	if err != nil {
		log.Printf("session for user_id %v not found", userDB.ID)
	} else {
		err := a.sessionQuery.DeleteSession(sessionDB.Token)
		if err != nil {
			log.Println(err)
		} else {
			log.Printf("session for user_id %d is deleted", user.ID)
		}
	}

	err = a.sessionQuery.CreateSession(session)
	if err != nil {
		return models.Session{}, fmt.Errorf("session for user %d was failed\n error: %w", user.ID, err)
	}

	log.Printf("user %s sign in was successfully\n ", user.Email)
	return session, nil
}

func (a authService) Register(user *models.User) error {
	_, emailExists := a.userQuery.GetUserByEmail(user.Email)
	_, usernameExists := a.userQuery.GetUserByUsername(user.Username)
	if emailExists == nil || usernameExists == nil {
		return errors.New("user exists")
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 0)
	if err != nil {
		return errors.New("password hash was failed")
	}
	newUser := models.User{
		Username: user.Username,
		Email:    user.Email,
		Password: string(passwordHash),
	}
	err = a.userQuery.CreateUser(&newUser)
	if err != nil {
		return err
	}
	return nil
}

func (a authService) Logout(token string) error {
	return a.sessionQuery.DeleteSession(token)
}
func (a authService) GoogleAuth(googleUser models.GoogleUser) (models.Session, error) {

	user, err := a.userQuery.GetUserByEmail(googleUser.Email)

	if err != nil {

		user := models.User{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			Password: user.Password,
		}
		err = a.userQuery.CreateUser(&user)

		if err != nil {
			return models.Session{}, err
		}
	}

	session := models.Session{
		UserID: user.ID,
		Token:  uuid.NewString(),
		Expiry: time.Now().Add(10 * time.Minute),
	}
	err = a.sessionQuery.DeleteSessionByUserId(int(session.UserID))

	err = a.sessionQuery.CreateSession(session)

	if err != nil {
		return models.Session{}, err
	}
	return session, nil
}
