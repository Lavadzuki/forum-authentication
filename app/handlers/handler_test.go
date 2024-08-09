package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"forum/app/config"

	"forum/app/repository"
	"forum/app/service/post"
	"forum/app/service/session"
	"forum/app/service/user/auth"
	"forum/app/service/user/user"
)

func TestAuthHandlers(t *testing.T) {
	tests := []struct {
		handler        string
		name           string
		method         string
		path           string
		reader         io.Reader
		expected       string
		expectedStatus int
	}{
		{
			handler:        "Login",
			name:           "Case status http.StatusOK",
			method:         "GET",
			path:           "/sign-in",
			reader:         nil,
			expected:       "Status http.StatusOK",
			expectedStatus: http.StatusOK,
		},
		{
			handler:        "Login",
			name:           "Status found",
			method:         "POST",
			path:           "/sign-in",
			reader:         nil,
			expected:       "status found",
			expectedStatus: http.StatusFound,
		},
		{
			handler:        "Login",
			name:           "Case method not allowed",
			method:         "PUT",
			path:           "/sign-in",
			reader:         nil,
			expected:       "status method not allowed",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			handler:        "Register",
			name:           "Status found (register)",
			method:         "POST",
			path:           "/sign-up",
			reader:         nil,
			expected:       "status found",
			expectedStatus: http.StatusFound,
		},
		{
			handler:        "Register",
			name:           "Case method not allowed (register)",
			method:         "PUT",
			path:           "/sign-in",
			reader:         nil,
			expected:       "status method not allowed",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			handler:        "Logout",
			name:           "Case method not allowed (logout)",
			method:         "POST",
			reader:         nil,
			expected:       "method not allowed",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			handler:        "Comment",
			name:           "status badrequest",
			method:         "POST",
			reader:         nil,
			expected:       "status badrequest",
			expectedStatus: http.StatusBadRequest,
		},
	}
	cfg, err := config.InitConfig("./config/config.json")
	if err != nil {
		return
	}
	db, err := repository.NewDB(cfg.Database)
	if err != nil {
		return
	}
	err = db.Ping()
	if err != nil {
		return
	}

	repo := repository.NewRepo(db)
	authservice := auth.NewAuthService(repo)
	userservice := user.NewUserService(repo)

	sessionService := session.NewSessionService(repo)

	postService := post.NewPostService(repo)

	app := NewAppService(authservice, sessionService, postService, userservice, cfg)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.path, tc.reader)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			switch tc.handler {
			case "Login":
				app.LoginHandler(rr, req)
			case "Register":
				app.RegisterHandler(rr, req)
			case "Logout":
				app.LogoutHandler(rr, req)
			case "Comment":
				app.CommentHandler(rr, req)
			}
			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
			}
		})
	}
}
