package main

import (
	"context"
	"fmt"
	"forum/app/config"
	"forum/app/handlers"
	"forum/app/repository"
	"forum/app/service/post"
	"forum/app/service/session"
	"forum/app/service/user/auth"
	"forum/app/service/user/user"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := config.InitConfig("./config/config.json")
	if err != nil {
		log.Fatalln(err)
		return
	}

	if cfg.ServerAddress != cfg.Port {
		fmt.Sprintf(cfg.ServerAddress+":", cfg.Port)
	}

	db, err := repository.NewDB(cfg.Database)
	if err != nil {
		log.Fatalln(err)
		return
	}
	defer db.Close()

	repo := repository.NewRepo(db)
	authservice := auth.NewAuthService(repo)
	userservice := user.NewUserService(repo)

	sessionService := session.NewSessionService(repo)

	postService := post.NewPostService(repo)

	app := handlers.NewAppService(authservice, sessionService, postService, userservice, cfg)
	server := app.Run(cfg.Http)

	go app.ClearSession()

	go func() {
		log.Printf("server started at http://localhost%s", cfg.Port)
		err := server.ListenAndServe()
		if err != nil {
			log.Printf("listen %s ", err)
		}
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	<-shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Println("shutting down servers ...")
	err = server.Shutdown(ctx)
	if err != nil {
		log.Printf("server shut down:%s", err)
	}
	log.Println("server stopped")
}
