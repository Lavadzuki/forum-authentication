package post

import (
	"forum/app/models"
	"forum/app/repository"
)

type PostService interface {
	// reaction.go
	LikePost(postId, userId int) int
	DislikePost(postId, userId int) int
	LikeComment(commentId, userId int) int
	DislikeComment(commentId, userId int) int
	// post.go
	GetAllPosts() ([]models.Post, error)
	CreatePost(post *models.Post) (int, error)
	GetAllCommentsAndPostsByPostId(id int64) (models.Post, int)
	CreateComment(comment *models.Comment) (int, error)
	// filter.go
	GetFilterPosts(genre string, user models.User) (models.Data, int)
	GetWelcomeFilterPosts(genre string) (models.Data, int)
}

type postService struct {
	repository repository.PostQuery
}

func NewPostService(repo repository.Repo) PostService {
	return &postService{repository: repo.NewPostQuery()}
}
