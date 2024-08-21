package repository

import (
	"database/sql"
	"fmt"
	"forum/app/models"
	"log"
)

type PostQuery interface {
	CreatePost(post models.Post) (int64, error)
	GetAllPosts() ([]models.Post, error)
	GetPostById(postId int64) (models.Post, error)
	CreateCategory(category *models.Category) error
	GetCategory() ([]models.Category, error)
	GetDislikeStatus(postId, userId int) int
	DeletePostDislike(postId, userId int) error
	DislikePost(postId, userId, status int) error
	GetLikedPostIdByUserId(userId int) ([]int64, error)
	GetLikeStatus(postId, userId int) int
	LikePost(postId, userId, status int) error
	UpdatePostLikeDislike(postId, like, dislike int) error
	DeletePostLike(postId, userId int) error
	GetAllCommentByPostId(postId int) ([]models.Comment, error)
	GetCommentByCommentID(commentId int64) (models.Comment, error)
	CommentPost(comment models.Comment) error

	GetCommentLikeStatus(commentId, userId int) int
	LikeComment(commentId, userID, status int) error
	UpdateCommentLikeDislike(commentId, like, dislike int) error
	DeleteCommentLike(commentId, userId int) error
	DislikeComment(commentId, userId, status int) error
	DeleteCommentDislike(commentId, userId int) error
	GetCommentDislikeStatus(commentId, userId int) int
}

type postQuery struct {
	db *sql.DB
}

func (p postQuery) CreatePost(post models.Post) (int64, error) {
	fmt.Println(post.Author.Username, "author")
	res, err := p.db.Exec(`insert into posts (user_id, username, title, message, like, dislike, category, born) VALUES (?,?,?,?,?,?,?,?)`, post.Author.ID, post.Author.Username, post.Title, post.Content, 0, 0, post.Category, post.CreatedTime)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		log.Println(err)
		return 0, err
	}
	post.Id = id
	return id, nil
}

func (p postQuery) GetAllPosts() ([]models.Post, error) {
	rows, err := p.db.Query(`select * from posts`)
	if err != nil {
		return []models.Post{}, err
	}
	defer rows.Close()
	var all []models.Post
	for rows.Next() {
		var post models.Post
		err := rows.Scan(&post.Id, &post.Author.ID, &post.Author.Username, &post.Title, &post.Content, &post.Like, &post.Dislike, &post.Category, &post.CreatedTime)
		if err != nil {
			return []models.Post{}, err
		}
		all = append(all, post)
	}
	return all, nil
}

func (p postQuery) GetPostById(postId int64) (models.Post, error) {
	row := p.db.QueryRow(`select post_id,title,message,user_id,username,like,dislike, category, born from posts where post_id=?`, postId)
	var post models.Post
	err := row.Scan(&post.Id, &post.Title, &post.Content, &post.Author.ID, &post.Author.Username, &post.Like, &post.Dislike, &post.Category, &post.CreatedTime)
	if err != nil {
		return models.Post{}, err
	}
	return post, nil
}

func (p postQuery) CreateCategory(category *models.Category) error {
	query := `insert into categories (category, post_id) values (?,?)`
	_, err := p.db.Exec(query, category.CategoryName, category.PostId)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func (p postQuery) GetCategory() ([]models.Category, error) {
	query := `select * from categories`
	rows, err := p.db.Query(query)
	if err != nil {
		return nil, err
	}
	var result []models.Category
	for rows.Next() {
		var category models.Category
		err := rows.Scan(&category.CategoryName, &category.PostId)
		if err != nil {
			return nil, err
		}
		result = append(result, category)
	}
	return result, nil
}

func (p postQuery) GetDislikeStatus(postId, userId int) int {
	query := `select status from dislikes where post_id=? and user_id=?`
	var dislikeStatus int
	p.db.QueryRow(query, postId, userId).Scan(&dislikeStatus)
	return dislikeStatus
}

func (p postQuery) DeletePostDislike(postId, userId int) error {
	query := `delete from dislikes where post_id=? and user_id=?`
	_, err := p.db.Exec(query, postId, userId)
	return err
}

func (p postQuery) DislikePost(postId, userId, status int) error {
	query := `insert into dislikes (user_id, post_id, status) values (?,?,?)`
	_, err := p.db.Exec(query, userId, postId, status)
	return err
}

func (p postQuery) GetLikedPostIdByUserId(userId int) ([]int64, error) {
	var postIds []int64
	query := `select post_id from likes where user_id=?`
	rows, err := p.db.Query(query, userId)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		err := rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		postIds = append(postIds, id)
	}
	return postIds, nil
}

func (p postQuery) GetLikeStatus(postId, userId int) int {
	query := `select status from likes where post_id=? and user_id=?`
	var likeStatus int
	p.db.QueryRow(query, postId, userId).Scan(&likeStatus)
	return likeStatus
}

func (p postQuery) LikePost(postId, userId, status int) error {
	query := `insert into likes (user_id, post_id, status) values (?,?,?)`

	_, err := p.db.Exec(query, userId, postId, status)
	return err
}

func (p postQuery) UpdatePostLikeDislike(postId, like, dislike int) error {
	query := `update posts set like=?, dislike=? where post_id=?`
	_, err := p.db.Exec(query, like, dislike, postId)
	return err
}

func (p postQuery) DeletePostLike(postId, userId int) error {
	query := `delete from likes where post_id=? and user_id=? `
	_, err := p.db.Exec(query, postId, userId)
	return err
}
