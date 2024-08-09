package repository

import (
	"forum/app/models"
	"log"
)

func (p postQuery) GetAllCommentByPostId(postId int) ([]models.Comment, error) {
	stmt, err := p.db.Prepare("select comment_id,post_id,user_id,username,message,like,dislike,born from	comments where post_id= ?")
	if err != nil {
		return nil, err
	}
	row, err := stmt.Query(&postId)
	if err != nil {
		log.Println(err)
	}
	var comments []models.Comment
	for row.Next() {
		var comment models.Comment
		err = row.Scan(&comment.Id, &comment.PostId, &comment.UserId, &comment.Username, &comment.Message, &comment.Like, &comment.Dislike, &comment.Born)
		if err != nil {
			return nil, err
		}
		comments = append(comments, comment)
	}
	return comments, nil
}

func (p postQuery) GetCommentByCommentID(commentId int64) (models.Comment, error) {
	stmt, err := p.db.Prepare("select comment_id,post_id,user_id,username,message,like,dislike,born from comments where comment_id=?")
	if err != nil {
		// fmt.Println(1)
		log.Println(err)
	}
	row := stmt.QueryRow(commentId)
	var comment models.Comment
	err = row.Scan(&comment.Id, &comment.PostId, &comment.UserId, &comment.Username, &comment.Message, &comment.Like, &comment.Dislike, &comment.Born)
	if err != nil {
		log.Println(err)
	}
	return comment, nil
}

func (p postQuery) CommentPost(comment models.Comment) error {
	stmt, err := p.db.Prepare("insert into comments (post_id, user_Id, username, message, like, dislike, born) VALUES (?,?,?,?,?,?,?)")
	if err != nil {

		log.Println(err)
		return err
	}
	_, err = stmt.Exec(comment.PostId, comment.UserId, comment.Username, comment.Message, comment.Like, comment.Dislike, comment.Born)
	if err != nil {
		return err
	}
	return nil
}
