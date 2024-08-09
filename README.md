# This project consists in creating a web forum that allows :

communication between users.
associating categories to posts.
liking and disliking posts and comments.
filtering posts.
SQLite

In order to store the data in forum (like users, posts, comments, etc.) we  use the database library SQLite.

SQLite is a popular choice as an embedded database software for local/client storage in application software such as web browsers. It enables us to create a database as well as controlling it by using queries.

We must use at least one SELECT, one CREATE and one INSERT queries.
To know more about SQLite you can check the SQLite page.

# Authentication

In this segment the client must be able to register as a new user on the forum, by inputting their credentials. You should have a login session to access the forum and be able to add posts and comments.

We use cookies to allow each user to have only one opened session. Each of this sessions must contain an expiration date. It is up to you to decide how long the cookie stays "alive". The use of UUID is a Bonus task.

# Instructions for user registration:

Must ask for email
When the email is already taken return an error response.
Must ask for username
Must ask for password
The password must be encrypted when stored (this is a Bonus task)
The forum must be able to check if the email provided is present in the database and if all credentials are correct. It will check if the password is the same with the one provided and, if the password is not the same, it will return an error response.

# Communication

In order for users to communicate between each other, they will have to be able to create posts and comments.

Only registered users will be able to create posts and comments.
When registered users are creating a post they can associate one or more categories to it.
The implementation and choice of the categories is up to you.
The posts and comments should be visible to all users (registered or not).
Non-registered users will only be able to see posts and comments.
Likes and Dislikes

Only registered users will be able to like or dislike posts and comments.

The number of likes and dislikes should be visible by all users (registered or not).

# Filter

We  implemented a filter mechanism, that will allow users to filter the displayed posts by :

categories
created posts
liked posts
You can look at filtering by categories as subforums. A subforum is a section of an online forum dedicated to a specific topic.

Note that the last two are only available for registered users and must refer to the logged in user.


# Allowed packages

All standard Go packages are allowed.
sqlite3
bcrypt
UUID


# Getting Started

clone the repository:
```
git clone git@git.01.alem.school:akiyazov/forum.git
```

## Type in the Terminal
```
go run ./cmd
```

then follow the link http://localhost:8000


If you wanna use make files write in the terminal:

### To Start the sever
``` 
make run 
```
### To Build docker image

``` 
make build
```
### To run docker container 

``` 
make run-img
```

### To Stop running of the sever

``` 
make stop
```

## Authors

- Abolat
- Nrakishe
- AKiyazov