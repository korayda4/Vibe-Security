package main

import (
	"crypto/md5"
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var SECRET = "hardcoded-jwt-secret"

func loginHandler(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}
	c.BindJSON(&body)

	// BE-004: SQL injection (string concat)
	row := db.QueryRow("SELECT * FROM users WHERE email = '" + body.Email + "'")

	// BE-003: alg none
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"user": row})
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	// BE-002: weak hash
	hash := md5.Sum([]byte(body.Password))

	c.JSON(http.StatusOK, gin.H{"token": tokenString, "hash": string(hash[:])})
}
