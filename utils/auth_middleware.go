package utils

import (
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func AuthMiddleWare()gin.HandlerFunc {
    return func(c *gin.Context){
        // Get the JWT token from the request header
        log.Print("Control is here")
        tokenString, err := c.Cookie("access-token")
        if err!=nil{
            log.Println("Error accessing access token:",err)
        }

        // Validate the JWT token
        token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
            // Verify the token with your secret key
            return []byte("I-am-a-TRADER"), nil
        })

        if err != nil {
            c.Header("Hx-Redirect","/login")
            c.AbortWithStatus(http.StatusUnauthorized)
            return
        }

        if !token.Valid {
            c.Header("Hx-Redirect","/login")
            c.AbortWithStatus(http.StatusUnauthorized)
            return
        }

        // Get the user information from the token claims
        claims := token.Claims.(*jwt.StandardClaims)
        userID := claims.Subject

        // Store the user information in the context
        c.Set("userID", userID)

        // Call the next middleware handler
        c.Next()
    }    
}

func AdminMiddleWare()gin.HandlerFunc {
    return func(c *gin.Context){
        // Get the JWT token from the request header
        log.Print("Control is here")
        tokenString, err := c.Cookie("access-token")
        if err!=nil{
            log.Println("Error accessing access token:",err)
        }

        // Validate the JWT token
        token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
            // Verify the token with your secret key
            return []byte("I-am-an-ADMIN"), nil
        })

        if err != nil {
            c.AbortWithStatus(http.StatusUnauthorized)
            return
        }

        if !token.Valid {
            c.AbortWithStatus(http.StatusUnauthorized)
            return
        }

        // Get the user information from the token claims
        claims := token.Claims.(*jwt.StandardClaims)
        userID := claims.Subject

        // Store the user information in the context
        c.Set("userID", userID)

        // Call the next middleware handler
        c.Next()
    }    
}

