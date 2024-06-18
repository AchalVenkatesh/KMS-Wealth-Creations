package utils

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const (
    accessTokenCookieName  = "access-token"
    // Just for the demo purpose, I declared a secret here. In the real-world application, you might need to get it from the env variables.
	jwtSecretKey = "I-am-a-TRADER"
)

func GetJWTSecret() string {
	return jwtSecretKey
}

// Create a struct that will be encoded to a JWT.
// We add jwt.StandardClaims as an embedded type, to provide fields like expiry time.
type Claims struct {
	Name  string `json:"name"`
	jwt.StandardClaims
}

// GenerateTokensAndSetCookies generates jwt token and saves it to the http-only cookie.
func GenerateTokensAndSetCookies(user string, c *gin.Context) error {
	accessToken, exp, err := generateAccessToken(user)
	if err != nil {
		return err
	}

	setTokenCookie(accessTokenCookieName, accessToken, exp, c)
	setUserCookie(user, exp, c)

	return nil
}

func generateAccessToken(user string) (string, time.Time, error) {
	// Declare the expiration time of the token (1h).
	expirationTime := time.Now().Add(12 * time.Hour)

	return generateToken(user, expirationTime, []byte(GetJWTSecret()))
}

// Pay attention to this function. It holds the main JWT token generation logic.
func generateToken(user string, expirationTime time.Time, secret []byte) (string, time.Time, error) {
	// Create the JWT claims, which includes the username and expiry time.
	claims := &Claims{
		Name:  user,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds.
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the HS256 algorithm used for signing, and the claims.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Create the JWT string.
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", time.Now(), err
	}

	return tokenString, expirationTime, nil
}

// Here we are creating a new cookie, which will store the valid JWT token.
func setTokenCookie(name string, token string, expiration time.Time, c *gin.Context) {
	cookie := new(http.Cookie)
	cookie.Name = name
	cookie.Value = token
	cookie.Expires = expiration
    cookie.Path = "/"
    // Http-only helps mitigate the risk of client side script accessing the protected cookie.
	cookie.HttpOnly = true


		// Set the cookie
		c.SetCookie(
			cookie.Name,
			cookie.Value,
			cookie.MaxAge,
			cookie.Path,
			cookie.Domain,
			cookie.Secure,
			cookie.HttpOnly,
		)
}

// Purpose of this cookie is to store the user's name.
func setUserCookie(user string, expiration time.Time, c *gin.Context) {
	cookie := new(http.Cookie)
	cookie.Name = "user"
	cookie.Value = user
	cookie.Expires = expiration
	cookie.Path = "/"

		// Set the cookie
		c.SetCookie(
			cookie.Name,
			cookie.Value,
			cookie.MaxAge,
			cookie.Path,
			cookie.Domain,
			cookie.Secure,
			cookie.HttpOnly,
		)
}
