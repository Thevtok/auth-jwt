package JWT

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var secretKey = []byte("thevtok") // change this to your own secret key

func Run() {
	router := gin.Default()

	// Login endpoint
	router.POST("/login", func(c *gin.Context) {
		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.BindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		var s string
		// Check if credentials are valid (e.g. by checking against a database)
		if credentials.Username != s || credentials.Password != s {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})

		}

		// Create JWT token
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)

		claims["username"] = credentials.Username
		claims["exp"] = time.Now().Add(time.Hour * 1).Unix()

		tokenString, err := token.SignedString(secretKey)
		if err != nil {

			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	// Start server

}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get JWT token from authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		// Parse JWT token
		token, err := jwt.Parse(authHeader, func(t *jwt.Token) (any, error) {
			return secretKey, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		// Verify JWT token
		claims := token.Claims.(jwt.MapClaims)
		c.Set("claims", claims)

		c.Next()
	}
}
