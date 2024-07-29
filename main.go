package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type User struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Admin struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Boss struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type JwtClaims struct {
	Name string `json:"name"`
	jwt.StandardClaims
}

func hola(c echo.Context) error {
	return c.String(http.StatusOK, "Hello, friend")
}
func addUser(c echo.Context) error {
	user := User{}

	defer c.Request().Body.Close()

	b, err := io.ReadAll((c.Request().Body))

	if err != nil {
		log.Printf("failed reading the request body: %s", err)
		return c.String(http.StatusInternalServerError, "")
	}

	err = json.Unmarshal(b, &user)
	if err != nil {
		log.Printf("failed unmarshalling in addUsers: %s\n", err)
		return c.String(http.StatusInternalServerError, "")
	}

	log.Printf("this is user: %#v\n", user)
	return c.String(http.StatusOK, "we got user")
}

func addAdmin(c echo.Context) error {
	admin := Admin{}

	defer c.Request().Body.Close()

	err := json.NewDecoder(c.Request().Body).Decode(&admin)
	if err != nil {
		log.Printf("failed proccesing addAdmin request: %s/n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	log.Printf("this is admin: %#v", admin)
	return c.String(http.StatusOK, "we got admin")
}

func addBoss(c echo.Context) error {
	boss := Boss{}

	err := c.Bind(&boss)
	if err != nil {
		log.Printf("failed proccessing addBoss request:")
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	log.Printf("this is boss: %#v", boss)
	return c.String(http.StatusOK, "we got boss")
}

func getUser(c echo.Context) error {

	userName := c.QueryParam("name")
	userType := c.QueryParam("type")
	dataType := c.Param("data")

	if dataType == "string" {
		return c.String(http.StatusOK, fmt.Sprintf("user name is: %s\n his type is: %s\n", userName, userType))
	}

	if dataType == "json" {
		return c.JSON(http.StatusOK, map[string]string{
			"name": userName,
			"type": userType,
		})
	}

	return c.JSON(http.StatusBadRequest, map[string]string{
		"error": "lets try again. string or json",
	})
}

func mainAdmin(c echo.Context) error {
	return c.String(http.StatusOK, "u are on main admin page")
}

func mainCookie(c echo.Context) error {
	return c.String(http.StatusOK, "you are on the secret cookie page!")
}

func login(c echo.Context) error {
	username := c.QueryParam("username")
	password := c.QueryParam("password")

	// check username and password against DB after hashing the password
	if username == "nikita" && password == "0909" {
		cookie := &http.Cookie{}

		// this is the same
		//cookie := new(http.Cookie)

		cookie.Name = "sessionID"
		cookie.Value = "some_string"
		cookie.Expires = time.Now().Add(48 * time.Hour)

		c.SetCookie(cookie)

		return c.String(http.StatusOK, "You were logged in!")
	}

	return c.String(http.StatusUnauthorized, "Your username or password were wrong")
}

func ServerHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderServer, "qwerty")
		return next(c)
	}
}

func checkCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie("sessionID")
		if err != nil {
			if strings.Contains(err.Error(), "named cookie not present") {
				return c.String(http.StatusUnauthorized, "you dont have any cookie")
			}

			log.Println(err)
			return err
		}

		if cookie.Value == "some_string" {
			return next(c)
		}

		return c.String(http.StatusUnauthorized, "you dont have the right cookie, cookie")
	}
}

func createJwtToken() (string, error) {
	claims := JwtClaims{
		"jack",
		jwt.StandardClaims{
			Id:        "main_user_id",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}

	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	token, err := rawToken.SignedString([]byte("mySecret"))
	if err != nil {
		return "", err
	}

	return token, nil
}

func main() {
	fmt.Println("welcome to the server")

	e := echo.New()

	e.Use(ServerHeader)

	adminGroup := e.Group("/admin")
	cookieGroup := e.Group("/cookie")

	adminGroup.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `[${time_rfc3339}]  ${status}  ${method} ${host}${path} ${latency_human}` + "\n",
	}))

	adminGroup.Use(middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
		if username == "nikita" && password == "0909" {
			return true, nil
		}
		return false, nil
	}))

	cookieGroup.Use(checkCookie)

	cookieGroup.GET("/main", mainCookie)

	adminGroup.GET("/main", mainAdmin)

	e.GET("/", hola)
	e.GET("/users/:data", getUser)

	e.POST("/users", addUser)
	e.POST("/admins", addAdmin)
	e.POST("/boss", addBoss)

	e.Logger.Fatal(e.Start(":1333"))
}
