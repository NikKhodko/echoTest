package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

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

func ServerHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderServer, "qwerty")
		return next(c)
	}
}

func main() {
	fmt.Println("welcome to the server")

	e := echo.New()

	e.Use(ServerHeader)

	g := e.Group("/admin")

	g.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `[${time_rfc3339}]  ${status}  ${method} ${host}${path} ${latency_human}` + "\n",
	}))

	g.Use(middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
		if username == "nikita" && password == "0909" {
			return true, nil
		}
		return false, nil
	}))

	g.GET("/main", mainAdmin)

	e.GET("/", hola)
	e.GET("/users/:data", getUser)

	e.POST("/users", addUser)
	e.POST("/admins", addAdmin)
	e.POST("/boss", addBoss)

	e.Logger.Fatal(e.Start(":1333"))
}
