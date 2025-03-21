// main.go
package main

import (
	// "UserManagement/config"
	"UserManagement/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/config"
)

func main() {
	config.LoadEnv()
	config.ConnectDB()

	app := fiber.New()
	routes.SetupRoutes(app)

	app.Listen(":8080")
}
