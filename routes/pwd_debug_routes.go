package routes

import (
	"UserManagement/controllers"

	"github.com/gofiber/fiber/v2"
)

func PwdDebugRoutes(app *fiber.App) {
	user := app.Group("/debug")
	user.Post("/test-register", controllers.TestRegisterAndVerify)
	user.Post("/view-password", controllers.ViewUserPassword)
	user.Post("/verify-password", controllers.TestPasswordVerification)
}
