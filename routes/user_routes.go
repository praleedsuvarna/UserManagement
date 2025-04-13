package routes

import (
	"UserManagement/controllers"
	// "UserManagement/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/middleware"
)

func UserRoutes(app *fiber.App) {
	user := app.Group("/users")
	user.Post("/register", controllers.RegisterUserV2)
	user.Get("/verify-email", controllers.VerifyEmail)
	user.Post("/login", controllers.LoginUser)
	user.Post("/resetpassword", controllers.ReseedUserPasswordV2)
	user.Post("/refresh-token", controllers.RefreshToken)
	app.Post("/auth/google", controllers.GoogleSignIn)

	// Protected Routes
	user.Get("/me", middleware.AuthMiddleware, controllers.GetUser)
	user.Put("/me", middleware.AuthMiddleware, controllers.UpdateUser)
	user.Delete("/me", middleware.AuthMiddleware, controllers.DeleteUser_ByEmail)
}
