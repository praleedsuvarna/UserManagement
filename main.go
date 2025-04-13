// main.go
package main

import (
	// "UserManagement/config"
	"UserManagement/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/praleedsuvarna/shared-libs/config"
)

func main() {
	config.LoadEnv()
	config.ConnectDB()

	app := fiber.New()

	// Get environment
	env := config.GetEnv("APP_ENV", "development")

	// Configure CORS based on environment
	configureCORS(app, env)

	// // Get allowed origins from environment variable or use default
	// allowedOrigins := config.GetEnv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")

	// // Add CORS middleware before routes
	// app.Use(cors.New(cors.Config{
	// 	AllowOrigins:     allowedOrigins,
	// 	AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
	// 	AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
	// 	AllowCredentials: true,
	// }))

	routes.SetupRoutes(app)

	// Get port from environment or use default
	port := config.GetEnv("PORT", "8080")

	app.Listen(":" + port)
}

// Configure CORS middleware based on environment
func configureCORS(app *fiber.App, env string) {
	var corsConfig cors.Config

	switch env {
	case "production":
		// Strict configuration for production
		allowedOrigins := config.GetEnv("ALLOWED_ORIGINS", "https://your-production-domain.com")
		corsConfig = cors.Config{
			AllowOrigins:     allowedOrigins,
			AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
			AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
			ExposeHeaders:    "Content-Length, Content-Type",
			AllowCredentials: true,
			MaxAge:           86400,
		}
	case "staging":
		// Moderate configuration for staging
		allowedOrigins := config.GetEnv("ALLOWED_ORIGINS", "https://staging.your-domain.com,https://uat.your-domain.com")
		corsConfig = cors.Config{
			AllowOrigins:     allowedOrigins,
			AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS,PATCH",
			AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Requested-With",
			ExposeHeaders:    "Content-Length, Content-Type",
			AllowCredentials: true,
			MaxAge:           3600,
		}
	default:
		// Permissive configuration for development
		allowedOrigins := config.GetEnv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5173")
		corsConfig = cors.Config{
			AllowOrigins:     allowedOrigins,
			AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS,PATCH",
			AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Requested-With",
			ExposeHeaders:    "Content-Length, Content-Type",
			AllowCredentials: true,
			MaxAge:           1800,
		}
	}

	app.Use(cors.New(corsConfig))
}
