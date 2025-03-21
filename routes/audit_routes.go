package routes

import (
	localMiddleware "UserManagement/middleware"

	"github.com/praleedsuvarna/shared-libs/controllers"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/middleware"
)

func AuditRoutes(app *fiber.App) {
	audit := app.Group("/audit")
	audit.Use(middleware.AuthMiddleware) // Apply auth middleware
	audit.Use(middleware.AdminOnly())    // Apply admin check
	// Only Super Admins can view logs
	audit.Get("/", localMiddleware.PermissionMiddleware("manage_all_organizations"), controllers.GetAuditLogs)
}
