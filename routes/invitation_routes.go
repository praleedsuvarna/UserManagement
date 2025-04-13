package routes

import (
	"UserManagement/controllers"
	localMiddleware "UserManagement/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/middleware"
)

func InvitationRoutes(app *fiber.App) {
	invite := app.Group("/invitations")

	// Admin invites user
	invite.Post("/invite", middleware.AuthMiddleware, localMiddleware.PermissionMiddleware("manage_users"), controllers.InviteUser)

	// User accepts invitation
	invite.Get("/accept", controllers.AcceptInvitation)
}
