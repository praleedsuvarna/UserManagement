package routes

import (
	"UserManagement/controllers"
	// localMiddleware "UserManagement/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/middleware"
)

func OrganizationRoutes(app *fiber.App) {
	org := app.Group("/organizations")

	// // Only Admins can create organizations
	// org.Post("/", middleware.AuthMiddleware, localMiddleware.AdminMiddleware, controllers.CreateOrganization)
	// org.Post("/create-and-assign", middleware.AuthMiddleware, localMiddleware.AdminMiddleware, controllers.CreateAndAssignOrganization)

	// // All authenticated users can view organizations
	// org.Get("/", middleware.AuthMiddleware, controllers.GetOrganizations)

	// // Admins manage users in their organization
	// org.Post("/assign-organization", middleware.AuthMiddleware, localMiddleware.AdminMiddleware, controllers.AssignAdminToOrganization)
	// org.Post("/add-user", middleware.AuthMiddleware, localMiddleware.AdminMiddleware, controllers.AddUserToOrganization)
	// org.Post("/remove-user", middleware.AuthMiddleware, localMiddleware.AdminMiddleware, controllers.RemoveUserFromOrganization)
	// org.Get("/users", middleware.AuthMiddleware, localMiddleware.AdminMiddleware, controllers.ListUsersInOrganization)

	// // New routes for updating organizations
	// org.Put("/", middleware.AuthMiddleware, localMiddleware.AdminMiddleware, controllers.UpdateOrganization)
	// org.Put("/:id", middleware.AuthMiddleware, localMiddleware.SuperAdminMiddleware, controllers.UpdateOrganizationByID)

	// Only Admins can create organizations
	org.Post("/", middleware.AuthMiddleware, middleware.AdminOnly(), controllers.CreateOrganization)
	org.Post("/create-and-assign", middleware.AuthMiddleware, middleware.AdminOnly(), controllers.CreateAndAssignOrganization)

	// All authenticated users can view organizations
	org.Get("/", middleware.AuthMiddleware, controllers.GetOrganizations)

	// Admins manage users in their organization
	org.Post("/assign-organization", middleware.AuthMiddleware, middleware.AdminOnly(), controllers.AssignAdminToOrganization)
	org.Post("/add-user", middleware.AuthMiddleware, middleware.AdminOnly(), controllers.AddUserToOrganization)
	org.Post("/remove-user", middleware.AuthMiddleware, middleware.AdminOnly(), controllers.RemoveUserFromOrganization)
	org.Get("/users", middleware.AuthMiddleware, middleware.AdminOnly(), controllers.ListUsersInOrganization)

	// New routes for updating organizations
	org.Put("/", middleware.AuthMiddleware, middleware.AdminOnly(), controllers.UpdateOrganization)
	org.Put("/:id", middleware.AuthMiddleware, middleware.SuperAdminOnly(), controllers.UpdateOrganizationByID)
}
