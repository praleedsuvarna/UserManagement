package routes

import "github.com/gofiber/fiber/v2"

func SetupRoutes(app *fiber.App) {
	OrganizationRoutes(app)
	UserRoutes(app)
	AuditRoutes(app)
	InvitationRoutes(app)
	PwdDebugRoutes(app)
	PaymentRoutes(app)
	SubscriptionRoutes(app)
}
