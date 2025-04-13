package routes

import (
	"UserManagement/controllers"
	localMiddleware "UserManagement/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/middleware"
)

func SubscriptionRoutes(app *fiber.App) {
	subscriptions := app.Group("/subscriptions")

	// Plan management (admin only)
	subscriptions.Post("/plans", middleware.AuthMiddleware, localMiddleware.AdminMiddleware, controllers.CreateSubscriptionPlan)
	subscriptions.Get("/plans", middleware.AuthMiddleware, controllers.GetSubscriptionPlans)
	subscriptions.Get("/plans/:id", middleware.AuthMiddleware, controllers.GetSubscriptionPlan)
	subscriptions.Put("/plans/:id", middleware.AuthMiddleware, localMiddleware.AdminMiddleware, controllers.UpdateSubscriptionPlan)

	// User subscription management
	subscriptions.Post("/subscribe", middleware.AuthMiddleware, controllers.SubscribeUserToPlan)
	subscriptions.Get("/active", middleware.AuthMiddleware, controllers.GetUserActiveSubscriptions)
	subscriptions.Get("/:id/invoices", middleware.AuthMiddleware, controllers.GetSubscriptionInvoices)

	// Analytics (admin only)
	subscriptions.Get("/analytics", middleware.AuthMiddleware, localMiddleware.AdminMiddleware, controllers.GetSubscriptionAnalytics)
}
