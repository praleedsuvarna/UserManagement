package routes

import (
	"UserManagement/controllers"
	// "UserManagement/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/middleware"
)

// PaymentRoutes registers all payment related routes
func PaymentRoutes(app *fiber.App) {
	// Initialize payment service
	controllers.InitializePaymentService()

	// Payment routes group
	payments := app.Group("/payments")

	// Protected routes - require authentication
	payments.Post("/", middleware.AuthMiddleware, controllers.CreatePayment)
	payments.Get("/:id", middleware.AuthMiddleware, controllers.GetPaymentStatus)

	// Subscription routes
	payments.Get("/subscriptions", middleware.AuthMiddleware, controllers.GetUserSubscriptions)
	payments.Get("/subscriptions/:id", middleware.AuthMiddleware, controllers.GetSubscription)
	payments.Delete("/subscriptions/:id", middleware.AuthMiddleware, controllers.CancelSubscription)

	// Webhook routes - no authentication required, but processed internally
	payments.Post("/webhook/:gateway", controllers.HandleWebhook)
}
