package middleware

import (
	localConfig "UserManagement/config"
	"UserManagement/models"

	// "UserManagement/utils"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/config"
	"github.com/praleedsuvarna/shared-libs/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Middleware to check user permissions
func PermissionMiddleware(requiredPermission string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(string)

		collection := config.GetCollection("oms_users")
		ctx, cancel := utils.GetContext()
		defer cancel()

		var user models.User
		err := collection.FindOne(ctx, bson.M{"_id": utils.ToObjectID(userID)}).Decode(&user)
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "User not found"})
		} else if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
		}

		if !localConfig.HasPermission(user.Role, requiredPermission) {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Permission denied"})
		}

		return c.Next()
	}
}
