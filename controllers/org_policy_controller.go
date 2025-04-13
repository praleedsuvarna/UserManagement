package controllers

import (
	// "UserManagement/config"
	"UserManagement/models"
	// "UserManagement/utils"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/config"
	"github.com/praleedsuvarna/shared-libs/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Update organization policy
func UpdateOrgPolicy(c *fiber.Ctx) error {
	var policy models.OrganizationPolicy
	if err := c.BodyParser(&policy); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	collection := config.GetCollection("oms_organization_policies")
	ctx, cancel := utils.GetContext()
	defer cancel()

	_, err := collection.UpdateOne(ctx, bson.M{"organization_id": policy.OrganizationID}, bson.M{"$set": policy}, options.Update().SetUpsert(true))
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update policy"})
	}

	return c.JSON(fiber.Map{"message": "Policy updated successfully"})
}
