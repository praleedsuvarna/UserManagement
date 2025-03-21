package controllers

import (
	// "UserManagement/config"
	"UserManagement/models"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/config"
	"github.com/praleedsuvarna/shared-libs/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Invite a user to an organization
func InviteUser(c *fiber.Ctx) error {
	adminID := c.Locals("user_id").(string)

	var req struct {
		Email          string `json:"email"`
		OrganizationID string `json:"organization_id"`
		Role           string `json:"role"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	orgPolicyCollection := config.GetCollection("oms_organization_policies")
	userCollection := config.GetCollection("oms_users")
	ctx, cancel := utils.GetContext()
	defer cancel()

	// Fetch organization policies
	var policy models.OrganizationPolicy
	err := orgPolicyCollection.FindOne(ctx, bson.M{"organization_id": req.OrganizationID}).Decode(&policy)
	if err != nil && err != mongo.ErrNoDocuments {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch policies"})
	}

	// Check max user limit
	userCount, _ := userCollection.CountDocuments(ctx, bson.M{"organization_id": req.OrganizationID})
	if policy.MaxUsers > 0 && userCount >= int64(policy.MaxUsers) {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Organization user limit reached"})
	}

	// Check allowed email domains
	emailDomain := utils.ExtractDomain(req.Email)
	if len(policy.AllowedDomains) > 0 && !utils.Contains(policy.AllowedDomains, emailDomain) {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Email domain not allowed"})
	}

	// Auto-approve users if enabled
	if policy.AutoApprove {
		newUser := models.User{
			Email:          req.Email,
			OrganizationID: utils.ToObjectID(req.OrganizationID),
			Role:           req.Role,
		}
		_, err := userCollection.InsertOne(ctx, newUser)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to auto-approve user"})
		}
		utils.LogAudit(adminID, "Auto-approved user", req.Email)
		return c.JSON(fiber.Map{"message": "User auto-approved"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "No action taken"}) // <-- Added this return statement

	// collection := config.GetCollection("oms_invitations")
	// ctx, cancel := utils.GetContext()
	// defer cancel()

	// // Generate a unique token
	// token := utils.GenerateToken(32)

	// invitation := models.Invitation{
	// 	Email:          req.Email,
	// 	OrganizationID: req.OrganizationID,
	// 	Role:           req.Role,
	// 	Token:          token,
	// 	ExpiresAt:      time.Now().Add(48 * time.Hour), // Valid for 48 hours
	// }

	// _, err := collection.InsertOne(ctx, invitation)
	// if err != nil {
	// 	return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to send invitation"})
	// }

	// // Send email with invitation link
	// utils.SendEmail(req.Email, "You're invited!", "Click the link to join: http://example.com/join?token="+token)

	// // Log audit
	// utils.LogAudit(adminID, "Invited user to organization", req.Email)

	// return c.JSON(fiber.Map{"message": "Invitation sent successfully"})
}

// Accept an invitation
func AcceptInvitation(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Token is required"})
	}

	collection := config.GetCollection("oms_invitations")
	userCollection := config.GetCollection("oms_users")
	ctx, cancel := utils.GetContext()
	defer cancel()

	var invite models.Invitation
	err := collection.FindOne(ctx, bson.M{"token": token}).Decode(&invite)
	if err == mongo.ErrNoDocuments || invite.ExpiresAt.Before(time.Now()) {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid or expired invitation"})
	}

	// Create user in the organization
	newUser := models.User{
		Email:          invite.Email,
		OrganizationID: utils.ToObjectID(invite.OrganizationID),
		Role:           invite.Role,
	}

	_, err = userCollection.InsertOne(ctx, newUser)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to accept invitation"})
	}

	// Delete the used invitation
	collection.DeleteOne(ctx, bson.M{"_id": invite.ID})

	// Log audit
	utils.LogAudit(invite.OrganizationID, "Accepted invitation", invite.Email)

	return c.JSON(fiber.Map{"message": "User joined successfully"})
}
