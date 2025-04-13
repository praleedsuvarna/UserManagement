package controllers

import (
	// "UserManagement/config"
	"UserManagement/models"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/config"
	"github.com/praleedsuvarna/shared-libs/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// GoogleSignIn handles Google OAuth sign-in/sign-up
func GoogleSignIn(c *fiber.Ctx) error {
	// Parse the request body
	var req struct {
		Code      string `json:"code"`
		CreateOrg bool   `json:"create_org"`
		// OrganizationDetails *models.Organization `json:"organization_details,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	// Get OAuth config
	oauth2Config := utils.GetGoogleOAuthConfig()

	// Exchange code for token
	token, err := oauth2Config.Exchange(context.Background(), req.Code)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "Failed to exchange token",
		})
	}

	// Fetch user info from Google
	googleUser, err := utils.FetchGoogleUserInfo(token.AccessToken)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user info",
		})
	}

	// Database operations
	userCollection := config.GetCollection("oms_users")
	orgCollection := config.GetCollection("oms_organizations")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if user exists by Google ID
	var existingUser models.User
	err = userCollection.FindOne(ctx, bson.M{"google_id": googleUser.ID}).Decode(&existingUser)

	// If user doesn't exist, create new user
	if err == mongo.ErrNoDocuments {
		// Create new user
		newUser := models.User{
			ID:            primitive.NewObjectID(),
			Email:         googleUser.Email,
			Username:      googleUser.Name,
			GoogleID:      googleUser.ID,
			GooglePicture: googleUser.Picture,
			EmailVerified: googleUser.VerifiedEmail,
			Role:          "user", // Default role, adjust as needed
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		// If CreateOrg is true, create organization and assign to user
		var organizationDetails map[string]interface{}
		// if req.CreateOrg && req.OrganizationDetails != nil {
		if req.CreateOrg {
			// Set user role to admin for organization creation
			newUser.Role = "admin"

			// // Create organization
			// now := time.Now()
			// org := req.OrganizationDetails
			// org.ID = primitive.NewObjectID()
			// org.CreatedAt = now
			// org.UpdatedAt = now

			// Create organization using user's username
			now := time.Now()
			org := &models.Organization{
				ID:        primitive.NewObjectID(),
				Name:      newUser.Username, // Use username as organization name
				CreatedAt: now,
				UpdatedAt: now,
			}

			// Insert organization
			_, err = orgCollection.InsertOne(ctx, org)
			if err != nil {
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to create organization",
				})
			}

			// Assign organization to user
			newUser.OrganizationID = org.ID

			// Store organization details for response
			bytes, _ := json.Marshal(org)
			json.Unmarshal(bytes, &organizationDetails)

			// Log the organization creation
			utils.LogAudit(newUser.ID.Hex(), "Created organization during Google sign-in", org.ID.Hex())
		}

		// Insert the new user
		_, err = userCollection.InsertOne(ctx, newUser)
		if err != nil {
			// Rollback organization creation if user insertion fails
			if req.CreateOrg && !newUser.OrganizationID.IsZero() {
				orgCollection.DeleteOne(ctx, bson.M{"_id": newUser.OrganizationID})
			}

			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create user",
			})
		}

		// Generate tokens for the new user
		accessToken, refreshToken, err := utils.GenerateTokenPair(newUser.ID.Hex(), newUser.OrganizationID.Hex(), newUser.Role)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to generate tokens",
			})
		}

		return c.JSON(fiber.Map{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"user": fiber.Map{
				"id":      newUser.ID.Hex(),
				"email":   newUser.Email,
				"name":    newUser.Username,
				"picture": newUser.GooglePicture,
				"role":    newUser.Role,
			},
			"is_new_user": true,
		})
	} else if err != nil {
		// Database error
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// User exists - generate tokens
	accessToken, refreshToken, err := utils.GenerateTokenPair(existingUser.ID.Hex(), existingUser.OrganizationID.Hex(), existingUser.Role)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate tokens",
		})
	}

	return c.JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user": fiber.Map{
			"id":      existingUser.ID.Hex(),
			"email":   existingUser.Email,
			"name":    existingUser.Username,
			"picture": existingUser.GooglePicture,
			"role":    existingUser.Role,
		},
		"is_new_user": false,
	})
}
