package controllers

import (
	// "UserManagement/config"
	"UserManagement/models"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/config"
	"github.com/praleedsuvarna/shared-libs/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Create Organization
func CreateOrganization(c *fiber.Ctx) error {
	var org models.Organization

	if err := c.BodyParser(&org); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	org.ID = primitive.NewObjectID()
	currentTime := time.Now()
	org.CreatedAt = currentTime
	org.UpdatedAt = currentTime
	collection := config.GetCollection("oms_organizations")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, org)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusCreated).JSON(org)
}

// Create Organization for an admin
func CreateAndAssignOrganization(c *fiber.Ctx) error {
	// Get the admin user ID from locals
	adminID := c.Locals("user_id").(string)

	// Collections
	orgCollection := config.GetCollection("oms_organizations")
	userCollection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Convert admin ID to ObjectID
	objAdminID, err := primitive.ObjectIDFromHex(adminID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid admin ID"})
	}

	// Check if admin already has an organization
	var admin models.User
	err = userCollection.FindOne(ctx, bson.M{
		"_id":  objAdminID,
		"role": "admin",
	}).Decode(&admin)

	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Admin not found"})
	}

	// Check if admin already has an organization
	if admin.OrganizationID != primitive.NilObjectID {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"error":                    "Admin is already assigned to an organization",
			"existing_organization_id": admin.OrganizationID.Hex(),
		})
	}

	// Prepare new organization
	var org models.Organization

	if err := c.BodyParser(&org); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	org.ID = primitive.NewObjectID()
	currentTime := time.Now()
	org.CreatedAt = currentTime
	org.UpdatedAt = currentTime

	// Insert organization
	_, err = orgCollection.InsertOne(ctx, org)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create organization"})
	}

	// Update the admin's organization
	update := bson.M{
		"$set": bson.M{
			"organization_id": org.ID,
		},
	}

	// Perform the update
	_, err = userCollection.UpdateOne(ctx,
		bson.M{
			"_id":  objAdminID,
			"role": "admin",
		},
		update,
	)

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update admin's organization"})
	}

	// Log the organization creation
	utils.LogAudit(adminID, "Created organization", org.ID.Hex())

	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"organization": org,
		"message":      "Organization created successfully",
	})
}

func AssignAdminToOrganization(c *fiber.Ctx) error {
	// Parse request body
	var req struct {
		AdminID        string `json:"admin_id"`
		OrganizationID string `json:"organization_id"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Convert IDs to ObjectID
	objAdminID, err := primitive.ObjectIDFromHex(req.AdminID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid admin ID format"})
	}

	objOrganizationID, err := primitive.ObjectIDFromHex(req.OrganizationID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid organization ID format"})
	}

	// Verify the admin exists and has admin role
	filter := bson.M{
		"_id":  objAdminID,
		"role": "admin",
	}

	// Prepare update operation
	update := bson.M{
		"$set": bson.M{
			"organization_id": objOrganizationID,
		},
	}

	// Update the admin's organization
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to assign organization to admin"})
	}

	// Check if an admin was actually updated
	if result.ModifiedCount == 0 {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Admin not found or already has an organization"})
	}

	// Optional: Log the action
	utils.LogAudit("system", "Assigned admin to organization", req.AdminID)

	return c.JSON(fiber.Map{
		"message":         "Admin assigned to organization successfully",
		"modified_count":  result.ModifiedCount,
		"organization_id": req.OrganizationID,
	})
}

// Get Organizations
func GetOrganizations(c *fiber.Ctx) error {
	collection := config.GetCollection("oms_organizations")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var organizations []models.Organization
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var org models.Organization
		cursor.Decode(&org)
		organizations = append(organizations, org)
	}

	return c.JSON(organizations)
}

// Add User to Organization (Admin Only)
func AddUserToOrganization(c *fiber.Ctx) error {
	adminID := c.Locals("user_id").(string)

	// Parse request body
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if Admin exists and retrieve their organization
	var admin models.User
	objAdminID, _ := primitive.ObjectIDFromHex(adminID)
	err := collection.FindOne(ctx, bson.M{"_id": objAdminID, "role": "admin"}).Decode(&admin)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Only admins can add users to an organization"})
	}

	// Check if admin has an organization
	if admin.OrganizationID == primitive.NilObjectID {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Admin does not belong to an organization"})
	}

	// Update user organization
	objUserID, _ := primitive.ObjectIDFromHex(req.UserID)
	update := bson.M{"$set": bson.M{"organization_id": admin.OrganizationID}}
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objUserID}, update)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add user to organization"})
	}

	// Log the action
	utils.LogAudit(adminID, "Added user to organization", req.UserID)

	return c.JSON(fiber.Map{"message": "User added to organization successfully"})
}

// Remove User from Organization (Admin Only)
func RemoveUserFromOrganization(c *fiber.Ctx) error {
	adminID := c.Locals("user_id").(string)

	// Parse request body
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if Admin exists and retrieve their organization
	var admin models.User
	objAdminID, _ := primitive.ObjectIDFromHex(adminID)
	err := collection.FindOne(ctx, bson.M{"_id": objAdminID, "role": "admin"}).Decode(&admin)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Only admins can remove users from an organization"})
	}

	// Remove user from organization
	objUserID, _ := primitive.ObjectIDFromHex(req.UserID)
	update := bson.M{"$set": bson.M{"organization_id": nil}}
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objUserID}, update)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove user from organization"})
	}

	// Log the action
	utils.LogAudit(adminID, "Removed user from organization", req.UserID)

	return c.JSON(fiber.Map{"message": "User removed from organization successfully"})
}

// List Users in Organization (Admin Only)
func ListUsersInOrganization(c *fiber.Ctx) error {
	adminID := c.Locals("user_id").(string)

	fmt.Println("Admin ID:", adminID)

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if Admin exists and retrieve their organization
	var admin models.User
	objAdminID, _ := primitive.ObjectIDFromHex(adminID)
	err := collection.FindOne(ctx, bson.M{"_id": objAdminID, "role": "admin"}).Decode(&admin)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Only admins can view users in their organization"})
	}

	// Fetch all users in the admin's organization
	var users []models.User
	cursor, err := collection.Find(ctx, bson.M{"organization_id": admin.OrganizationID})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve users"})
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var user models.User
		if err := cursor.Decode(&user); err != nil {
			continue
		}
		user.Password = "" // Hide password
		users = append(users, user)
	}

	return c.JSON(users)
}
