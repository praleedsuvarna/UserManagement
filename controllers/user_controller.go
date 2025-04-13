package controllers

import (
	// "UserManagement/config"
	"UserManagement/models"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/config"
	"github.com/praleedsuvarna/shared-libs/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Register User
func RegisterUser(c *fiber.Ctx) error {
	var user models.User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Validate
	user.Email = strings.TrimSpace(user.Email)
	user.Password = strings.TrimSpace(user.Password)

	// Validate Role
	if user.Role != "admin" && user.Role != "user" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid role"})
	}

	// Ensure organization ID is valid
	if user.Role == "user" && user.OrganizationID.IsZero() {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Users must belong to an organization"})
	}

	// Check if email already exists
	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	existingUser := &models.User{}
	err := collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(existingUser)
	if err == nil {
		// Email already exists
		fmt.Println("Email already in use:", user.Email)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Email already in use"})
	} else if err != mongo.ErrNoDocuments {
		// Some other error occurred during the database operation
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to check email uniqueness"})
	}
	fmt.Println("Current Email:", user.Email)
	// Hash password directly with bcrypt
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	// Store hash as a base64 encoded string
	encodedPassword := base64.StdEncoding.EncodeToString(hashedBytes)

	// DEBUG: Show what we encoded
	fmt.Println("Encoded password:", encodedPassword)

	currentTime := time.Now()
	user.ID = primitive.NewObjectID()
	user.Password = encodedPassword
	user.CreatedAt = currentTime
	user.UpdatedAt = currentTime

	_, err = collection.InsertOne(ctx, user)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create user"})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{"message": "User registered successfully"})
}

// Login User
func LoginUser(c *fiber.Ctx) error {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&credentials); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Trim spaces from credentials to avoid common issues
	credentials.Email = strings.TrimSpace(credentials.Email)
	credentials.Password = strings.TrimSpace(credentials.Password)

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err := collection.FindOne(ctx, bson.M{"email": credentials.Email}).Decode(&user)
	if err != nil {
		fmt.Println("User lookup error:", err)
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid 1 email or password"})
	}

	// // Enhanced debugging
	// fmt.Println("User found:", user.Email)
	// fmt.Println("Stored Password:", user.Password)
	// fmt.Println("Password length:", len(user.Password))
	// fmt.Println("Entered Password:", credentials.Password)

	// // Try to decode the stored hash to check if it's base64 encoded
	// decodedBytes, err := base64.StdEncoding.DecodeString(user.Password)
	// if err != nil {
	// 	fmt.Println("Base64 decoding error:", err)
	// 	fmt.Println("Not a valid base64 string - trying direct comparison")
	// } else {
	// 	fmt.Println("Successfully decoded from base64")
	// 	fmt.Println("Decoded hash:", string(decodedBytes))
	// 	fmt.Println("Decoded length:", len(decodedBytes))
	// 	fmt.Println("Starts with $:", len(decodedBytes) > 0 && decodedBytes[0] == '$')
	// }

	// Check if email is verified
	if !user.EmailVerified {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "Please verify your email before logging in",
		})
	}

	// Compare password
	if !utils.ComparePasswords(user.Password, credentials.Password) {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid 2 email or password"})
	}

	// Generate JWT token
	// token, err := utils.GenerateToken(user.ID.Hex(), user.Role)
	accessToken, refreshToken, err := utils.GenerateTokenPair(user.ID.Hex(), user.OrganizationID.Hex(), user.Role)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	// Update user with new refresh token
	update := bson.M{
		"$set": bson.M{
			"refresh_token": refreshToken,
			"token_expiry":  primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 24 * 7)),
		},
	}
	_, err = collection.UpdateOne(ctx, bson.M{"_id": user.ID}, update)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update refresh token"})
	}

	// return c.JSON(fiber.Map{"token": token})

	return c.JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user": fiber.Map{
			"id":    user.ID.Hex(),
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

// Get User by ID (Protected)
func GetUser(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	OrganizationID := c.Locals("organization_id").(string)

	collection := config.GetCollection("oms_users")
	orgCollection := config.GetCollection("oms_organizations")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	objID, _ := primitive.ObjectIDFromHex(userID)
	err := collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	// Fetch organization details
	var organization models.Organization
	orgObjID, _ := primitive.ObjectIDFromHex(OrganizationID)
	err = orgCollection.FindOne(ctx, bson.M{"_id": orgObjID}).Decode(&organization)
	if err != nil {
		// Handle organization not found, but still return user data
		return c.JSON(fiber.Map{
			"user":              user,
			"organization_name": "",
			"error":             "Organization not found",
		})
	}

	// Create response with organization name
	type UserResponse struct {
		models.User
		OrganizationName string `json:"organization_name,omitempty"`
	}

	response := UserResponse{
		User:             user,
		OrganizationName: organization.Name, // Assuming organization has a Name field
	}

	response.Password = "" // Hide password
	return c.JSON(response)
}

// Update User (Protected)
func UpdateUser(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var partialUpdate models.PartialUpdate
	if err := c.BodyParser(&partialUpdate); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Prepare safe update document
	updateDoc, err := models.PrepareSafeUpdate(partialUpdate)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to prepare update"})
	}

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	objID, _ := primitive.ObjectIDFromHex(userID)
	// update := bson.M{"$set": updateData}

	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, updateDoc)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update user"})
	}

	return c.JSON(fiber.Map{"message": "User updated successfully"})
}

// Delete User (Protected)
func DeleteUser(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	objID, _ := primitive.ObjectIDFromHex(userID)
	_, err := collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete user"})
	}

	return c.JSON(fiber.Map{"message": "User deleted successfully"})
}

func DeleteUser_ByEmail(c *fiber.Ctx) error {
	// Parse the request body to get the email
	type DeleteRequest struct {
		Email string `json:"email"`
	}

	var req DeleteRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	email := req.Email

	// Validate that email is provided
	if email == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Email is required"})
	}

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Delete the user based on email
	result, err := collection.DeleteOne(ctx, bson.M{"email": email})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete user"})
	}

	// Check if any document was deleted
	if result.DeletedCount == 0 {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	return c.JSON(fiber.Map{"message": "User deleted successfully"})
}

// ReseedUserPassword can be used to reset a user's password if needed
func ReseedUserPassword(c *fiber.Ctx) error {
	// This should be protected by admin authentication

	var credentials struct {
		Email       string `json:"email"`
		NewPassword string `json:"new_password"`
	}

	if err := c.BodyParser(&credentials); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Hash password directly with bcrypt
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(credentials.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("Password hashing error: %v\n", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to process password",
		})
	}

	// Encode with base64
	encodedPassword := base64.StdEncoding.EncodeToString(hashedBytes)

	// Update the user's password
	result, err := collection.UpdateOne(
		ctx,
		bson.M{"email": credentials.Email},
		bson.M{"$set": bson.M{
			"password":   encodedPassword,
			"updated_at": time.Now(),
		}},
	)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update password"})
	}

	if result.MatchedCount == 0 {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	return c.JSON(fiber.Map{"message": "Password updated successfully"})
}

// // LoginUserV2 is a completely rewritten login function
// func LoginUserV2(c *fiber.Ctx) error {
// 	fmt.Println("\n===== LOGIN USER V2 =====")

// 	// Parse request body
// 	var input struct {
// 		Email    string `json:"email"`
// 		Password string `json:"password"`
// 	}

// 	if err := c.BodyParser(&input); err != nil {
// 		fmt.Printf("Body parse error: %v\n", err)
// 		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
// 			"success": false,
// 			"error":   "Invalid request format",
// 		})
// 	}

// 	// Clean input
// 	input.Email = strings.TrimSpace(input.Email)
// 	input.Password = strings.TrimSpace(input.Password)

// 	fmt.Printf("Login attempt - Email: %s, Password length: %d\n",
// 		input.Email, len(input.Password))

// 	// Get user from database
// 	collection := config.GetCollection("oms_users")
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()

// 	var user models.User
// 	err := collection.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user)
// 	if err != nil {
// 		fmt.Printf("User lookup error: %v\n", err)
// 		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
// 			"success": false,
// 			"error":   "Invalid email or password",
// 		})
// 	}

// 	fmt.Printf("User found - ID: %s, Stored password length: %d\n",
// 		user.ID.Hex(), len(user.Password))

// 	// Decode base64-encoded hash
// 	hashedBytes, err := base64.StdEncoding.DecodeString(user.Password)
// 	if err != nil {
// 		fmt.Printf("Base64 decode error: %v\n", err)
// 		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
// 			"success": false,
// 			"error":   "Authentication error",
// 		})
// 	}

// 	fmt.Printf("Decoded hash length: %d\n", len(hashedBytes))

// 	// Compare password
// 	err = bcrypt.CompareHashAndPassword(hashedBytes, []byte(input.Password))
// 	if err != nil {
// 		fmt.Printf("Password verification error: %v\n", err)
// 		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
// 			"success": false,
// 			"error":   "Invalid email or password",
// 		})
// 	}

// 	fmt.Println("Password verified successfully")

// 	// Generate JWT token
// 	token, err := utils.GenerateToken(user.ID.Hex(), user.Role)
// 	if err != nil {
// 		fmt.Printf("Token generation error: %v\n", err)
// 		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
// 			"success": false,
// 			"error":   "Authentication error",
// 		})
// 	}

// 	return c.JSON(fiber.Map{
// 		"success": true,
// 		"token":   token,
// 		"user": fiber.Map{
// 			"id":       user.ID.Hex(),
// 			"email":    user.Email,
// 			"username": user.Username,
// 			"role":     user.Role,
// 		},
// 	})
// }

// TestPasswordEncoding creates a test user and validates password comparison
func TestPasswordEncoding(c *fiber.Ctx) error {
	// Step 1: Create a test password
	testPassword := "testpassword123"

	// Step 2: Hash it like RegisterUser does
	hashedPassword, err := utils.HashPassword(testPassword)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to hash password",
			"step":  "hashing",
		})
	}

	// Step 3: Base64 encode the hash
	encodedPassword := base64.StdEncoding.EncodeToString([]byte(hashedPassword))

	// Step 4: Try to compare with the password
	// 4.1 - Direct comparison with encoded password (should fail)
	directComparison := bcrypt.CompareHashAndPassword([]byte(encodedPassword), []byte(testPassword)) == nil

	// 4.2 - Decode and then compare
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedPassword)
	decodingSuccessful := err == nil

	decodedComparison := false
	if decodingSuccessful {
		decodedComparison = bcrypt.CompareHashAndPassword(decodedBytes, []byte(testPassword)) == nil
	}

	// 4.3 - Using our utility function
	utilityComparison := utils.ComparePasswords(encodedPassword, testPassword)

	// Return all results for analysis
	return c.JSON(fiber.Map{
		"test_password":            testPassword,
		"hashed_password":          hashedPassword,
		"encoded_password":         encodedPassword,
		"direct_comparison_works":  directComparison,
		"decoding_successful":      decodingSuccessful,
		"decoded_comparison_works": decodedComparison,
		"utility_function_works":   utilityComparison,
		"decoded_password":         string(decodedBytes),
	})
}

// RegisterUserV2 is a completely rewritten registration function
func RegisterUserV2(c *fiber.Ctx) error {
	fmt.Println("\n===== REGISTER USER V2 =====")

	// Parse request body
	var input struct {
		Email               string               `json:"email"`
		Password            string               `json:"password"`
		Username            string               `json:"username"`
		OrganizationID      primitive.ObjectID   `json:"organization_id"`
		Role                string               `json:"role"`
		CreateOrg           bool                 `json:"create_org"`
		OrganizationDetails *models.Organization `json:"organization_details,omitempty"`
	}

	if err := c.BodyParser(&input); err != nil {
		fmt.Printf("Body parse error: %v\n", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid request format",
		})
	}

	// Clean input
	input.Email = strings.TrimSpace(input.Email)
	input.Password = strings.TrimSpace(input.Password)
	input.Username = strings.TrimSpace(input.Username)

	fmt.Printf("Registration request - Email: %s, Password length: %d\n",
		input.Email, len(input.Password))

	// Validate role
	if input.Role != "admin" && input.Role != "user" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid role. Must be 'admin' or 'user'",
		})
	}

	// Validate organization for non-admin users
	if input.Role == "user" && input.OrganizationID.IsZero() {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Users must belong to an organization",
		})
	}

	// Check if email already exists
	userCollection := config.GetCollection("oms_users")
	orgCollection := config.GetCollection("oms_organizations")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	existingUser := &models.User{}
	err := userCollection.FindOne(ctx, bson.M{"email": input.Email}).Decode(existingUser)
	if err == nil {
		// Email already exists
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Email already in use"})
	} else if err != mongo.ErrNoDocuments {
		// Some other error occurred during the database operation
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to check email uniqueness"})
	}

	// Hash password directly with bcrypt
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("Password hashing error: %v\n", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to process password",
		})
	}

	// Encode with base64
	encodedPassword := base64.StdEncoding.EncodeToString(hashedBytes)

	fmt.Printf("Bcrypt hash length: %d\n", len(hashedBytes))
	fmt.Printf("Base64 encoded password length: %d\n", len(encodedPassword))

	// Generate email verification token
	emailVerifyToken := utils.GenerateEmailVerificationToken()

	// Create user object
	now := time.Now()
	user := models.User{
		ID:                primitive.NewObjectID(),
		Email:             input.Email,
		Username:          input.Username,
		Password:          encodedPassword,
		OrganizationID:    input.OrganizationID,
		Role:              input.Role,
		EmailVerified:     false,
		EmailVerifyToken:  emailVerifyToken,
		EmailVerifyExpiry: primitive.NewDateTimeFromTime(now.Add(24 * time.Hour)),
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	_, err = userCollection.InsertOne(ctx, user)
	if err != nil {
		fmt.Printf("Database insert error: %v\n", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to create user",
		})
	}
	//======

	var organizationDetails map[string]interface{}

	// If CreateOrg is true and role is admin, create organization directly
	if input.CreateOrg && input.Role == "admin" && input.OrganizationDetails != nil {
		// Create organization directly
		org := input.OrganizationDetails
		org.ID = primitive.NewObjectID()
		org.CreatedAt = time.Now()
		org.UpdatedAt = time.Now()

		// Insert organization
		_, err = orgCollection.InsertOne(ctx, org)
		if err != nil {
			// Rollback user creation if organization creation fails
			userCollection.DeleteOne(ctx, bson.M{"_id": user.ID})
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"error":   "Failed to create organization",
			})
		}

		// Update user with organization ID
		_, err = userCollection.UpdateOne(
			ctx,
			bson.M{"_id": user.ID},
			bson.M{"$set": bson.M{"organization_id": org.ID}},
		)
		if err != nil {
			// Rollback organization and user creation
			orgCollection.DeleteOne(ctx, bson.M{"_id": org.ID})
			userCollection.DeleteOne(ctx, bson.M{"_id": user.ID})
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"error":   "Failed to assign organization to user",
			})
		}

		// Update local user object with organization ID
		user.OrganizationID = org.ID

		// Log the organization creation
		utils.LogAudit(user.ID.Hex(), "Created organization during registration", org.ID.Hex())

		// Store organization details for response
		bytes, _ := json.Marshal(org)
		json.Unmarshal(bytes, &organizationDetails)
	}

	// Send verification email
	err = utils.SendVerificationEmail(input.Email, emailVerifyToken)
	if err != nil {
		fmt.Printf("Email sending error: %v\n", err)
		// Optional: You might want to delete the user if email fails
		// collection.DeleteOne(ctx, bson.M{"_id": user.ID})
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "User created but verification email failed",
		})
	}

	fmt.Println("User registered successfully")

	// // Generate JWT token with organization_id for the user's future authentication
	// accessToken, newRefreshToken, err := utils.GenerateTokenPair(user.ID.Hex(), user.OrganizationID.Hex(), user.Role)
	// if err != nil {
	// 	fmt.Printf("JWT generation error: %v\n", err)
	// 	// We don't fail registration just because token generation failed
	// }

	// Create response
	responseObj := fiber.Map{
		"success": true,
		"message": "User registered successfully",
		"user": fiber.Map{
			"id":    user.ID.Hex(),
			"email": user.Email,
			"role":  user.Role,
		},
	}

	// Include organization ID in response if available
	if !user.OrganizationID.IsZero() {
		responseObj["organization_id"] = user.OrganizationID.Hex()
	}

	// Include organization details if available
	if organizationDetails != nil {
		responseObj["organization_details"] = organizationDetails
	}

	// // Include token in response
	// if accessToken != "" {
	// 	responseObj["access_token"] = accessToken
	// }
	// if newRefreshToken != "" {
	// 	responseObj["refresh_token"] = newRefreshToken
	// }

	return c.Status(http.StatusCreated).JSON(responseObj)
}

// VerifyEmail handles email verification
func VerifyEmail(c *fiber.Ctx) error {
	// Get verification token from query
	token := c.Query("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Missing verification token",
		})
	}

	// Find user with the token
	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err := collection.FindOne(ctx, bson.M{
		"email_verify_token": token,
		"email_verified":     false,
	}).Decode(&user)

	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid or expired verification token",
		})
	}

	// Check token expiry
	now := time.Now()
	if primitive.NewDateTimeFromTime(now).Time().After(user.EmailVerifyExpiry.Time()) {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"success": false,
			"error":   "Verification token has expired",
		})
	}

	// Update user as verified
	update := bson.M{
		"$set": bson.M{
			"email_verified":     true,
			"email_verify_token": "",
		},
	}
	_, err = collection.UpdateOne(ctx, bson.M{"_id": user.ID}, update)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to verify email",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Email verified successfully",
	})
}

// ReseedUserPasswordV2 provides a more robust password reset mechanism
func ReseedUserPasswordV2(c *fiber.Ctx) error {
	var input struct {
		Email       string `json:"email"`
		NewPassword string `json:"password"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid request format",
		})
	}

	// Trim spaces
	input.Email = strings.TrimSpace(input.Email)
	input.NewPassword = strings.TrimSpace(input.NewPassword)

	// Validate input
	if input.Email == "" || input.NewPassword == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Email and password cannot be empty",
		})
	}

	// Hash password directly with bcrypt
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to hash password",
		})
	}

	// Encode with base64
	encodedPassword := base64.StdEncoding.EncodeToString(hashedBytes)

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Update the user's password
	result, err := collection.UpdateOne(
		ctx,
		bson.M{"email": input.Email},
		bson.M{"$set": bson.M{
			"password":   encodedPassword, // Store bcrypt hash directly as string
			"updated_at": time.Now(),
		}},
	)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to update password",
		})
	}

	if result.MatchedCount == 0 {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"error":   "User not found",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Password updated successfully",
	})
}

// Refresh Token
func RefreshToken(c *fiber.Ctx) error {
	var refreshRequest struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.BodyParser(&refreshRequest); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Verify the refresh token
	_, claims, err := utils.VerifyRefreshToken(refreshRequest.RefreshToken)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid refresh token"})
	}

	// Extract user ID from claims
	userID, ok := claims["user_id"].(string)
	if !ok {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	// Find user in database
	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	objUserID, _ := primitive.ObjectIDFromHex(userID)
	err = collection.FindOne(ctx, bson.M{
		"_id":           objUserID,
		"refresh_token": refreshRequest.RefreshToken,
	}).Decode(&user)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "User not found or invalid refresh token"})
	}

	// Generate new token pair
	accessToken, newRefreshToken, err := utils.GenerateTokenPair(userID, user.OrganizationID.Hex(), user.Role)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate new tokens"})
	}

	// Update user with new refresh token
	update := bson.M{
		"$set": bson.M{
			"refresh_token": newRefreshToken,
			"token_expiry":  primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 24 * 7)),
		},
	}
	_, err = collection.UpdateOne(ctx, bson.M{"_id": user.ID}, update)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update refresh token"})
	}

	return c.JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}
