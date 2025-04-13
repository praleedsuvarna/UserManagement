package controllers

import (
	// "UserManagement/config"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// TestRegisterAndVerify creates a test user and immediately tries to verify the password
func TestRegisterAndVerify(c *fiber.Ctx) error {
	// Get test credentials from request
	var data struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&data); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	// =============== REGISTRATION PROCESS ===============
	fmt.Println("\n===== REGISTRATION PHASE =====")
	fmt.Printf("Raw password: %q (length: %d)\n", data.Password, len(data.Password))

	// Step 1: Hash with bcrypt directly
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to hash password",
		})
	}
	fmt.Printf("Bcrypt hash: %q (length: %d)\n", string(hashedBytes), len(hashedBytes))

	// Step 2: Encode with base64
	encodedHash := base64.StdEncoding.EncodeToString(hashedBytes)
	fmt.Printf("Base64 encoded: %q (length: %d)\n", encodedHash, len(encodedHash))

	// Step 3: Create user
	user := struct {
		ID        primitive.ObjectID `bson:"_id"`
		Email     string             `bson:"email"`
		Password  string             `bson:"password"`
		CreatedAt time.Time          `bson:"created_at"`
	}{
		ID:        primitive.NewObjectID(),
		Email:     data.Email,
		Password:  encodedHash,
		CreatedAt: time.Now(),
	}

	// Step 4: Store in database
	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Delete existing user first
	_, _ = collection.DeleteOne(ctx, bson.M{"email": data.Email})

	// Insert the new user
	_, err = collection.InsertOne(ctx, user)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Failed to create user",
			"details": err.Error(),
		})
	}
	fmt.Println("User created successfully in database")

	// =============== VERIFICATION PROCESS ===============
	fmt.Println("\n===== VERIFICATION PHASE =====")

	// Step 1: Retrieve the user from database
	var retrievedUser struct {
		ID       primitive.ObjectID `bson:"_id"`
		Email    string             `bson:"email"`
		Password string             `bson:"password"`
	}

	err = collection.FindOne(ctx, bson.M{"email": data.Email}).Decode(&retrievedUser)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Failed to retrieve user",
			"details": err.Error(),
		})
	}
	fmt.Printf("Retrieved password from DB: %q (length: %d)\n", retrievedUser.Password, len(retrievedUser.Password))

	// Step 2: Check if the retrieved hash matches what we stored
	fmt.Printf("Original encoded hash: %q\n", encodedHash)
	fmt.Printf("Retrieved encoded hash: %q\n", retrievedUser.Password)
	fmt.Printf("Hashes match: %v\n", encodedHash == retrievedUser.Password)

	// Step 3: Try to decode the retrieved hash
	retrievedHashBytes, err := base64.StdEncoding.DecodeString(retrievedUser.Password)
	if err != nil {
		fmt.Printf("Error decoding retrieved hash: %v\n", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Failed to decode hash",
			"details": err.Error(),
		})
	}
	fmt.Printf("Decoded retrieved hash: %q (length: %d)\n", string(retrievedHashBytes), len(retrievedHashBytes))

	// Step 4: Compare with the original password
	err = bcrypt.CompareHashAndPassword(retrievedHashBytes, []byte(data.Password))
	passwordsMatch := err == nil
	if err != nil {
		fmt.Printf("Password verification error: %v\n", err)
	} else {
		fmt.Println("Password verified successfully!")
	}

	// Return detailed results
	return c.JSON(fiber.Map{
		"test_completed":        true,
		"email":                 data.Email,
		"stored_hash_length":    len(encodedHash),
		"retrieved_hash_length": len(retrievedUser.Password),
		"hashes_match":          encodedHash == retrievedUser.Password,
		"password_verifies":     passwordsMatch,
		"user_id":               retrievedUser.ID.Hex(),
	})
}

// ViewUserPassword retrieves and shows a user's password (for debugging only)
func ViewUserPassword(c *fiber.Ctx) error {
	email := c.Query("email")
	if email == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Email parameter is required",
		})
	}

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user struct {
		ID       primitive.ObjectID `bson:"_id"`
		Email    string             `bson:"email"`
		Password string             `bson:"password"`
	}

	err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error":   "User not found",
			"details": err.Error(),
		})
	}

	// Try to decode if it's base64
	decodedBytes, decodeErr := base64.StdEncoding.DecodeString(user.Password)
	decodedPassword := ""
	if decodeErr == nil {
		decodedPassword = string(decodedBytes)
	}

	return c.JSON(fiber.Map{
		"user_id":            user.ID.Hex(),
		"email":              user.Email,
		"encoded_password":   user.Password,
		"encoded_length":     len(user.Password),
		"decoded_success":    decodeErr == nil,
		"decoded_password":   decodedPassword,
		"decoded_length":     len(decodedPassword),
		"starts_with_dollar": len(decodedPassword) > 0 && decodedPassword[0] == '$',
	})
}

// TestPasswordVerification tests if a password matches a user's stored password
func TestPasswordVerification(c *fiber.Ctx) error {
	var data struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&data); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user struct {
		ID       primitive.ObjectID `bson:"_id"`
		Email    string             `bson:"email"`
		Password string             `bson:"password"`
	}

	err := collection.FindOne(ctx, bson.M{"email": data.Email}).Decode(&user)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	fmt.Printf("\n===== PASSWORD VERIFICATION TEST =====\n")
	fmt.Printf("User: %s\n", data.Email)
	fmt.Printf("Testing password: %q\n", data.Password)
	fmt.Printf("Stored hash: %q\n", user.Password)

	// Try to decode as base64
	decodedBytes, decodeErr := base64.StdEncoding.DecodeString(user.Password)
	if decodeErr != nil {
		fmt.Printf("Base64 decode error: %v\n", decodeErr)

		// Try direct comparison as fallback
		directErr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data.Password))
		directMatch := directErr == nil

		fmt.Printf("Direct comparison result: %v\n", directMatch)
		if directErr != nil {
			fmt.Printf("Direct comparison error: %v\n", directErr)
		}

		return c.JSON(fiber.Map{
			"base64_decode_failed": true,
			"direct_match":         directMatch,
			"match":                directMatch,
		})
	}

	fmt.Printf("Decoded hash: %q\n", string(decodedBytes))

	// Compare with bcrypt
	compareErr := bcrypt.CompareHashAndPassword(decodedBytes, []byte(data.Password))
	passwordsMatch := compareErr == nil

	fmt.Printf("Password match result: %v\n", passwordsMatch)
	if compareErr != nil {
		fmt.Printf("Comparison error: %v\n", compareErr)
	}

	return c.JSON(fiber.Map{
		"test_completed":      true,
		"match":               passwordsMatch,
		"raw_password_length": len(data.Password),
		"encoded_hash_length": len(user.Password),
		"decoded_hash_length": len(decodedBytes),
	})
}
