package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	OrganizationID    primitive.ObjectID `bson:"organization_id,omitempty" json:"organization_id,omitempty"`
	Username          string             `bson:"username" json:"username"`
	Email             string             `bson:"email" json:"email"`
	Password          string             `bson:"password" json:"-"`
	Role              string             `bson:"role" json:"role"` // "admin" or "user"
	RefreshToken      string             `bson:"refresh_token,omitempty"`
	TokenExpiry       primitive.DateTime `bson:"token_expiry,omitempty"`
	EmailVerified     bool               `bson:"email_verified" json:"email_verified"`
	EmailVerifyToken  string             `bson:"email_verify_token,omitempty" json:"-"`
	EmailVerifyExpiry primitive.DateTime `bson:"email_verify_expiry,omitempty" json:"-"`
	GoogleID          string             `bson:"google_id,omitempty"`
	GooglePicture     string             `bson:"google_picture,omitempty"`
	CreatedAt         time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt         time.Time          `bson:"updated_at" json:"updated_at"`
}

// PartialUpdate represents a safe way to update user fields
type PartialUpdate struct {
	Username *string `json:"username,omitempty" bson:"username,omitempty"`
	Email    *string `json:"email,omitempty" bson:"email,omitempty"`
}

// PrepareSafeUpdate creates a safe update document that only updates provided fields
func PrepareSafeUpdate(update PartialUpdate) (bson.M, error) {
	updateDoc := bson.M{}

	if update.Username != nil {
		updateDoc["username"] = *update.Username
	}

	if update.Email != nil {
		updateDoc["email"] = *update.Email
	}

	// Always update the updated_at timestamp
	updateDoc["updated_at"] = time.Now()

	return bson.M{"$set": updateDoc}, nil
}
