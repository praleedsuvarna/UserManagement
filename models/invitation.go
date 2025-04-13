package models

import "time"

type Invitation struct {
	ID             string    `bson:"_id,omitempty" json:"id"`
	Email          string    `bson:"email" json:"email"`
	OrganizationID string    `bson:"organization_id" json:"organization_id"`
	Role           string    `bson:"role" json:"role"`
	Token          string    `bson:"token" json:"token"`
	ExpiresAt      time.Time `bson:"expires_at" json:"expires_at"`
}
