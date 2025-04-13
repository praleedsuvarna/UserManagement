package models

import (
	"time"

	"UserManagement/payment"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Subscription represents a subscription record in the database
type Subscription struct {
	ID                    primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	UserID                primitive.ObjectID     `bson:"user_id" json:"user_id"`
	OrganizationID        primitive.ObjectID     `bson:"organization_id,omitempty" json:"organization_id,omitempty"`
	PlanID                string                 `bson:"plan_id" json:"plan_id"`
	Gateway               string                 `bson:"gateway" json:"gateway"`
	GatewaySubscriptionID string                 `bson:"gateway_subscription_id" json:"gateway_subscription_id"`
	Status                string                 `bson:"status" json:"status"`
	Amount                float64                `bson:"amount" json:"amount"`
	Currency              string                 `bson:"currency" json:"currency"`
	PaymentMethod         string                 `bson:"payment_method" json:"payment_method"`
	BillingCycle          payment.BillingCycle   `bson:"billing_cycle" json:"billing_cycle"`
	StartAt               time.Time              `bson:"start_at" json:"start_at"`
	NextBillingAt         time.Time              `bson:"next_billing_at" json:"next_billing_at"`
	EndAt                 *time.Time             `bson:"end_at,omitempty" json:"end_at,omitempty"`
	Metadata              map[string]interface{} `bson:"metadata,omitempty" json:"metadata,omitempty"`
	CreatedAt             time.Time              `bson:"created_at" json:"created_at"`
	UpdatedAt             time.Time              `bson:"updated_at" json:"updated_at"`
	CancelledAt           *time.Time             `bson:"cancelled_at,omitempty" json:"cancelled_at,omitempty"`
}

// SubscriptionPlan represents a subscription plan that users can subscribe to
type SubscriptionPlan struct {
	ID           primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	Name         string                 `bson:"name" json:"name"`
	Description  string                 `bson:"description" json:"description"`
	Amount       float64                `bson:"amount" json:"amount"`
	Currency     string                 `bson:"currency" json:"currency"`
	BillingCycle payment.BillingCycle   `bson:"billing_cycle" json:"billing_cycle"`
	Features     []string               `bson:"features,omitempty" json:"features,omitempty"`
	IsActive     bool                   `bson:"is_active" json:"is_active"`
	Metadata     map[string]interface{} `bson:"metadata,omitempty" json:"metadata,omitempty"`
	CreatedAt    time.Time              `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time              `bson:"updated_at" json:"updated_at"`
}
