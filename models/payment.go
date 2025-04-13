package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	PaymentStatusPending   = "pending"
	PaymentStatusSucceeded = "succeeded"
	PaymentStatusFailed    = "failed"
)

// Payment represents a payment record in the database
type Payment struct {
	ID               primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	UserID           primitive.ObjectID     `bson:"user_id" json:"user_id"`
	OrganizationID   primitive.ObjectID     `bson:"organization_id,omitempty" json:"organization_id,omitempty"`
	SubscriptionID   primitive.ObjectID     `bson:"subscription_id,omitempty" json:"subscription_id,omitempty"`
	Amount           float64                `bson:"amount" json:"amount"`
	Currency         string                 `bson:"currency" json:"currency"`
	Description      string                 `bson:"description" json:"description"`
	PaymentType      string                 `bson:"payment_type" json:"payment_type"`
	PaymentMethod    string                 `bson:"payment_method" json:"payment_method"`
	Gateway          string                 `bson:"gateway" json:"gateway"`
	GatewayPaymentID string                 `bson:"gateway_payment_id" json:"gateway_payment_id"`
	GatewayOrderID   string                 `bson:"gateway_order_id,omitempty" json:"gateway_order_id,omitempty"`
	Status           string                 `bson:"status" json:"status"`
	PaymentURL       string                 `bson:"payment_url,omitempty" json:"payment_url,omitempty"`
	Metadata         map[string]interface{} `bson:"metadata,omitempty" json:"metadata,omitempty"`
	CreatedAt        time.Time              `bson:"created_at" json:"created_at"`
	UpdatedAt        time.Time              `bson:"updated_at" json:"updated_at"`
	CompletedAt      *time.Time             `bson:"completed_at,omitempty" json:"completed_at,omitempty"`
}

// WebhookLog represents a log of webhook events
type WebhookLog struct {
	ID               primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	Gateway          string                 `bson:"gateway" json:"gateway"`
	EventType        string                 `bson:"event_type" json:"event_type"`
	PaymentID        string                 `bson:"payment_id,omitempty" json:"payment_id,omitempty"`
	SubscriptionID   string                 `bson:"subscription_id,omitempty" json:"subscription_id,omitempty"`
	RawPayload       map[string]interface{} `bson:"raw_payload" json:"raw_payload"`
	ProcessedAt      time.Time              `bson:"processed_at" json:"processed_at"`
	ProcessingStatus string                 `bson:"processing_status" json:"processing_status"`
	ErrorMessage     string                 `bson:"error_message,omitempty" json:"error_message,omitempty"`
}
