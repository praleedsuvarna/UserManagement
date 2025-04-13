package payment

import (
	"context"
	"time"
)

// Common payment constants
const (
	PaymentStatusPending   = "pending"
	PaymentStatusSucceeded = "succeeded"
	PaymentStatusFailed    = "failed"

	PaymentTypeOneTime      = "one_time"
	PaymentTypeSubscription = "subscription"

	PaymentMethodUPI        = "upi"
	PaymentMethodUPIAutopay = "upi_autopay"
	PaymentMethodCard       = "card"
	PaymentMethodNetBanking = "netbanking"

	GatewayRazorpay = "razorpay"
	GatewayCashfree = "cashfree"
	GatewayPhonePe  = "phonepe"
)

// PaymentRequest represents a payment request with all necessary details
type PaymentRequest struct {
	Amount        float64                `json:"amount"`
	Currency      string                 `json:"currency"`
	Description   string                 `json:"description"`
	CustomerID    string                 `json:"customer_id"`
	CustomerEmail string                 `json:"customer_email"`
	CustomerPhone string                 `json:"customer_phone"`
	PaymentType   string                 `json:"payment_type"`
	PaymentMethod string                 `json:"payment_method"`
	Gateway       string                 `json:"gateway"`
	BillingCycle  *BillingCycle          `json:"billing_cycle,omitempty"`
	ReturnURL     string                 `json:"return_url"`
	WebhookURL    string                 `json:"webhook_url"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// PaymentResponse represents a response from payment gateway
type PaymentResponse struct {
	PaymentID        string                 `json:"payment_id"`
	GatewayPaymentID string                 `json:"gateway_payment_id"`
	Status           string                 `json:"status"`
	Amount           float64                `json:"amount"`
	Currency         string                 `json:"currency"`
	PaymentURL       string                 `json:"payment_url,omitempty"` // URL to redirect for completing payment
	GatewayResponse  map[string]interface{} `json:"gateway_response,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
}

// SubscriptionResponse represents a subscription created/managed response
type SubscriptionResponse struct {
	SubscriptionID        string                 `json:"subscription_id"`
	GatewaySubscriptionID string                 `json:"gateway_subscription_id"`
	Status                string                 `json:"status"`
	CustomerID            string                 `json:"customer_id"`
	PlanID                string                 `json:"plan_id"`
	StartAt               time.Time              `json:"start_at"`
	EndAt                 *time.Time             `json:"end_at,omitempty"`
	NextBillingAt         time.Time              `json:"next_billing_at"`
	GatewayResponse       map[string]interface{} `json:"gateway_response,omitempty"`
}

// BillingCycle represents subscription billing details
type BillingCycle struct {
	Interval        string `json:"interval"` // day, week, month, year
	IntervalCount   int    `json:"interval_count"`
	TrialPeriodDays int    `json:"trial_period_days,omitempty"`
}

// WebhookEvent represents a payment event received from a gateway
type WebhookEvent struct {
	GatewayName    string                 `json:"gateway_name"`
	EventType      string                 `json:"event_type"`
	PaymentID      string                 `json:"payment_id,omitempty"`
	SubscriptionID string                 `json:"subscription_id,omitempty"`
	Amount         float64                `json:"amount,omitempty"`
	Currency       string                 `json:"currency,omitempty"`
	Status         string                 `json:"status,omitempty"`
	RawPayload     map[string]interface{} `json:"raw_payload"`
	ReceivedAt     time.Time              `json:"received_at"`
}

// PaymentGateway defines the interface that all payment gateways must implement
type PaymentGateway interface {
	// Initialize sets up the gateway with credentials and configuration
	Initialize(config map[string]string) error

	// CreatePayment initiates a new payment
	CreatePayment(ctx context.Context, req PaymentRequest) (*PaymentResponse, error)

	// GetPaymentStatus retrieves the current status of a payment
	GetPaymentStatus(ctx context.Context, paymentID string) (*PaymentResponse, error)

	// CreateSubscription creates a new subscription
	CreateSubscription(ctx context.Context, req PaymentRequest) (*SubscriptionResponse, error)

	// CancelSubscription cancels an existing subscription
	CancelSubscription(ctx context.Context, subscriptionID string) (*SubscriptionResponse, error)

	// ProcessWebhook processes incoming webhook events
	ProcessWebhook(ctx context.Context, payload []byte, headers map[string]string) (*WebhookEvent, error)

	// Name returns the name of the gateway
	Name() string

	// SupportedPaymentMethods returns a list of payment methods supported by this gateway
	SupportedPaymentMethods() []string
}
