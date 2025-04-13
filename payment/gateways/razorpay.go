package gateways

import (
	"UserManagement/payment"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// RazorpayGateway implements the PaymentGateway interface for Razorpay
type RazorpayGateway struct {
	keyID     string
	keySecret string
	apiBase   string
	webhook   struct {
		secret string
	}
}

// RazorpayPaymentResponse represents a Razorpay payment response
type RazorpayPaymentResponse struct {
	ID           string                 `json:"id"`
	Entity       string                 `json:"entity"`
	Amount       int                    `json:"amount"`
	Currency     string                 `json:"currency"`
	Status       string                 `json:"status"`
	Method       string                 `json:"method"`
	CreatedAt    int64                  `json:"created_at"`
	Notes        map[string]interface{} `json:"notes"`
	OrderID      string                 `json:"order_id"`
	PaymentLink  string                 `json:"short_url,omitempty"`
	RefundStatus string                 `json:"refund_status,omitempty"`
}

// RazorpayOrderResponse represents a Razorpay order response
type RazorpayOrderResponse struct {
	ID       string `json:"id"`
	Entity   string `json:"entity"`
	Amount   int    `json:"amount"`
	Currency string `json:"currency"`
	Receipt  string `json:"receipt"`
	Status   string `json:"status"`
}

// NewRazorpayGateway creates a new instance of Razorpay payment gateway
func NewRazorpayGateway() *RazorpayGateway {
	return &RazorpayGateway{
		apiBase: "https://api.razorpay.com/v1",
	}
}

// Initialize sets up the Razorpay gateway with credentials and configuration
func (g *RazorpayGateway) Initialize(config map[string]string) error {
	keyID, ok := config["key_id"]
	if !ok {
		return errors.New("razorpay key_id is required")
	}

	keySecret, ok := config["key_secret"]
	if !ok {
		return errors.New("razorpay key_secret is required")
	}

	g.keyID = keyID
	g.keySecret = keySecret

	if webhookSecret, ok := config["webhook_secret"]; ok {
		g.webhook.secret = webhookSecret
	}

	return nil
}

// Name returns the name of the gateway
func (g *RazorpayGateway) Name() string {
	return payment.GatewayRazorpay
}

// SupportedPaymentMethods returns a list of payment methods supported by Razorpay
func (g *RazorpayGateway) SupportedPaymentMethods() []string {
	return []string{
		payment.PaymentMethodUPI,
		payment.PaymentMethodUPIAutopay,
		payment.PaymentMethodCard,
		payment.PaymentMethodNetBanking,
	}
}

// CreatePayment creates a new payment through Razorpay
func (g *RazorpayGateway) CreatePayment(ctx context.Context, req payment.PaymentRequest) (*payment.PaymentResponse, error) {
	// For Razorpay, we need to create an order first
	orderID, paymentURL, err := g.createOrder(ctx, req)
	if err != nil {
		return nil, err
	}

	// Create payment response
	paymentResp := &payment.PaymentResponse{
		PaymentID:        orderID, // Use order ID as payment ID for now
		GatewayPaymentID: orderID,
		Status:           payment.PaymentStatusPending,
		Amount:           req.Amount,
		Currency:         req.Currency,
		PaymentURL:       paymentURL,
		GatewayResponse: map[string]interface{}{
			"order_id": orderID,
		},
		CreatedAt: time.Now(),
	}

	return paymentResp, nil
}

// createOrder creates a new order in Razorpay
func (g *RazorpayGateway) createOrder(ctx context.Context, req payment.PaymentRequest) (string, string, error) {
	// Convert amount to paise (Razorpay expects amount in paise)
	amountInPaise := int(req.Amount * 100)

	// Create order request
	orderReq := map[string]interface{}{
		"amount":   amountInPaise,
		"currency": req.Currency,
		"receipt":  fmt.Sprintf("rcpt_%d", time.Now().Unix()),
		"notes":    req.Metadata,
	}

	// Convert order request to JSON
	orderReqJSON, err := json.Marshal(orderReq)
	if err != nil {
		return "", "", err
	}

	// Prepare HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		fmt.Sprintf("%s/orders", g.apiBase),
		strings.NewReader(string(orderReqJSON)),
	)
	if err != nil {
		return "", "", err
	}

	// Set headers
	httpReq.SetBasicAuth(g.keyID, g.keySecret)
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return "", "", fmt.Errorf("razorpay API error: %s", string(body))
		}
		return "", "", fmt.Errorf("razorpay API error: %v", errorResp)
	}

	// Parse response
	var orderResp RazorpayOrderResponse
	if err := json.Unmarshal(body, &orderResp); err != nil {
		return "", "", err
	}

	// For UPI payments, create a payment link
	var paymentURL string

	if req.PaymentMethod == payment.PaymentMethodUPI || req.PaymentMethod == payment.PaymentMethodUPIAutopay {
		// For UPI, we'll use Razorpay's standard checkout which handles UPI payment flows
		paymentURL = fmt.Sprintf(
			"https://checkout.razorpay.com/v1/payment?key=%s&order_id=%s&prefill[email]=%s&method=upi",
			g.keyID,
			orderResp.ID,
			req.CustomerEmail,
		)

		// Add phone if available
		if req.CustomerPhone != "" {
			paymentURL += "&prefill[contact]=" + req.CustomerPhone
		}
	} else {
		// For other payment methods, use standard checkout
		paymentURL = fmt.Sprintf(
			"https://checkout.razorpay.com/v1/checkout.js?key=%s&order_id=%s",
			g.keyID,
			orderResp.ID,
		)
	}

	return orderResp.ID, paymentURL, nil
}

// GetPaymentStatus retrieves the current status of a payment
func (g *RazorpayGateway) GetPaymentStatus(ctx context.Context, paymentID string) (*payment.PaymentResponse, error) {
	// First, check if this is an order ID or payment ID
	// If it's an order ID, fetch the payment by order ID

	// Prepare HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"GET",
		fmt.Sprintf("%s/orders/%s/payments", g.apiBase, paymentID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.SetBasicAuth(g.keyID, g.keySecret)

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return nil, fmt.Errorf("razorpay API error: %s", string(body))
		}
		return nil, fmt.Errorf("razorpay API error: %v", errorResp)
	}

	// Parse response - this will be an array of payments for the order
	var paymentsResp struct {
		Items []RazorpayPaymentResponse `json:"items"`
	}
	if err := json.Unmarshal(body, &paymentsResp); err != nil {
		return nil, err
	}

	// Check if there are any payments
	if len(paymentsResp.Items) == 0 {
		return &payment.PaymentResponse{
			PaymentID:        paymentID,
			GatewayPaymentID: paymentID,
			Status:           payment.PaymentStatusPending, // If no payments, the order is still pending
			CreatedAt:        time.Now(),
		}, nil
	}

	// Use the most recent payment
	paymentInfo := paymentsResp.Items[0]

	// Map Razorpay status to our status
	status := payment.PaymentStatusPending
	switch paymentInfo.Status {
	case "authorized", "captured":
		status = payment.PaymentStatusSucceeded
	case "failed":
		status = payment.PaymentStatusFailed
	}

	// Create response
	return &payment.PaymentResponse{
		PaymentID:        paymentInfo.OrderID,
		GatewayPaymentID: paymentInfo.ID,
		Status:           status,
		Amount:           float64(paymentInfo.Amount) / 100, // Convert from paise to rupees
		Currency:         paymentInfo.Currency,
		GatewayResponse: map[string]interface{}{
			"razorpay_payment_id": paymentInfo.ID,
			"razorpay_order_id":   paymentInfo.OrderID,
			"method":              paymentInfo.Method,
		},
		CreatedAt: time.Unix(paymentInfo.CreatedAt, 0),
	}, nil
}

// CreateSubscription creates a new subscription through Razorpay
// CreateSubscription creates a new subscription through Razorpay
func (g *RazorpayGateway) CreateSubscription(ctx context.Context, req payment.PaymentRequest) (*payment.SubscriptionResponse, error) {
	// For Razorpay subscriptions, we need to:
	// 1. Create a plan (if not already created)
	// 2. Create a subscription with auto-collection

	// First, check if we have a plan ID in metadata
	planID, hasPlanID := req.Metadata["plan_id"].(string)
	if !hasPlanID {
		// Create a plan if no plan ID provided
		var err error
		planID, err = g.createPlan(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to create plan: %v", err)
		}
	}

	// Now create the subscription
	startAt := time.Now().Unix()
	if req.BillingCycle.TrialPeriodDays > 0 {
		startAt = time.Now().AddDate(0, 0, req.BillingCycle.TrialPeriodDays).Unix()
	}

	// For UPI Autopay, use the upi_autopay auth type
	authType := "link"
	if req.PaymentMethod == payment.PaymentMethodUPIAutopay {
		authType = "upi_autopay"
	}

	// Prepare subscription request
	subReq := map[string]interface{}{
		"plan_id":         planID,
		"total_count":     12, // Default to 12 billing cycles
		"start_at":        startAt,
		"customer_notify": 1,
		"notes":           req.Metadata,
		"auth_type":       authType,
		"expire_by":       time.Now().AddDate(0, 0, 7).Unix(), // Expire in 7 days if not authenticated
	}

	// Convert subscription request to JSON
	subReqJSON, err := json.Marshal(subReq)
	if err != nil {
		return nil, err
	}

	// Prepare HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		fmt.Sprintf("%s/subscriptions", g.apiBase),
		strings.NewReader(string(subReqJSON)),
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.SetBasicAuth(g.keyID, g.keySecret)
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return nil, fmt.Errorf("razorpay API error: %s", string(body))
		}
		return nil, fmt.Errorf("razorpay API error: %v", errorResp)
	}

	// Parse response
	var subResp struct {
		ID             string                 `json:"id"`
		Status         string                 `json:"status"`
		PlanID         string                 `json:"plan_id"`
		CustomerID     string                 `json:"customer_id"`
		StartAt        int64                  `json:"start_at"`
		EndAt          int64                  `json:"end_at"`
		ChargeAt       int64                  `json:"charge_at"`
		AuthType       string                 `json:"auth_type"`
		FailedAttempts int                    `json:"failed_attempts"`
		Notes          map[string]interface{} `json:"notes"`
		AuthLink       string                 `json:"short_url"`
	}
	if err := json.Unmarshal(body, &subResp); err != nil {
		return nil, err
	}

	// Create authentication URL for subscription
	var authURL string
	if subResp.AuthLink != "" {
		authURL = subResp.AuthLink
	} else {
		// For UPI autopay, create a standard subscription auth URL
		authURL = fmt.Sprintf(
			"https://api.razorpay.com/v1/subscription-auth/%s/%s",
			g.keyID,
			subResp.ID,
		)
	}

	// Create subscription response
	var endAt *time.Time
	if subResp.EndAt > 0 {
		t := time.Unix(subResp.EndAt, 0)
		endAt = &t
	}

	return &payment.SubscriptionResponse{
		SubscriptionID:        subResp.ID,
		GatewaySubscriptionID: subResp.ID,
		Status:                subResp.Status,
		CustomerID:            subResp.CustomerID,
		PlanID:                subResp.PlanID,
		StartAt:               time.Unix(subResp.StartAt, 0),
		EndAt:                 endAt,
		NextBillingAt:         time.Unix(subResp.ChargeAt, 0),
		GatewayResponse: map[string]interface{}{
			"razorpay_subscription_id": subResp.ID,
			"auth_type":                subResp.AuthType,
			"auth_url":                 authURL,
		},
	}, nil
}

// createPlan creates a new plan in Razorpay
func (g *RazorpayGateway) createPlan(ctx context.Context, req payment.PaymentRequest) (string, error) {
	if req.BillingCycle == nil {
		return "", errors.New("billing cycle is required for subscription")
	}

	// Convert amount to paise (Razorpay expects amount in paise)
	amountInPaise := int(req.Amount * 100)

	// Create plan request
	planReq := map[string]interface{}{
		"period":   req.BillingCycle.Interval,
		"interval": req.BillingCycle.IntervalCount,
		"item": map[string]interface{}{
			"name":     req.Description,
			"amount":   amountInPaise,
			"currency": req.Currency,
		},
		"notes": req.Metadata,
	}

	// Convert plan request to JSON
	planReqJSON, err := json.Marshal(planReq)
	if err != nil {
		return "", err
	}

	// Prepare HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		fmt.Sprintf("%s/plans", g.apiBase),
		strings.NewReader(string(planReqJSON)),
	)
	if err != nil {
		return "", err
	}

	// Set headers
	httpReq.SetBasicAuth(g.keyID, g.keySecret)
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return "", fmt.Errorf("razorpay API error: %s", string(body))
		}
		return "", fmt.Errorf("razorpay API error: %v", errorResp)
	}

	// Parse response
	var planResp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &planResp); err != nil {
		return "", err
	}

	return planResp.ID, nil
}

// CancelSubscription cancels an existing subscription
func (g *RazorpayGateway) CancelSubscription(ctx context.Context, subscriptionID string) (*payment.SubscriptionResponse, error) {
	// Prepare HTTP request for cancellation
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		fmt.Sprintf("%s/subscriptions/%s/cancel", g.apiBase, subscriptionID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.SetBasicAuth(g.keyID, g.keySecret)
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return nil, fmt.Errorf("razorpay API error: %s", string(body))
		}
		return nil, fmt.Errorf("razorpay API error: %v", errorResp)
	}

	// Parse response
	var subResp struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		PlanID     string `json:"plan_id"`
		CustomerID string `json:"customer_id"`
		StartAt    int64  `json:"start_at"`
		EndAt      int64  `json:"end_at"`
		ChargeAt   int64  `json:"charge_at"`
	}
	if err := json.Unmarshal(body, &subResp); err != nil {
		return nil, err
	}

	// Create subscription response
	var endAt *time.Time
	if subResp.EndAt > 0 {
		t := time.Unix(subResp.EndAt, 0)
		endAt = &t
	}

	return &payment.SubscriptionResponse{
		SubscriptionID:        subResp.ID,
		GatewaySubscriptionID: subResp.ID,
		Status:                subResp.Status,
		CustomerID:            subResp.CustomerID,
		PlanID:                subResp.PlanID,
		StartAt:               time.Unix(subResp.StartAt, 0),
		EndAt:                 endAt,
		NextBillingAt:         time.Unix(subResp.ChargeAt, 0),
		GatewayResponse: map[string]interface{}{
			"razorpay_subscription_id": subResp.ID,
			"status":                   subResp.Status,
		},
	}, nil
}

// ProcessWebhook processes incoming webhook events from Razorpay
func (g *RazorpayGateway) ProcessWebhook(ctx context.Context, payload []byte, headers map[string]string) (*payment.WebhookEvent, error) {
	// Verify webhook signature if secret is configured
	if g.webhook.secret != "" {
		signature, ok := headers["X-Razorpay-Signature"]
		if !ok {
			return nil, errors.New("missing Razorpay signature header")
		}

		// Compute HMAC
		mac := hmac.New(sha256.New, []byte(g.webhook.secret))
		mac.Write(payload)
		expectedSignature := hex.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
			return nil, errors.New("invalid webhook signature")
		}
	}

	// Parse webhook payload
	var webhookData map[string]interface{}
	if err := json.Unmarshal(payload, &webhookData); err != nil {
		return nil, err
	}

	// Extract event type
	event, ok := webhookData["event"].(string)
	if !ok {
		return nil, errors.New("missing event type in webhook payload")
	}

	// Extract payment or subscription data
	var paymentID, subscriptionID string
	var amount float64
	var currency, status string

	// Handle different event types
	switch {
	case strings.HasPrefix(event, "payment."):
		// Payment related events
		paymentObj, ok := webhookData["payload"].(map[string]interface{})["payment"].(map[string]interface{})
		if ok {
			if id, ok := paymentObj["entity"].(map[string]interface{})["id"].(string); ok {
				paymentID = id
			}
			if amt, ok := paymentObj["entity"].(map[string]interface{})["amount"].(float64); ok {
				amount = amt / 100 // Convert from paise to rupees
			}
			if curr, ok := paymentObj["entity"].(map[string]interface{})["currency"].(string); ok {
				currency = curr
			}
			if stat, ok := paymentObj["entity"].(map[string]interface{})["status"].(string); ok {
				status = stat
			}
		}
	// In the ProcessWebhook method, add this to the switch statement:

	case strings.HasPrefix(event, "subscription."):
		// Subscription related events
		subObj, ok := webhookData["payload"].(map[string]interface{})["subscription"].(map[string]interface{})
		if ok {
			if id, ok := subObj["entity"].(map[string]interface{})["id"].(string); ok {
				subscriptionID = id
			}
			if stat, ok := subObj["entity"].(map[string]interface{})["status"].(string); ok {
				status = stat
			}

			// For subscription.charged, also extract payment details
			if event == "subscription.charged" {
				paymentObj, ok := webhookData["payload"].(map[string]interface{})["payment"].(map[string]interface{})
				if ok {
					if id, ok := paymentObj["entity"].(map[string]interface{})["id"].(string); ok {
						paymentID = id
					}
					if amt, ok := paymentObj["entity"].(map[string]interface{})["amount"].(float64); ok {
						amount = amt / 100 // Convert from paise to rupees
					}
					if curr, ok := paymentObj["entity"].(map[string]interface{})["currency"].(string); ok {
						currency = curr
					}
				}
			}
		}
	}

	// Create webhook event
	webhookEvent := &payment.WebhookEvent{
		GatewayName:    payment.GatewayRazorpay,
		EventType:      event,
		PaymentID:      paymentID,
		SubscriptionID: subscriptionID,
		Amount:         amount,
		Currency:       currency,
		Status:         status,
		RawPayload:     webhookData,
		ReceivedAt:     time.Now(),
	}

	return webhookEvent, nil
}
