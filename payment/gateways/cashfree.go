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
	"io"
	"net/http"
	"strings"
	"time"
)

// CashfreeGateway implements the PaymentGateway interface for Cashfree
type CashfreeGateway struct {
	appID     string
	secretKey string
	apiBase   string
	webhook   struct {
		secret string
	}
	isProd bool
}

// CashfreeOrderResponse represents a Cashfree order response
type CashfreeOrderResponse struct {
	Status        string `json:"status"`
	Message       string `json:"message"`
	OrderID       string `json:"orderId"`
	OrderToken    string `json:"orderToken"`
	OrderStatus   string `json:"orderStatus"`
	OrderAmount   string `json:"orderAmount"`
	OrderCurrency string `json:"orderCurrency"`
	PaymentLink   string `json:"paymentLink"`
}

// CashfreePaymentResponse represents a Cashfree payment response
type CashfreePaymentResponse struct {
	OrderID         string `json:"orderId"`
	OrderAmount     string `json:"orderAmount"`
	OrderCurrency   string `json:"orderCurrency"`
	OrderStatus     string `json:"orderStatus"`
	PaymentID       string `json:"paymentId"`
	PaymentStatus   string `json:"paymentStatus"`
	PaymentAmount   string `json:"paymentAmount"`
	PaymentCurrency string `json:"paymentCurrency"`
	PaymentMethod   string `json:"paymentMethod"`
	PaymentTime     string `json:"paymentTime"`
}

// CashfreeSubscriptionResponse represents a Cashfree subscription response
type CashfreeSubscriptionResponse struct {
	Status             string `json:"status"`
	Message            string `json:"message"`
	SubscriptionID     string `json:"subscriptionId"`
	SubscriptionStatus string `json:"subscriptionStatus"`
	AuthLink           string `json:"authorizationLink"`
	PlanID             string `json:"planId"`
	CustomerID         string `json:"customerId"`
	FirstChargeDate    string `json:"firstChargeDate"`
	NextChargeDate     string `json:"nextChargeDate"`
}

// NewCashfreeGateway creates a new instance of Cashfree payment gateway
func NewCashfreeGateway() *CashfreeGateway {
	return &CashfreeGateway{
		apiBase: "https://api.cashfree.com/pg",
		isProd:  false, // Default to test mode
	}
}

// Initialize sets up the Cashfree gateway with credentials and configuration
func (g *CashfreeGateway) Initialize(config map[string]string) error {
	appID, ok := config["app_id"]
	if !ok {
		return errors.New("cashfree app_id is required")
	}

	secretKey, ok := config["secret_key"]
	if !ok {
		return errors.New("cashfree secret_key is required")
	}

	g.appID = appID
	g.secretKey = secretKey

	// Set webhook secret if provided
	if webhookSecret, ok := config["webhook_secret"]; ok {
		g.webhook.secret = webhookSecret
	}

	// Check if production mode is enabled
	if mode, ok := config["mode"]; ok && mode == "production" {
		g.isProd = true
		g.apiBase = "https://api.cashfree.com/pg"
	} else {
		g.isProd = false
		g.apiBase = "https://sandbox.cashfree.com/pg"
	}

	return nil
}

// Name returns the name of the gateway
func (g *CashfreeGateway) Name() string {
	return payment.GatewayCashfree
}

// SupportedPaymentMethods returns a list of payment methods supported by Cashfree
func (g *CashfreeGateway) SupportedPaymentMethods() []string {
	return []string{
		payment.PaymentMethodUPI,
		payment.PaymentMethodUPIAutopay,
		payment.PaymentMethodCard,
		payment.PaymentMethodNetBanking,
	}
}

// CreatePayment creates a new payment through Cashfree
func (g *CashfreeGateway) CreatePayment(ctx context.Context, req payment.PaymentRequest) (*payment.PaymentResponse, error) {
	// Create an order first
	orderID := fmt.Sprintf("order_%d", time.Now().UnixNano())

	// Build order request
	orderReq := map[string]interface{}{
		"order_id":       orderID,
		"order_amount":   req.Amount,
		"order_currency": req.Currency,
		"customer_details": map[string]string{
			"customer_id":    req.CustomerID,
			"customer_email": req.CustomerEmail,
			"customer_phone": req.CustomerPhone,
		},
		"order_meta": map[string]string{
			"return_url": req.ReturnURL + "?order_id={order_id}&order_token={order_token}",
			"notify_url": req.WebhookURL,
		},
		"order_note": req.Description,
	}

	// Add payment method specific details for UPI
	if req.PaymentMethod == payment.PaymentMethodUPI {
		// For UPI intent flow
		orderReq["order_meta"].(map[string]string)["payment_methods"] = "upi"
	}

	// Convert to JSON
	orderReqJSON, err := json.Marshal(orderReq)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		g.apiBase+"/orders",
		strings.NewReader(string(orderReqJSON)),
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-version", "2022-01-01")
	httpReq.Header.Set("x-client-id", g.appID)
	httpReq.Header.Set("x-client-secret", g.secretKey)

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return nil, fmt.Errorf("cashfree API error: %s", string(body))
		}
		return nil, fmt.Errorf("cashfree API error: %v", errorResp)
	}

	// Parse response
	var orderResp CashfreeOrderResponse
	if err := json.Unmarshal(body, &orderResp); err != nil {
		return nil, err
	}

	// Create payment response
	paymentResp := &payment.PaymentResponse{
		PaymentID:        orderID,
		GatewayPaymentID: orderID,
		Status:           payment.PaymentStatusPending,
		Amount:           req.Amount,
		Currency:         req.Currency,
		PaymentURL:       orderResp.PaymentLink,
		GatewayResponse: map[string]interface{}{
			"order_token": orderResp.OrderToken,
			"order_id":    orderResp.OrderID,
		},
		CreatedAt: time.Now(),
	}

	return paymentResp, nil
}

// GetPaymentStatus retrieves the current status of a payment
func (g *CashfreeGateway) GetPaymentStatus(ctx context.Context, paymentID string) (*payment.PaymentResponse, error) {
	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"GET",
		fmt.Sprintf("%s/orders/%s", g.apiBase, paymentID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.Header.Set("x-api-version", "2022-01-01")
	httpReq.Header.Set("x-client-id", g.appID)
	httpReq.Header.Set("x-client-secret", g.secretKey)

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return nil, fmt.Errorf("cashfree API error: %s", string(body))
		}
		return nil, fmt.Errorf("cashfree API error: %v", errorResp)
	}

	// Parse response
	var orderResp struct {
		OrderID     string                    `json:"orderId"`
		OrderAmount float64                   `json:"orderAmount"`
		OrderStatus string                    `json:"orderStatus"`
		Payments    []CashfreePaymentResponse `json:"payments"`
	}
	if err := json.Unmarshal(body, &orderResp); err != nil {
		return nil, err
	}

	// Map Cashfree status to our status
	status := payment.PaymentStatusPending
	var gatewayPaymentID string

	if len(orderResp.Payments) > 0 {
		// Get the latest payment
		latestPayment := orderResp.Payments[0]
		gatewayPaymentID = latestPayment.PaymentID

		switch latestPayment.PaymentStatus {
		case "SUCCESS":
			status = payment.PaymentStatusSucceeded
		case "FAILED":
			status = payment.PaymentStatusFailed
		}
	} else {
		// No payments yet
		switch orderResp.OrderStatus {
		case "PAID":
			status = payment.PaymentStatusSucceeded
		case "EXPIRED", "CANCELLED":
			status = payment.PaymentStatusFailed
		}
	}

	// Create response
	return &payment.PaymentResponse{
		PaymentID:        orderResp.OrderID,
		GatewayPaymentID: gatewayPaymentID,
		Status:           status,
		Amount:           orderResp.OrderAmount,
		Currency:         "INR", // Cashfree might not return currency in response
		GatewayResponse: map[string]interface{}{
			"order_status": orderResp.OrderStatus,
			"payments":     orderResp.Payments,
		},
		CreatedAt: time.Now(),
	}, nil
}

// CreateSubscription creates a new subscription through Cashfree
func (g *CashfreeGateway) CreateSubscription(ctx context.Context, req payment.PaymentRequest) (*payment.SubscriptionResponse, error) {
	// Check required fields
	if req.BillingCycle == nil {
		return nil, errors.New("billing cycle is required for subscription")
	}

	// First create a plan if needed
	planID, hasPlanID := req.Metadata["plan_id"].(string)
	if !hasPlanID {
		var err error
		planID, err = g.createPlan(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to create plan: %v", err)
		}
	}

	// Create customer if needed
	customerID := req.CustomerID
	if _, hasCustomerID := req.Metadata["cashfree_customer_id"]; !hasCustomerID {
		var err error
		customerID, err = g.createCustomer(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to create customer: %v", err)
		}
	}

	// Generate subscription ID
	subscriptionID := fmt.Sprintf("sub_%d", time.Now().UnixNano())

	// Build subscription request
	var firstChargeDate time.Time
	if req.BillingCycle.TrialPeriodDays > 0 {
		firstChargeDate = time.Now().AddDate(0, 0, req.BillingCycle.TrialPeriodDays)
	} else {
		firstChargeDate = time.Now()
	}

	subReq := map[string]interface{}{
		"subscription_id":   subscriptionID,
		"plan_id":           planID,
		"customer_id":       customerID,
		"first_charge_date": firstChargeDate.Format("2006-01-02"),
		"return_url":        req.ReturnURL,
	}

	// Add UPI Autopay specific configuration
	if req.PaymentMethod == payment.PaymentMethodUPIAutopay {
		subReq["payment_method"] = "upi_autopay"
	}

	// Convert to JSON
	subReqJSON, err := json.Marshal(subReq)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		g.apiBase+"/subscriptions",
		strings.NewReader(string(subReqJSON)),
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-version", "2022-01-01")
	httpReq.Header.Set("x-client-id", g.appID)
	httpReq.Header.Set("x-client-secret", g.secretKey)

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return nil, fmt.Errorf("cashfree API error: %s", string(body))
		}
		return nil, fmt.Errorf("cashfree API error: %v", errorResp)
	}

	// Parse response
	var subResp CashfreeSubscriptionResponse
	if err := json.Unmarshal(body, &subResp); err != nil {
		return nil, err
	}

	// Parse dates
	startAt, _ := time.Parse("2006-01-02", subResp.FirstChargeDate)
	nextBillingAt, _ := time.Parse("2006-01-02", subResp.NextChargeDate)

	// Create subscription response
	return &payment.SubscriptionResponse{
		SubscriptionID:        subscriptionID,
		GatewaySubscriptionID: subResp.SubscriptionID,
		Status:                subResp.SubscriptionStatus,
		CustomerID:            customerID,
		PlanID:                planID,
		StartAt:               startAt,
		NextBillingAt:         nextBillingAt,
		GatewayResponse: map[string]interface{}{
			"auth_link": subResp.AuthLink,
		},
	}, nil
}

// createPlan creates a new plan in Cashfree
func (g *CashfreeGateway) createPlan(ctx context.Context, req payment.PaymentRequest) (string, error) {
	// Generate plan ID
	planID := fmt.Sprintf("plan_%d", time.Now().UnixNano())

	// Map intervals to Cashfree format
	interval := "day"
	switch req.BillingCycle.Interval {
	case "day":
		interval = "day"
	case "week":
		interval = "week"
	case "month":
		interval = "month"
	case "year":
		interval = "year"
	}

	// Build plan request
	planReq := map[string]interface{}{
		"plan_id":       planID,
		"plan_name":     req.Description,
		"type":          "PERIODIC",
		"amount":        req.Amount,
		"currency":      req.Currency,
		"interval_type": interval,
		"intervals":     req.BillingCycle.IntervalCount,
		"max_cycles":    12, // Default to 12 billing cycles
		"description":   req.Description,
	}

	// Convert to JSON
	planReqJSON, err := json.Marshal(planReq)
	if err != nil {
		return "", err
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		g.apiBase+"/recurring-payments/plans",
		strings.NewReader(string(planReqJSON)),
	)
	if err != nil {
		return "", err
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-version", "2022-01-01")
	httpReq.Header.Set("x-client-id", g.appID)
	httpReq.Header.Set("x-client-secret", g.secretKey)

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return "", fmt.Errorf("cashfree API error: %s", string(body))
		}
		return "", fmt.Errorf("cashfree API error: %v", errorResp)
	}

	// Parse response
	var planResp struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		PlanID  string `json:"planId"`
	}
	if err := json.Unmarshal(body, &planResp); err != nil {
		return "", err
	}

	return planResp.PlanID, nil
}

// createCustomer creates a new customer in Cashfree
func (g *CashfreeGateway) createCustomer(ctx context.Context, req payment.PaymentRequest) (string, error) {
	// Generate customer ID
	customerID := fmt.Sprintf("cust_%d", time.Now().UnixNano())

	// Build customer request
	custReq := map[string]interface{}{
		"customer_id":   customerID,
		"email":         req.CustomerEmail,
		"phone":         req.CustomerPhone,
		"customer_name": req.CustomerID, // Using customer ID as name if not provided
	}

	// Convert to JSON
	custReqJSON, err := json.Marshal(custReq)
	if err != nil {
		return "", err
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		g.apiBase+"/customers",
		strings.NewReader(string(custReqJSON)),
	)
	if err != nil {
		return "", err
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-version", "2022-01-01")
	httpReq.Header.Set("x-client-id", g.appID)
	httpReq.Header.Set("x-client-secret", g.secretKey)

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return "", fmt.Errorf("cashfree API error: %s", string(body))
		}
		return "", fmt.Errorf("cashfree API error: %v", errorResp)
	}

	// Return the customer ID
	return customerID, nil
}

// CancelSubscription cancels an existing subscription
func (g *CashfreeGateway) CancelSubscription(ctx context.Context, subscriptionID string) (*payment.SubscriptionResponse, error) {
	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		fmt.Sprintf("%s/subscriptions/%s/cancel", g.apiBase, subscriptionID),
		nil, // Empty body for cancellation
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-version", "2022-01-01")
	httpReq.Header.Set("x-client-id", g.appID)
	httpReq.Header.Set("x-client-secret", g.secretKey)

	// Send request
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return nil, fmt.Errorf("cashfree API error: %s", string(body))
		}
		return nil, fmt.Errorf("cashfree API error: %v", errorResp)
	}

	// Parse response
	var subResp struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &subResp); err != nil {
		return nil, err
	}

	// Get subscription details to return
	getSubReq, err := http.NewRequestWithContext(
		ctx,
		"GET",
		fmt.Sprintf("%s/subscriptions/%s", g.apiBase, subscriptionID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	getSubReq.Header.Set("x-api-version", "2022-01-01")
	getSubReq.Header.Set("x-client-id", g.appID)
	getSubReq.Header.Set("x-client-secret", g.secretKey)

	// Send request
	getResp, err := httpClient.Do(getSubReq)
	if err != nil {
		return nil, err
	}
	defer getResp.Body.Close()

	// Read response
	getBody, err := io.ReadAll(getResp.Body)
	if err != nil {
		return nil, err
	}

	// Parse subscription details
	var subscriptionDetails CashfreeSubscriptionResponse
	if err := json.Unmarshal(getBody, &subscriptionDetails); err != nil {
		// Return a basic response if we can't get details
		return &payment.SubscriptionResponse{
			SubscriptionID:        subscriptionID,
			GatewaySubscriptionID: subscriptionID,
			Status:                "CANCELLED",
		}, nil
	}

	// Parse dates
	startAt, _ := time.Parse("2006-01-02", subscriptionDetails.FirstChargeDate)
	nextBillingAt, _ := time.Parse("2006-01-02", subscriptionDetails.NextChargeDate)

	// Return subscription response
	return &payment.SubscriptionResponse{
		SubscriptionID:        subscriptionID,
		GatewaySubscriptionID: subscriptionDetails.SubscriptionID,
		Status:                "CANCELLED", // Force cancelled status
		CustomerID:            subscriptionDetails.CustomerID,
		PlanID:                subscriptionDetails.PlanID,
		StartAt:               startAt,
		NextBillingAt:         nextBillingAt,
	}, nil
}

// ProcessWebhook processes incoming webhook events from Cashfree
func (g *CashfreeGateway) ProcessWebhook(ctx context.Context, payload []byte, headers map[string]string) (*payment.WebhookEvent, error) {
	// Verify webhook signature if secret is configured
	if g.webhook.secret != "" {
		signature, ok := headers["X-Cashfree-Signature"]
		if !ok {
			return nil, errors.New("missing Cashfree signature header")
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
	eventType, ok := webhookData["event"].(string)
	if !ok {
		return nil, errors.New("missing event type in webhook payload")
	}

	// Extract data based on event type
	var paymentID, subscriptionID string
	var amount float64
	var currency, status string

	// Extract order/payment data
	if strings.HasPrefix(eventType, "ORDER_") || strings.HasPrefix(eventType, "PAYMENT_") {
		data, ok := webhookData["data"].(map[string]interface{})
		if ok {
			// Extract order details
			order, ok := data["order"].(map[string]interface{})
			if ok {
				if id, ok := order["order_id"].(string); ok {
					paymentID = id
				}
				if amt, ok := order["order_amount"].(float64); ok {
					amount = amt
				}
				if curr, ok := order["order_currency"].(string); ok {
					currency = curr
				}
			}

			// Extract payment details
			payment, ok := data["payment"].(map[string]interface{})
			if ok && paymentID == "" {
				if id, ok := payment["payment_id"].(string); ok {
					paymentID = id
				}
			}

			// Map status
			if eventType == "ORDER_PAID" || eventType == "PAYMENT_SUCCESS" {
				status = "SUCCESS"
			} else if eventType == "ORDER_FAILED" || eventType == "PAYMENT_FAILED" {
				status = "FAILED"
			} else {
				status = "PENDING"
			}
		}
	} else if strings.HasPrefix(eventType, "SUBSCRIPTION_") {
		data, ok := webhookData["data"].(map[string]interface{})
		if ok {
			subscription, ok := data["subscription"].(map[string]interface{})
			if ok {
				if id, ok := subscription["subscription_id"].(string); ok {
					subscriptionID = id
				}
				if statusValue, ok := subscription["subscription_status"].(string); ok {
					status = statusValue
				}
			}
		}
	}

	// Create webhook event
	webhookEvent := &payment.WebhookEvent{
		GatewayName:    payment.GatewayCashfree,
		EventType:      eventType,
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
