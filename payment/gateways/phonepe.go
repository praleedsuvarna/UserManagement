package gateways

import (
	"UserManagement/payment"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PhonePeGateway implements the PaymentGateway interface for PhonePe
type PhonePeGateway struct {
	merchantID string
	saltKey    string
	saltIndex  string
	apiBase    string
	webhook    struct {
		secret string
	}
	isProd bool
}

// PhonePePaymentResponse represents a PhonePe payment response
type PhonePePaymentResponse struct {
	Success            bool               `json:"success"`
	Code               string             `json:"code"`
	Message            string             `json:"message"`
	Data               PhonePePaymentData `json:"data"`
	InstrumentResponse interface{}        `json:"instrumentResponse"`
}

// PhonePePaymentData represents the data in a PhonePe payment response
type PhonePePaymentData struct {
	MerchantID            string `json:"merchantId"`
	MerchantTransactionID string `json:"merchantTransactionId"`
	TransactionID         string `json:"transactionId"`
	Amount                int    `json:"amount"`
	State                 string `json:"state"`
	ResponseCode          string `json:"responseCode"`
	PaymentInstrument     string `json:"paymentInstrument"`
}

// PhonePeSubscriptionResponse represents a PhonePe subscription response
type PhonePeSubscriptionResponse struct {
	Success bool                    `json:"success"`
	Code    string                  `json:"code"`
	Message string                  `json:"message"`
	Data    PhonePeSubscriptionData `json:"data"`
}

// PhonePeSubscriptionData represents the data in a PhonePe subscription response
type PhonePeSubscriptionData struct {
	MerchantID             string `json:"merchantId"`
	MerchantSubscriptionID string `json:"merchantSubscriptionId"`
	SubscriptionID         string `json:"subscriptionId"`
	Status                 string `json:"status"`
	StartDate              string `json:"startDate"`
	NextPaymentDate        string `json:"nextPaymentDate"`
}

// NewPhonePeGateway creates a new instance of PhonePe payment gateway
func NewPhonePeGateway() *PhonePeGateway {
	return &PhonePeGateway{
		apiBase: "https://api-preprod.phonepe.com/apis/pg-sandbox",
		isProd:  false, // Default to test mode
	}
}

// Initialize sets up the PhonePe gateway with credentials and configuration
func (g *PhonePeGateway) Initialize(config map[string]string) error {
	merchantID, ok := config["merchant_id"]
	if !ok {
		return errors.New("PhonePe merchant_id is required")
	}

	saltKey, ok := config["salt_key"]
	if !ok {
		return errors.New("PhonePe salt_key is required")
	}

	g.merchantID = merchantID
	g.saltKey = saltKey

	// Set salt index with a default of "1"
	g.saltIndex = "1"
	if saltIndex, ok := config["salt_index"]; ok {
		g.saltIndex = saltIndex
	}

	// Set webhook secret if provided
	if webhookSecret, ok := config["webhook_secret"]; ok {
		g.webhook.secret = webhookSecret
	}

	// Check if production mode is enabled
	if mode, ok := config["mode"]; ok && mode == "production" {
		g.isProd = true
		g.apiBase = "https://api.phonepe.com/apis/hermes"
	} else {
		g.isProd = false
		g.apiBase = "https://api-preprod.phonepe.com/apis/pg-sandbox"
	}

	return nil
}

// Name returns the name of the gateway
func (g *PhonePeGateway) Name() string {
	return payment.GatewayPhonePe
}

// SupportedPaymentMethods returns a list of payment methods supported by PhonePe
func (g *PhonePeGateway) SupportedPaymentMethods() []string {
	return []string{
		payment.PaymentMethodUPI,
		payment.PaymentMethodUPIAutopay,
		payment.PaymentMethodCard,
		payment.PaymentMethodNetBanking,
	}
}

// generatePayload generates the encoded payload and checksum for PhonePe API
func (g *PhonePeGateway) generatePayload(payload interface{}) (string, string, error) {
	// Convert payload to JSON
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	// Base64 encode the payload
	encodedPayload := base64.StdEncoding.EncodeToString(payloadJSON)

	// Generate checksum
	data := encodedPayload + "/pg/v1/pay" + g.saltKey
	hash := sha256.Sum256([]byte(data))
	checksum := hex.EncodeToString(hash[:]) + "###" + g.saltIndex

	return encodedPayload, checksum, nil
}

// CreatePayment creates a new payment through PhonePe
func (g *PhonePeGateway) CreatePayment(ctx context.Context, req payment.PaymentRequest) (*payment.PaymentResponse, error) {
	// Generate transaction ID
	transactionID := fmt.Sprintf("txn_%d", time.Now().UnixNano())

	// Convert amount to paise
	amountInPaise := int(req.Amount * 100)

	// Prepare payment request
	phonepePayload := map[string]interface{}{
		"merchantId":            g.merchantID,
		"merchantTransactionId": transactionID,
		"merchantUserId":        req.CustomerID,
		"amount":                amountInPaise,
		"redirectUrl":           req.ReturnURL,
		"redirectMode":          "POST",
		"callbackUrl":           req.WebhookURL,
		"paymentInstrument":     map[string]interface{}{},
	}

	// Add payment method specific details
	if req.PaymentMethod == payment.PaymentMethodUPI {
		phonepePayload["paymentInstrument"] = map[string]interface{}{
			"type":      "UPI_INTENT",
			"targetApp": "PHONEPE",
		}
	} else {
		// Default to ALL payment options
		phonepePayload["paymentInstrument"] = map[string]interface{}{
			"type": "PAY_PAGE",
		}
	}

	// Generate encoded payload and checksum
	encodedPayload, checksum, err := g.generatePayload(phonepePayload)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	requestBody := map[string]string{
		"request": encodedPayload,
	}

	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		g.apiBase+"/pg/v1/pay",
		strings.NewReader(string(requestJSON)),
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-VERIFY", checksum)

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
			return nil, fmt.Errorf("PhonePe API error: %s", string(body))
		}
		return nil, fmt.Errorf("PhonePe API error: %v", errorResp)
	}

	// Parse response
	var phonepeResp struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Data    struct {
			MerchantID            string `json:"merchantId"`
			MerchantTransactionID string `json:"merchantTransactionId"`
			InstrumentResponse    struct {
				Type         string `json:"type"`
				RedirectInfo struct {
					URL string `json:"url"`
				} `json:"redirectInfo"`
			} `json:"instrumentResponse"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &phonepeResp); err != nil {
		return nil, err
	}

	// Check if the response is successful
	if !phonepeResp.Success {
		return nil, fmt.Errorf("PhonePe API error: %s", phonepeResp.Message)
	}

	// Get payment URL
	paymentURL := phonepeResp.Data.InstrumentResponse.RedirectInfo.URL

	// Create payment response
	paymentResp := &payment.PaymentResponse{
		PaymentID:        phonepeResp.Data.MerchantTransactionID,
		GatewayPaymentID: phonepeResp.Data.MerchantTransactionID,
		Status:           payment.PaymentStatusPending,
		Amount:           req.Amount,
		Currency:         req.Currency,
		PaymentURL:       paymentURL,
		GatewayResponse: map[string]interface{}{
			"merchant_id":    phonepeResp.Data.MerchantID,
			"transaction_id": phonepeResp.Data.MerchantTransactionID,
		},
		CreatedAt: time.Now(),
	}

	return paymentResp, nil
}

// GetPaymentStatus retrieves the current status of a payment
func (g *PhonePeGateway) GetPaymentStatus(ctx context.Context, paymentID string) (*payment.PaymentResponse, error) {
	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"GET",
		fmt.Sprintf("%s/pg/v1/status/%s/%s", g.apiBase, g.merchantID, paymentID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Generate checksum
	data := "/pg/v1/status/" + g.merchantID + "/" + paymentID + g.saltKey
	hash := sha256.Sum256([]byte(data))
	checksum := hex.EncodeToString(hash[:]) + "###" + g.saltIndex

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-VERIFY", checksum)
	httpReq.Header.Set("X-MERCHANT-ID", g.merchantID)

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
			return nil, fmt.Errorf("PhonePe API error: %s", string(body))
		}
		return nil, fmt.Errorf("PhonePe API error: %v", errorResp)
	}

	// Parse response
	var phonepeResp PhonePePaymentResponse
	if err := json.Unmarshal(body, &phonepeResp); err != nil {
		return nil, err
	}

	// Check if the response is successful
	if !phonepeResp.Success {
		return nil, fmt.Errorf("PhonePe API error: %s", phonepeResp.Message)
	}

	// Map PhonePe status to our status
	status := payment.PaymentStatusPending
	switch phonepeResp.Data.State {
	case "COMPLETED":
		status = payment.PaymentStatusSucceeded
	case "FAILED":
		status = payment.PaymentStatusFailed
	}

	// Create response
	return &payment.PaymentResponse{
		PaymentID:        phonepeResp.Data.MerchantTransactionID,
		GatewayPaymentID: phonepeResp.Data.TransactionID,
		Status:           status,
		Amount:           float64(phonepeResp.Data.Amount) / 100, // Convert from paise to rupees
		Currency:         "INR",                                  // PhonePe might not return currency in response
		GatewayResponse: map[string]interface{}{
			"state":              phonepeResp.Data.State,
			"response_code":      phonepeResp.Data.ResponseCode,
			"payment_instrument": phonepeResp.Data.PaymentInstrument,
		},
		CreatedAt: time.Now(),
	}, nil
}

// CreateSubscription creates a new subscription through PhonePe
func (g *PhonePeGateway) CreateSubscription(ctx context.Context, req payment.PaymentRequest) (*payment.SubscriptionResponse, error) {
	if req.BillingCycle == nil {
		return nil, errors.New("billing cycle is required for subscription")
	}

	// Generate subscription ID
	subscriptionID := fmt.Sprintf("sub_%d", time.Now().UnixNano())

	// Convert amount to paise
	amountInPaise := int(req.Amount * 100)

	// Map frequency based on billing cycle
	frequency := "MONTHLY"
	switch req.BillingCycle.Interval {
	case "day":
		frequency = "DAILY"
	case "week":
		frequency = "WEEKLY"
	case "month":
		frequency = "MONTHLY"
	case "year":
		frequency = "YEARLY"
	}

	// Calculate start date
	startDate := time.Now()
	if req.BillingCycle.TrialPeriodDays > 0 {
		startDate = startDate.AddDate(0, 0, req.BillingCycle.TrialPeriodDays)
	}

	// Prepare subscription request
	phonepePayload := map[string]interface{}{
		"merchantId":             g.merchantID,
		"merchantSubscriptionId": subscriptionID,
		"merchantUserId":         req.CustomerID,
		"amount":                 amountInPaise,
		"redirectUrl":            req.ReturnURL,
		"redirectMode":           "POST",
		"callbackUrl":            req.WebhookURL,
		"frequency":              frequency,
		"startDate":              startDate.Format("2006-01-02"),
		"maxAmount":              amountInPaise * 2, // Setting max amount as double the regular amount
	}

	// Add payment method specific details for UPI AutoPay
	if req.PaymentMethod == payment.PaymentMethodUPIAutopay {
		phonepePayload["paymentInstrument"] = map[string]interface{}{
			"type":      "UPI_MANDATE",
			"targetApp": "PHONEPE",
		}
	} else {
		return nil, errors.New("only UPI_AUTOPAY is supported for subscriptions")
	}

	// Generate encoded payload and checksum
	encodedPayload, checksum, err := g.generatePayload(phonepePayload)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	requestBody := map[string]string{
		"request": encodedPayload,
	}

	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		g.apiBase+"/pg/v1/subscription/create",
		strings.NewReader(string(requestJSON)),
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-VERIFY", checksum)

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

	// Parse response
	var phonepeResp struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Data    struct {
			MerchantID             string `json:"merchantId"`
			MerchantSubscriptionID string `json:"merchantSubscriptionId"`
			SubscriptionID         string `json:"subscriptionId"`
			AuthenticationURL      string `json:"authenticationUrl"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &phonepeResp); err != nil {
		return nil, err
	}

	// Check if the response is successful
	if !phonepeResp.Success {
		return nil, fmt.Errorf("PhonePe API error: %s", phonepeResp.Message)
	}

	// Create subscription response
	return &payment.SubscriptionResponse{
		SubscriptionID:        phonepeResp.Data.MerchantSubscriptionID,
		GatewaySubscriptionID: phonepeResp.Data.SubscriptionID,
		Status:                "CREATED",
		CustomerID:            req.CustomerID,
		PlanID:                "", // PhonePe doesn't use the concept of plans
		StartAt:               startDate,
		NextBillingAt:         calculateNextBillingDate(startDate, req.BillingCycle),
		GatewayResponse: map[string]interface{}{
			"auth_url": phonepeResp.Data.AuthenticationURL,
		},
	}, nil
}

// calculateNextBillingDate calculates the next billing date based on start date and billing cycle
func calculateNextBillingDate(startDate time.Time, billingCycle *payment.BillingCycle) time.Time {
	switch billingCycle.Interval {
	case "day":
		return startDate.AddDate(0, 0, billingCycle.IntervalCount)
	case "week":
		return startDate.AddDate(0, 0, 7*billingCycle.IntervalCount)
	case "month":
		return startDate.AddDate(0, billingCycle.IntervalCount, 0)
	case "year":
		return startDate.AddDate(billingCycle.IntervalCount, 0, 0)
	default:
		return startDate.AddDate(0, 1, 0) // Default to monthly
	}
}

// CancelSubscription cancels an existing subscription
func (g *PhonePeGateway) CancelSubscription(ctx context.Context, subscriptionID string) (*payment.SubscriptionResponse, error) {
	// Prepare cancel request
	cancelPayload := map[string]interface{}{
		"merchantId":             g.merchantID,
		"merchantSubscriptionId": subscriptionID,
	}

	// Generate encoded payload and checksum
	encodedPayload, checksum, err := g.generatePayload(cancelPayload)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	requestBody := map[string]string{
		"request": encodedPayload,
	}

	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		g.apiBase+"/pg/v1/subscription/cancel",
		strings.NewReader(string(requestJSON)),
	)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-VERIFY", checksum)

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

	// Parse response
	var phonepeResp struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &phonepeResp); err != nil {
		return nil, err
	}

	// Check if the response is successful
	if !phonepeResp.Success {
		return nil, fmt.Errorf("PhonePe API error: %s", phonepeResp.Message)
	}

	// Create subscription response
	return &payment.SubscriptionResponse{
		SubscriptionID:        subscriptionID,
		GatewaySubscriptionID: subscriptionID,
		Status:                "CANCELLED",
	}, nil
}

// ProcessWebhook processes incoming webhook events from PhonePe
func (g *PhonePeGateway) ProcessWebhook(ctx context.Context, payload []byte, headers map[string]string) (*payment.WebhookEvent, error) {
	// Verify webhook signature if secret is configured
	if g.webhook.secret != "" {
		signature, ok := headers["X-VERIFY"]
		if !ok {
			return nil, errors.New("missing PhonePe signature header")
		}

		// Extract salt index from signature
		parts := strings.Split(signature, "###")
		if len(parts) != 2 {
			return nil, errors.New("invalid signature format")
		}

		// Compute hash
		hash := sha256.Sum256(append(payload, []byte(g.webhook.secret)...))
		expectedSignature := hex.EncodeToString(hash[:]) + "###" + parts[1]

		if signature != expectedSignature {
			return nil, errors.New("invalid webhook signature")
		}
	}

	// Parse webhook payload
	var webhookData map[string]interface{}
	if err := json.Unmarshal(payload, &webhookData); err != nil {
		return nil, err
	}

	// Extract event type - PhonePe doesn't have explicit event types, so we infer from the payload
	eventType := "UNKNOWN"

	// Check if this is a transaction update
	if _, hasTransaction := webhookData["transactionId"]; hasTransaction {
		eventType = "TRANSACTION_UPDATE"
	}

	// Check if this is a subscription update
	if _, hasSubscription := webhookData["subscriptionId"]; hasSubscription {
		eventType = "SUBSCRIPTION_UPDATE"
	}

	// Extract data from payload
	var paymentID, subscriptionID string
	var amount float64
	var currency, status string

	// Extract transaction data
	if eventType == "TRANSACTION_UPDATE" {
		if id, ok := webhookData["merchantTransactionId"].(string); ok {
			paymentID = id
		}
		if amt, ok := webhookData["amount"].(float64); ok {
			amount = amt / 100 // Convert from paise to rupees
		}

		// PhonePe typically uses INR
		currency = "INR"

		// Map status
		if state, ok := webhookData["state"].(string); ok {
			status = state
		}
	}

	// Extract subscription data
	if eventType == "SUBSCRIPTION_UPDATE" {
		if id, ok := webhookData["merchantSubscriptionId"].(string); ok {
			subscriptionID = id
		}
		if statusValue, ok := webhookData["status"].(string); ok {
			status = statusValue
		}
	}

	// Create webhook event
	webhookEvent := &payment.WebhookEvent{
		GatewayName:    payment.GatewayPhonePe,
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
