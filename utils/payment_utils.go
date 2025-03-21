package utils

import (
	"UserManagement/models"
	"UserManagement/payment"
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// PaymentStatuses represents all valid payment statuses
var PaymentStatuses = struct {
	Pending   string
	Succeeded string
	Failed    string
}{
	Pending:   payment.PaymentStatusPending,
	Succeeded: payment.PaymentStatusSucceeded,
	Failed:    payment.PaymentStatusFailed,
}

// PaymentMethods represents all valid payment methods
var PaymentMethods = struct {
	UPI        string
	UPIAutopay string
	Card       string
	NetBanking string
}{
	UPI:        payment.PaymentMethodUPI,
	UPIAutopay: payment.PaymentMethodUPIAutopay,
	Card:       payment.PaymentMethodCard,
	NetBanking: payment.PaymentMethodNetBanking,
}

// PaymentTypes represents all valid payment types
var PaymentTypes = struct {
	OneTime      string
	Subscription string
}{
	OneTime:      payment.PaymentTypeOneTime,
	Subscription: payment.PaymentTypeSubscription,
}

// GetPaymentGateways returns all available payment gateways
var PaymentGateways = struct {
	Razorpay string
	Cashfree string
	PhonePe  string
}{
	Razorpay: payment.GatewayRazorpay,
	Cashfree: payment.GatewayCashfree,
	PhonePe:  payment.GatewayPhonePe,
}

// FormatAmount formats the amount with currency symbol
func FormatAmount(amount float64, currency string) string {
	switch currency {
	case "INR":
		return fmt.Sprintf("₹%.2f", amount)
	case "USD":
		return fmt.Sprintf("$%.2f", amount)
	case "EUR":
		return fmt.Sprintf("€%.2f", amount)
	default:
		return fmt.Sprintf("%.2f %s", amount, currency)
	}
}

// GetUserPaymentHistory retrieves payment history for a user
func GetUserPaymentHistory(ctx context.Context, userID primitive.ObjectID, limit, offset int) ([]models.Payment, error) {
	// Set default values if not provided
	if limit <= 0 {
		limit = 10
	}
	if offset < 0 {
		offset = 0
	}

	// Create options for pagination and sorting
	opts := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetSkip(int64(offset)).
		SetLimit(int64(limit))

	// Get payments collection
	collection := GetDBCollection("oms_payments")

	// Perform query
	cursor, err := collection.Find(ctx, bson.M{"user_id": userID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	// Decode results
	var payments []models.Payment
	if err := cursor.All(ctx, &payments); err != nil {
		return nil, err
	}

	return payments, nil
}

// GetPaymentsByDateRange retrieves payments within a specific date range
func GetPaymentsByDateRange(ctx context.Context, startDate, endDate time.Time,
	status string, gateway string) ([]models.Payment, error) {
	// Create filter
	filter := bson.M{
		"created_at": bson.M{
			"$gte": startDate,
			"$lte": endDate,
		},
	}

	// Add optional filters
	if status != "" {
		filter["status"] = status
	}
	if gateway != "" {
		filter["gateway"] = gateway
	}

	// Set options for sorting
	opts := options.Find().SetSort(bson.M{"created_at": -1})

	// Get payments collection
	collection := GetDBCollection("oms_payments")

	// Perform query
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	// Decode results
	var payments []models.Payment
	if err := cursor.All(ctx, &payments); err != nil {
		return nil, err
	}

	return payments, nil
}

// GetPaymentAnalytics returns analytics data for payments
func GetPaymentAnalytics(ctx context.Context, startDate, endDate time.Time) (map[string]interface{}, error) {
	// Get payments collection
	collection := GetDBCollection("oms_payments")

	// Aggregate to get total revenue by status
	pipelineRevenue := mongo.Pipeline{
		{{"$match", bson.M{
			"created_at": bson.M{
				"$gte": startDate,
				"$lte": endDate,
			},
		}}},
		{{"$group", bson.M{
			"_id":   "$status",
			"total": bson.M{"$sum": "$amount"},
			"count": bson.M{"$sum": 1},
		}}},
	}

	// Execute pipeline
	revenueResults, err := collection.Aggregate(ctx, pipelineRevenue)
	if err != nil {
		return nil, err
	}
	defer revenueResults.Close(ctx)

	// Decode revenue results
	var revenueStats []struct {
		Status string  `bson:"_id"`
		Total  float64 `bson:"total"`
		Count  int     `bson:"count"`
	}
	if err := revenueResults.All(ctx, &revenueStats); err != nil {
		return nil, err
	}

	// Aggregate to get payments by method
	pipelineMethod := mongo.Pipeline{
		{{"$match", bson.M{
			"created_at": bson.M{
				"$gte": startDate,
				"$lte": endDate,
			},
			"status": payment.PaymentStatusSucceeded,
		}}},
		{{"$group", bson.M{
			"_id":   "$payment_method",
			"total": bson.M{"$sum": "$amount"},
			"count": bson.M{"$sum": 1},
		}}},
	}

	// Execute pipeline
	methodResults, err := collection.Aggregate(ctx, pipelineMethod)
	if err != nil {
		return nil, err
	}
	defer methodResults.Close(ctx)

	// Decode method results
	var methodStats []struct {
		Method string  `bson:"_id"`
		Total  float64 `bson:"total"`
		Count  int     `bson:"count"`
	}
	if err := methodResults.All(ctx, &methodStats); err != nil {
		return nil, err
	}

	// Aggregate to get payments by gateway
	pipelineGateway := mongo.Pipeline{
		{{"$match", bson.M{
			"created_at": bson.M{
				"$gte": startDate,
				"$lte": endDate,
			},
			"status": payment.PaymentStatusSucceeded,
		}}},
		{{"$group", bson.M{
			"_id":   "$gateway",
			"total": bson.M{"$sum": "$amount"},
			"count": bson.M{"$sum": 1},
		}}},
	}

	// Execute pipeline
	gatewayResults, err := collection.Aggregate(ctx, pipelineGateway)
	if err != nil {
		return nil, err
	}
	defer gatewayResults.Close(ctx)

	// Decode gateway results
	var gatewayStats []struct {
		Gateway string  `bson:"_id"`
		Total   float64 `bson:"total"`
		Count   int     `bson:"count"`
	}
	if err := gatewayResults.All(ctx, &gatewayStats); err != nil {
		return nil, err
	}

	// Calculate total successful revenue
	var totalSuccessful float64
	var totalSuccessfulCount int
	for _, stat := range revenueStats {
		if stat.Status == payment.PaymentStatusSucceeded {
			totalSuccessful = stat.Total
			totalSuccessfulCount = stat.Count
			break
		}
	}

	// Prepare analytics response
	analytics := map[string]interface{}{
		"revenue": map[string]interface{}{
			"total_successful":       totalSuccessful,
			"total_successful_count": totalSuccessfulCount,
			"by_status":              revenueStats,
		},
		"method_distribution":  methodStats,
		"gateway_distribution": gatewayStats,
		"time_range": map[string]interface{}{
			"start_date":    startDate,
			"end_date":      endDate,
			"duration_days": int(endDate.Sub(startDate).Hours() / 24),
		},
	}

	return analytics, nil
}

// CalculateSubscriptionEndDate calculates the end date for a subscription based on billing cycle
func CalculateSubscriptionEndDate(startDate time.Time, cycle *payment.BillingCycle, cycles int) time.Time {
	if cycles <= 0 {
		cycles = 12 // Default to 12 billing cycles
	}

	switch cycle.Interval {
	case "day":
		return startDate.AddDate(0, 0, cycle.IntervalCount*cycles)
	case "week":
		return startDate.AddDate(0, 0, 7*cycle.IntervalCount*cycles)
	case "month":
		return startDate.AddDate(0, cycle.IntervalCount*cycles, 0)
	case "year":
		return startDate.AddDate(cycle.IntervalCount*cycles, 0, 0)
	default:
		// Default to monthly
		return startDate.AddDate(0, cycles, 0)
	}
}

// GetDBCollection is a helper to get a MongoDB collection
// You may need to adjust this to match your actual DB access pattern
func GetDBCollection(collectionName string) *mongo.Collection {
	// This depends on your existing DB connection setup
	// Example implementation - replace with your actual DB access method
	return GetCollection(collectionName)
}

// GetCollection is a placeholder for your actual database connection method
// Replace this with a call to your actual config.GetCollection method
func GetCollection(collectionName string) *mongo.Collection {
	// This is just a placeholder - use your actual DB connection
	// return config.GetCollection(collectionName)

	// For now, we'll return nil since this is just a utility file
	// and you'll replace this with your actual implementation
	return nil
}

// GetSubscriptionStatus returns a user-friendly subscription status
func GetSubscriptionStatus(status string) string {
	switch status {
	case "ACTIVE":
		return "Active"
	case "CANCELLED":
		return "Cancelled"
	case "COMPLETED":
		return "Completed"
	case "PENDING":
		return "Pending"
	case "AUTHENTICATED":
		return "Authenticated"
	case "CREATED":
		return "Created"
	default:
		return status
	}
}

// GeneratePaymentReceipt generates a receipt string for a payment
func GeneratePaymentReceipt(payment models.Payment, user models.User) string {
	receiptTime := payment.CompletedAt
	if receiptTime == nil {
		now := time.Now()
		receiptTime = &now
	}

	receipt := fmt.Sprintf("RECEIPT\n")
	receipt += fmt.Sprintf("Date: %s\n", receiptTime.Format("2006-01-02 15:04:05"))
	receipt += fmt.Sprintf("Receipt #: %s\n", payment.ID.Hex())
	receipt += fmt.Sprintf("-----------------------------------\n")
	receipt += fmt.Sprintf("Customer: %s\n", user.Username)
	receipt += fmt.Sprintf("Email: %s\n", user.Email)
	receipt += fmt.Sprintf("-----------------------------------\n")
	receipt += fmt.Sprintf("Description: %s\n", payment.Description)
	receipt += fmt.Sprintf("Amount: %s\n", FormatAmount(payment.Amount, payment.Currency))
	receipt += fmt.Sprintf("Payment Method: %s\n", GetPaymentMethodDisplayName(payment.PaymentMethod))
	receipt += fmt.Sprintf("Status: %s\n", GetPaymentStatus(payment.Status))
	receipt += fmt.Sprintf("-----------------------------------\n")
	receipt += fmt.Sprintf("Thank you for your payment!\n")

	return receipt
}

// GetPaymentMethodDisplayName returns a user-friendly payment method name
func GetPaymentMethodDisplayName(method string) string {
	switch method {
	case payment.PaymentMethodUPI:
		return "UPI"
	case payment.PaymentMethodUPIAutopay:
		return "UPI AutoPay"
	case payment.PaymentMethodCard:
		return "Card"
	case payment.PaymentMethodNetBanking:
		return "Net Banking"
	default:
		return method
	}
}

// GetPaymentStatus returns a user-friendly payment status
func GetPaymentStatus(status string) string {
	switch status {
	case payment.PaymentStatusPending:
		return "Pending"
	case payment.PaymentStatusSucceeded:
		return "Succeeded"
	case payment.PaymentStatusFailed:
		return "Failed"
	default:
		return status
	}
}
