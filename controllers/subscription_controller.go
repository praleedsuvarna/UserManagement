package controllers

import (
	localConfig "UserManagement/config"
	"UserManagement/models"
	"UserManagement/payment"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// CreateSubscriptionPlan creates a new subscription plan
func CreateSubscriptionPlan(c *fiber.Ctx) error {
	// Only admins can create subscription plans
	userRole := c.Locals("user_role").(string)
	if userRole != "admin" {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"error": "only administrators can create subscription plans",
		})
	}

	// Parse request body
	var plan models.SubscriptionPlan
	if err := c.BodyParser(&plan); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request format",
		})
	}

	// Validate request
	if plan.Name == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "plan name is required",
		})
	}

	if plan.Amount <= 0 {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "plan amount must be greater than zero",
		})
	}

	if plan.Currency == "" {
		plan.Currency = "INR" // Default to INR
	}

	if plan.BillingCycle.Interval == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "billing cycle interval is required",
		})
	}

	if plan.BillingCycle.IntervalCount <= 0 {
		plan.BillingCycle.IntervalCount = 1 // Default to 1
	}

	// Generate ID if not provided
	if plan.ID.IsZero() {
		plan.ID = primitive.NewObjectID()
	}

	// Set created and updated timestamps
	now := time.Now()
	plan.CreatedAt = now
	plan.UpdatedAt = now

	// Insert plan into database
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := config.GetCollection("oms_subscription_plans").InsertOne(ctx, plan)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to create subscription plan",
		})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"success": true,
		"message": "subscription plan created successfully",
		"plan":    plan,
	})
}

// GetSubscriptionPlans retrieves all subscription plans
func GetSubscriptionPlans(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get parameters for filtering and pagination
	active := c.Query("active", "true") == "true"
	limit := c.QueryInt("limit", 50)
	offset := c.QueryInt("offset", 0)

	// Create filter
	filter := bson.M{}
	if active {
		filter["is_active"] = true
	}

	// Set options for pagination and sorting
	opts := options.Find().
		SetSort(bson.M{"name": 1}).
		SetSkip(int64(offset)).
		SetLimit(int64(limit))

	// Execute query
	cursor, err := config.GetCollection("oms_subscription_plans").Find(ctx, filter, opts)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch subscription plans",
		})
	}
	defer cursor.Close(ctx)

	// Decode results
	var plans []models.SubscriptionPlan
	if err := cursor.All(ctx, &plans); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to decode subscription plans",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"plans":   plans,
		"count":   len(plans),
	})
}

// GetSubscriptionPlan retrieves a specific subscription plan
func GetSubscriptionPlan(c *fiber.Ctx) error {
	planID := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(planID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid plan ID",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get plan from database
	var plan models.SubscriptionPlan
	err = config.GetCollection("oms_subscription_plans").FindOne(ctx, bson.M{"_id": objID}).Decode(&plan)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"error": "subscription plan not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch subscription plan",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"plan":    plan,
	})
}

// UpdateSubscriptionPlan updates a subscription plan
func UpdateSubscriptionPlan(c *fiber.Ctx) error {
	// Only admins can update subscription plans
	userRole := c.Locals("user_role").(string)
	if userRole != "admin" {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"error": "only administrators can update subscription plans",
		})
	}

	planID := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(planID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid plan ID",
		})
	}

	// Parse request body
	var updateData struct {
		Name         string               `json:"name"`
		Description  string               `json:"description"`
		Amount       float64              `json:"amount"`
		Currency     string               `json:"currency"`
		BillingCycle payment.BillingCycle `json:"billing_cycle"`
		Features     []string             `json:"features"`
		IsActive     *bool                `json:"is_active"`
	}

	if err := c.BodyParser(&updateData); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request format",
		})
	}

	// Build update document
	update := bson.M{
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	// Add fields to update if provided
	if updateData.Name != "" {
		update["$set"].(bson.M)["name"] = updateData.Name
	}
	if updateData.Description != "" {
		update["$set"].(bson.M)["description"] = updateData.Description
	}
	if updateData.Amount > 0 {
		update["$set"].(bson.M)["amount"] = updateData.Amount
	}
	if updateData.Currency != "" {
		update["$set"].(bson.M)["currency"] = updateData.Currency
	}
	if updateData.BillingCycle.Interval != "" {
		update["$set"].(bson.M)["billing_cycle"] = updateData.BillingCycle
	}
	if updateData.Features != nil {
		update["$set"].(bson.M)["features"] = updateData.Features
	}
	if updateData.IsActive != nil {
		update["$set"].(bson.M)["is_active"] = *updateData.IsActive
	}

	// Execute update
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := config.GetCollection("oms_subscription_plans").UpdateOne(
		ctx,
		bson.M{"_id": objID},
		update,
	)

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to update subscription plan",
		})
	}

	if result.MatchedCount == 0 {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "subscription plan not found",
		})
	}

	// Fetch updated plan
	var updatedPlan models.SubscriptionPlan
	err = config.GetCollection("oms_subscription_plans").FindOne(ctx, bson.M{"_id": objID}).Decode(&updatedPlan)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch updated plan",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "subscription plan updated successfully",
		"plan":    updatedPlan,
	})
}

// SubscribeUserToPlan subscribes a user to a plan
func SubscribeUserToPlan(c *fiber.Ctx) error {
	// Get user information from context
	userID := c.Locals("user_id").(string)
	userObjID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid user ID",
		})
	}

	// Parse request body
	var req struct {
		PlanID        string `json:"plan_id"`
		PaymentMethod string `json:"payment_method"`
		Gateway       string `json:"gateway"`
		ReturnURL     string `json:"return_url"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request format",
		})
	}

	// Validate request
	if req.PlanID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "plan ID is required",
		})
	}

	if req.PaymentMethod == "" {
		req.PaymentMethod = payment.PaymentMethodUPIAutopay // Default to UPI AutoPay
	}

	if req.Gateway == "" {
		req.Gateway = payment.GatewayRazorpay // Default to Razorpay
	}

	if req.ReturnURL == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "return URL is required",
		})
	}

	// Convert plan ID to ObjectID
	planObjID, err := primitive.ObjectIDFromHex(req.PlanID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid plan ID",
		})
	}

	// Get plan details
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var plan models.SubscriptionPlan
	err = config.GetCollection("oms_subscription_plans").FindOne(ctx, bson.M{"_id": planObjID}).Decode(&plan)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"error": "subscription plan not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch subscription plan",
		})
	}

	// Get user details
	var user models.User
	err = config.GetCollection("oms_users").FindOne(ctx, bson.M{"_id": userObjID}).Decode(&user)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch user information",
		})
	}

	// Create payment request
	paymentReq := payment.PaymentRequest{
		Amount:        plan.Amount,
		Currency:      plan.Currency,
		Description:   fmt.Sprintf("Subscription to %s", plan.Name),
		CustomerID:    userID,
		CustomerEmail: user.Email,
		// CustomerPhone: user.Phone, // Assuming User model has a Phone field
		PaymentType:   payment.PaymentTypeSubscription,
		PaymentMethod: req.PaymentMethod,
		Gateway:       req.Gateway,
		BillingCycle:  &plan.BillingCycle,
		ReturnURL:     req.ReturnURL,
		WebhookURL:    fmt.Sprintf("%s/api/payments/webhook/%s", localConfig.GetPaymentWebhookBaseURL(), req.Gateway),
		Metadata: map[string]interface{}{
			"plan_id":           plan.ID.Hex(),
			"plan_name":         plan.Name,
			"subscription_type": "plan",
		},
	}

	// Create subscription
	subResp, err := paymentService.CreateSubscription(ctx, paymentReq)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("failed to create subscription: %v", err),
		})
	}

	// Create subscription record in database
	subscription := models.Subscription{
		ID:                    primitive.NewObjectID(),
		UserID:                userObjID,
		OrganizationID:        user.OrganizationID,
		PlanID:                plan.ID.Hex(),
		Gateway:               req.Gateway,
		GatewaySubscriptionID: subResp.GatewaySubscriptionID,
		Status:                subResp.Status,
		Amount:                plan.Amount,
		Currency:              plan.Currency,
		PaymentMethod:         req.PaymentMethod,
		BillingCycle:          plan.BillingCycle,
		StartAt:               subResp.StartAt,
		NextBillingAt:         subResp.NextBillingAt,
		EndAt:                 subResp.EndAt,
		Metadata: map[string]interface{}{
			"plan_name": plan.Name,
			"features":  plan.Features,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save subscription to database
	_, err = config.GetCollection("oms_subscriptions").InsertOne(ctx, subscription)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to save subscription",
		})
	}

	// Return the subscription information with auth URL
	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"success":      true,
		"message":      "subscription created successfully",
		"subscription": subscription,
		"auth_url":     subResp.GatewayResponse["auth_url"],
	})
}

// GetUserActiveSubscriptions retrieves all active subscriptions for the current user
func GetUserActiveSubscriptions(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	userObjID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid user ID",
		})
	}

	// Get active subscriptions
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Define active statuses
	activeStatuses := []string{"ACTIVE", "AUTHENTICATED", "CREATED"}

	cursor, err := config.GetCollection("oms_subscriptions").Find(
		ctx,
		bson.M{
			"user_id": userObjID,
			"status":  bson.M{"$in": activeStatuses},
		},
		options.Find().SetSort(bson.M{"created_at": -1}),
	)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch subscriptions",
		})
	}
	defer cursor.Close(ctx)

	// Decode results
	var subscriptions []models.Subscription
	if err := cursor.All(ctx, &subscriptions); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to decode subscriptions",
		})
	}

	// Enhance with plan information
	var enhancedSubscriptions []map[string]interface{}
	for _, sub := range subscriptions {
		// Fetch plan information if available
		var planInfo map[string]interface{}
		if sub.PlanID != "" {
			planObjID, err := primitive.ObjectIDFromHex(sub.PlanID)
			if err == nil {
				var plan models.SubscriptionPlan
				err = config.GetCollection("oms_subscription_plans").FindOne(ctx, bson.M{"_id": planObjID}).Decode(&plan)
				if err == nil {
					planInfo = map[string]interface{}{
						"id":          plan.ID.Hex(),
						"name":        plan.Name,
						"description": plan.Description,
						"features":    plan.Features,
					}
				}
			}
		}

		// Build enhanced subscription
		enhancedSub := map[string]interface{}{
			"id":             sub.ID.Hex(),
			"status":         sub.Status,
			"amount":         sub.Amount,
			"currency":       sub.Currency,
			"start_date":     sub.StartAt,
			"next_billing":   sub.NextBillingAt,
			"payment_method": sub.PaymentMethod,
			"created_at":     sub.CreatedAt,
		}

		if planInfo != nil {
			enhancedSub["plan"] = planInfo
		} else if sub.Metadata != nil {
			// Use metadata if available
			enhancedSub["plan"] = map[string]interface{}{
				"name":     sub.Metadata["plan_name"],
				"features": sub.Metadata["features"],
			}
		}

		enhancedSubscriptions = append(enhancedSubscriptions, enhancedSub)
	}

	return c.JSON(fiber.Map{
		"success":       true,
		"subscriptions": enhancedSubscriptions,
		"count":         len(enhancedSubscriptions),
	})
}

// GetSubscriptionInvoices gets invoices for a specific subscription
func GetSubscriptionInvoices(c *fiber.Ctx) error {
	// Get subscription ID from parameters
	subscriptionID := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(subscriptionID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid subscription ID",
		})
	}

	// Get user ID for permission check
	userID := c.Locals("user_id").(string)
	userObjID, _ := primitive.ObjectIDFromHex(userID)

	// Get subscription from database
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var subscription models.Subscription
	err = config.GetCollection("oms_subscriptions").FindOne(ctx, bson.M{"_id": objID}).Decode(&subscription)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"error": "subscription not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch subscription",
		})
	}

	// Check if user has permission to view this subscription
	if subscription.UserID != userObjID {
		// For admin users, check if they belong to the same organization
		hasAccess := false

		if !subscription.OrganizationID.IsZero() {
			var user models.User
			err = config.GetCollection("oms_users").FindOne(ctx, bson.M{
				"_id":             userObjID,
				"organization_id": subscription.OrganizationID,
				"role":            "admin",
			}).Decode(&user)

			if err == nil {
				hasAccess = true
			}
		}

		if !hasAccess {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{
				"error": "you don't have permission to view this subscription",
			})
		}
	}

	// Get payment history for this subscription
	cursor, err := config.GetCollection("oms_payments").Find(
		ctx,
		bson.M{"subscription_id": subscription.ID},
		options.Find().SetSort(bson.M{"created_at": -1}),
	)

	var payments []models.Payment
	if err == nil {
		if err := cursor.All(ctx, &payments); err != nil {
			// Log error but continue
			fmt.Printf("failed to fetch subscription payments: %v\n", err)
		}
	}

	// Transform payments to invoices
	var invoices []map[string]interface{}
	for _, payment := range payments {
		invoice := map[string]interface{}{
			"invoice_id":     payment.ID.Hex(),
			"amount":         payment.Amount,
			"currency":       payment.Currency,
			"status":         payment.Status,
			"payment_date":   payment.CreatedAt,
			"completed_at":   payment.CompletedAt,
			"payment_method": payment.PaymentMethod,
		}

		invoices = append(invoices, invoice)
	}

	return c.JSON(fiber.Map{
		"success":      true,
		"subscription": subscription,
		"invoices":     invoices,
	})
}

// GetSubscriptionAnalytics generates analytics for subscriptions
func GetSubscriptionAnalytics(c *fiber.Ctx) error {
	// Only admins can view analytics
	userRole := c.Locals("user_role").(string)
	if userRole != "admin" {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"error": "only administrators can view subscription analytics",
		})
	}

	// Get time range
	var startDate, endDate time.Time
	period := c.Query("period", "month")

	switch period {
	case "week":
		startDate = time.Now().AddDate(0, 0, -7)
	case "month":
		startDate = time.Now().AddDate(0, -1, 0)
	case "quarter":
		startDate = time.Now().AddDate(0, -3, 0)
	case "year":
		startDate = time.Now().AddDate(-1, 0, 0)
	default:
		startDate = time.Now().AddDate(0, -1, 0) // Default to 1 month
	}

	endDate = time.Now()

	// Parse custom date range if provided
	customStart := c.Query("start_date", "")
	customEnd := c.Query("end_date", "")

	if customStart != "" {
		if customStartDate, err := time.Parse("2006-01-02", customStart); err == nil {
			startDate = customStartDate
		}
	}

	if customEnd != "" {
		if customEndDate, err := time.Parse("2006-01-02", customEnd); err == nil {
			endDate = customEndDate
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Aggregate total active subscriptions
	activeSubscriptionPipeline := mongo.Pipeline{
		{{"$match", bson.M{
			"status": bson.M{"$in": []string{"ACTIVE", "AUTHENTICATED"}},
		}}},
		{{"$group", bson.M{
			"_id":     nil,
			"count":   bson.M{"$sum": 1},
			"revenue": bson.M{"$sum": "$amount"},
		}}},
	}

	activeSubscriptionCursor, err := config.GetCollection("oms_subscriptions").Aggregate(ctx, activeSubscriptionPipeline)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to generate subscription analytics",
		})
	}
	defer activeSubscriptionCursor.Close(ctx)

	// Extract active subscription stats
	var activeSubscriptionStats []struct {
		Count   int     `bson:"count"`
		Revenue float64 `bson:"revenue"`
	}
	if err := activeSubscriptionCursor.All(ctx, &activeSubscriptionStats); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to decode subscription analytics",
		})
	}

	activeCount := 0
	activeRevenue := 0.0
	if len(activeSubscriptionStats) > 0 {
		activeCount = activeSubscriptionStats[0].Count
		activeRevenue = activeSubscriptionStats[0].Revenue
	}

	// Aggregate subscriptions by plan
	planPipeline := mongo.Pipeline{
		{{"$match", bson.M{
			"status": bson.M{"$in": []string{"ACTIVE", "AUTHENTICATED"}},
		}}},
		{{"$group", bson.M{
			"_id":       "$plan_id",
			"count":     bson.M{"$sum": 1},
			"plan_name": bson.M{"$first": "$metadata.plan_name"},
			"revenue":   bson.M{"$sum": "$amount"},
		}}},
		{{"$sort", bson.M{"count": -1}}},
	}

	planCursor, err := config.GetCollection("oms_subscriptions").Aggregate(ctx, planPipeline)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to generate plan analytics",
		})
	}
	defer planCursor.Close(ctx)

	// Extract plan stats
	var planStats []map[string]interface{}
	if err := planCursor.All(ctx, &planStats); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to decode plan analytics",
		})
	}

	// Get new subscriptions in time range
	newSubPipeline := mongo.Pipeline{
		{{"$match", bson.M{
			"created_at": bson.M{
				"$gte": startDate,
				"$lte": endDate,
			},
		}}},
		{{"$group", bson.M{
			"_id":   nil,
			"count": bson.M{"$sum": 1},
		}}},
	}

	newSubCursor, err := config.GetCollection("oms_subscriptions").Aggregate(ctx, newSubPipeline)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to generate new subscription analytics",
		})
	}
	defer newSubCursor.Close(ctx)

	// Extract new subscription stats
	var newSubStats []struct {
		Count int `bson:"count"`
	}
	if err := newSubCursor.All(ctx, &newSubStats); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to decode new subscription analytics",
		})
	}

	newSubscriptions := 0
	if len(newSubStats) > 0 {
		newSubscriptions = newSubStats[0].Count
	}

	// Get cancelled subscriptions in time range
	cancelledPipeline := mongo.Pipeline{
		{{"$match", bson.M{
			"cancelled_at": bson.M{
				"$gte": startDate,
				"$lte": endDate,
			},
		}}},
		{{"$group", bson.M{
			"_id":   nil,
			"count": bson.M{"$sum": 1},
		}}},
	}

	cancelledCursor, err := config.GetCollection("oms_subscriptions").Aggregate(ctx, cancelledPipeline)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to generate cancelled subscription analytics",
		})
	}
	defer cancelledCursor.Close(ctx)

	// Extract cancelled subscription stats
	var cancelledStats []struct {
		Count int `bson:"count"`
	}
	if err := cancelledCursor.All(ctx, &cancelledStats); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to decode cancelled subscription analytics",
		})
	}

	cancelledSubscriptions := 0
	if len(cancelledStats) > 0 {
		cancelledSubscriptions = cancelledStats[0].Count
	}

	// Calculate churn rate
	churnRate := 0.0
	if activeCount > 0 {
		churnRate = float64(cancelledSubscriptions) / float64(activeCount) * 100
	}

	// Build analytics response
	analytics := map[string]interface{}{
		"active_subscriptions":      activeCount,
		"monthly_recurring_revenue": activeRevenue,
		"new_subscriptions":         newSubscriptions,
		"cancelled_subscriptions":   cancelledSubscriptions,
		"churn_rate":                churnRate,
		"by_plan":                   planStats,
		"time_range": map[string]interface{}{
			"start_date": startDate,
			"end_date":   endDate,
			"period":     period,
		},
	}

	return c.JSON(fiber.Map{
		"success":   true,
		"analytics": analytics,
	})
}
