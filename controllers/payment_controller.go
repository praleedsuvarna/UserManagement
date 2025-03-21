package controllers

import (
	localConfig "UserManagement/config"
	"UserManagement/models"
	"UserManagement/payment"
	"UserManagement/payment/gateways"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/praleedsuvarna/shared-libs/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// paymentService is a global instance of the PaymentService
var paymentService *payment.PaymentService

// InitializePaymentService initializes the payment service with configured gateways
func InitializePaymentService() {
	// Create payment service
	paymentService = payment.NewPaymentService()

	// Initialize Razorpay gateway
	razorpayGateway := gateways.NewRazorpayGateway()
	razorpayGateway.Initialize(localConfig.GetRazorpayConfig())

	// Initialize Cashfree gateway
	cashfreeGateway := gateways.NewCashfreeGateway()
	cashfreeGateway.Initialize(localConfig.GetCashfreeConfig())

	// Initialize PhonePe gateway
	phonePeGateway := gateways.NewPhonePeGateway()
	phonePeGateway.Initialize(localConfig.GetPhonePeConfig())

	// Register the gateway with the service
	paymentService.RegisterGateway(razorpayGateway)
	paymentService.RegisterGateway(cashfreeGateway)
	paymentService.RegisterGateway(phonePeGateway)

	// Set the default gateway
	paymentService.SetDefaultGateway(payment.GatewayCashfree)

	// TODO: Add more gateways as needed (PhonePe, Cashfree, etc.)
}

// CreatePayment initiates a new payment transaction
func CreatePayment(c *fiber.Ctx) error {
	// Get user information from context
	userID := c.Locals("user_id").(string)
	organizationID := c.Locals("organization_id").(string)

	// Parse request body
	var req struct {
		Amount        float64                `json:"amount"`
		Currency      string                 `json:"currency"`
		Description   string                 `json:"description"`
		PaymentType   string                 `json:"payment_type"`
		PaymentMethod string                 `json:"payment_method"`
		Gateway       string                 `json:"gateway"`
		ReturnURL     string                 `json:"return_url"`
		Metadata      map[string]interface{} `json:"metadata,omitempty"`
		BillingCycle  *payment.BillingCycle  `json:"billing_cycle,omitempty"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	// Validate request
	if req.Amount <= 0 {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Amount must be greater than zero",
		})
	}

	if req.Currency == "" {
		req.Currency = "INR" // Default to INR
	}

	if req.PaymentType == "" {
		req.PaymentType = payment.PaymentTypeOneTime // Default to one-time payment
	}

	if req.PaymentMethod == "" {
		req.PaymentMethod = payment.PaymentMethodUPI // Default to UPI
	}

	if req.ReturnURL == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Return URL is required",
		})
	}

	// Convert IDs to ObjectID
	userObjID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	var orgObjID primitive.ObjectID
	if organizationID != "" {
		orgObjID, err = primitive.ObjectIDFromHex(organizationID)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid organization ID",
			})
		}
	}

	// Get user information for customer details
	collection := config.GetCollection("oms_users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err = collection.FindOne(ctx, bson.M{"_id": userObjID}).Decode(&user)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user information",
		})
	}

	// Create payment request
	paymentReq := payment.PaymentRequest{
		Amount:        req.Amount,
		Currency:      req.Currency,
		Description:   req.Description,
		CustomerID:    userID,
		CustomerEmail: user.Email,
		// CustomerPhone: user.Phone, // Assuming User model has a Phone field
		PaymentType:   req.PaymentType,
		PaymentMethod: req.PaymentMethod,
		Gateway:       req.Gateway,
		BillingCycle:  req.BillingCycle,
		ReturnURL:     req.ReturnURL,
		WebhookURL:    fmt.Sprintf("%s/payments/webhook/%s", localConfig.GetPaymentWebhookBaseURL(), req.Gateway),
		Metadata:      req.Metadata,
	}

	// For subscriptions, use the CreateSubscription method
	if req.PaymentType == payment.PaymentTypeSubscription {
		if req.BillingCycle == nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error": "Billing cycle is required for subscription",
			})
		}

		subResp, err := paymentService.CreateSubscription(ctx, paymentReq)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error": fmt.Sprintf("Failed to create subscription: %v", err),
			})
		}

		// Create subscription record in database
		subscription := models.Subscription{
			ID:                    primitive.NewObjectID(),
			UserID:                userObjID,
			OrganizationID:        orgObjID,
			PlanID:                subResp.PlanID,
			Gateway:               req.Gateway,
			GatewaySubscriptionID: subResp.GatewaySubscriptionID,
			Status:                subResp.Status,
			Amount:                req.Amount,
			Currency:              req.Currency,
			PaymentMethod:         req.PaymentMethod,
			BillingCycle:          *req.BillingCycle,
			StartAt:               subResp.StartAt,
			NextBillingAt:         subResp.NextBillingAt,
			EndAt:                 subResp.EndAt,
			Metadata:              req.Metadata,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
		}

		// Save subscription to database
		_, err = config.GetCollection("oms_subscriptions").InsertOne(ctx, subscription)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to save subscription",
			})
		}

		// Return the subscription information with auth URL
		return c.Status(http.StatusCreated).JSON(fiber.Map{
			"success":      true,
			"subscription": subscription,
			"auth_url":     subResp.GatewayResponse["auth_url"],
		})
	}

	// For one-time payments
	paymentResp, err := paymentService.CreatePayment(ctx, paymentReq)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to create payment: %v", err),
		})
	}

	// Create payment record in database
	paymentRecord := models.Payment{
		ID:               primitive.NewObjectID(),
		UserID:           userObjID,
		OrganizationID:   orgObjID,
		Amount:           req.Amount,
		Currency:         req.Currency,
		Description:      req.Description,
		PaymentType:      req.PaymentType,
		PaymentMethod:    req.PaymentMethod,
		Gateway:          req.Gateway,
		GatewayPaymentID: paymentResp.GatewayPaymentID,
		Status:           paymentResp.Status,
		PaymentURL:       paymentResp.PaymentURL,
		Metadata:         req.Metadata,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Save payment to database
	_, err = config.GetCollection("oms_payments").InsertOne(ctx, paymentRecord)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to save payment",
		})
	}

	// Return the payment information with payment URL
	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"success": true,
		"payment": paymentRecord,
	})
}

// HandleWebhook processes webhook events from payment gateways
func HandleWebhook(c *fiber.Ctx) error {
	// Get gateway from parameters
	gateway := c.Params("gateway")

	// Read the request body
	payload := c.Request().Body()

	// Convert headers to map
	headers := make(map[string]string)
	c.Request().Header.VisitAll(func(key, value []byte) {
		headers[string(key)] = string(value)
	})

	// Process webhook
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	event, err := paymentService.ProcessWebhook(ctx, gateway, payload, headers)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to process webhook: %v", err),
		})
	}

	// Log the webhook event
	webhookLog := models.WebhookLog{
		ID:               primitive.NewObjectID(),
		Gateway:          event.GatewayName,
		EventType:        event.EventType,
		PaymentID:        event.PaymentID,
		SubscriptionID:   event.SubscriptionID,
		RawPayload:       event.RawPayload,
		ProcessedAt:      time.Now(),
		ProcessingStatus: "success",
	}

	_, err = config.GetCollection("oms_webhook_logs").InsertOne(ctx, webhookLog)
	if err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to log webhook: %v\n", err)
	}

	// Handle payment status update if this is a payment event
	if event.PaymentID != "" && strings.HasPrefix(event.EventType, "payment.") {
		updatePaymentStatus(ctx, event)
	}

	// In the HandleWebhook method after handling payment events:
	if event.SubscriptionID != "" && strings.HasPrefix(event.EventType, "subscription.") {
		updateSubscriptionFromWebhook(ctx, event)
	}

	// Acknowledge receipt of webhook
	return c.JSON(fiber.Map{
		"success": true,
	})
}

// updatePaymentStatus updates a payment's status based on webhook event
func updatePaymentStatus(ctx context.Context, event *payment.WebhookEvent) {
	// Find the payment using gateway payment ID
	var paymentRecord models.Payment
	err := config.GetCollection("oms_payments").FindOne(
		ctx,
		bson.M{"gateway_payment_id": event.PaymentID},
	).Decode(&paymentRecord)

	if err != nil {
		fmt.Printf("Payment not found for webhook: %s\n", event.PaymentID)
		return
	}

	// Map status appropriately
	status := payment.PaymentStatusPending
	switch event.Status {
	case "authorized", "captured":
		status = payment.PaymentStatusSucceeded
	case "failed":
		status = payment.PaymentStatusFailed
	}

	// Update payment status
	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"status":     status,
			"updated_at": now,
		},
	}

	// Add completed_at if payment succeeded
	if status == payment.PaymentStatusSucceeded {
		update["$set"].(bson.M)["completed_at"] = now
	}

	_, err = config.GetCollection("oms_payments").UpdateOne(
		ctx,
		bson.M{"_id": paymentRecord.ID},
		update,
	)

	if err != nil {
		fmt.Printf("Failed to update payment status: %v\n", err)
	} else {
		fmt.Printf("Updated payment %s status to %s\n", paymentRecord.ID.Hex(), status)
	}
}

// updateSubscriptionFromWebhook updates subscription status based on webhook event
func updateSubscriptionFromWebhook(ctx context.Context, event *payment.WebhookEvent) {
	// Find the subscription using gateway subscription ID
	var subscription models.Subscription
	err := config.GetCollection("oms_subscriptions").FindOne(
		ctx,
		bson.M{"gateway_subscription_id": event.SubscriptionID},
	).Decode(&subscription)

	if err != nil {
		fmt.Printf("Subscription not found for webhook: %s\n", event.SubscriptionID)
		return
	}

	// Update subscription status
	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"status":     event.Status,
			"updated_at": now,
		},
	}

	// Handle specific subscription events
	switch event.EventType {
	case "subscription.authenticated":
		// Update authentication status
		update["$set"].(bson.M)["auth_status"] = "authenticated"

	case "subscription.charged":
		// Create a new payment record for this charge
		if event.PaymentID != "" {
			payment := models.Payment{
				ID:               primitive.NewObjectID(),
				UserID:           subscription.UserID,
				OrganizationID:   subscription.OrganizationID,
				SubscriptionID:   subscription.ID,
				Amount:           event.Amount,
				Currency:         event.Currency,
				Description:      fmt.Sprintf("Subscription payment for %s", subscription.PlanID),
				PaymentType:      payment.PaymentTypeSubscription,
				PaymentMethod:    subscription.PaymentMethod,
				Gateway:          subscription.Gateway,
				GatewayPaymentID: event.PaymentID,
				Status:           payment.PaymentStatusSucceeded,
				CreatedAt:        now,
				UpdatedAt:        now,
				CompletedAt:      &now,
			}

			// Save payment record
			_, err := config.GetCollection("oms_payments").InsertOne(ctx, payment)
			if err != nil {
				fmt.Printf("Failed to save subscription payment: %v\n", err)
			}

			// Update next billing date
			if subscription.BillingCycle.Interval == "month" {
				update["$set"].(bson.M)["next_billing_at"] = now.AddDate(0, subscription.BillingCycle.IntervalCount, 0)
			} else if subscription.BillingCycle.Interval == "year" {
				update["$set"].(bson.M)["next_billing_at"] = now.AddDate(subscription.BillingCycle.IntervalCount, 0, 0)
			} else if subscription.BillingCycle.Interval == "week" {
				update["$set"].(bson.M)["next_billing_at"] = now.AddDate(0, 0, 7*subscription.BillingCycle.IntervalCount)
			} else if subscription.BillingCycle.Interval == "day" {
				update["$set"].(bson.M)["next_billing_at"] = now.AddDate(0, 0, subscription.BillingCycle.IntervalCount)
			}
		}

	case "subscription.cancelled":
		// Set cancelled at date
		update["$set"].(bson.M)["cancelled_at"] = now

	case "subscription.completed":
		// Set end date
		update["$set"].(bson.M)["end_at"] = now
	}

	_, err = config.GetCollection("oms_subscriptions").UpdateOne(
		ctx,
		bson.M{"_id": subscription.ID},
		update,
	)

	if err != nil {
		fmt.Printf("Failed to update subscription status: %v\n", err)
	} else {
		fmt.Printf("Updated subscription %s status to %s\n", subscription.ID.Hex(), event.Status)
	}
}

// GetUserSubscriptions returns all subscriptions for the current user
func GetUserSubscriptions(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	userObjID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	// Get subscriptions from database
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := config.GetCollection("oms_subscriptions").Find(
		ctx,
		bson.M{"user_id": userObjID},
	)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch subscriptions",
		})
	}

	var subscriptions []models.Subscription
	if err := cursor.All(ctx, &subscriptions); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to decode subscriptions",
		})
	}

	return c.JSON(fiber.Map{
		"subscriptions": subscriptions,
	})
}

// GetSubscription returns details of a specific subscription
func GetSubscription(c *fiber.Ctx) error {
	subscriptionID := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(subscriptionID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid subscription ID",
		})
	}

	// Get user ID for permission check
	userID := c.Locals("user_id").(string)
	userObjID, _ := primitive.ObjectIDFromHex(userID)

	// Get subscription from database
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var subscription models.Subscription
	err = config.GetCollection("oms_subscriptions").FindOne(
		ctx,
		bson.M{"_id": objID},
	).Decode(&subscription)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"error": "Subscription not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch subscription",
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
				"error": "You don't have permission to view this subscription",
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
			fmt.Printf("Failed to fetch subscription payments: %v\n", err)
		}
	}

	return c.JSON(fiber.Map{
		"subscription": subscription,
		"payments":     payments,
	})
}

// CancelSubscription cancels an active subscription
func CancelSubscription(c *fiber.Ctx) error {
	// Get subscription ID from parameters
	subscriptionID := c.Params("id")

	// Validate subscription ID
	objID, err := primitive.ObjectIDFromHex(subscriptionID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid subscription ID",
		})
	}

	// Get subscription from database
	collection := config.GetCollection("oms_subscriptions")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var subscription models.Subscription
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&subscription)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"error": "Subscription not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch subscription",
		})
	}

	// Validate user has permission to cancel this subscription
	userID := c.Locals("user_id").(string)
	userObjID, _ := primitive.ObjectIDFromHex(userID)

	if subscription.UserID != userObjID {
		// Check if user is admin of the organization
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
				"error": "You don't have permission to cancel this subscription",
			})
		}
	}

	// Cancel subscription with gateway
	subResp, err := paymentService.CancelSubscription(ctx, subscription.Gateway, subscription.GatewaySubscriptionID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to cancel subscription: %v", err),
		})
	}

	// Update subscription in database
	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"status":       subResp.Status,
			"updated_at":   now,
			"cancelled_at": now,
		},
	}

	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update subscription status",
		})
	}

	// Update local subscription object
	subscription.Status = subResp.Status
	subscription.UpdatedAt = now
	subscription.CancelledAt = &now

	return c.JSON(fiber.Map{
		"success":      true,
		"message":      "Subscription cancelled successfully",
		"subscription": subscription,
	})
}

// GetPaymentStatus retrieves the status of a payment
func GetPaymentStatus(c *fiber.Ctx) error {
	// Get payment ID from parameters
	paymentID := c.Params("id")

	// Validate payment ID
	objID, err := primitive.ObjectIDFromHex(paymentID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid payment ID",
		})
	}

	// Get user ID for permission check
	userID := c.Locals("user_id").(string)
	userObjID, _ := primitive.ObjectIDFromHex(userID)

	// Get payment from database
	collection := config.GetCollection("oms_payments")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var paymentRecord models.Payment
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&paymentRecord)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"error": "Payment not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch payment",
		})
	}

	// Check if user has permission to view this payment
	if paymentRecord.UserID != userObjID {
		// For admin users, check if they belong to the same organization
		hasAccess := false

		if !paymentRecord.OrganizationID.IsZero() {
			var user models.User
			err = config.GetCollection("oms_users").FindOne(ctx, bson.M{
				"_id":             userObjID,
				"organization_id": paymentRecord.OrganizationID,
				"role":            "admin",
			}).Decode(&user)

			if err == nil {
				hasAccess = true
			}
		}

		if !hasAccess {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{
				"error": "You don't have permission to view this payment",
			})
		}
	}

	// Check with payment gateway for latest status
	if paymentRecord.Status == payment.PaymentStatusPending {
		paymentResp, err := paymentService.GetPaymentStatus(ctx, paymentRecord.Gateway, paymentRecord.GatewayPaymentID)
		if err == nil && paymentResp.Status != paymentRecord.Status {
			// Update payment status if changed
			now := time.Now()
			update := bson.M{
				"$set": bson.M{
					"status":     paymentResp.Status,
					"updated_at": now,
				},
			}

			// If payment is completed, set completed_at
			if paymentResp.Status == payment.PaymentStatusSucceeded {
				update["$set"].(bson.M)["completed_at"] = now
			}

			_, updateErr := collection.UpdateOne(ctx, bson.M{"_id": objID}, update)
			if updateErr == nil {
				// Update local payment object
				paymentRecord.Status = paymentResp.Status
				paymentRecord.UpdatedAt = now
				if paymentResp.Status == payment.PaymentStatusSucceeded {
					paymentRecord.CompletedAt = &now
				}
			}
		}
	}

	return c.JSON(fiber.Map{
		"payment": paymentRecord,
	})
}

// Implement other payment controller methods as needed
