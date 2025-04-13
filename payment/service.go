package payment

import (
	"context"
	"errors"
)

// PaymentService is the main service for handling payments across different gateways
type PaymentService struct {
	gateways       map[string]PaymentGateway
	defaultGateway string
}

// NewPaymentService creates a new payment service
func NewPaymentService() *PaymentService {
	return &PaymentService{
		gateways: make(map[string]PaymentGateway),
	}
}

// RegisterGateway adds a payment gateway to the service
func (s *PaymentService) RegisterGateway(gateway PaymentGateway) {
	s.gateways[gateway.Name()] = gateway
}

// SetDefaultGateway sets the default gateway to use when none is specified
func (s *PaymentService) SetDefaultGateway(name string) error {
	if _, exists := s.gateways[name]; !exists {
		return errors.New("gateway not registered")
	}
	s.defaultGateway = name
	return nil
}

// getGateway returns the requested gateway or the default one
func (s *PaymentService) getGateway(name string) (PaymentGateway, error) {
	if name == "" {
		name = s.defaultGateway
	}

	gateway, exists := s.gateways[name]
	if !exists {
		return nil, errors.New("payment gateway not found")
	}

	return gateway, nil
}

// CreatePayment creates a new payment using the specified gateway
func (s *PaymentService) CreatePayment(ctx context.Context, req PaymentRequest) (*PaymentResponse, error) {
	gateway, err := s.getGateway(req.Gateway)
	if err != nil {
		return nil, err
	}

	// Validate payment method is supported
	supported := false
	for _, method := range gateway.SupportedPaymentMethods() {
		if method == req.PaymentMethod {
			supported = true
			break
		}
	}

	if !supported {
		return nil, errors.New("payment method not supported by gateway")
	}

	return gateway.CreatePayment(ctx, req)
}

// GetPaymentStatus gets the status of a payment
func (s *PaymentService) GetPaymentStatus(ctx context.Context, gatewayName, paymentID string) (*PaymentResponse, error) {
	gateway, err := s.getGateway(gatewayName)
	if err != nil {
		return nil, err
	}

	return gateway.GetPaymentStatus(ctx, paymentID)
}

// CreateSubscription creates a new subscription
func (s *PaymentService) CreateSubscription(ctx context.Context, req PaymentRequest) (*SubscriptionResponse, error) {
	if req.BillingCycle == nil {
		return nil, errors.New("billing cycle required for subscription")
	}

	gateway, err := s.getGateway(req.Gateway)
	if err != nil {
		return nil, err
	}

	// Validate payment method is supported for subscriptions
	if req.PaymentMethod != PaymentMethodUPIAutopay && req.PaymentMethod != PaymentMethodCard {
		return nil, errors.New("payment method not supported for subscriptions")
	}

	return gateway.CreateSubscription(ctx, req)
}

// CancelSubscription cancels an existing subscription
func (s *PaymentService) CancelSubscription(ctx context.Context, gatewayName, subscriptionID string) (*SubscriptionResponse, error) {
	gateway, err := s.getGateway(gatewayName)
	if err != nil {
		return nil, err
	}

	return gateway.CancelSubscription(ctx, subscriptionID)
}

// ProcessWebhook processes a webhook from a payment gateway
func (s *PaymentService) ProcessWebhook(ctx context.Context, gatewayName string, payload []byte, headers map[string]string) (*WebhookEvent, error) {
	gateway, err := s.getGateway(gatewayName)
	if err != nil {
		return nil, err
	}

	return gateway.ProcessWebhook(ctx, payload, headers)
}
