package config

import (
	"github.com/praleedsuvarna/shared-libs/config"
)

// Payment gateway constants
const (
	// Razorpay environment variable keys
	RazorpayKeyIDEnv         = "RAZORPAY_KEY_ID"
	RazorpayKeySecretEnv     = "RAZORPAY_KEY_SECRET"
	RazorpayWebhookSecretEnv = "RAZORPAY_WEBHOOK_SECRET"

	// Cashfree environment variable keys
	CashfreeAppIDEnv     = "CASHFREE_APP_ID"
	CashfreeSecretKeyEnv = "CASHFREE_SECRET_KEY"

	// PhonePe environment variable keys
	PhonePeMerchantIDEnv = "PHONEPE_MERCHANT_ID"
	PhonePeSaltKeyEnv    = "PHONEPE_SALT_KEY"
	PhonePeSaltIndexEnv  = "PHONEPE_SALT_INDEX"

	// General payment settings
	PaymentWebhookBaseURLEnv = "PAYMENT_WEBHOOK_BASE_URL"
)

// GetRazorpayConfig returns all Razorpay configuration
func GetRazorpayConfig() map[string]string {
	return map[string]string{
		"key_id":         config.GetEnv(RazorpayKeyIDEnv, ""),
		"key_secret":     config.GetEnv(RazorpayKeySecretEnv, ""),
		"webhook_secret": config.GetEnv(RazorpayWebhookSecretEnv, ""),
	}
}

// GetCashfreeConfig returns all Cashfree configuration
func GetCashfreeConfig() map[string]string {
	return map[string]string{
		"app_id":     config.GetEnv(CashfreeAppIDEnv, ""),
		"secret_key": config.GetEnv(CashfreeSecretKeyEnv, ""),
	}
}

// GetPhonePeConfig returns all PhonePe configuration
func GetPhonePeConfig() map[string]string {
	return map[string]string{
		"merchant_id": config.GetEnv(PhonePeMerchantIDEnv, ""),
		"salt_key":    config.GetEnv(PhonePeSaltKeyEnv, ""),
		"salt_index":  config.GetEnv(PhonePeSaltIndexEnv, "1"),
	}
}

// GetPaymentWebhookBaseURL returns the base URL for payment webhooks
func GetPaymentWebhookBaseURL() string {
	return config.GetEnv(PaymentWebhookBaseURLEnv, "http://172.0.0.1:8080/")
}
