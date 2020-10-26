package otp_generator

import (
	"testing"
)

func generateSecret(myPlainSecret *string) string {
	return GenerateSharedSecret(myPlainSecret)
}

func TestGenerateSharedSecret(t *testing.T) {
	Seed := "TestSeedForTesting"
	SharedSecret := generateSecret(&Seed)
	t.Logf("Encoded secret :: %s", SharedSecret)
}

func generateOTP(config *OTPConfiguration) string {
	return config.GenerateHMACPasscode()
}

func TestGenerateOTP(t *testing.T) {
	seed := "TestSeed2ForGeneratingOTP"
	encodedSharedSecret := generateSecret(&seed)
	t.Logf("Shared Secret is :: %s", encodedSharedSecret)
	config := OTPConfiguration{Secret: &encodedSharedSecret, Length: 6, ValidityInterval: 30}
	t.Logf("OTP :: %s", generateOTP(&config))
}
