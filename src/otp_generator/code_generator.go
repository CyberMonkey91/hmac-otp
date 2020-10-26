package otp_generator

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"strings"
	"time"
)

type OTPConfiguration struct {
	Secret           *string
	Length           int
	ValidityInterval int
}

func GenerateSharedSecret(Seed *string) string {
	secret := base64.StdEncoding.EncodeToString([]byte(strings.ToUpper(*Seed)))
	return secret
}

func (conf *OTPConfiguration) GenerateHMACPasscode() string {
	key, err := base64.StdEncoding.DecodeString(strings.ToUpper(*conf.Secret))
	interval := time.Now().Unix() / int64(conf.ValidityInterval)
	if err != nil {
		log.Panicf("Error occurred in decoding secret ::: %s", err.Error())
	}

	hmacData := make([]byte, 8)
	binary.BigEndian.PutUint64(hmacData, uint64(interval))

	hash := hmac.New(sha1.New, key)
	hash.Write(hmacData)
	largeCode := hash.Sum(nil)

	nibbleOffset := largeCode[len(hmacData)-1] & 0x0F
	code := (int(largeCode[nibbleOffset]&0x7F) << 24) |
		(int(largeCode[nibbleOffset+1]&0xFF) << 16) |
		(int(largeCode[nibbleOffset+2])&0xFF)<<8 |
		(int(largeCode[nibbleOffset+3]) & 0xFF)

	otp := int64(code) % int64(math.Pow10(conf.Length))
	return fmt.Sprintf("%06d", otp)
}
