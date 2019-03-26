package service

import (
	"net/smtp"
	"os"
	"fmt"
	"regexp"
)

func SendOtpByEmail(recipient string, otp string)  bool{

	auth := smtp.PlainAuth(
		"",
		os.Getenv("EMAIL_USER"),//email
		os.Getenv("EMAIL_PSW"),//email pass
		os.Getenv("EMAIL_HOST"),
	)
	msg := []byte("To: " +
		recipient + "\r\n" +
		"Subject: 2FA\r\n" +
		"\r\n" +
		os.Getenv("BOT_API_KEY") + "/?otp=" + otp + "\r\n")
	err := smtp.SendMail(
		os.Getenv("BOT_API_KEY") + ":" + os.Getenv("EMAIL_PORT"),
		auth,
		"wspdev@gmail.com",
		[]string{recipient},
		msg,
	)
	if err != nil {
		fmt.Println(err)
		return false
	}

	return true
}

func ValidateEmail(email string) bool {
	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return Re.MatchString(email)
}
