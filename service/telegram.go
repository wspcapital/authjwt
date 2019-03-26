package service

import (
	"strings"
	"os"
	"net/http"
)

func SendOtpByTelegram(chat_id int64, otp string)  bool{
	body := strings.NewReader("chat_id=" + string(chat_id) + "&text=" + os.Getenv("BOT_API_KEY") + "/?otp=" + otp)
	req, err := http.NewRequest("POST", "https://api.telegram.org/bot" + os.Getenv("BOT_API_KEY") + "/sendMessage", body)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return true
}
