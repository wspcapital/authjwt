package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"authjwt/model"
	"time"
	"regexp"
	"net/smtp"
	"authjwt/sevice"
)

var DbConnect *gorm.DB

var jwtSecret string

type JwtToken struct {
	Token string `json:"token"`
}

func SignJwt(claims jwt.MapClaims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func VerifyJwt(token string, secret string) (map[string]interface{}, error) {

	jwToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !jwToken.Valid {
		return nil, fmt.Errorf("Invalid authorization token")
	}
	return jwToken.Claims.(jwt.MapClaims), nil
}

func GetBearerToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("An authorization header is required")
	}
	token := strings.Split(header, " ")
	if len(token) != 2 {
		return "", fmt.Errorf("Malformed bearer token")
	}
	return token[1], nil
}

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		bearerToken, err := GetBearerToken(req.Header.Get("authorization"))
		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}

		decodedToken, err := VerifyJwt(bearerToken, jwtSecret)
		fmt.Println(decodedToken)
		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}
		if decodedToken["authorized"] == true {
			context.Set(req, "decoded", decodedToken)
			next(w, req)
		} else {
			json.NewEncoder(w).Encode("2FA is required")
		}
	})
}

type signinUser struct {
	Email string `json:"email"`
	Password string `json:"password"`
}

func CreateTokenEndpoint(w http.ResponseWriter, req *http.Request) {
	var u signinUser
	_ = json.NewDecoder(req.Body).Decode(&u)
	var user model.User
	if err := DbConnect.Table("users").
		Select("users.email, users.passw, users.salt, users.chat_id").
		Where("users.email =  ?", u.Email).Find(&user).Error; err != nil {
		json.NewEncoder(w).Encode("Indicated Email is absent")
		return
	}

	if VerifyPassword(u.Password, user.Passw) == false {
		json.NewEncoder(w).Encode("Wrong password")
		return
	}

	authUser := make(map[string]interface{})
	authUser["username"] = u.Email
	authUser["password"] = u.Password
	authUser["authorized"] = false

	tokenString, err := SignJwt(authUser, jwtSecret)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}
	otp := sevice.GetRandomString(24)
	DbConnect.Model(&user).Update("session_key", otp)
	if !SendOtpByEmail(u.Email, otp) {
		json.NewEncoder(w).Encode("OTP is not sent by email")
		return
	}
	if !SendOtpByTelegram(user.ChatID, tokenString){
		json.NewEncoder(w).Encode("OTP is not sent by telegram")
		return
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func VerifyPassword(rawPwd, encodedPwd string) bool {
	var salt, encoded string
	salt = encodedPwd[:15]
	encoded = encodedPwd[16:]

	return sevice.EncodePassword(rawPwd, salt) == encoded
}

func ProtectedEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")

	json.NewEncoder(w).Encode(decoded)
}

func VerifyOtpGetEndpoint(w http.ResponseWriter, req *http.Request) {
	bearerToken, err := GetBearerToken(req.Header.Get("authorization"))

	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}

	decodedToken, err := VerifyJwt(bearerToken, jwtSecret)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}

	//var otpToken OtpToken
	keys, ok := req.URL.Query()["otp"]
	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'otp' is missing")
		return
	}

	if decodedToken["authorized"] != false {
		json.NewEncoder(w).Encode("Invalid one-time password!")
		return
	}

	var user model.User
	if err := DbConnect.Table("users").
		Select("users.session_key").
		Where("users.email =  ?", decodedToken["username"]).Find(&user).Error; err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}

	if user.SessionKey == keys[0] {
		decodedToken["authorized"] = true
	} else {
		json.NewEncoder(w).Encode("Invalid one-time password")
		return
	}

	jwToken, _ := SignJwt(decodedToken, jwtSecret)
	json.NewEncoder(w).Encode(jwToken)
}

type newUser struct {
	FirstName string `json:"firstname"`
	LastName string `json:"lastname"`
	Email string `json:"email"`
	Password string `json:"password"`
	ConfPassword string `json:"confpassword"`
	ChatID int64 `json:"chatid"`
}

func SignUpEndpoint(w http.ResponseWriter, req *http.Request) {
	var u newUser
	_ = json.NewDecoder(req.Body).Decode(&u)

	salt := sevice.GetRandomString(15)
	encodedPwd := salt + "$" + sevice.EncodePassword(u.Password, salt)

	if !ValidateEmail(u.Email) {
		json.NewEncoder(w).Encode("Incorrect Email address")
		return
	}

	User := model.User{
		FirstName:	u.FirstName,
		LastName:	u.LastName,
		Alias:		u.FirstName+"_"+u.LastName,
		Passw:		encodedPwd,
		Active:		true,
		Email:      u.Email,
		Salt:		salt,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		ChatID:     u.ChatID,
	}

	DbConnect.Create(&User)

	if DbConnect.Error != nil {
		fmt.Println(DbConnect.Error)
		json.NewEncoder(w).Encode(nil)
	}
	json.NewEncoder(w).Encode(User.ID)
}

func main() {
	db, err := gorm.Open("postgres",
		"host=127.0.0.1 port=54320 user=homestead dbname=stock password=secret")
	DbConnect = db
	if err != nil {
		panic(err)
	}
	defer db.Close()

	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	jwtSecret = "JC7qMMZh4G"
	router.HandleFunc("/signup", SignUpEndpoint).Methods("POST")
	router.HandleFunc("/authenticate", CreateTokenEndpoint).Methods("POST")
	router.HandleFunc("/verify-otp", VerifyOtpGetEndpoint).Methods("GET")
	router.HandleFunc("/protected", ValidateMiddleware(ProtectedEndpoint)).Methods("GET")
	router.HandleFunc("/generate-secret", sevice.GenerateSecretEndpoint).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func ValidateEmail(email string) bool {
	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return Re.MatchString(email)
}

func SendOtpByEmail(recipient string, otp string)  bool{

	auth := smtp.PlainAuth(
		"",
		"wspdev@gmail.com",//email
		"Hurka2017",//email pass
		"smtp.gmail.com",
	)
	msg := []byte("To: " +
		recipient + "\r\n" +
		"Subject: 2FA\r\n" +
		"\r\n" +
		otp + "\r\n")
	err := smtp.SendMail(
		"smtp.gmail.com:587",
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

func SendOtpByTelegram(chat_id int64, otp string)  bool{

	body := strings.NewReader("chat_id=" + string(chat_id) + "&text=" + otp)
	req, err := http.NewRequest("POST", "https://api.telegram.org/767108852:AAEs5E84kXHeV9Lqttm8sf5_ADhaitxEzU4/sendMessage", body)
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