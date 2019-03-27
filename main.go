package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"authjwt/model"
	"time"
	"authjwt/service"
	"os"
	"github.com/joho/godotenv"
)

var DbConnect *gorm.DB

var jwtSecret string

type JwtToken struct {
	Token string `json:"token"`
}

type signinUser struct {
	Email string `json:"email"`
	Password string `json:"password"`
}

type newUser struct {
	FirstName string `json:"firstname"`
	LastName string `json:"lastname"`
	Email string `json:"email"`
	Password string `json:"password"`
	ConfPassword string `json:"confpassword"`
	ChatID int64 `json:"chatid"`
}

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		bearerToken, err := service.GetBearerToken(req.Header.Get("authorization"))
		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}

		decodedToken, err := service.VerifyJwt(bearerToken, jwtSecret)
		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}

		var user model.User
		err = DbConnect.Table("users").
			Select("users.email, users.passw, users.salt, users.chat_id").
			Where("users.id =  ? and users.passw = ?", decodedToken["user_id"], decodedToken["password"]).First(&user).Error

		if err != nil && gorm.IsRecordNotFoundError(err) == true {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("JWT is incorrect"))
			return
		} else if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		//TODO: Check Expires
		/*if decodedToken["expiresIn"] < time.Now().Unix() {
		}*/

		if decodedToken["authorized"] == true {
			context.Set(req, "decoded", decodedToken)
			next(w, req)
		} else {
			json.NewEncoder(w).Encode("2FA is required")
		}
	})
}

func CreateTokenEndpoint(w http.ResponseWriter, req *http.Request) {
	var u signinUser
	_ = json.NewDecoder(req.Body).Decode(&u)
	var user model.User
	if err := DbConnect.Table("users").
		Select("users.id, users.email, users.passw, users.salt, users.chat_id, users.two_factor_email, users.two_factor_telegram").
		Where("users.email =  ?", u.Email).Find(&user).Error; err != nil {
		json.NewEncoder(w).Encode("Indicated Email is absent")
		return
	}

	if service.VerifyPassword(u.Password, user.Passw) == false {
		json.NewEncoder(w).Encode("Wrong password")
		return
	}

	otp := service.GetRandomString(24)

	authUser := make(map[string]interface{})
	authUser["expiresIn"] = time.Now().Add(time.Second * 3600).Unix()
	authUser["user_id"] = user.ID
	authUser["password"] = user.Passw
	authUser["otp"] = otp
	authUser["authorized"] = false

	tokenString, err := service.SignJwt(authUser, jwtSecret)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}

	var sentOtp bool
	if user.TwoFactorEmail {
		sentOtp = service.SendOtpByEmail(u.Email, otp)
	} else if user.TwoFactorTelegram {
		sentOtp = service.SendOtpByTelegram(user.ChatID, tokenString)
	}
	if !sentOtp {
		json.NewEncoder(w).Encode("OTP is not sent")
		return
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func ProtectedEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")

	json.NewEncoder(w).Encode(decoded)
}

func VerifyOtpGetEndpoint(w http.ResponseWriter, req *http.Request) {
	bearerToken, err := service.GetBearerToken(req.Header.Get("authorization"))

	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}

	decodedToken, err := service.VerifyJwt(bearerToken, jwtSecret)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}

	var user model.User
	err = DbConnect.Table("users").
		Select("users.email, users.passw, users.salt, users.chat_id").
		Where("users.id =  ? and users.passw = ?", decodedToken["user_id"], decodedToken["password"]).First(&user).Error

	if err != nil && gorm.IsRecordNotFoundError(err) == true {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("JWT is incorrect"))
		return
	} else if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
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

	if decodedToken["otp"] == keys[0] {
		decodedToken["authorized"] = true
	} else {
		json.NewEncoder(w).Encode("Invalid one-time password")
		return
	}

	jwToken, _ := service.SignJwt(decodedToken, jwtSecret)
	json.NewEncoder(w).Encode(jwToken)
}

func SignUpEndpoint(w http.ResponseWriter, req *http.Request) {
	var u newUser
	_ = json.NewDecoder(req.Body).Decode(&u)

	if !service.ValidateEmail(u.Email) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Incorrect Email address"))
		return
	}

	var user model.User
	err := DbConnect.Table("users").
	Select("users.email, users.passw, users.salt, users.chat_id").
	Where("users.email =  ?", u.Email).First(&user).Error

	if gorm.IsRecordNotFoundError(err) == true {
		salt := service.GetRandomString(15)
		encodedPwd := salt + "$" + service.EncodePassword(u.Password, salt)

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
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(User.ID)
		return
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte("Email " + user.Email + " is used"))
}

func main() {
	err := godotenv.Load()
	db, err := gorm.Open("postgres",
		"host=" + os.Getenv("DB_HOST") + " port=" + os.Getenv("DB_PORT") + " user=" + os.Getenv("DB_USER") + " dbname=" + os.Getenv("DB_NAME") + " password=" + os.Getenv("DB_PSW"))
	DbConnect = db
	if err != nil {
		panic(err)
	}
	defer db.Close()

	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	jwtSecret = os.Getenv("APP_JWT_SECRET")
	router.HandleFunc("/signup", SignUpEndpoint).Methods("POST")
	router.HandleFunc("/authenticate", CreateTokenEndpoint).Methods("POST")
	router.HandleFunc("/verify-otp", VerifyOtpGetEndpoint).Methods("GET")
	router.HandleFunc("/protected", ValidateMiddleware(ProtectedEndpoint)).Methods("GET")
	router.HandleFunc("/generate-secret", service.GenerateSecretEndpoint).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", router))
}