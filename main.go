package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgryski/dgoogauth"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"os"
	"authjwt/model"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"crypto/hmac"
	"time"
)

var DbConnect *gorm.DB

var jwtSecret string

type JwtToken struct {
	Token string `json:"token"`
}

type OtpToken struct {
	Token string `json:"otp"`
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
		//fmt.Println(decodedToken)
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
		Select("users.email, users.passw, users.salt").
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

	DbConnect.Model(&user).Update("session_key", GetRandomString(24))
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func VerifyPassword(rawPwd, encodedPwd string) bool {
	var salt, encoded string
	salt = encodedPwd[:15]
	encoded = encodedPwd[16:]

	return EncodePassword(rawPwd, salt) == encoded
}

func ProtectedEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")

	json.NewEncoder(w).Encode(decoded)
}

func VerifyOtpGetEndpoint(w http.ResponseWriter, req *http.Request) {
	secret := "7DRUFISBBUCNXPM6"
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
	fmt.Println(decodedToken)
	otpc := &dgoogauth.OTPConfig{
		Secret:      secret,
		WindowSize:  3,
		HotpCounter: 0,
	}
	var otpToken OtpToken
	_ = json.NewDecoder(req.Body).Decode(&otpToken)
	fmt.Println(otpToken.Token)
	decodedToken["authorized"], _ = otpc.Authenticate(otpToken.Token)

	if decodedToken["authorized"] != false {
		json.NewEncoder(w).Encode("Invalid one-time password!")
		return
	}
	decodedToken["authorized"] = true
	jwToken, _ := SignJwt(decodedToken, jwtSecret)
	json.NewEncoder(w).Encode(jwToken)
}

func VerifyOtpPostEndpoint(w http.ResponseWriter, req *http.Request) {
	secret := "7DRUFISBBUCNXPM6"
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
	fmt.Println(decodedToken)
	otpc := &dgoogauth.OTPConfig{
		Secret:      secret,
		WindowSize:  3,
		HotpCounter: 0,
	}
	var otpToken OtpToken
	_ = json.NewDecoder(req.Body).Decode(&otpToken)
	fmt.Println(otpToken.Token)
	decodedToken["authorized"], _ = otpc.Authenticate(otpToken.Token)

	if decodedToken["authorized"] != false {
		json.NewEncoder(w).Encode("Invalid one-time password!")
		return
	}
	decodedToken["authorized"] = true
	jwToken, _ := SignJwt(decodedToken, jwtSecret)
	json.NewEncoder(w).Encode(jwToken)
}

func GenerateSecretEndpoint(w http.ResponseWriter, req *http.Request) {
	random := make([]byte, 10)
	rand.Read(random)
	secret := base32.StdEncoding.EncodeToString(random)
	json.NewEncoder(w).Encode(secret)
}

func confdb() (string) {
	file, err := os.Open("conf/conf")
	if err != nil {
		panic(err)
	}
	type dbConf struct {
		DbHost string
		DbPort string
		DbName string
		DbUser string
		DbPsw string
		BotKey string
		BotSesDuration int64
	}
	dbconf := dbConf{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&dbconf)
	if err != nil {
		panic(err)
	}

	return "host=" + dbconf.DbHost + " port=" + dbconf.DbPort + " user=" + dbconf.DbUser + " dbname=" + dbconf.DbName + " password=" + dbconf.DbPsw
}

type newUser struct {
	FirstName string `json:"firstname"`
	LastName string `json:"lastname"`
	Email string `json:"email"`
	Password string `json:"password"`
	ConfPassword string `json:"confpassword"`
}

func SignUpEndpoint(w http.ResponseWriter, req *http.Request) {
	var u newUser
	_ = json.NewDecoder(req.Body).Decode(&u)

	salt := GetRandomString(15)
	encodedPwd := salt + "$" + EncodePassword(u.Password, salt)

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
	}

	DbConnect.Create(&User)

	if DbConnect.Error != nil {
		fmt.Println(DbConnect.Error)
		json.NewEncoder(w).Encode(nil)
	}
	json.NewEncoder(w).Encode(User.ID)
}

func main() {
	db, err := gorm.Open("postgres", confdb())
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
	router.HandleFunc("/verify-otp", VerifyOtpPostEndpoint).Methods("POST")
	router.HandleFunc("/verify-otp", VerifyOtpGetEndpoint).Methods("GET")
	router.HandleFunc("/protected", ValidateMiddleware(ProtectedEndpoint)).Methods("GET")
	router.HandleFunc("/generate-secret", GenerateSecretEndpoint).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", router))
}

// Random generate string
func GetRandomString(n int) string {
	const alphanum = "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func EncodePassword(rawPwd string, salt string) string {
	pwd := PBKDF2([]byte(rawPwd), []byte(salt), 10000, 50, sha256.New)
	return hex.EncodeToString(pwd)
}

func PBKDF2(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}