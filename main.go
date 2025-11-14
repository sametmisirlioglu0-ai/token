// @title Fiber JWT API
// @version 1.1
// @description Basit JWT kimlik doğrulama sistemi
// @host localhost:8080
// @BasePath /
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "deneme-token/docs"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	fcors "github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/swagger"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var jwtSecret = []byte("basit-bir-sifre")
var validate = validator.New()
var db *gorm.DB

type User struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Name         string    `json:"name" validate:"required"`
	Email        string    `json:"email" validate:"required,email" gorm:"uniqueIndex;not null"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role" gorm:"default:'user'"`
	RefreshToken string    `json:"-"`
	CreatedAt    time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt    time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

type RegisterRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6,max=72"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func main() {
	initDB()

	app := fiber.New()

	app.Get("/swagger/*", swagger.HandlerDefault)

	app.Use(func(c *fiber.Ctx) error {
		log.Printf("REQ %s %s", c.Method(), c.Path())
		return c.Next()
	})

	app.Use(fcors.New(fcors.Config{
		AllowOrigins: "*",
		AllowMethods: "POST, GET, PUT, DELETE, OPTIONS",
	}))

	app.Get("/", rootHandler)
	app.Get("/me", authMiddleware, meHandler)
	app.Get("/admin", authMiddleware, requiredRole("admin"), adminHandler)
	app.Post("/login", loginHandler)
	app.Post("/register", registerHandler)
	app.Post("/refresh", refreshHandler)

	go func() {
		if err := app.Listen(":8080"); err != nil {
			log.Fatalf("Sunucu başlatılamadı %v", err)
		}
		log.Println("Sunucu başlatılıyor")
	}()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Sunucu kapatılıyor")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(ctx); err != nil {
		log.Fatalf("Sunucu kapatlamadı %v", err)
	}
	log.Println("Sunucu kapatıldı")
}

func hashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

func checkPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func parseToken(tokenStr string) (*jwt.Token, jwt.MapClaims, error) {
	parser := jwt.Parser{}
	claims := jwt.MapClaims{}
	tkn, err := parser.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, nil, err
	}
	if !tkn.Valid {
		return nil, nil, errors.New("token is invalid")
	}
	return tkn, claims, nil
}

func generateToken(userID uint, role string) (access string, refresh string, err error) {
	atClaims := jwt.MapClaims{
		"sub":  userID,
		"role": role,
		"exp":  time.Now().Add(time.Minute * 15).Unix(),
		"iat":  time.Now().Unix(),
	}
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	access, err = at.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}
	rtClaims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour * 7 * 24).Unix(),
		"iat": time.Now().Unix(),
		"rnd": time.Now().UnixNano(),
	}
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	refresh, err = rt.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

// @Summary Yeni kullanıcı kaydı oluşturur
// @Tags Auth
// @Accept json
// @Produce json
// @Param data body RegisterRequest true "Kayıt bilgileri"
// @Success 200 {object} User
// @Failure 400 {object} map[string]interface{}
// @Router /register [post]
func registerHandler(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{})
	}
	if err := validate.Struct(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{})
	}
	pwHash, err := hashPassword(req.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{})
	}
	user := User{
		Name:         req.Name,
		Email:        strings.ToLower(req.Email),
		PasswordHash: pwHash,
		Role:         "user",
	}

	if err := db.Create(&user).Error; err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "UNIQUE") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{})
	}
	user.RefreshToken = ""
	user.PasswordHash = ""
	return c.Status(fiber.StatusOK).JSON(user)
}

// @Summary Kullanıcı girişi yapar ve token döndürür
// @Tags Auth
// @Accept json
// @Produce json
// @Param data body LoginRequest true "Giriş bilgileri"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /login [post]
func loginHandler(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{})
	}
	if err := validate.Struct(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{})
	}
	var user User
	if err := db.Where("email = ?", strings.ToLower(req.Email)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{})
	}
	if err := checkPassword(req.Password, user.PasswordHash); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{})
	}
	access, refresh, err := generateToken(user.ID, user.Role)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{})
	}
	user.RefreshToken = refresh
	if err := db.Save(&user).Error; err != nil {
		log.Println(err, "failed to save user")
	}
	return c.JSON(TokenResponse{AccessToken: access, RefreshToken: refresh})
}

// @Summary Access token yeniler
// @Tags Auth
// @Accept json
// @Produce json
// @Param data body map[string]string true "Refresh token"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /refresh [post]
func refreshHandler(c *fiber.Ctx) error {
	type payload struct {
		RefreshToken string `json:"refresh_token"`
	}
	var p payload
	if err := c.BodyParser(&p); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{})
	}
	if err := validate.Struct(p); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{})
	}
	_, claims, err := parseToken(p.RefreshToken)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{})
	}
	subFloat, ok := claims["sub"].(float64)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{})
	}
	userID := uint(subFloat)

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{})
	}

	if user.RefreshToken == "" || user.RefreshToken == p.RefreshToken {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{})
	}
	access, refresh, err := generateToken(userID, user.Role)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{})
	}
	user.RefreshToken = refresh
	if err := db.Save(&user).Error; err != nil {
		log.Println(err, "failed to save user")
	}
	return c.JSON(TokenResponse{AccessToken: access, RefreshToken: refresh})
}

func authMiddleware(c *fiber.Ctx) error {
	auth := c.Get("Authorization")
	if strings.TrimSpace(auth) == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{})
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{})
	}
	tokenStr := parts[1]
	_, claims, err := parseToken(tokenStr)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{})
	}
	subFloat, ok := claims["sub"].(float64)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{})
	}
	userID := uint(subFloat)

	role, _ := claims["role"].(string)

	c.Locals("userID", userID)
	c.Locals("role", role)
	return c.Next()
}

func requiredRole(allowed ...string) fiber.Handler {
	allowedMap := map[string]bool{}
	for _, r := range allowed {
		allowedMap[r] = true
	}
	return func(c *fiber.Ctx) error {
		roleVal := c.Locals("role")
		roleStr := roleVal.(string)
		if !allowedMap[roleStr] {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{})
		}
		return c.Next()
	}
}

func currentUser(c *fiber.Ctx) (*User, error) {
	uID := c.Locals("userID")
	if uID == nil {
		return nil, errors.New("user ID not found")
	}
	uid, ok := uID.(uint)
	if !ok {
		if f, ok2 := uID.(float64); ok2 {
			uid = uint(f)
		} else {
			return nil, errors.New("user ID not found")
		}
	}
	var user User
	if err := db.First(&user, uid).Error; err != nil {
		return nil, err
	}
	user.PasswordHash = ""
	user.RefreshToken = ""
	return &user, nil
}

// @Summary API durumunu döndürür
// @Tags Genel
// @Produce plain
// @Success 200 {string} string "API running"
// @Router / [get]
func rootHandler(c *fiber.Ctx) error {
	return c.SendString("API running. Use GET /me, GET /admin, POST /register, POST /login")
}

// @Summary Admin sayfasını gösterir
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]interface{}
// @Router /admin [get]
func adminHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "welcome to the admin page"})
}

// @Summary Giriş yapan kullanıcının bilgilerini döndürür
// @Tags Kullanıcı
// @Produce json
// @Security BearerAuth
// @Success 200 {object} User
// @Failure 401 {object} map[string]interface{}
// @Router /me [get]
func meHandler(c *fiber.Ctx) error {
	u, err := currentUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(u)
}

func initDB() {
	var err error
	db, err := gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Veritabanına bağlanamadı", err)
	}
	if err := db.AutoMigrate(&User{}); err != nil {
		log.Fatal("Tablo oluşturulamadı", err)
	}
}
