package http

import (
	"github.com/gin-gonic/gin"
	"github.com/quangdangfit/gocommon/validation"

	"goshop/internal/user/repository"
	"goshop/internal/user/service"
	"goshop/pkg/authentik"
	"goshop/pkg/config"
	"goshop/pkg/dbs"
	"goshop/pkg/middleware"
)

func Routes(r *gin.RouterGroup, sqlDB dbs.Database, validator validation.Validation) {
	cfg := config.GetConfig()
	userRepo := repository.NewUserRepository(sqlDB)

	// In headless OIDC mode the service delegates credential checks and
	// self-service registration to Authentik; in JWT mode it stays purely
	// local (ak = nil).
	var ak service.AuthentikClient
	if cfg.AuthMode == config.AuthModeOIDC {
		ak = authentik.New(authentik.Config{
			BaseURL:      cfg.AuthentikAPIBase,
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			AdminToken:   cfg.AuthentikAdminToken,
			FlowSlug:     cfg.AuthentikFlowSlug,
		})
	}
	userSvc := service.NewUserService(validator, userRepo, ak)
	userHandler := NewUserHandler(userSvc)

	addressRepo := repository.NewAddressRepository(sqlDB)
	addressSvc := service.NewAddressService(validator, addressRepo)
	addressHandler := NewAddressHandler(addressSvc)

	wishlistRepo := repository.NewWishlistRepository(sqlDB)
	wishlistSvc := service.NewWishlistService(wishlistRepo)
	wishlistHandler := NewWishlistHandler(wishlistSvc)

	authRoute := r.Group("/auth")

	var authMiddleware gin.HandlerFunc
	var refreshAuthMiddleware gin.HandlerFunc

	// Protected routes always use JWTAuth — both auth modes mint GoShop JWT
	// session tokens (the OIDC callback exchanges the Authentik ID token for
	// our own JWT pair before redirecting back to the FE).
	authMiddleware = middleware.JWTAuth()
	refreshAuthMiddleware = middleware.JWTRefresh()

	// Password-based endpoints are always mounted — both auth modes accept
	// email/password sign-in and self-service registration. OIDC mode adds
	// SSO on top of that rather than replacing it.
	authRoute.POST("/register", userHandler.Register)
	authRoute.POST("/login", userHandler.Login)
	authRoute.POST("/refresh", refreshAuthMiddleware, userHandler.RefreshToken)
	authRoute.GET("/me", authMiddleware, userHandler.GetMe)
	authRoute.PUT("/change-password", authMiddleware, userHandler.ChangePassword)

	addressRoute := r.Group("/addresses", authMiddleware)
	{
		addressRoute.GET("", addressHandler.ListAddresses)
		addressRoute.POST("", addressHandler.CreateAddress)
		addressRoute.GET("/:id", addressHandler.GetAddressByID)
		addressRoute.PUT("/:id", addressHandler.UpdateAddress)
		addressRoute.DELETE("/:id", addressHandler.DeleteAddress)
		addressRoute.PUT("/:id/default", addressHandler.SetDefaultAddress)
	}

	wishlistRoute := r.Group("/wishlist", authMiddleware)
	{
		wishlistRoute.GET("", wishlistHandler.GetWishlist)
		wishlistRoute.POST("", wishlistHandler.AddProduct)
		wishlistRoute.DELETE("/:productId", wishlistHandler.RemoveProduct)
	}

	r.PUT("/me/cart-snapshot", authMiddleware, PutCartSnapshot)
}
