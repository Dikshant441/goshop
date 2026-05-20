package grpc

import (
	"github.com/quangdangfit/gocommon/validation"
	"google.golang.org/grpc"

	"goshop/internal/user/repository"
	"goshop/internal/user/service"
	"goshop/pkg/dbs"
	pb "goshop/proto/gen/go/user"
)

func RegisterHandlers(svr *grpc.Server, db dbs.Database, validator validation.Validation) {
	userRepo := repository.NewUserRepository(db)
	// gRPC stays on the local password flow; only the HTTP edge wires the
	// headless Authentik client when auth_mode=oidc.
	userSvc := service.NewUserService(validator, userRepo, nil)
	userHandler := NewUserHandler(userSvc)

	pb.RegisterUserServiceServer(svr, userHandler)
}
