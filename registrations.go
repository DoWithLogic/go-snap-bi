package snap

import (
	"context"
	"net/http"

	"github.com/DoWithLogic/go-snap-bi/types"
)

type registration struct {
	tm *tokenManager
}

func (r *registration) CardBind(ctx context.Context, request CardBindRequest) (response CardBindResponse, err error) {
	if err := r.tm.buildTransactionHeaders(ctx, http.MethodPost, types.RegistrationCardBind.String(), request.JSON(), &request.Params); err != nil {
		return response, err
	}

	if err := r.tm.tp.CallWithContext(ctx, http.MethodPost, types.RegistrationCardBind, &request, &response); err != nil {
		return response, err
	}

	return response, nil
}

func (r *registration) CardBindLimit(ctx context.Context, request CardBindLimitRequest) (response CardBindLimitResponse, err error) {
	if err := r.tm.buildTransactionHeaders(ctx, http.MethodPost, types.RegistrationCardBind.String(), request.JSON(), &request.Params); err != nil {
		return response, err
	}

	if err := r.tm.tp.CallWithContext(ctx, http.MethodPost, types.RegistrationCardBindLimit, &request, &response); err != nil {
		return response, err
	}

	return response, nil
}
