package main

// import (
// 	"strconv"

// 	"github.com/go-resty/resty/v2"
// 	"github.com/opendigitalpay-io/open-pay/internal/common/errorz"
// )

// type Adapter interface {
// 	TryTopUp(uint64, TryTopUpRequest) (TryTopUpResponse, error)
// 	CommitTopUp(uint64, uint64, map[string]interface{}) error
// 	CancelTopUp(uint64, uint64, map[string]interface{}) error

// 	TryExternalPay(uint64, TryPayRequest) (TryPayResponse, error)
// 	TryPay(uint64, TryPayRequest) (TryPayResponse, error)
// 	CommitPay(uint64, CommitPayRequest) error
// 	CancelPay(uint64, CancelPayRequest) error
// }

// type adapter struct {
// 	client *resty.Client
// }

// func NewAdapter() Adapter {
// 	client := resty.New()
// 	client.SetHostURL("http://127.0.0.1:8080")
// 	client.SetHeader("Content-Type", "application/json")
// 	client.OnAfterResponse(func(client *resty.Client, response *resty.Response) error {
// 		return nil
// 	})

// 	return &adapter{
// 		client: client,
// 	}
// }

// func (a *adapter) TryTopUp(idemKey uint64, request TryTopUpRequest) (TryTopUpResponse, error) {
// 	req := TryTopUpRequest{
// 		UserID:   request.UserID,
// 		Amount:   request.Amount,
// 		Currency: request.Currency,
// 		Metadata: request.Metadata,
// 	}

// 	resp, err := a.client.R().
// 		SetHeader("idemKey", strconv.FormatUint(idemKey, 10)).
// 		SetBody(req).
// 		SetResult(TryTopUpResponse{}).
// 		SetError(errorz.Response{}).
// 		Post("/v1/topup/try")

// 	if err != nil {
// 		println(err)
// 		return TryTopUpResponse{}, err
// 	}

// 	if resp.IsError() {
// 		return TryTopUpResponse{}, *resp.Error().(*errorz.Response)
// 	}

// 	return *resp.Result().(*TryTopUpResponse), nil
// }

// func (a *adapter) CommitTopUp(idemKey uint64, parentID uint64, metadata map[string]interface{}) error {
// 	req := CommitTopUpRequest{
// 		ParentID: parentID,
// 		Metadata: metadata,
// 	}

// 	resp, err := a.client.R().
// 		SetHeader("idemKey", strconv.FormatUint(idemKey, 10)).
// 		SetBody(req).
// 		SetError(errorz.Response{}).
// 		Post("/v1/topup/commit")

// 	if err != nil {
// 		return err
// 	}

// 	if resp.IsError() {
// 		return *resp.Error().(*errorz.Response)
// 	}

// 	return nil
// }

// func (a *adapter) CancelTopUp(idemKey uint64, parentID uint64, metadata map[string]interface{}) error {
// 	req := CancelTopUpRequest{
// 		ParentID: parentID,
// 		Metadata: metadata,
// 	}

// 	resp, err := a.client.R().
// 		SetHeader("idemKey", strconv.FormatUint(idemKey, 10)).
// 		SetBody(req).
// 		SetError(errorz.Response{}).
// 		Post("/v1/topup/cancel")

// 	if err != nil {
// 		return err
// 	}

// 	if resp.IsError() {
// 		return *resp.Error().(*errorz.Response)
// 	}

// 	return nil
// }

// func (a *adapter) TryExternalPay(idemKey uint64, request TryPayRequest) (TryPayResponse, error) {
// 	resp, err := a.client.R().
// 		SetHeader("idemKey", strconv.FormatUint(idemKey, 10)).
// 		SetBody(request).
// 		SetResult(TryPayResponse{}).
// 		SetError(errorz.Response{}).
// 		Post("/v1/pay/tryExternal")

// 	if err != nil {
// 		println(err)
// 		return TryPayResponse{}, err
// 	}

// 	if resp.IsError() {
// 		return TryPayResponse{}, *resp.Error().(*errorz.Response)
// 	}

// 	return *resp.Result().(*TryPayResponse), nil
// }

// func (a *adapter) TryPay(idemKey uint64, request TryPayRequest) (TryPayResponse, error) {
// 	resp, err := a.client.R().
// 		SetHeader("idemKey", strconv.FormatUint(idemKey, 10)).
// 		SetBody(request).
// 		SetResult(TryPayResponse{}).
// 		SetError(errorz.Response{}).
// 		Post("/v1/pay/try")

// 	if err != nil {
// 		println(err)
// 		return TryPayResponse{}, err
// 	}

// 	if resp.IsError() {
// 		return TryPayResponse{}, *resp.Error().(*errorz.Response)
// 	}

// 	return *resp.Result().(*TryPayResponse), nil
// }

// func (a *adapter) CommitPay(idemKey uint64, request CommitPayRequest) error {
// 	resp, err := a.client.R().
// 		SetHeader("idemKey", strconv.FormatUint(idemKey, 10)).
// 		SetBody(request).
// 		SetError(errorz.Response{}).
// 		Post("/v1/pay/commit")

// 	if err != nil {
// 		return err
// 	}

// 	if resp.IsError() {
// 		return *resp.Error().(*errorz.Response)
// 	}

// 	return nil
// }

// func (a *adapter) CancelPay(idemKey uint64, request CancelPayRequest) error {
// 	resp, err := a.client.R().
// 		SetHeader("idemKey", strconv.FormatUint(idemKey, 10)).
// 		SetBody(request).
// 		SetError(errorz.Response{}).
// 		Post("/v1/pay/cancel")

// 	if err != nil {
// 		return err
// 	}

// 	if resp.IsError() {
// 		return *resp.Error().(*errorz.Response)
// 	}

// 	return nil
// }
