package oauth

import (
	"encoding/json"
	"errors"

	"fmt"

	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Delaram-Gholampoor-Sagha/bookstore_utils-go/rest_errors"

	//An extremely simple to use, lightweight, yet powerful REST Client
	"github.com/mercadolibre/golang-restclient/rest"
)

// NOTE ABOUT mercadolibre package :
// The Go http standard library is a great library, but it might sometimes be a bit too low level to use, and it doesn't offer features like fork-join requests for better performance, response caching based on headers, and the possibility to mockup responses.

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	// RequestBuilder is the baseline for creating requests
	// There's a Default Builder that you may use for simple requests
	// RequestBuilder si thread-safe, and you should store it for later re-used.
	oauthRestClient = rest.RequestBuilder{
		// Base URL to be used for each Request. The final URL will be BaseURL + URL.
		BaseURL: "http://localhost:8080",
		// Complete request time out.
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {
	// In Restful, GET is used for "reading" or retrieving a resource.
	// Client should expect a response status code of 200(OK) if resource exists,
	// 404(Not Found) if it doesn't, or 400(Bad Request).
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerError("invalid restclient response when trying to get access token",
			errors.New("network timeout"))
	}

	if response.StatusCode > 299 {
		restErr, err := rest_errors.NewRestErrorFromBytes(response.Bytes())
		if err != nil {
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get access token", err)
		}

		return nil, restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal access token response",
			errors.New("error processing json"))
	}
	return &at, nil
}
