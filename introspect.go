package cidaasinterceptor

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

type introspectRequest struct {
	Token                 string                   `json:"token"`
	TokenTypeHint         string                   `json:"token_type_hint"`
	ClientID              string                   `json:"client_id"`
	Roles                 []string                 `json:"roles"`
	Scopes                []string                 `json:"scopes"`
	Groups                []GroupValidationOptions `json:"groups"`
	StrictGroupValidation bool                     `json:"strictGroupValidation"`
	StrictScopeValidation bool                     `json:"strictScopeValidation"`
	StrictRoleValidation  bool                     `json:"strictRoleValidation"`
	StrictValidation      bool                     `json:"strictValidation"`
}

type introspectResponse struct {
	Iss    string         `json:"iss"`
	Active bool           `json:"active"`
	Aud    string         `json:"aud"`
	Sub    string         `json:"sub"`
	Roles  []string       `json:"roles"`
	Scopes []string       `json:"scopes"`
	Groups []GroupDetails `json:"groups"`
}

// GroupDetails represents the group details returned in token
type GroupDetails struct {
	GroupID   string   `json:"groupId,omitempty"`   // group id
	GroupType string   `json:"groupType,omitempty"` // group type
	Roles     []string `json:"roles,omitempty"`     // roles of user in this group
}

func introspectToken(opts Options, endpoints cidaasEndpoints, tokenString string, apiOptions SecurityOptions) *TokenData {
	introspectReq := introspectRequest{
		Token:                 tokenString,
		TokenTypeHint:         "access_token",
		ClientID:              opts.ClientID,
		Roles:                 apiOptions.Roles,
		Scopes:                apiOptions.Scopes,
		Groups:                apiOptions.Groups,
		StrictRoleValidation:  apiOptions.StrictRoleValidation,
		StrictScopeValidation: apiOptions.StrictScopeValidation,
		StrictGroupValidation: apiOptions.StrictGroupValidation,
		StrictValidation:      apiOptions.StrictValidation,
	}
	// marshal token to introspect request and perform POST call to introspect endpoint
	introspectReqBody, err := json.Marshal(introspectReq)
	if err != nil {
		log.Printf("Error mapping introspect request: %v", err)
		return nil
	}
	if opts.Debug {
		log.Printf("IntrospectReqBody: %v", string(introspectReqBody))
	}
	// if introspect was not successful log error and return unauthorized
	resp, err := http.Post(endpoints.IntrospectionEndpoint, "application/json", bytes.NewBuffer(introspectReqBody))
	if err != nil {
		log.Printf("Error calling introspect: %v", err)
		return nil
	}
	defer resp.Body.Close()
	// map introspect call response (decode)
	var introspectRespBody introspectResponse
	errDec := json.NewDecoder(resp.Body).Decode(&introspectRespBody)
	if errDec != nil {
		log.Printf("Error mapping introspect Response: %v", err)
		return nil
	}
	if opts.Debug {
		log.Printf("IntrospectRespBody: %v", introspectRespBody)
	}
	// check if token is active, if not return unauthorized, root cause could be that token is expired or revoked
	if !introspectRespBody.Active {
		log.Printf("Token Expired/Revoked: Token.Active: %v", introspectRespBody.Active)
		return nil
	}
	// check for issuer in token data
	if introspectRespBody.Iss != opts.BaseURI {
		log.Println("Issuer mismatch")
		return nil
	}
	return &TokenData{Sub: introspectRespBody.Sub, Aud: introspectRespBody.Aud}
}
