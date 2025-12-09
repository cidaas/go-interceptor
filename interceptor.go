package cidaasinterceptor

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

const anonymousSub = "ANONYMOUS"

// SecurityOptions which should be passsed to restrict the api access
type SecurityOptions struct {
	Roles                 []string                 // roles which are allowed to access this api
	Scopes                []string                 // scopes which are allowed to acces this api
	Groups                []GroupValidationOptions // groups which are allowed to acces this api (only possible with introspect)
	AllowAnonymousSub     bool                     // false (by default) indicates that tokens which have an anonymous sub are rejected, true indicates that tokens which have an ANONYMOUS sub are allowed (only possible with the signature check for now)
	StrictRoleValidation  bool                     // by default false, true indicates that all provided roles must match (only possible with introspect)
	StrictScopeValidation bool                     // by default false, true indicates that all provided scopes must match (also possible with the signature check)
	StrictGroupValidation bool                     // by default false, true indicates that all provided groups must match (only possible with introspect)
	StrictValidation      bool                     // by default false, true indicates that all provided roles, scopes and groups must match (the signature check just checks for the scopes)
}

// GroupValidationOptions provides options to allow API access only to certain groups
type GroupValidationOptions struct {
	GroupID              string   `json:"groupId,omitempty"`              // the group id to match
	GroupType            string   `json:"groupType,omitempty"`            // the group type to match
	Roles                []string `json:"roles,omitempty"`                // the roles to match
	StrictRoleValidation bool     `json:"strictRoleValidation,omitempty"` // true indicates that all roles must match
	StrictValidation     bool     `json:"strictValidation,omitempty"`     // true indicates that the group id, group type and all roles must match
}

// TokenData which can be accessed via the request context and provides the resolved information about the aud and the sub of the token
type TokenData struct {
	Sub string
	Aud string
}

type cidaasEndpoints struct {
	Issuer                              string `json:"issuer"`
	UserinfoEndpoint                    string `json:"userinfo_endpoint"`
	AuthorizationEndpoint               string `json:"authorization_endpoint"`
	IntrospectionEndpoint               string `json:"introspection_endpoint"`
	IntrospectionasyncupdateEndpoint    string `json:"introspection_async_update_endpoint"`
	RevocationEndpoint                  string `json:"revocation_endpoint"`
	TokenEndpoint                       string `json:"token_endpoint"`
	JwksURI                             string `json:"jwks_uri"`
	Checksessioniframe                  string `json:"check_session_iframe"`
	EndsessionEndpoint                  string `json:"end_session_endpoint"`
	SocialprovidertokenresolverEndpoint string `json:"social_provider_token_resolver_endpoint"`
	DeviceauthorizationEndpoint         string `json:"device_authorization_endpoint"`
}

// Options passed to the Interceptor (Base URI, ClientID)
type Options struct {
	BaseURI  string
	ClientID string
	Debug    bool
}

func newInterceptor(opts Options) (cidaasEndpoints, Jwks, error) {
	if opts == (Options{}) || opts.BaseURI == "" {
		log.Printf("No options passed! BaseURI: %v", opts.BaseURI)
		return cidaasEndpoints{}, Jwks{}, errors.New("no Base URI passed")
	}
	log.Println("Initialization started")
	resp, err := http.Get(opts.BaseURI + "/.well-known/openid-configuration")
	if err != nil { // check if any error when retrieving the JWKS
		log.Printf("Well Known call failed! Error: %v", err)
		return cidaasEndpoints{}, Jwks{}, err
	}
	defer resp.Body.Close()
	// Decode cidaas well-known to endpoints object
	endpoints := cidaasEndpoints{}
	err = json.NewDecoder(resp.Body).Decode(&endpoints)
	if err != nil {
		return cidaasEndpoints{}, Jwks{}, err
	}
	keys, err := getKeys(endpoints.JwksURI)
	if err != nil {
		return cidaasEndpoints{}, Jwks{}, err
	}
	return endpoints, keys, nil
}

// CheckScopesAndRoles based on Introspect Response and requested scopes and roles
func checkScopesAndRoles(tokenScopes []string, tokenRoles []string, apiOptions SecurityOptions, isAnonymous bool) bool {
	scopesValid := true
	rolesValid := true
	rolesRequested := false
	scopesRequested := false
	if len(apiOptions.Scopes) > 0 {
		scopesRequested = true
		// Check for request scopes in token data
		if apiOptions.StrictScopeValidation {
			// check all requested scopes are present in token
			if !contains(tokenScopes, apiOptions.Scopes) {
				log.Println("Scopes mismatch")
				scopesValid = false
			}
		} else {
			// check any one of the requested scopes are present in token
			if !containsAny(tokenScopes, apiOptions.Scopes) {
				log.Println("Scopes mismatch")
				scopesValid = false
			}
		}
	}
	if len(apiOptions.Roles) > 0 && !isAnonymous {
		rolesRequested = true
		// Check for request roles in token data
		if apiOptions.StrictRoleValidation {
			// check all requested roles are present in token
			if !contains(tokenRoles, apiOptions.Roles) {
				log.Println("Roles mismatch")
				rolesValid = false
			}
		} else {
			// check any one of the requested roles are present in token
			if !containsAny(tokenRoles, apiOptions.Roles) {
				log.Println("Roles mismatch")
				rolesValid = false
			}
		}
	}
	// validate both roles and scopes if strictValidation is applied
	if apiOptions.StrictValidation {
		return rolesValid && scopesValid
	}
	// selective validation based on roles/scopes requested in api security
	if rolesRequested && scopesRequested {
		return rolesValid || scopesValid
	} else if !rolesRequested && scopesRequested {
		return scopesValid
	} else if rolesRequested && !scopesRequested {
		return rolesValid
	} else {
		return true
	}
}

// contains Call checking if scopes/roles in the tokendata
func contains(tokenData []string, requestedData []string) bool {
	matchedCount := 0
	for _, r := range requestedData {
		for _, t := range tokenData {
			if t == r {
				matchedCount++
				break
			}
		}
	}
	return matchedCount == len(requestedData)
}

// containsAny check if any one of the tokenData matches with requestedData
func containsAny(tokenData []string, requestedData []string) bool {
	for _, r := range requestedData {
		for _, t := range tokenData {
			if t == r {
				return true
			}
		}
	}
	return false
}
