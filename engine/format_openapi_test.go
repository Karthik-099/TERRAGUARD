package engine

import "testing"

func TestOpenAPIRules(t *testing.T) {
	weak := `openapi: 3.0.3
info: { title: t, version: "1" }
servers:
  - url: http://api.example.com
components:
  securitySchemes:
    key: { type: apiKey, in: query, name: api_key }
    legacy:
      type: oauth2
      flows:
        implicit: { authorizationUrl: https://a/x, scopes: {} }
paths:
  /users:
    post:
      security: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name: { type: string }
      responses: { "200": { description: ok } }
  /items:
    get:
      security: [ { missing: [] } ]
      responses: { "200": { description: ok } }
`
	got := ids(Scan(Input{Files: map[string]string{"api.yaml": weak}}))
	for _, id := range []string{"TG-OAS-002", "TG-OAS-003", "TG-OAS-004", "TG-OAS-006", "TG-OAS-007", "TG-OAS-008", "TG-OAS-009"} {
		if got[id] == 0 {
			t.Errorf("expected %s: %v", id, got)
		}
	}
	safe := `openapi: 3.1.0
info: { title: t, version: "1" }
servers: [ { url: https://api.example.com } ]
security: [ { bearer: [] } ]
components:
  securitySchemes:
    bearer: { type: http, scheme: bearer }
paths:
  /users/{id}:
    get:
      parameters:
        - { name: id, in: path, required: true, schema: { type: string, format: uuid } }
      responses: { "200": { description: ok } }
`
	for id, n := range ids(Scan(Input{Files: map[string]string{"api.yaml": safe}})) {
		if n > 0 && len(id) > 6 && id[:6] == "TG-OAS" {
			t.Errorf("a well-secured API must be clean, got %s", id)
		}
	}
}
