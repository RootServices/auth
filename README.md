# gateway-auth
A Traefik Plugin that verifies JWTs from Google Cloud Identity Platform including checking with the Google ID Server if the token is still active.

## About
Follows the Traefik plugin [docs](https://plugins.traefik.io/create) and example [repository](https://github.com/traefik/plugindemo).

## Configuration

| Field             | Type   | Description                                                                 | Default |
| ----------------- | ------ | --------------------------------------------------------------------------- | ------- |
| `headerName`      | string | The name of the header to look for the token.                               | `""`    |
| `provider`        | string | The authentication provider. Allowed values: `google`, `firebase`.          | `""`    |
| `audience`        | string | The expected audience (aud) claim in the token.                             | `""`    |
| `forwardHeaderName`| string | The header name to use when forwarding the validated token to the backend.  | `"X-Forward-IdToken"`    |
| `required`        | bool   | If `true`, the request will be rejected if the token is missing or invalid. | `true` |


## Contributing

Please feel free to Fork then Submit a Pull Request.

## Index

- Google ID Token Validation [Go Lang Package](https://pkg.go.dev/google.golang.org/api/idtoken) 
- Firebase Auth [Go Lang Package](https://pkg.go.dev/firebase.google.com/go/v4/auth)
- Traefik Plugin Create [docs](https://plugins.traefik.io/create)
- Traefik Example Plugin [repository](https://github.com/traefik/plugindemo)
- Logging was sourced from crowdsec-bouncer-traefik-plugin [repository](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/pkg/logger/logger.go