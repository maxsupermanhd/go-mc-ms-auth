# go-mc-ms-auth
### GOlang MineCraft MicroSoft AUTHenticator
[![Go Reference](https://pkg.go.dev/badge/github.com/maxsupermanhd/go-mc-ms-auth.svg)](https://pkg.go.dev/github.com/maxsupermanhd/go-mc-ms-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/maxsupermanhd/go-mc-ms-auth)](https://goreportcard.com/report/github.com/maxsupermanhd/go-mc-ms-auth)

Require Go version: 1.16

Package for getting Auth object from Microsoft to use with Tnze/go-mc.

Example:

```go
mauth, err := GMMAuth.GetMCcredentials("", "")
if err != nil {
	log.Print(err)
	return
}
log.Print("Authenticated as ", mauth.Name, " (", mauth.UUID, ")")
mcClient := bot.NewClient()
mcClient.Auth = mauth
// client can go brrr
```
