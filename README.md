# go-mc-ms-auth

[![Go Reference](https://pkg.go.dev/badge/github.com/maxsupermanhd/go-mc-ms-auth.svg)](https://pkg.go.dev/github.com/maxsupermanhd/go-mc-ms-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/maxsupermanhd/go-mc-ms-auth)](https://goreportcard.com/report/github.com/maxsupermanhd/go-mc-ms-auth)

Require Go version: 1.16

Package for getting Minecraft credentials from Microsoft.

Example:

```go
mauth, err := GMMAuth.GetMCcredentials("./auth.cache", "88650e7e-efee-4857-b9a9-cf580a00ef43")
if err != nil {
    log.Print(err)
    return
}
log.Print("Authenticated as ", mauth.Name, " (", mauth.UUID, ")")
mcClient := bot.NewClient()
mcClient.Auth = mauth
// client can go brrr
```

What is AzureAppId and how to get one: see issue #2\
TLDR: you can use this one: `88650e7e-efee-4857-b9a9-cf580a00ef43`

