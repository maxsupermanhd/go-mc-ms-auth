package GMMAuth

// Go MC MIcroSoft Auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/Tnze/go-mc/bot"
)

// MSauth holds Microsoft auth credentials
type MSauth struct {
	AccessToken  string
	ExpiresAfter int64
	RefreshToken string
}

// AzureClientIDEnvVar Used to lookup Azure client id via os.Getenv if cid is not passed
const AzureClientIDEnvVar = "AzureClientID"

// CheckRefreshMS Checks MSauth for expired token and refreshes if needed
func CheckRefreshMS(auth *MSauth, cid string) error {
	if auth.ExpiresAfter <= time.Now().Unix() {
		if cid == "" {
			cid = os.Getenv(AzureClientIDEnvVar)
		}
		MSdata := url.Values{
			"client_id": {cid},
			// "client_secret": {os.Getenv("AzureSecret")},
			"refresh_token": {auth.RefreshToken},
			"grant_type":    {"refresh_token"},
			"redirect_uri":  {"https://login.microsoftonline.com/common/oauth2/nativeclient"},
		}
		MSresp, err := http.PostForm("https://login.live.com/oauth20_token.srf", MSdata)
		if err != nil {
			return err
		}
		var MSres map[string]interface{}
		json.NewDecoder(MSresp.Body).Decode(&MSres)
		MSresp.Body.Close()
		if MSresp.StatusCode != 200 {
			return fmt.Errorf("MS refresh attempt answered not HTTP200! Instead got %s and following json: %#v", MSresp.Status, MSres)
		}
		MSaccessToken, ok := MSres["access_token"].(string)
		if !ok {
			return errors.New("Access_token not found in response")
		}
		auth.AccessToken = MSaccessToken
		MSrefreshToken, ok := MSres["refresh_token"].(string)
		if !ok {
			return errors.New("Refresh_token not found in response")
		}
		auth.RefreshToken = MSrefreshToken
		MSexpireSeconds, ok := MSres["expires_in"].(float64)
		if !ok {
			return errors.New("Expires_in not found in response")
		}
		auth.ExpiresAfter = time.Now().Unix() + int64(MSexpireSeconds)
	}
	return nil
}

// AuthMSdevice Attempts to authorize user via device flow. Will block thread until gets error, timeout or actual authorization
func AuthMSdevice(cid string) (MSauth, error) {
	var auth MSauth
	if cid == "" {
		cid = os.Getenv(AzureClientIDEnvVar)
	}
	DeviceResp, err := http.PostForm("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode", url.Values{
		"client_id": {cid},
		"scope":     {`XboxLive.signin offline_access`},
	})
	if err != nil {
		return auth, err
	}
	var DeviceRes map[string]interface{}
	json.NewDecoder(DeviceResp.Body).Decode(&DeviceRes)
	DeviceResp.Body.Close()
	if DeviceResp.StatusCode != 200 {
		return auth, fmt.Errorf("MS device request answered not HTTP200! Instead got %s and following json: %#v", DeviceResp.Status, DeviceRes)
	}
	DeviceCode, ok := DeviceRes["device_code"].(string)
	if !ok {
		return auth, errors.New("Device code not found in response")
	}
	UserCode, ok := DeviceRes["user_code"].(string)
	if !ok {
		return auth, errors.New("User code not found in response")
	}
	log.Print("User code: ", UserCode)
	VerificationURI, ok := DeviceRes["verification_uri"].(string)
	if !ok {
		return auth, errors.New("Verification URI not found in response")
	}
	log.Print("Verification URI: ", VerificationURI)
	ExpiresIn, ok := DeviceRes["expires_in"].(float64)
	if !ok {
		return auth, errors.New("Expires In not found in response")
	}
	log.Print("Expires in: ", ExpiresIn, " seconds")
	PoolInterval, ok := DeviceRes["interval"].(float64)
	if !ok {
		return auth, errors.New("Pooling interval not found in response")
	}
	UserMessage, ok := DeviceRes["message"].(string)
	if !ok {
		return auth, errors.New("Pooling interval not found in response")
	}
	log.Println(UserMessage)
	time.Sleep(4 * time.Second)

	for {
		time.Sleep(time.Duration(int(PoolInterval)+1) * time.Second)
		CodeResp, err := http.PostForm("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", url.Values{
			"client_id":   {cid},
			"scope":       {"XboxLive.signin offline_access"},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {DeviceCode},
		})
		if err != nil {
			return auth, err
		}
		var CodeRes map[string]interface{}
		json.NewDecoder(CodeResp.Body).Decode(&CodeRes)
		CodeResp.Body.Close()
		if CodeResp.StatusCode == 400 {
			PoolError, ok := CodeRes["error"].(string)
			if !ok {
				return auth, fmt.Errorf("While pooling token got this unknown json: %#v", CodeRes)
			}
			if PoolError == "authorization_pending" {
				continue
			}
			if PoolError == "authorization_declined" {
				return auth, errors.New("User declined authorization")
			}
			if PoolError == "expired_token" {
				return auth, errors.New("Turns out " + strconv.Itoa(int(PoolInterval)) + " seconds is not enough to authorize user, go faster ma monkey")
			}
			if PoolError == "invalid_grant" {
				return auth, errors.New("While pooling token got invalid_grant error: " + CodeRes["error_description"].(string))
			}
		} else if CodeResp.StatusCode == 200 {
			MSaccessToken, ok := CodeRes["access_token"].(string)
			if !ok {
				return auth, errors.New("Access token not found in response")
			}
			auth.AccessToken = MSaccessToken
			MSrefreshToken, ok := CodeRes["refresh_token"].(string)
			if !ok {
				return auth, errors.New("Refresh token not found in response")
			}
			auth.RefreshToken = MSrefreshToken
			MSexpireSeconds, ok := CodeRes["expires_in"].(float64)
			if !ok {
				return auth, errors.New("Expires in not found in response")
			}
			auth.ExpiresAfter = time.Now().Unix() + int64(MSexpireSeconds)
			return auth, nil
		} else {
			return auth, fmt.Errorf("MS answered not HTTP200! Instead got %s and following json: %#v", CodeResp.Status, CodeRes)
		}
	}

}

// AuthMSCode Attempts to authorize user via user code (default browser flow)
func AuthMSCode(code string, cid string) (MSauth, error) {
	var auth MSauth
	if cid == "" {
		cid = os.Getenv(AzureClientIDEnvVar)
	}
	MSdata := url.Values{
		"client_id": {cid},
		// "client_secret": {os.Getenv("AzureSecret")},
		"code":         {code},
		"grant_type":   {"authorization_code"},
		"redirect_uri": {"https://login.microsoftonline.com/common/oauth2/nativeclient"},
	}
	MSresp, err := http.PostForm("https://login.live.com/oauth20_token.srf", MSdata)
	if err != nil {
		return auth, err
	}
	var MSres map[string]interface{}
	json.NewDecoder(MSresp.Body).Decode(&MSres)
	MSresp.Body.Close()
	if MSresp.StatusCode != 200 {
		return auth, fmt.Errorf("MS answered not HTTP200! Instead got %s and following json: %#v", MSresp.Status, MSres)
	}
	MSaccessToken, ok := MSres["access_token"].(string)
	if !ok {
		return auth, errors.New("Access_token not found in response")
	}
	auth.AccessToken = MSaccessToken
	MSrefreshToken, ok := MSres["refresh_token"].(string)
	if !ok {
		return auth, errors.New("Refresh_token not found in response")
	}
	auth.RefreshToken = MSrefreshToken
	MSexpireSeconds, ok := MSres["expires_in"].(float64)
	if !ok {
		return auth, errors.New("Expires_in not found in response")
	}
	auth.ExpiresAfter = time.Now().Unix() + int64(MSexpireSeconds)
	return auth, nil
}

// AuthXBL Gets XBox Live token from Microsoft token
func AuthXBL(MStoken string) (string, error) {
	XBLdataMap := map[string]interface{}{
		"Properties": map[string]interface{}{
			"AuthMethod": "RPS",
			"SiteName":   "user.auth.xboxlive.com",
			"RpsTicket":  "d=" + MStoken,
		},
		"RelyingParty": "http://auth.xboxlive.com",
		"TokenType":    "JWT",
	}
	XBLdata, err := json.Marshal(XBLdataMap)
	if err != nil {
		return "", err
	}
	XBLreq, err := http.NewRequest(http.MethodPost, "https://user.auth.xboxlive.com/user/authenticate", bytes.NewBuffer(XBLdata))
	if err != nil {
		return "", err
	}
	XBLreq.Header.Set("Content-Type", "application/json")
	XBLreq.Header.Set("Accept", "application/json")
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	XBLresp, err := client.Do(XBLreq)
	if err != nil {
		return "", err
	}
	var XBLres map[string]interface{}
	json.NewDecoder(XBLresp.Body).Decode(&XBLres)
	XBLresp.Body.Close()
	if XBLresp.StatusCode != 200 {
		return "", fmt.Errorf("XBL answered not HTTP200! Instead got %s and following json: %#v", XBLresp.Status, XBLres)
	}
	XBLtoken, ok := XBLres["Token"].(string)
	if !ok {
		return "", errors.New("Token not found in XBL response")
	}
	return XBLtoken, nil
}

// XSTSauth Holds XSTS token and UHS
type XSTSauth struct {
	Token string
	UHS   string
}

// AuthXSTS Gets XSTS token using XBL
func AuthXSTS(XBLtoken string) (XSTSauth, error) {
	var auth XSTSauth
	XSTSdataMap := map[string]interface{}{
		"Properties": map[string]interface{}{
			"SandboxId":  "RETAIL",
			"UserTokens": []string{XBLtoken},
		},
		"RelyingParty": "rp://api.minecraftservices.com/",
		"TokenType":    "JWT",
	}
	XSTSdata, err := json.Marshal(XSTSdataMap)
	if err != nil {
		return auth, err
	}
	XSTSreq, err := http.NewRequest(http.MethodPost, "https://xsts.auth.xboxlive.com/xsts/authorize", bytes.NewBuffer(XSTSdata))
	if err != nil {
		return auth, err
	}
	XSTSreq.Header.Set("Content-Type", "application/json")
	XSTSreq.Header.Set("Accept", "application/json")
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	XSTSresp, err := client.Do(XSTSreq)
	if err != nil {
		return auth, err
	}
	var XSTSres map[string]interface{}
	json.NewDecoder(XSTSresp.Body).Decode(&XSTSres)
	XSTSresp.Body.Close()
	if XSTSresp.StatusCode != 200 {
		return auth, fmt.Errorf("XSTS answered not HTTP200! Instead got %s and following json: %#v", XSTSresp.Status, XSTSres)
	}
	XSTStoken, ok := XSTSres["Token"].(string)
	if !ok {
		return auth, errors.New("Could not find Token in XSTS response")
	}
	auth.Token = XSTStoken
	XSTSdc, ok := XSTSres["DisplayClaims"].(map[string]interface{})
	if !ok {
		return auth, errors.New("Could not find DisplayClaims object in XSTS response")
	}
	XSTSxui, ok := XSTSdc["xui"].([]interface{})
	if !ok {
		return auth, errors.New("Could not find xui array in DisplayClaims object")
	}
	if len(XSTSxui) < 1 {
		return auth, errors.New("xui array in DisplayClaims object does not have any elements")
	}
	XSTSuhsObject, ok := XSTSxui[0].(map[string]interface{})
	if !ok {
		return auth, errors.New("Could not get ush object in xui array")
	}
	XSTSuhs, ok := XSTSuhsObject["uhs"].(string)
	if !ok {
		return auth, errors.New("Could not get uhs string from ush object")
	}
	auth.UHS = XSTSuhs
	return auth, nil
}

// MCauth Represents Minecraft auth response
type MCauth struct {
	Token        string
	ExpiresAfter int64
}

// AuthMC Gets Minecraft authorization from XSTS token
func AuthMC(token XSTSauth) (MCauth, error) {
	var auth MCauth
	MCdataMap := map[string]interface{}{
		"identityToken": "XBL3.0 x=" + token.UHS + ";" + token.Token,
	}
	MCdata, err := json.Marshal(MCdataMap)
	if err != nil {
		return auth, err
	}
	MCreq, err := http.NewRequest(http.MethodPost, "https://api.minecraftservices.com/authentication/login_with_xbox", bytes.NewBuffer(MCdata))
	if err != nil {
		return auth, err
	}
	MCreq.Header.Set("Content-Type", "application/json")
	MCreq.Header.Set("Accept", "application/json")
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	MCresp, err := client.Do(MCreq)
	if err != nil {
		return auth, err
	}
	var MCres map[string]interface{}
	json.NewDecoder(MCresp.Body).Decode(&MCres)
	MCresp.Body.Close()
	if MCresp.StatusCode != 200 {
		return auth, fmt.Errorf("MC answered not HTTP200! Instead got %s and following json: %#v", MCresp.Status, MCres)
	}
	MCtoken, ok := MCres["access_token"].(string)
	if !ok {
		return auth, errors.New("Could not find access_token in MC response")
	}
	auth.Token = MCtoken
	MCexpire, ok := MCres["expires_in"].(float64)
	if !ok {
		return auth, errors.New("Could not find expires_in in MC response")
	}
	auth.ExpiresAfter = time.Now().Unix() + int64(MCexpire)
	return auth, nil
}

// GetMCprofile Gets bot.Auth from token
func GetMCprofile(token string) (bot.Auth, error) {
	var profile bot.Auth
	PRreq, err := http.NewRequest("GET", "https://api.minecraftservices.com/minecraft/profile", nil)
	if err != nil {
		return profile, err
	}
	PRreq.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	PRresp, err := client.Do(PRreq)
	if err != nil {
		return profile, err
	}
	var PRres map[string]interface{}
	json.NewDecoder(PRresp.Body).Decode(&PRres)
	PRresp.Body.Close()
	if PRresp.StatusCode != 200 {
		return profile, fmt.Errorf("MC (profile) answered not HTTP200! Instead got %s and following json: %#v", PRresp.Status, PRres)
	}
	PRuuid, ok := PRres["id"].(string)
	if !ok {
		return profile, errors.New("Could not find uuid in profile response")
	}
	profile.UUID = PRuuid
	PRname, ok := PRres["name"].(string)
	if !ok {
		return profile, errors.New("Could not find username in profile response")
	}
	profile.Name = PRname
	return profile, nil
}

// DefaultCacheFilename Used to load and save Microsoft auth because it gives token that lasts from a day to a week
const DefaultCacheFilename = "./auth.cache"

// GetMCcredentials From 0 to Minecraft bot.Auth with cache using device code flow
func GetMCcredentials(CacheFilename, cid string) (bot.Auth, error) {
	var resauth bot.Auth
	var MSa MSauth
	if CacheFilename == "" {
		CacheFilename = DefaultCacheFilename
	}
	if _, err := os.Stat(CacheFilename); os.IsNotExist(err) {
		var err error
		MSa, err = AuthMSdevice(cid)
		if err != nil {
			return resauth, err
		}
		tocache, err := json.Marshal(MSa)
		if err != nil {
			return resauth, err
		}
		err = ioutil.WriteFile(CacheFilename, tocache, 0600)
		if err != nil {
			return resauth, err
		}
		log.Println("Got an authorization token, trying to authenticate XBL...")
	} else {
		cachefile, err := os.Open(CacheFilename)
		if err != nil {
			return resauth, err
		}
		defer cachefile.Close()
		cachecontent, err := ioutil.ReadAll(cachefile)
		if err != nil {
			return resauth, err
		}
		err = json.Unmarshal(cachecontent, &MSa)
		if err != nil {
			return resauth, err
		}
		MSaOld := MSa
		err = CheckRefreshMS(&MSa, cid)
		if err != nil {
			return resauth, err
		}
		if MSaOld.AccessToken != MSa.AccessToken {
			tocache, err := json.Marshal(MSa)
			if err != nil {
				return resauth, err
			}
			err = ioutil.WriteFile(CacheFilename, tocache, 0600)
			if err != nil {
				return resauth, err
			}
		}
		log.Println("Got cached authorization token, trying to authenticate XBL...")
	}

	XBLa, err := AuthXBL(MSa.AccessToken)
	if err != nil {
		return resauth, err
	}
	log.Println("Authorized on XBL, trying to get XSTS token...")

	XSTSa, err := AuthXSTS(XBLa)
	if err != nil {
		return resauth, err
	}
	log.Println("Got XSTS token, trying to get MC token...")

	MCa, err := AuthMC(XSTSa)
	if err != nil {
		return resauth, err
	}
	log.Println("Got MC token, NOT checking that you own the game because it is too complicated and going straight for MC profile...")

	resauth, err = GetMCprofile(MCa.Token)
	if err != nil {
		return resauth, err
	}
	log.Println("Got MC profile")
	log.Println("UUID: " + resauth.UUID)
	log.Println("Name: " + resauth.Name)
	resauth.AsTk = MCa.Token
	return resauth, nil
}
