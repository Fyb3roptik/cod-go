package cod

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
	"log"
)

const (
	CSRF_URL  = "https://profile.callofduty.com/cod/login"
	LOGIN_URL = "https://profile.callofduty.com/do_login?new_SiteId=cod"
	USER_URL  = "https://profile.callofduty.com/cod/userInfo"
	STATS_URL = "https://my.callofduty.com/api/papi-client/crm/cod/v2/title/mw/platform"
)

// AUTHENTICATION Structs
type Session struct {
	Xsrf         string
	Atkn         string
	Rtkn         string
	ActSsoCookie string
	Cookies      []*http.Cookie
}
type Identity struct {
	Identities []UserData `json:"identities"`
}
type UserData struct {
	Username string `json:"username"`
	Provider string `json:"provider"`
}

// Player Data Structs
type RawRecentMatchesResponse struct {
	Data *MatchData `json:"data"`
}
type MatchData struct {
	Matches []Match `json:"matches"`
}
type Match struct {
	UtcStartSeconds int          `json:"utcStartSeconds"`
	UtcEndSeconds   int          `json:"utcEndSeconds"`
	Map             string       `json:"map"`
	Mode            string       `json:"mode"`
	MatchID         string       `json:"matchID"`
	Duration        int64        `json:"duration"`
	GameType        string       `json:"gameType"`
	PlayerCount     int          `json:"playerCount"`
	PlayerStats     *PlayerStats `json:"playerStats"`
	Player          *Player      `json:"player"`
	TeamCount       int          `json:"teamCount"`
	Draw            bool         `json:"draw"`
	PrivateMatch    bool         `json:"privateMatch"`
}
type Player struct {
	Team     string  `json:"team"`
	Rank     float64 `json:"rank"`
	Username string  `json:"username"`
}
type PlayerStats struct {
	Kills            float64 `json:"kills"`
	MedalXp          float64 `json:"medalXp"`
	MatchXp          float64 `json:"matchXp"`
	ScoreXp          float64 `json:"scoreXp"`
	Score            float64 `json:"score"`
	TotalXp          float64 `json:"totalXp"`
	Heashots         float64 `json:"headshots"`
	Assists          float64 `json:"assists"`
	ChallengeXp      float64 `json:"challengeXp"`
	Rank             float64 `json:"rank"`
	ScorePerMinute   float64 `json:"scorePerMinute"`
	DistanceTraveled float64 `json:"distanceTraveled"`
	TeamSurvivalTime float64 `json:"teamSurvivalTime"`
	Deaths           float64 `json:"deaths"`
	KdRatio          float64 `json:"kdRatio"`
	BonusXp          float64 `json:"bonusXp"`
	GulagDeaths      float64 `json:"gulagDeaths"`
	TimePlayed       float64 `json:"timePlayed"`
	Executions       float64 `json:"executions"`
	GulagKills       float64 `json:"gulagKills"`
	MiscXp           float64 `json:"miscXp"`
	LongestStreak    float64 `json:"longestStreak"`
	TeamPlacement    float64 `json:"teamPlacement"`
	DamageDone       float64 `json:"damageDone"`
	DamageTaken      float64 `json:"damageTaken"`
}

func Login(username string, password string) (*Session, error) {
	jar, _ := cookiejar.New(nil)

	// CSRF FIRST
	resp, err := http.Get(CSRF_URL)
	if err != nil {
		return nil, err
	}

	session := &Session{}
	cookies := []*http.Cookie{}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "XSRF-TOKEN" {
			session.Xsrf = cookie.Value
		}
		cookie := &http.Cookie{
			Name:   cookie.Name,
			Value:  cookie.Value,
			Path:   "/",
			Domain: ".callofduty.com",
		}
		cookies = append(cookies, cookie)
	}

	u, _ := url.Parse("https://callofduty.com/")
	jar.SetCookies(u, cookies)
	timeout := time.Duration(10 * time.Second)
	client := http.Client{
		Timeout: timeout,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Login Form
	data := url.Values{}
	data.Add("username", username)
	data.Add("password", password)
	data.Add("remember_me", "true")
	data.Add("_csrf", session.Xsrf)
	req, err := http.NewRequest("POST", LOGIN_URL, strings.NewReader(data.Encode()))
	req.Header.Set("Cookie", fmt.Sprintf("XSRF-TOKEN=%s", session.Xsrf))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	location, _ := resp.Location()
	if strings.Contains(location.String(), "failure") {
		errors.New("Invalid Login")
		return nil, err
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "atkn" {
			session.Atkn = cookie.Value
		}
		if cookie.Name == "rtkn" {
			session.Rtkn = cookie.Value
		}
		if cookie.Name == "ACT_SSO_COOKIE" {
			session.ActSsoCookie = cookie.Value
		}
		log.Println("DEBUG: COOKIE NAME ", cookie.Name)
		log.Println("DEBUG: COOKIE VALUE ", cookie.Value)
	}
	session.Cookies = resp.Cookies()
	return session, nil
}

// Title options: mw, bo4, wwii
func (c Session) GetIdentities() (*Identity, error) {
	jar, _ := cookiejar.New(nil)

	u, _ := url.Parse("https://callofduty.com/")
	timeout := time.Duration(10 * time.Second)
	client := http.Client{
		Timeout: timeout,
		Jar:     jar,
	}
	cookie_string_slice := []string{}
	for _, cookie := range c.Cookies {
		if cookie.Name == "XSRF-TOKEN" {
			cookie.Value = c.Xsrf
		}
		if cookie.Name == "ACT_SSO_COOKIE" {
			c.ActSsoCookie = cookie.Value
		}
		// log.Println("DEBUG: COOKIE NAME ", cookie.Name)
		// log.Println("DEBUG: COOKIE VALUE ", cookie.Value)
		cookie_string := fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
		cookie_string_slice = append(cookie_string_slice, cookie_string)
	}
	jar.SetCookies(u, c.Cookies)
	cookie_string := strings.Join(cookie_string_slice, ";")
	user_url := fmt.Sprintf("%s/%s", USER_URL, c.ActSsoCookie)
	log.Println("DEBUG: URL ", user_url)
	req, err := http.NewRequest("GET", user_url, nil)
	req.Header.Set("Cookie", cookie_string)
	req.Header.Set("X-XSRF-TOKEN", c.Xsrf)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	identities := &Identity{}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	bodyString := strings.TrimSuffix(strings.Replace(string(bodyBytes), "userInfo(", "", 1), ");")
	err = json.Unmarshal([]byte(bodyString), identities)
	if err != nil {
		return nil, err
	}

	if len(identities.Identities) == 0 {
		return nil, errors.New("No Linked Accounts Found")
	}
	for _, identity := range identities.Identities {
		if identity.Provider == "battle" || identity.Provider == "xbl" || identity.Provider == "psn" {
			identities.Identities = append(identities.Identities, identity)
		}
	}

	return identities, nil
}

// Platform options: uno(Activision), xbl(Xbox), psn(Playstation), battle(PC)
func (c Session) GetPlayerStats(platform string, username string) ([]Match, error) {
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("https://callofduty.com/")
	jar.SetCookies(u, c.Cookies)
	timeout := time.Duration(10 * time.Second)
	client := http.Client{
		Timeout: timeout,
		Jar:     jar,
	}
	cookie_string_slice := []string{}
	for _, cookie := range c.Cookies {
		cookie_string_slice = append(cookie_string_slice, cookie.String())
	}
	cookie_string := strings.Join(cookie_string_slice, ";")

	stats_url := fmt.Sprintf("%s/%s/gamer/%s/matches/wz/start/0/end/0/details?", STATS_URL, platform, url.QueryEscape(username))
	req, err := http.NewRequest("GET", stats_url, nil)
	req.Header.Set("Cookie", cookie_string)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw_resp := &RawRecentMatchesResponse{}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(bodyBytes, raw_resp)
	if err != nil {
		return nil, err
	}
	return raw_resp.Data.Matches, nil
}
