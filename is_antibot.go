package isantibot

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Detection specifies where the signal came from
type Detection string

const (
	DetectionHeaders    Detection = "headers"
	DetectionCookies    Detection = "cookies"
	DetectionHTML       Detection = "html"
	DetectionURL        Detection = "url"
	DetectionStatusCode Detection = "statusCode"
)

// Result is the output of the antibot detection
type Result struct {
	Detected  bool
	Provider  *string
	Detection *Detection
}

// Input is the input for the antibot detection
type Input struct {
	Headers    http.Header
	HTML       string
	Body       string
	URL        string
	StatusCode int
	Status     int
}

func createResult(detected bool, provider string, detection Detection) Result {
	var p *string
	var d *Detection
	if provider != "" {
		p = &provider
	}
	if string(detection) != "" {
		d = &detection
	}
	return Result{Detected: detected, Provider: p, Detection: d}
}

func createEmptyResult() Result {
	return Result{Detected: false, Provider: nil, Detection: nil}
}

type patternMatcher interface {
	match(value string) bool
}

type stringPattern string

func (s stringPattern) match(value string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(string(s)))
}

type regexpPattern struct {
	re *regexp.Regexp
}

func (r regexpPattern) match(value string) bool {
	return r.re.MatchString(value)
}

func newRegexpPattern(expr string) regexpPattern {
	return regexpPattern{re: regexp.MustCompile(expr)}
}

func createTestPattern(value string) func([]patternMatcher) bool {
	if value == "" {
		return func(patterns []patternMatcher) bool { return false }
	}
	return func(patterns []patternMatcher) bool {
		for _, p := range patterns {
			if p.match(value) {
				return true
			}
		}
		return false
	}
}

// Detect identifies if a response is an antibot challenge
func Detect(input Input) Result {
	headers := input.Headers
	if headers == nil {
		headers = http.Header{}
	}

	htmlContent := input.HTML
	if htmlContent == "" {
		htmlContent = input.Body
	}

	statusCode := input.StatusCode
	if statusCode == 0 {
		statusCode = input.Status
	}

	getHeader := func(name string) string {
		return headers.Get(name)
	}

	hasCookie := func(pattern string) bool {
		cookies := headers.Values("set-cookie")
		for _, c := range cookies {
			if strings.HasPrefix(strings.ToLower(c), strings.ToLower(pattern)) {
				return true
			}
		}
		return false
	}

	htmlHas := createTestPattern(htmlContent)
	urlHas := createTestPattern(input.URL)

	hasAnyHeader := func(headerNames []string) bool {
		for _, name := range headerNames {
			if getHeader(name) != "" {
				return true
			}
		}
		return false
	}

	hasAnyCookie := func(cookieNames []string) bool {
		for _, name := range cookieNames {
			if hasCookie(name) {
				return true
			}
		}
		return false
	}

	hasAnyHtml := func(patterns []patternMatcher) bool {
		return htmlHas(patterns)
	}

	hasAnyUrl := func(patterns []patternMatcher) bool {
		return urlHas(patterns)
	}

	byHeaders := func(provider string) Result { return createResult(true, provider, DetectionHeaders) }
	byCookies := func(provider string) Result { return createResult(true, provider, DetectionCookies) }
	byHtml := func(provider string) Result { return createResult(true, provider, DetectionHTML) }
	byUrl := func(provider string) Result { return createResult(true, provider, DetectionURL) }
	byStatusCode := func(provider string) Result { return createResult(true, provider, DetectionStatusCode) }

	// CloudFlare
	if getHeader("cf-mitigated") == "challenge" {
		return byHeaders("cloudflare")
	}
	if hasAnyCookie([]string{"cf_clearance="}) {
		return byCookies("cloudflare")
	}

	// Vercel
	if getHeader("x-vercel-mitigated") == "challenge" {
		return byHeaders("vercel")
	}

	// Akamai
	if strings.HasPrefix(getHeader("akamai-cache-status"), "Error") {
		return byHeaders("akamai")
	}
	if hasAnyHeader([]string{"akamai-grn", "x-akamai-session-info"}) {
		return byHeaders("akamai")
	}
	if hasAnyCookie([]string{"_abck="}) {
		return byCookies("akamai")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("bmak.")}) {
		return byHtml("akamai")
	}

	// DataDome
	if xddb := getHeader("x-dd-b"); xddb == "1" || xddb == "2" {
		return byHeaders("datadome")
	}
	if xdatadome := getHeader("x-datadome"); xdatadome != "" && strings.ToLower(xdatadome) != "protected" {
		return byHeaders("datadome")
	}
	if hasAnyHeader([]string{"x-datadome-cid"}) {
		return byHeaders("datadome")
	}
	if hasAnyCookie([]string{"datadome="}) {
		return byCookies("datadome")
	}

	// PerimeterX
	if getHeader("x-px-authorization") != "" {
		return byHeaders("perimeterx")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("window._pxAppId"), stringPattern("pxInit"), stringPattern("_pxAction")}) {
		return byHtml("perimeterx")
	}
	if hasAnyCookie([]string{"_px3=", "_pxhd="}) {
		return byCookies("perimeterx")
	}

	// Shape Security
	shapeHeaderRe := regexp.MustCompile(`(?i)^x-[a-z0-9]{8}-[abcdfz]$`)
	for name := range headers {
		if shapeHeaderRe.MatchString(name) {
			return byHeaders("shapesecurity")
		}
	}
	if hasAnyHtml([]patternMatcher{stringPattern("shapesecurity")}) {
		return byHtml("shapesecurity")
	}

	// Kasada
	if hasAnyHeader([]string{"x-kasada", "x-kasada-challenge"}) {
		return byHeaders("kasada")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("__kasada"), stringPattern("kasada.js")}) {
		return byHtml("kasada")
	}

	// Imperva/Incapsula
	if getHeader("x-cdn") == "Incapsula" || hasAnyHeader([]string{"x-iinfo"}) {
		return byHeaders("imperva")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("incapsula"), stringPattern("imperva")}) {
		return byHtml("imperva")
	}
	if hasAnyCookie([]string{"incap_ses_", "visid_incap_", "reese84="}) {
		return byCookies("imperva")
	}

	// Reblaze
	if hasAnyCookie([]string{"rbzid=", "rbzsessionid="}) {
		return byCookies("reblaze")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("reblaze")}) {
		return byHtml("reblaze")
	}

	// Cheq
	if hasAnyHtml([]patternMatcher{stringPattern("CheqSdk"), stringPattern("cheqzone.com")}) {
		return byHtml("cheq")
	}
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)cheqzone\.com`), newRegexpPattern(`(?i)cheq\.ai`)}) {
		return byUrl("cheq")
	}

	// Sucuri
	if hasAnyHtml([]patternMatcher{stringPattern("sucuri")}) {
		return byHtml("sucuri")
	}

	// ThreatMetrix
	if hasAnyHtml([]patternMatcher{stringPattern("ThreatMetrix")}) {
		return byHtml("threatmetrix")
	}
	if hasAnyUrl([]patternMatcher{stringPattern("fp/check.js")}) {
		return byUrl("threatmetrix")
	}

	// Meetrics
	if hasAnyHtml([]patternMatcher{stringPattern("meetrics")}) {
		return byHtml("meetrics")
	}
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)meetrics\.com`)}) {
		return byUrl("meetrics")
	}

	// Ocule
	if hasAnyHtml([]patternMatcher{stringPattern("ocule.co.uk")}) {
		return byHtml("ocule")
	}
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)ocule\.co\.uk`)}) {
		return byUrl("ocule")
	}

	// reCAPTCHA
	if hasAnyUrl([]patternMatcher{stringPattern("recaptcha/api"), stringPattern("gstatic.com/recaptcha"), stringPattern("recaptcha.net"), newRegexpPattern(`(?i)google\.com/recaptcha`)}) {
		return byUrl("recaptcha")
	}
	if hasAnyHtml([]patternMatcher{
		newRegexpPattern(`(?i)\b(?:window\.)?grecaptcha\s*\.(?:execute|render|ready|getResponse|enterprise)\b`),
		newRegexpPattern(`(?i)\b(?:window\.)?grecaptcha\s*\(`),
		newRegexpPattern(`(?i)\b__grecaptcha_cfg\b`),
	}) {
		return byHtml("recaptcha")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("g-recaptcha")}) {
		return byHtml("recaptcha")
	}

	// hCaptcha
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)hcaptcha\.com`)}) {
		return byUrl("hcaptcha")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("hcaptcha.com"), stringPattern("h-captcha")}) {
		return byHtml("hcaptcha")
	}

	// FunCaptcha
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)arkoselabs\.com`), stringPattern("funcaptcha")}) {
		return byUrl("funcaptcha")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("arkoselabs.com"), stringPattern("funcaptcha")}) {
		return byHtml("funcaptcha")
	}

	// GeeTest
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)geetest\.com`)}) {
		return byUrl("geetest")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("geetest")}) {
		return byHtml("geetest")
	}

	// Cloudflare Turnstile
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)challenges\.cloudflare\.com/turnstile`)}) {
		return byUrl("cloudflare-turnstile")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("cf-turnstile"), stringPattern("challenges.cloudflare.com/turnstile")}) {
		return byHtml("cloudflare-turnstile")
	}

	// Friendly Captcha
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)friendlycaptcha\.com`)}) {
		return byUrl("friendly-captcha")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("frc-captcha"), stringPattern("friendlyChallenge")}) {
		return byHtml("friendly-captcha")
	}

	// Captcha.eu
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)captcha\.eu`)}) {
		return byUrl("captcha-eu")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("CaptchaEU"), stringPattern("captchaeu")}) {
		return byHtml("captcha-eu")
	}

	// QCloud Captcha
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)turing\.captcha\.qcloud\.com`)}) {
		return byUrl("qcloud-captcha")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("TencentCaptcha"), stringPattern("turing.captcha")}) {
		return byHtml("qcloud-captcha")
	}

	// AliExpress CAPTCHA
	if hasAnyUrl([]patternMatcher{newRegexpPattern(`(?i)punish\?x5secdata`)}) {
		return byUrl("aliexpress-captcha")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("x5secdata")}) {
		return byHtml("aliexpress-captcha")
	}

	domain := ""
	if input.URL != "" {
		parsedUrl, err := url.Parse(input.URL)
		if err == nil {
			domain = parsedUrl.Hostname()
			if strings.HasPrefix(domain, "www.") {
				domain = domain[4:]
			}
		}
	}

	// Reddit
	if domain == "reddit.com" && hasAnyHtml([]patternMatcher{newRegexpPattern(`(?i)blocked by network security\.`)}) {
		return byHtml("reddit")
	}

	// LinkedIn
	if domain == "linkedin.com" && statusCode == 999 {
		return byStatusCode("linkedin")
	}

	// Instagram
	if domain == "instagram.com" && hasAnyHtml([]patternMatcher{newRegexpPattern(`(?i)<title>\s*Login\s*[•·]\s*Instagram\s*</title>`)}) {
		return byHtml("instagram")
	}

	// YouTube
	if hasAnyHtml([]patternMatcher{newRegexpPattern(`(?i)<title>\s*-\s*YouTube</title>`)}) {
		return byHtml("youtube")
	}

	// AWS WAF
	if hasAnyHeader([]string{"x-amzn-waf-action", "x-amzn-requestid"}) {
		return byHeaders("aws-waf")
	}
	if hasAnyHtml([]patternMatcher{stringPattern("aws-waf"), stringPattern("awswaf")}) {
		return byHtml("aws-waf")
	}
	if hasAnyCookie([]string{"aws-waf-token="}) {
		return byCookies("aws-waf")
	}

	return createEmptyResult()
}
