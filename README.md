<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/microlinkhq/cdn/raw/master/dist/logo/banner-dark.png">
  <img alt="microlink cdn" src="https://github.com/microlinkhq/cdn/raw/master/dist/logo/banner.png" align="center">
</picture>

![Last version](https://img.shields.io/github/tag/microlinkhq/is-antibot.svg?style=flat-square)
[![Coverage Status](https://img.shields.io/coveralls/microlinkhq/is-antibot.svg?style=flat-square)](https://coveralls.io/github/microlinkhq/is-antibot)
[![NPM Status](https://img.shields.io/npm/dm/is-antibot.svg?style=flat-square)](https://www.npmjs.org/package/is-antibot)

> Identify if a response is an antibot challenge from CloudFlare, Akamai, DataDome, Vercel, and more.

**Note:** This project is a Golang port of the original JavaScript library [is-antibot](https://github.com/microlinkhq/is-antibot).

## Supported Providers

### Anti-Bot Systems

- **CloudFlare** - Bot management and challenge pages
- **Vercel** - Attack mode protection
- **Akamai** - Bot Manager and Web Application Protector
- **DataDome** - Bot protection with CAPTCHA challenges
- **PerimeterX** - Behavioral bot detection
- **Shape Security** - Enterprise bot management
- **Kasada** - Advanced bot mitigation
- **Imperva/Incapsula** - Web application firewall
- **AWS WAF** - Amazon Web Services Web Application Firewall
- **Reblaze** - Cloud-based web security platform
- **Cheq** - Bot detection and prevention
- **Sucuri** - Website security platform and WAF
- **ThreatMetrix** - LexisNexis fraud prevention and device fingerprinting
- **Meetrics** - User authenticity verification
- **Ocule** - Bot detection with advanced obfuscation
- **YouTube** - BotGuard attestation and abuse detection
- **LinkedIn** - Bot filter protection
- **Reddit** - Network security challenge-page detection

### CAPTCHA Providers

- **reCAPTCHA** - Google's CAPTCHA service (v2 and v3)
- **hCaptcha** - Privacy-focused CAPTCHA alternative
- **FunCaptcha** - Arkose Labs interactive challenges
- **GeeTest** - AI-powered CAPTCHA
- **Cloudflare Turnstile** - Privacy-preserving CAPTCHA alternative
- **Friendly Captcha** - GDPR-compliant privacy-first CAPTCHA
- **Captcha.eu** - European GDPR-compliant CAPTCHA service
- **QCloud Captcha** - Tencent Cloud CAPTCHA service
- **AliExpress CAPTCHA** - AliExpress x5sec security challenge

## Why

Websites receiving massive quantities of traffic throughout the day, like LinkedIn, Reddit, Instagram, or YouTube, have sophisticated antibot systems to prevent automated access.

When you try to fetch the HTML of these sites without the right tools, you often hit a 403 Forbidden, 429 Too Many Requests, or a "Please prove you're human" challenge, leaving you with a response that contains no useful data.

**is-antibot** is a lightweight, vendor-agnostic Golang library that identifies when a response is actually an antibot challenge, helping you understand when and why your request was blocked.

## Install

```bash
go get github.com/ba0f3/is-antibot-go
```

## Usage

Just pass `Headers`, `HTML`, `URL`, and `StatusCode` from any HTTP response:

```go
package main

import (
	"fmt"
	"io"
	"net/http"

	isantibot "github.com/ba0f3/is-antibot-go"
)

func main() {
	resp, err := http.Get("https://www.linkedin.com/in/kikobeats/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	html := string(bodyBytes)

	result := isantibot.Detect(isantibot.Input{
		Headers:    resp.Header,
		StatusCode: resp.StatusCode,
		HTML:       html,
		URL:        resp.Request.URL.String(),
	})

	if result.Detected {
		fmt.Printf("Antibot detected: %s via %s\n", *result.Provider, *result.Detection)
	}
}
```

The library returns a `Result` struct with the following properties:

- `Detected` (bool): Whether an antibot challenge was detected
- `Provider` (*string): The name of the detected provider (e.g., 'cloudflare', 'recaptcha')
- `Detection` (*Detection): Where the signal came from: `'headers'`, `'cookies'`, `'html'`, `'url'`, or `'statusCode'`

## License

**is-antibot** © [microlink.io](https://microlink.io), released under the [MIT](https://github.com/microlinkhq/is-antibot/blob/master/LICENSE.md) License.<br>
Authored and maintained by [microlink.io](https://microlink.io) with help from [contributors](https://github.com/microlinkhq/is-antibot/contributors).

> [microlink.io](https://microlink.io) · GitHub [microlink.io](https://github.com/microlinkhq) · X [@microlinkhq](https://x.com/microlinkhq)
