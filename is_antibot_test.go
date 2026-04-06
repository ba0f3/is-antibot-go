package isantibot

import (
	"net/http"
	"testing"
)

func TestCloudflareCfMitigatedHeader(t *testing.T) {
	headers := http.Header{"Cf-Mitigated": []string{"challenge"}}
	result := Detect(Input{Headers: headers})
	if !result.Detected || *result.Provider != "cloudflare" || *result.Detection != DetectionHeaders {
		t.Errorf("Expected cloudflare headers, got %v", result)
	}
}

func TestCloudflareCfClearanceCookie(t *testing.T) {
	headers := http.Header{"Set-Cookie": []string{"cf_clearance=abc123; path=/"}}
	result := Detect(Input{Headers: headers})
	if !result.Detected || *result.Provider != "cloudflare" || *result.Detection != DetectionCookies {
		t.Errorf("Expected cloudflare cookies, got %v", result)
	}
}

func TestVercel(t *testing.T) {
	headers := http.Header{"X-Vercel-Mitigated": []string{"challenge"}}
	result := Detect(Input{Headers: headers})
	if !result.Detected || *result.Provider != "vercel" {
		t.Errorf("Expected vercel, got %v", result)
	}
}

func TestAkamaiCacheStatus(t *testing.T) {
	headers := http.Header{"Akamai-Cache-Status": []string{"Error from child"}}
	result := Detect(Input{Headers: headers})
	if !result.Detected || *result.Provider != "akamai" {
		t.Errorf("Expected akamai, got %v", result)
	}
}

func TestDatadomeXddb(t *testing.T) {
	for _, val := range []string{"1", "2"} {
		headers := http.Header{"X-Dd-B": []string{val}}
		result := Detect(Input{Headers: headers})
		if !result.Detected || *result.Provider != "datadome" {
			t.Errorf("Expected datadome for x-dd-b=%s, got %v", val, result)
		}
	}
}

func TestPerimeterXHeader(t *testing.T) {
	headers := http.Header{"X-Px-Authorization": []string{"test"}}
	result := Detect(Input{Headers: headers})
	if !result.Detected || *result.Provider != "perimeterx" {
		t.Errorf("Expected perimeterx, got %v", result)
	}
}

func TestShapeSecurityHeader(t *testing.T) {
	headers := http.Header{"X-Abc12345-A": []string{"test"}}
	result := Detect(Input{Headers: headers})
	if !result.Detected || *result.Provider != "shapesecurity" {
		t.Errorf("Expected shapesecurity, got %v", result)
	}
}

func TestKasadaHtml(t *testing.T) {
	html := "<script>__kasada.init();</script>"
	result := Detect(Input{HTML: html})
	if !result.Detected || *result.Provider != "kasada" {
		t.Errorf("Expected kasada, got %v", result)
	}
}

func TestImpervaHeader(t *testing.T) {
	headers := http.Header{"X-Cdn": []string{"Incapsula"}}
	result := Detect(Input{Headers: headers})
	if !result.Detected || *result.Provider != "imperva" {
		t.Errorf("Expected imperva, got %v", result)
	}
}

func TestRecaptchaUrl(t *testing.T) {
	url := "https://www.google.com/recaptcha/api.js"
	result := Detect(Input{URL: url})
	if !result.Detected || *result.Provider != "recaptcha" {
		t.Errorf("Expected recaptcha, got %v", result)
	}
}

func TestRecaptchaHtml(t *testing.T) {
	html := "<script>grecaptcha.execute();</script>"
	result := Detect(Input{HTML: html})
	if !result.Detected || *result.Provider != "recaptcha" {
		t.Errorf("Expected recaptcha, got %v", result)
	}
}

func TestRedditBlockedHtml(t *testing.T) {
	html := "<div>blocked by network security.</div>"
	url := "https://www.reddit.com/r/lotus/comments/1pzbv0z/my_lotus_elise_72d_with_17_rays_volk_gtp/"
	result := Detect(Input{HTML: html, URL: url})
	if !result.Detected || *result.Provider != "reddit" || *result.Detection != DetectionHTML {
		t.Errorf("Expected reddit html, got %v", result)
	}
}

func TestLinkedinStatus999(t *testing.T) {
	result := Detect(Input{StatusCode: 999, URL: "https://www.linkedin.com/in/wesbos"})
	if !result.Detected || *result.Provider != "linkedin" || *result.Detection != DetectionStatusCode {
		t.Errorf("Expected linkedin statusCode, got %v", result)
	}
}

func TestInstagramRedirect(t *testing.T) {
	html := "<!DOCTYPE html><html lang=\"en\"><head><title>Login \u2022 Instagram</title></head><body></body></html>"
	result := Detect(Input{HTML: html, URL: "https://www.instagram.com/kikobeats/"})
	if !result.Detected || *result.Provider != "instagram" || *result.Detection != DetectionHTML {
		t.Errorf("Expected instagram html, got %v", result)
	}
}

func TestYoutubeEmptyTitle(t *testing.T) {
	html := "<!DOCTYPE html><html><head><title> - YouTube</title></head><body><ytd-app disable-upgrade=\"true\"></ytd-app></body></html>"
	result := Detect(Input{HTML: html})
	if !result.Detected || *result.Provider != "youtube" {
		t.Errorf("Expected youtube, got %v", result)
	}
}

func TestNoAntibot(t *testing.T) {
	result := Detect(Input{})
	if result.Detected || result.Provider != nil || result.Detection != nil {
		t.Errorf("Expected no antibot, got %v", result)
	}
}

func TestFallbackBodyString(t *testing.T) {
	result := Detect(Input{Body: "<script>grecaptcha.execute();</script>"})
	if !result.Detected || *result.Provider != "recaptcha" {
		t.Errorf("Expected recaptcha, got %v", result)
	}
}

func TestAwsWafToken(t *testing.T) {
	headers := http.Header{"Set-Cookie": []string{"aws-waf-token=abc123; path=/"}}
	result := Detect(Input{Headers: headers})
	if !result.Detected || *result.Provider != "aws-waf" {
		t.Errorf("Expected aws-waf, got %v", result)
	}
}

func TestStatusFallback(t *testing.T) {
	result := Detect(Input{Status: 999, URL: "https://www.linkedin.com/in/wesbos"})
	if !result.Detected || *result.Provider != "linkedin" {
		t.Errorf("Expected linkedin with Status fallback, got %v", result)
	}
}
