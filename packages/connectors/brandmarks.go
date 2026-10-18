package connectors

import (
	"embed"
	"regexp"
	"unicode/utf8"
)

// brandmarkFiles contains only reviewed, canonical single-path brand vectors.
// It is separate from definitions, whose directories contain provider manifests.
//
//go:embed brandmarks/*.svg
var brandmarkFiles embed.FS

const brandmarkMaximumBytes = 32 * 1024

// The complete grammar is shared with consumers: no optional attributes,
// references, CSS, executable nodes, or caller-selected SVG documents.
var brandmarkCanonical = regexp.MustCompile(`^<svg xmlns="http://www\.w3\.org/2000/svg" viewBox="0 0 24 24"><path fill="#[0-9A-F]{6}" d="[Mm][MmZzLlHhVvCcSsQqTtAa0-9eE.,+ -]*"/></svg>$`)

func validBrandmarkSVG(raw []byte) bool {
	return len(raw) > 0 && len(raw) <= brandmarkMaximumBytes && utf8.Valid(raw) && brandmarkCanonical.Match(raw)
}

// Brandmark returns a reviewed brand's immutable SVG, or an empty string when
// the exact provider ID has no verified mark. It never fetches remote assets or
// substitutes a similarly named brand. The returned text is a copy.
func Brandmark(id string) string {
	path, ok := brandmarkPaths[id]
	if !ok {
		return ""
	}
	raw, err := brandmarkFiles.ReadFile(path)
	if err != nil || !validBrandmarkSVG(raw) {
		return ""
	}
	return string(raw)
}

// Populated only from exact brand identities recorded in brandmark-sources.json.
var brandmarkPaths = map[string]string{
	"airtable":      "brandmarks/airtable.svg",
	"asana":         "brandmarks/asana.svg",
	"better_stack":  "brandmarks/better_stack.svg",
	"box":           "brandmarks/box.svg",
	"brevo":         "brandmarks/brevo.svg",
	"brex":          "brandmarks/brex.svg",
	"cal_com":       "brandmarks/cal_com.svg",
	"calendly":      "brandmarks/calendly.svg",
	"cloudflare":    "brandmarks/cloudflare.svg",
	"coda":          "brandmarks/coda.svg",
	"coinmarketcap": "brandmarks/coinmarketcap.svg",
	"contentful":    "brandmarks/contentful.svg",
	"digitalocean":  "brandmarks/digitalocean.svg",
	"dovetail":      "brandmarks/dovetail.svg",
	"dropbox":       "brandmarks/dropbox.svg",
	"elevenlabs":    "brandmarks/elevenlabs.svg",
	"figma":         "brandmarks/figma.svg",
	"gitbook":       "brandmarks/gitbook.svg",
	"gitlab":        "brandmarks/gitlab.svg",
	"gusto":         "brandmarks/gusto.svg",
	"hubspot":       "brandmarks/hubspot.svg",
	"hugging_face":  "brandmarks/hugging_face.svg",
	"linear":        "brandmarks/linear.svg",
	"lucid":         "brandmarks/lucid.svg",
	"miro":          "brandmarks/miro.svg",
	"neon":          "brandmarks/neon.svg",
	"netlify":       "brandmarks/netlify.svg",
	"posthog":       "brandmarks/posthog.svg",
	"postman":       "brandmarks/postman.svg",
	"railway":       "brandmarks/railway.svg",
	"render":        "brandmarks/render.svg",
	"resend":        "brandmarks/resend.svg",
	"revenuecat":    "brandmarks/revenuecat.svg",
	"spotify":       "brandmarks/spotify.svg",
	"stripe":        "brandmarks/stripe.svg",
	"supabase":      "brandmarks/supabase.svg",
	"surveymonkey":  "brandmarks/surveymonkey.svg",
	"ticktick":      "brandmarks/ticktick.svg",
	"todoist":       "brandmarks/todoist.svg",
	"typeform":      "brandmarks/typeform.svg",
	"vercel":        "brandmarks/vercel.svg",
	"webex":         "brandmarks/webex.svg",
	"webflow":       "brandmarks/webflow.svg",
	"wistia":        "brandmarks/wistia.svg",
	"zoom":          "brandmarks/zoom.svg",
}
