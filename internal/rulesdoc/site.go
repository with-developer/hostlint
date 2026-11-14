package rulesdoc

import (
	"fmt"
	"html"
	"slices"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
)

// pageText is what differs between the pages of the profiles: the language and the words of the page.
type pageText struct {
	lang, locale, url, home, homeLabel, cssPath string
	title, desc, h1, lead, cmd, hint, tocLabel  string
	// per check
	why, fix, human, importance, handOnly, params string
	// per control: the label of the severity words
	severity func(engine.Severity) string
	// title, description and so on in the language of the page
	pick func(ko, en string) string
	// footer
	footer string
}

// RenderKISASiteKo returns the Korean project page of the KISA profile (site/ko/kisa/index.html): every control with the
// checks behind it, in Korean, as a static page that a search engine can read. It is made from the same rules as the rule
// reference, so it cannot drift from them. The control IDs come from the guide; the titles and texts are vmsctl's own.
func RenderKISASiteKo(content *engine.Content, profileID string) (string, error) {
	p := content.Profiles[profileID]
	if p == nil {
		return "", fmt.Errorf("no profile %q", profileID)
	}
	first, last := p.Controls[0].ID, p.Controls[len(p.Controls)-1].ID
	return renderProfilePage(content, p, pageText{
		lang: "ko", locale: "ko_KR", url: "https://with-developer.github.io/vmsctl/ko/kisa/", home: "../", homeLabel: "홈", cssPath: "../../style.css",
		title:    fmt.Sprintf("KISA 2026 Unix 서버 점검 항목 %s~%s: 점검 내용과 조치 방법 — vmsctl", first, last),
		desc:     fmt.Sprintf("주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드(2026) Unix 서버 점검 항목 %d개가 무엇을 보고, 왜 중요하고, 어떻게 고치는지 한국어로 정리했습니다. vmsctl이 각 항목을 자동으로 점검합니다.", len(p.Controls)),
		h1:       fmt.Sprintf("KISA 2026 Unix 서버 점검 항목 %s~%s", first, last),
		lead:     fmt.Sprintf("주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드(2026)의 Unix 서버 점검 항목 %d개가 각각 무엇을 보고, 왜 중요하고, 어떻게 고치는지 정리했습니다. 점검 항목 번호는 가이드의 것이고, 제목과 설명은 vmsctl이 직접 쓴 것입니다. 아래 항목은 모두 <code>vmsctl</code>이 서버에서 읽기만 하며 자동으로 점검하고, 사람이 판단해야 하는 항목은 근거를 모아 보여 줍니다.", len(p.Controls)),
		cmd:      "curl -fsSL https://raw.githubusercontent.com/with-developer/vmsctl/main/install.sh | sh\nsudo vmsctl scan --profile kisa-2026 --lang ko",
		hint:     "결과마다 값과 파일, 줄 번호가 근거로 붙고, 조치 방법은 <code>vmsctl explain 점검ID --lang ko</code>로도 볼 수 있습니다. 설치와 사용법은 <a href=\"../\">vmsctl 소개</a>와 <a href=\"https://github.com/with-developer/vmsctl/blob/main/README.ko.md\">README</a>를 보세요.",
		tocLabel: "점검 항목 목록", why: "왜 중요한가.", fix: "조치 방법.", human: "사람이 판단합니다.", importance: "중요도", handOnly: "이 항목은 자동 점검이 없고 사람이 직접 검토합니다.", params: "이 항목에서 쓰는 값",
		severity: sev,
		pick:     ko,
		footer:   "<span>Apache-2.0 라이선스 · <a href=\"https://github.com/with-developer/vmsctl\">github.com/with-developer/vmsctl</a></span>\n    <span><a href=\"https://github.com/with-developer/vmsctl/blob/main/docs/rules.ko.md\">전체 규칙 참조</a> · <a href=\"../\">vmsctl 소개</a></span>",
	})
}

var severityEn = map[engine.Severity]string{"high": "high (CAT I)", "medium": "medium (CAT II)", "low": "low (CAT III)"}

// RenderStigSiteEn returns the English page of the DISA STIG profile for Ubuntu 22.04 (site/stig/ubuntu2204/index.html).
func RenderStigSiteEn(content *engine.Content, profileID string) (string, error) {
	p := content.Profiles[profileID]
	if p == nil {
		return "", fmt.Errorf("no profile %q", profileID)
	}
	return renderProfilePage(content, p, pageText{
		lang: "en", locale: "en_US", url: "https://with-developer.github.io/vmsctl/stig/ubuntu2204/", home: "../../", homeLabel: "Home", cssPath: "../../style.css",
		title:    fmt.Sprintf("Ubuntu 22.04 STIG: the %d controls vmsctl checks, and how to fix them — vmsctl", len(p.Controls)),
		desc:     fmt.Sprintf("The %d controls of the DISA STIG for Canonical Ubuntu 22.04 LTS (V2R8) that vmsctl checks on a server: what each one looks at, why it matters and how to fix it. Not a complete STIG assessment.", len(p.Controls)),
		h1:       fmt.Sprintf("Ubuntu 22.04 STIG: the %d controls vmsctl checks", len(p.Controls)),
		lead:     fmt.Sprintf("These are %d of the 188 controls of the DISA Security Technical Implementation Guide for Canonical Ubuntu 22.04 LTS (V2R8) that <code>vmsctl</code> can decide by reading the host, each with what it looks at, why it matters and how to fix it. <strong>This is not a complete STIG assessment:</strong> the other controls (audit rules, file ownership of system commands, smart cards, FIPS, the boot loader password, ...) are not checked yet. The control IDs and importance are the STIG's, a US government work; the titles and texts are vmsctl's own. A check is mapped only when it decides exactly what the STIG requires.", len(p.Controls)),
		cmd:      "curl -fsSL https://raw.githubusercontent.com/with-developer/vmsctl/main/install.sh | sh\nsudo vmsctl scan --profile stig-ubuntu2204",
		hint:     "Every result carries its evidence (the value, the file and the line); <code>vmsctl explain UBTU-22-255040</code> prints a control in the terminal. What the profile covers: <a href=\"https://github.com/with-developer/vmsctl/blob/main/docs/stig.md\">docs/stig.md</a>. About the tool: <a href=\"../../\">vmsctl</a>.",
		tocLabel: "Controls", why: "Why it matters.", fix: "How to fix it.", human: "A person decides.", importance: "Importance", handOnly: "This control has no automatic check: a person reviews it.", params: "Values used for this control",
		severity: func(s engine.Severity) string {
			if v, ok := severityEn[s]; ok {
				return v
			}
			return string(s)
		},
		pick:   func(_, en string) string { return oneLine(en) },
		footer: "<span>Apache-2.0 license · <a href=\"https://github.com/with-developer/vmsctl\">github.com/with-developer/vmsctl</a></span>\n    <span><a href=\"https://github.com/with-developer/vmsctl/blob/main/docs/rules.md\">Rule reference</a> · <a href=\"../../\">About vmsctl</a></span>",
	})
}

func renderProfilePage(content *engine.Content, p *engine.Profile, t pageText) (string, error) {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	// the text of an English page is the English one, and of a Korean page the Korean one where there is one
	title := func(c engine.Control) string { return t.pick(c.TitleKo, c.Title) }

	w("<!doctype html>\n<!-- Generated by `make docs` from rules/ and profiles/. Do not edit. -->\n")
	w("<html lang=\"%s\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n", t.lang)
	w("<title>%s</title>\n", html.EscapeString(t.title))
	w("<meta name=\"description\" content=\"%s\">\n", html.EscapeString(t.desc))
	w("<meta name=\"color-scheme\" content=\"light dark\">\n")
	w("<link rel=\"canonical\" href=\"%s\">\n", t.url)
	w("<meta property=\"og:type\" content=\"article\">\n<meta property=\"og:site_name\" content=\"vmsctl\">\n<meta property=\"og:locale\" content=\"%s\">\n", t.locale)
	w("<meta property=\"og:title\" content=\"%s\">\n<meta property=\"og:description\" content=\"%s\">\n<meta property=\"og:url\" content=\"%s\">\n", html.EscapeString(t.title), html.EscapeString(t.desc), t.url)
	w("<link rel=\"stylesheet\" href=\"%s\">\n</head>\n<body>\n", t.cssPath)
	w("<header class=\"top\">\n  <div class=\"wrap\">\n    <a class=\"brand\" href=\"%s\">vmsctl</a>\n    <nav>\n      <a href=\"https://github.com/with-developer/vmsctl\">GitHub</a>\n      <a class=\"lang\" href=\"%s\">%s</a>\n    </nav>\n  </div>\n</header>\n", t.home, t.home, t.homeLabel)
	w("<main>\n<article class=\"wrap doc\">\n")
	w("<h1>%s</h1>\n", html.EscapeString(t.h1))
	w("<p class=\"lead\">%s</p>\n", t.lead)
	w("<pre class=\"cmd\" tabindex=\"0\"><code>%s</code></pre>\n", t.cmd)
	w("<p class=\"muted\">%s</p>\n", t.hint)

	w("<nav class=\"toc\" aria-label=\"%s\">\n<ul>\n", t.tocLabel)
	for _, c := range p.Controls {
		w("<li><a href=\"#%s\"><b>%s</b> %s</a></li>\n", anchorID(c.ID), html.EscapeString(c.ID), html.EscapeString(title(c)))
	}
	w("</ul>\n</nav>\n")

	for _, c := range p.Controls {
		w("<section class=\"control\" id=\"%s\">\n<h2><span class=\"cid\">%s</span> %s</h2>\n", anchorID(c.ID), html.EscapeString(c.ID), html.EscapeString(title(c)))
		w("<p class=\"meta\">%s <b class=\"sev-%s\">%s</b></p>\n", t.importance, html.EscapeString(string(c.Severity)), html.EscapeString(t.severity(c.Severity)))
		if len(c.Checks) == 0 {
			w("<p>%s %s</p>\n", t.handOnly, html.EscapeString(t.pick(c.ManualKo, c.Manual)))
		}
		for _, ref := range c.Checks {
			ck := content.Checks[ref]
			if ck == nil {
				continue
			}
			w("<div class=\"check\">\n<h3><code>%s</code> %s</h3>\n", html.EscapeString(ck.ID), html.EscapeString(t.pick(ck.TitleKo, ck.Title)))
			w("<p>%s</p>\n", inline(t.pick(ck.DescriptionKo, ck.Description)))
			if ck.Rationale != "" || ck.RationaleKo != "" {
				w("<p><b>%s</b> %s</p>\n", t.why, inline(t.pick(ck.RationaleKo, ck.Rationale)))
			}
			if ck.Remediation != "" || ck.RemediationKo != "" {
				w("<p><b>%s</b> %s</p>\n", t.fix, inline(t.pick(ck.RemediationKo, ck.Remediation)))
			}
			if ck.Manual != nil && (ck.Manual.Guidance != "" || ck.Manual.GuidanceKo != "") {
				w("<p><b>%s</b> %s</p>\n", t.human, inline(t.pick(ck.Manual.GuidanceKo, ck.Manual.Guidance)))
			}
			if ps := c.Params[ref]; len(ps) > 0 {
				names := make([]string, 0, len(ps))
				for n := range ps {
					names = append(names, n)
				}
				slices.Sort(names)
				var parts []string
				for _, n := range names {
					parts = append(parts, fmt.Sprintf("<code>%s</code> = <code>%s</code>", html.EscapeString(n), html.EscapeString(fmt.Sprint(ps[n]))))
				}
				w("<p class=\"muted\">%s: %s</p>\n", t.params, strings.Join(parts, ", "))
			}
			w("</div>\n")
		}
		w("</section>\n")
	}
	w("</article>\n</main>\n")
	w("<footer>\n  <div class=\"wrap\">\n    %s\n  </div>\n</footer>\n</body>\n</html>\n", t.footer)
	return b.String(), nil
}

// anchorID is the fragment of a control: u-01.
func anchorID(id string) string { return strings.ToLower(strings.ReplaceAll(id, " ", "-")) }

// inline escapes text and makes `code` spans of what is in backticks.
func inline(s string) string {
	parts := strings.Split(s, "`")
	var b strings.Builder
	for i, p := range parts {
		switch {
		case i%2 == 1 && i < len(parts)-1:
			b.WriteString("<code>" + html.EscapeString(p) + "</code>")
		case i%2 == 1: // an unpaired backtick at the end: keep it as text
			b.WriteString("`" + html.EscapeString(p))
		default:
			b.WriteString(html.EscapeString(p))
		}
	}
	return b.String()
}
