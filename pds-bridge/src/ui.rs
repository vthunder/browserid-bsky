//! The shared visual system for the bridge's human-facing pages (UX revamp,
//! bean spxl).
//!
//! Tokens and component classes are lifted from the browserid.me marketing
//! site (`browserid-ng/marketing/index.html`) so the bridge reads as part of
//! the same product. Light is the mockups' palette; dark is the marketing
//! page's dark palette, applied automatically via `prefers-color-scheme`.
//!
//! Pages remain what they were: server-rendered static HTML with vanilla JS,
//! no framework, no build step. Every dynamic string reaches the DOM via
//! `textContent` (or is server-side HTML-escaped) — nothing here changes
//! that property; this module only centralizes the styling so the root,
//! verify, agent, and dashboard pages cannot drift apart visually.

/// Design tokens + component classes shared by every page.
pub const BASE_CSS: &str = r#"
:root {
  color-scheme: light;
  --bg:#F7F5F0; --panel:#FFFFFF; --well:#F1EEE6;
  --line:#E3DFD4; --line-strong:#CDC7B8;
  --text:#1A1C22; --muted:#5D6370; --faint:#9AA0AB;
  --gold:#946608; --gold-hi:#7A5406;
  --gold-btn:#E3AE4C; --gold-btn-hover:#D9A238; --gold-ink:#16110A;
  --gold-border:rgba(148,102,8,.5); --gold-tint:rgba(148,102,8,.1);
  --cyan:#17708F; --cyan-border:rgba(23,112,143,.5); --cyan-border-soft:rgba(23,112,143,.4); --cyan-tint:rgba(23,112,143,.1);
  --green:#2F7A50; --green-border:rgba(47,122,80,.5); --green-tint:rgba(47,122,80,.12);
  --red:#B00020; --red-border:rgba(176,0,32,.4); --red-tint:rgba(176,0,32,.08);
  --nav-bg:rgba(247,245,240,.9);
  --shadow:0 1px 2px rgba(26,28,34,.08);
  --codewell-bg:#1A1C22; --codewell-text:#ECEFF7; --codewell-muted:#99A3BD; --codewell-line:transparent;
  --mono:ui-monospace,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --bg:#080B15; --panel:#10162A; --well:#080B15;
    --line:#232C46; --line-strong:#313C5C;
    --text:#ECEFF7; --muted:#99A3BD; --faint:#5E6A8C;
    --gold:#E3AE4C; --gold-hi:#F0BE5E;
    --gold-btn:#E3AE4C; --gold-btn-hover:#F0BE5E; --gold-ink:#16110A;
    --gold-border:rgba(227,174,76,.45); --gold-tint:rgba(227,174,76,.12);
    --cyan:#6FC2DE; --cyan-border:rgba(111,194,222,.45); --cyan-border-soft:rgba(111,194,222,.4); --cyan-tint:rgba(111,194,222,.12);
    --green:#57C083; --green-border:rgba(87,192,131,.45); --green-tint:rgba(87,192,131,.16);
    --red:#E5484D; --red-border:rgba(229,72,77,.5); --red-tint:rgba(229,72,77,.12);
    --nav-bg:rgba(8,11,21,.86);
    --shadow:0 1px 2px rgba(0,0,0,.4);
    --codewell-bg:#080B15; --codewell-text:#ECEFF7; --codewell-muted:#99A3BD; --codewell-line:#232C46;
  }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); font-size:15px; line-height:1.5; -webkit-font-smoothing:antialiased; }
.mono { font-family:var(--mono); }
a { color:var(--gold); }
a:hover { color:var(--gold-hi); }
:focus-visible { outline:2px solid var(--cyan); outline-offset:2px; }
[hidden] { display:none !important; }

/* ---- nav ---- */
.nav { position:sticky; top:0; z-index:10; display:flex; align-items:center; justify-content:space-between; gap:12px; height:54px; padding:0 24px; border-bottom:1px solid var(--line); background:var(--nav-bg); backdrop-filter:blur(8px); -webkit-backdrop-filter:blur(8px); }
.brand { display:flex; align-items:center; gap:9px; font:600 14px var(--mono); color:var(--text); text-decoration:none; }
.brand:hover { color:var(--text); }
.ring { width:20px; height:20px; border-radius:50%; border:2px solid var(--gold); display:inline-grid; place-items:center; flex:none; }
.ring i { width:6px; height:6px; border-radius:50%; background:var(--gold); }
.brand .tld { color:var(--gold); }
.tag { font:500 11px var(--mono); color:var(--muted); border:1px solid var(--line); border-radius:999px; padding:2px 9px; margin-left:4px; }
.nav-right { display:flex; align-items:center; gap:18px; font:600 12px var(--mono); }
.nav-link { color:var(--muted); text-decoration:none; font:600 12px var(--mono); }
.nav-link:hover { color:var(--gold); }

/* ---- kickers & labels ---- */
.kicker { font:600 11px var(--mono); letter-spacing:.16em; text-transform:uppercase; display:flex; align-items:center; gap:8px; }
.kicker::before { content:""; width:20px; height:1px; background:currentColor; opacity:.6; }
.label { font:600 11px var(--mono); letter-spacing:.12em; text-transform:uppercase; }
.c-cyan { color:var(--cyan); } .c-green { color:var(--green); } .c-gold { color:var(--gold); } .c-muted { color:var(--muted); }

/* ---- cards & panels ---- */
.card { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:18px 20px; box-shadow:var(--shadow); }
.card-strong { border-color:var(--line-strong); }
.card-head { display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:6px; }
.card-title { font:600 13.5px var(--mono); }

/* ---- pills ---- */
.pill { font:600 10.5px var(--mono); color:var(--muted); border:1px solid var(--line-strong); border-radius:999px; padding:3px 10px; white-space:nowrap; }
.pill-green { color:var(--green); border-color:var(--green-border); background:var(--green-tint); }
.pill-red { color:var(--red); border-color:var(--red-border); background:none; }
.badge-chip { font:11px var(--mono); color:var(--green); border:1px solid var(--green-border); border-radius:999px; padding:1px 7px; white-space:nowrap; }

/* ---- buttons & inputs ---- */
.btn { display:inline-block; font:600 12.5px var(--mono); border:1px solid transparent; border-radius:9px; padding:10px 18px; cursor:pointer; text-decoration:none; text-align:center; }
.btn-gold { background:var(--gold-btn); color:var(--gold-ink); }
.btn-gold:hover { background:var(--gold-btn-hover); color:var(--gold-ink); }
.btn-outline { background:transparent; color:var(--text); border-color:var(--line-strong); font:600 12px var(--mono); border-radius:8px; padding:8px 14px; }
.btn-outline:hover { border-color:var(--gold); color:var(--gold); }
.btn-nav { color:var(--gold); border:1px solid var(--gold-border); border-radius:8px; padding:6px 13px; text-decoration:none; font:600 12px var(--mono); background:transparent; cursor:pointer; }
.btn-nav:hover { color:var(--gold-hi); border-color:var(--gold); }
.btn[disabled], .btn-outline[disabled] { opacity:.55; cursor:default; }
.input { background:var(--well); border:1px solid var(--line-strong); border-radius:10px; padding:12px 14px; font:13px var(--mono); color:var(--text); width:100%; }
.input::placeholder { color:var(--faint); }
.chip { display:flex; gap:8px; align-items:center; background:var(--well); border:1px solid var(--line-strong); border-radius:10px; padding:10px 13px; }
.chip code { flex:1; font:12px/1.5 var(--mono); overflow-wrap:anywhere; }
.btn-copy { font:600 12px var(--mono); border:1px solid var(--line-strong); border-radius:8px; padding:7px 13px; background:var(--panel); color:var(--text); cursor:pointer; white-space:nowrap; }
.btn-copy:hover { border-color:var(--gold); color:var(--gold); }
.goldlink { font:600 12.5px var(--mono); color:var(--gold); text-decoration:none; }
.goldlink:hover { color:var(--gold-hi); }

/* ---- misc ---- */
.muted { color:var(--muted); }
.micro { font-size:11.5px; color:var(--muted); }
.err { color:var(--red); }
.dot { width:7px; height:7px; border-radius:50%; display:inline-block; flex:none; }
.dot-green { background:var(--green); } .dot-gold { background:var(--gold-btn); } .dot-gray { background:var(--line-strong); }
.avatar { border-radius:50%; background:linear-gradient(135deg,#17708F,#E3AE4C); }
.codewell { background:var(--codewell-bg); color:var(--codewell-text); border:1px solid var(--codewell-line); border-radius:10px; padding:14px 16px; font:11px/1.7 var(--mono); white-space:pre-wrap; overflow-wrap:anywhere; margin:0; }
.site-footer { display:flex; justify-content:space-between; gap:10px 24px; flex-wrap:wrap; padding:16px 24px; border-top:1px solid var(--line); font:11.5px var(--mono); color:var(--muted); }
.site-footer a { color:var(--muted); text-decoration:none; }
.site-footer a:hover { color:var(--gold); }
"#;

/// Wrap a built body (nav + content + optional inline script, already
/// escaped where needed) in the document shell.
pub fn document(title: &str, extra_css: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{BASE_CSS}{extra_css}</style></head>
<body>
{body}
</body></html>"#
    )
}

/// The root page's brand: the browserid.me wordmark plus the bridge tag.
pub fn brand_home() -> String {
    r#"<a class="brand" href="/"><span class="ring"><i></i></span>browserid<span class="tld">.me</span><span class="tag">bsky bridge</span></a>"#.to_string()
}

/// Every other page's brand: this origin's own name.
pub fn brand_site() -> String {
    r#"<a class="brand" href="/"><span class="ring"><i></i></span>bsky<span class="tld">.browserid.me</span></a>"#.to_string()
}

/// The 54px top bar. `brand` and `right` are trusted, already-built HTML.
pub fn nav(brand: &str, right: &str) -> String {
    format!(r#"<nav class="nav">{brand}<div class="nav-right">{right}</div></nav>"#)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shell_carries_both_palettes() {
        let page = document("t", "", "<p>x</p>");
        assert!(page.contains("--bg:#F7F5F0"), "light palette");
        assert!(page.contains("--bg:#080B15"), "dark palette");
        assert!(page.contains("prefers-color-scheme: dark"));
    }
}
