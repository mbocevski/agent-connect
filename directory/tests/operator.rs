//! The operator notice and the terms and abuse links: on every page, in
//! every Markdown copy and in llms.txt, escaped, and absent when unset.

mod common;

use agentconnect_core::operator::OperatorLinks;
use agentconnect_directory::http::CSP;
use axum::http::StatusCode;
use common::{HOST, Harness, identity};

const NOTICE: &str = "Maintenance <script>alert(1)</script> tonight: [x](y) ] & *more*";
const NOTICE_HTML: &str = "<p class=\"notice\" role=\"note\">Maintenance \
&lt;script&gt;alert(1)&lt;/script&gt; tonight: [x](y) ] &amp; *more*</p>\n";
const NOTICE_MD: &str = "> Notice: Maintenance \\<script\\>alert\\(1\\)\\<\\/script\\> \
tonight\\: \\[x\\]\\(y\\) \\] \\& \\*more\\*\n\n";
const TERMS: &str = "https://example.org/terms?a=1&b=2";
const ABUSE: &str = "mailto:abuse@example.org";
const LINKS_HTML: &str = "<p class=\"operator\"><a href=\"https://example.org/terms?a=1&amp;b=2\" \
rel=\"noreferrer\">Terms</a> · <a href=\"mailto:abuse@example.org\" rel=\"noreferrer\">Report \
abuse</a></p>\n";
const LINKS_MD: &str =
    "\n[Terms](https://example.org/terms?a=1&b=2) · [Report abuse](mailto:abuse@example.org)\n";
const LINKS_LLMS: &str = "\n## Operator\n\n- [Terms](https://example.org/terms?a=1&b=2)\n\
- [Report abuse](mailto:abuse@example.org)\n";

/// HTML pages and their expected status.
const HTML_PAGES: [(&str, StatusCode); 6] = [
    ("/", StatusCode::OK),
    ("/?q=release", StatusCode::OK),
    ("/a/release-planner", StatusCode::OK),
    ("/a/going", StatusCode::GONE),
    ("/a/nobody-here", StatusCode::NOT_FOUND),
    ("/nothing/at/all", StatusCode::NOT_FOUND),
];

/// Markdown copies, by URL or by `Accept`, and their expected status.
const MD_PAGES: [(&str, StatusCode); 7] = [
    ("/index.md", StatusCode::OK),
    ("/index.md?q=release", StatusCode::OK),
    ("/a/release-planner.md", StatusCode::OK),
    ("/a/going.md", StatusCode::GONE),
    ("/a/nobody-here.md", StatusCode::NOT_FOUND),
    ("/a/nobody-here", StatusCode::NOT_FOUND),
    ("/nothing/at/all", StatusCode::NOT_FOUND),
];

/// A directory with one listing and one withdrawn listing.
async fn listed() -> Harness {
    let h = Harness::new();
    h.publish(&h.spec("release-planner", &identity())).await;
    let id = identity();
    h.publish(&h.spec("going", &id)).await;
    let r = h
        .post("/v0/withdrawals", h.withdrawal("going", &id, 1))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    h
}

fn configure(h: &mut Harness, notice: Option<&str>, terms: Option<&str>, abuse: Option<&str>) {
    h.http.notice = notice.map(str::to_owned);
    h.http.links = OperatorLinks {
        terms: terms.map(str::to_owned),
        abuse: abuse.map(str::to_owned),
    };
}

async fn html(h: &Harness, path: &str, status: StatusCode) -> String {
    let r = h.get(path).await;
    assert_eq!(r.status, status, "{path}");
    assert!(r.header("content-type").unwrap().starts_with("text/html"));
    r.text()
}

async fn markdown(h: &Harness, path: &str, status: StatusCode) -> String {
    let r = h.get_with(path, &[("accept", "text/markdown")]).await;
    assert_eq!(r.status, status, "{path}");
    assert!(
        r.header("content-type")
            .unwrap()
            .starts_with("text/markdown")
    );
    r.text()
}

/// The first ASCII punctuation character in `line` that isn't
/// backslash-escaped, after the `> Notice: ` prefix.
fn unescaped_markup(line: &str) -> Option<char> {
    let mut chars = line.strip_prefix("> Notice: ").unwrap().chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            chars.next();
        } else if c.is_ascii_punctuation() {
            return Some(c);
        }
    }
    None
}

async fn llms(h: &Harness) -> String {
    h.get("/llms.txt").await.text()
}

#[tokio::test]
async fn the_notice_and_links_are_on_every_page_copy_and_llms_txt() {
    let mut h = listed().await;
    configure(&mut h, Some(NOTICE), Some(TERMS), Some(ABUSE));
    for (path, status) in HTML_PAGES {
        let page = html(&h, path, status).await;
        assert!(
            page.contains(&format!("<body>\n{NOTICE_HTML}<header class=\"site\">")),
            "{path}: {page}"
        );
        assert!(
            page.ends_with(&format!("{LINKS_HTML}</footer>\n</body>\n</html>\n")),
            "{path}: {page}"
        );
        let lower = page.to_lowercase();
        assert!(!lower.contains("<script"), "{path}");
        assert_eq!(page.matches("class=\"notice\"").count(), 1, "{path}");
    }
    for (path, status) in MD_PAGES {
        let md = markdown(&h, path, status).await;
        assert!(md.starts_with(&format!("{NOTICE_MD}# ")), "{path}: {md}");
        assert!(md.ends_with(LINKS_MD), "{path}: {md}");
        // The notice is one line: nothing after it continues the quote.
        assert_eq!(md.lines().filter(|l| l.starts_with('>')).count(), 1);
        assert!(
            unescaped_markup(md.lines().next().unwrap()).is_none(),
            "{path}"
        );
    }
    let t = llms(&h).await;
    assert!(
        t.starts_with(&format!("{NOTICE_MD}# AgentConnect directory at {HOST}\n")),
        "{t}"
    );
    assert!(t.ends_with(LINKS_LLMS), "{t}");
    assert!(unescaped_markup(t.lines().next().unwrap()).is_none());
}

#[tokio::test]
async fn unset_renders_nothing_and_setting_adds_only_the_notice_and_links() {
    let mut h = listed().await;
    let mut before = Vec::new();
    for (path, status) in HTML_PAGES {
        before.push(html(&h, path, status).await);
    }
    for (path, status) in MD_PAGES {
        before.push(markdown(&h, path, status).await);
    }
    before.push(llms(&h).await);
    for body in &before {
        for absent in [
            "class=\"notice\"",
            "class=\"operator\"",
            "> Notice:",
            "[Terms]",
            "Terms</a>",
            "Report abuse",
            "## Operator",
        ] {
            assert!(!body.contains(absent), "{absent}: {body}");
        }
    }
    assert_eq!(
        before[HTML_PAGES.len() + 4],
        "# Not found\n\nNothing is listed here.\n"
    );

    configure(&mut h, Some(NOTICE), Some(TERMS), Some(ABUSE));
    let mut after = Vec::new();
    for (path, status) in HTML_PAGES {
        let page = html(&h, path, status).await;
        after.push(
            page.replacen(NOTICE_HTML, "", 1)
                .replacen(LINKS_HTML, "", 1),
        );
    }
    for (path, status) in MD_PAGES {
        let md = markdown(&h, path, status).await;
        let md = md.strip_prefix(NOTICE_MD).unwrap();
        after.push(md.strip_suffix(LINKS_MD).unwrap().to_owned());
    }
    let t = llms(&h).await;
    let t = t.strip_prefix(NOTICE_MD).unwrap();
    after.push(t.strip_suffix(LINKS_LLMS).unwrap().to_owned());
    assert_eq!(before, after);
}

#[tokio::test]
async fn each_setting_shows_on_its_own() {
    let mut h = listed().await;
    configure(&mut h, None, Some(TERMS), None);
    let page = html(&h, "/", StatusCode::OK).await;
    assert!(page.contains(
        "<p class=\"operator\"><a href=\"https://example.org/terms?a=1&amp;b=2\" \
rel=\"noreferrer\">Terms</a></p>\n</footer>"
    ));
    assert!(!page.contains("Report abuse") && !page.contains("class=\"notice\""));
    let md = markdown(&h, "/index.md", StatusCode::OK).await;
    assert!(md.starts_with("# AgentConnect directory\n"));
    assert!(md.ends_with("\n[Terms](https://example.org/terms?a=1&b=2)\n"));
    assert!(
        llms(&h)
            .await
            .ends_with("\n## Operator\n\n- [Terms](https://example.org/terms?a=1&b=2)\n")
    );

    configure(&mut h, None, None, Some("https://example.org/abuse"));
    let page = html(&h, "/a/release-planner", StatusCode::OK).await;
    assert!(page.contains(
        "<p class=\"operator\"><a href=\"https://example.org/abuse\" rel=\"noreferrer\">Report \
abuse</a></p>\n</footer>"
    ));
    assert!(!page.contains("Terms</a>"));
    let md = markdown(&h, "/a/release-planner.md", StatusCode::OK).await;
    assert!(md.ends_with("\n[Report abuse](https://example.org/abuse)\n"));

    configure(&mut h, Some("Read-only until Monday"), None, None);
    let page = html(&h, "/a/nobody-here", StatusCode::NOT_FOUND).await;
    assert!(
        page.contains(
            "<body>\n<p class=\"notice\" role=\"note\">Read-only until Monday</p>\n<header"
        )
    );
    assert!(!page.contains("class=\"operator\""));
    let md = markdown(&h, "/a/going.md", StatusCode::GONE).await;
    assert!(md.starts_with("> Notice: Read\\-only until Monday\n\n# Withdrawn\n\n"));
    assert!(md.ends_with(".\n") && !md.contains("[Terms]"));
}

#[tokio::test]
async fn the_csp_and_the_well_known_file_are_unchanged() {
    let mut h = listed().await;
    let plain_known = h.get("/.well-known/agentconnect-directory.json").await.body;
    configure(&mut h, Some(NOTICE), Some(TERMS), Some(ABUSE));
    for (path, status) in HTML_PAGES {
        let r = h.get(path).await;
        assert_eq!(r.status, status, "{path}");
        assert_eq!(
            r.header("content-security-policy").as_deref(),
            Some(CSP),
            "{path}"
        );
    }
    assert_eq!(
        CSP,
        "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; \
form-action 'self'; frame-ancestors 'none'"
    );
    let known = h.get("/.well-known/agentconnect-directory.json").await;
    assert_eq!(known.body, plain_known);
    let mut keys: Vec<String> = known.json().as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["directory", "relays", "token_keys", "v"]);
}

#[tokio::test]
async fn the_default_stylesheet_styles_the_notice_in_both_schemes() {
    let h = Harness::new();
    let css = h.get("/static/directory.css").await.text();
    assert!(css.contains(".notice {"), "{css}");
    let (light, dark) = css
        .split_once("@media (prefers-color-scheme: dark)")
        .unwrap();
    for scheme in [light, dark] {
        assert!(scheme.contains("--notice-bg:") && scheme.contains("--notice-line:"));
    }
}
