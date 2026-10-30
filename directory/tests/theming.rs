//! The pages' markup is a theming interface (`AC_DIRECTORY_STYLESHEET`,
//! directory/README.md "Theming"): the class names, data attributes and ids
//! listed there are stable, and a change to them is called out in the
//! CHANGELOG. This test holds the list: a class or data attribute the pages
//! render that isn't in it, or a documented one they no longer render,
//! fails here first.

mod common;

use std::collections::BTreeSet;

use agentconnect_core::operator::OperatorLinks;
use axum::http::StatusCode;
use common::{Harness, identity};

/// The documented classes (directory/README.md, "Theming").
const CLASSES: &[&str] = &[
    "about-cols",
    "card-text",
    "door",
    "empty",
    "facts",
    "kicker",
    "label",
    "listing",
    "method",
    "name",
    "note",
    "notice",
    "operator",
    "results",
    "site",
    "site-name",
    "steps",
    "warning",
];

/// The documented data attributes.
const DATA: &[&str] = &["data-method", "data-state"];

/// Documented, but only on a listing whose key changed.
const RARE: &[&str] = &["warning"];

/// Every value of `attr="…"` in `html`, split on spaces for `class`.
fn values(html: &str, attr: &str) -> BTreeSet<String> {
    let needle = format!("{attr}=\"");
    let mut out = BTreeSet::new();
    let mut rest = html;
    while let Some(at) = rest.find(&needle) {
        rest = &rest[at + needle.len()..];
        let end = rest.find('"').expect("closed attribute");
        out.extend(rest[..end].split_whitespace().map(str::to_owned));
        rest = &rest[end..];
    }
    out
}

/// Every `data-*` attribute name in `html`.
fn data_attributes(html: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = html;
    while let Some(at) = rest.find(" data-") {
        rest = &rest[at + 1..];
        let end = rest.find('=').expect("data attribute with a value");
        out.insert(rest[..end].to_owned());
    }
    out
}

#[tokio::test]
async fn the_pages_render_only_the_documented_hooks() {
    let mut h = Harness::new();
    h.http.name = Some("Example agents".into());
    h.http.notice = Some("Maintenance tonight".into());
    h.http.links = OperatorLinks {
        terms: Some("https://example.org/terms".into()),
        abuse: Some("mailto:abuse@example.org".into()),
    };
    h.publish(&h.spec("release-planner", &identity())).await;
    let mut html = String::new();
    for (path, status) in [
        ("/", StatusCode::OK),
        ("/?q=release", StatusCode::OK),
        ("/?q=nothing-matches-this", StatusCode::OK),
        ("/a/release-planner", StatusCode::OK),
        ("/a/nobody-by-this-name", StatusCode::NOT_FOUND),
    ] {
        let r = h.get(path).await;
        assert_eq!(r.status, status, "{path}");
        html.push_str(&r.text());
    }

    let classes = values(&html, "class");
    let documented: BTreeSet<String> = CLASSES.iter().map(|c| (*c).to_owned()).collect();
    let undocumented: Vec<_> = classes.difference(&documented).collect();
    assert!(
        undocumented.is_empty(),
        "classes not in the theming interface: {undocumented:?}; document them in \
         directory/README.md and the CHANGELOG"
    );
    let missing: Vec<_> = documented
        .difference(&classes)
        .filter(|c| !RARE.contains(&c.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "documented classes no page renders: {missing:?}"
    );

    let data = data_attributes(&html);
    let documented: BTreeSet<String> = DATA.iter().map(|d| (*d).to_owned()).collect();
    assert_eq!(data, documented);
    for state in values(&html, "data-state") {
        assert!(["open", "closed"].contains(&state.as_str()), "{state}");
    }
    assert_eq!(
        values(&html, "data-method"),
        ["GET", "POST"].map(str::to_owned).into()
    );
    // The documented ids: the linkable sections and the search fields.
    let ids = values(&html, "id");
    for id in ["about", "listed", "api", "q", "skill"] {
        assert!(ids.contains(id), "no element has id {id}");
    }
}
