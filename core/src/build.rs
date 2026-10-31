//! What the relay and the directory say about their own build in
//! `/metrics` (`agentconnect_relay_build_info`,
//! `agentconnect_directory_build_info`): the release version and the
//! source revision. Neither identifies anyone.

/// The release spelling of a Cargo version, as the tags, packages and
/// images name it: `0.1.0-alpha.2` is `0.1.0a2`, `-beta.N` is `bN`,
/// `-rc.N` is `rcN`, and the development version `main` carries between
/// releases keeps its `.devN`: `0.1.0-alpha.5.dev.0` is `0.1.0a5.dev0` and
/// `0.2.0-dev.0` is `0.2.0.dev0`. A version without a pre-release is
/// unchanged.
#[must_use]
pub fn release_version(cargo: &str) -> String {
    let Some((base, pre)) = cargo.split_once('-') else {
        return cargo.to_owned();
    };
    let (pre, dev) = match pre.split_once(".dev.") {
        Some((pre, n)) => (pre, Some(n)),
        None => match pre.strip_prefix("dev.") {
            Some(n) => ("", Some(n)),
            None => (pre, None),
        },
    };
    let mut version = base.to_owned();
    if !pre.is_empty() {
        let Some((short, n)) = [("alpha.", "a"), ("beta.", "b"), ("rc.", "rc")]
            .into_iter()
            .find_map(|(word, short)| pre.strip_prefix(word).map(|n| (short, n)))
        else {
            return cargo.to_owned();
        };
        version.push_str(short);
        version.push_str(n);
    }
    if let Some(n) = dev {
        version.push_str(".dev");
        version.push_str(n);
    }
    version
}

/// A metric label value built from build-time input: kept when it is 1 to
/// 64 characters of `[0-9A-Za-z.+_-]`, else `unknown`, so it can never end
/// the label or the line it is written into.
#[must_use]
pub fn label_value(value: Option<&str>) -> &str {
    match value {
        Some(v)
            if (1..=64).contains(&v.len())
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".+_-".contains(&b)) =>
        {
            v
        }
        _ => "unknown",
    }
}

/// The build-info gauge `name`, in Prometheus text: the release spelling
/// of `cargo_version` and `revision` (`unknown` when missing or not a
/// plain label value) as labels, and the value 1.
#[must_use]
pub fn metric(name: &str, cargo_version: &str, revision: Option<&str>) -> String {
    let version = release_version(cargo_version);
    let version = label_value(Some(&version)).to_owned();
    let revision = label_value(revision);
    format!(
        "# HELP {name} The release version and source revision of this build; always 1.\n\
         # TYPE {name} gauge\n\
         {name}{{version=\"{version}\",revision=\"{revision}\"}} 1\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_pre_releases_take_the_release_spelling() {
        assert_eq!(release_version("0.1.0-alpha.2"), "0.1.0a2");
        assert_eq!(release_version("0.2.0-beta.1"), "0.2.0b1");
        assert_eq!(release_version("1.0.0-rc.3"), "1.0.0rc3");
        assert_eq!(release_version("1.0.0"), "1.0.0");
        assert_eq!(release_version("1.0.0-dev"), "1.0.0-dev");
    }

    #[test]
    fn development_versions_take_the_release_spelling_too() {
        // What main carries between releases (scripts/check_version.py).
        assert_eq!(release_version("0.1.0-alpha.5.dev.0"), "0.1.0a5.dev0");
        assert_eq!(release_version("0.2.0-beta.1.dev.3"), "0.2.0b1.dev3");
        assert_eq!(release_version("1.0.0-rc.2.dev.0"), "1.0.0rc2.dev0");
        assert_eq!(release_version("0.2.0-dev.0"), "0.2.0.dev0");
        assert_eq!(release_version("0.2.0-dev.12"), "0.2.0.dev12");
    }

    #[test]
    fn only_plain_label_values_are_kept() {
        assert_eq!(label_value(Some("2d6a97d1f00b")), "2d6a97d1f00b");
        assert_eq!(label_value(Some("v0.1.0a2+local")), "v0.1.0a2+local");
        assert_eq!(label_value(None), "unknown");
        assert_eq!(label_value(Some("")), "unknown");
        for bad in ["a\"} 1\nevil 1", "a b", "a,b", "é"] {
            assert_eq!(label_value(Some(bad)), "unknown", "{bad:?}");
        }
        assert_eq!(label_value(Some(&"a".repeat(65))), "unknown");
    }

    #[test]
    fn the_gauge_names_the_build_and_nothing_else() {
        assert_eq!(
            metric("x_build_info", "0.1.0-alpha.2", Some("2d6a97d1f00b")),
            "# HELP x_build_info The release version and source revision of this build; always 1.\n\
             # TYPE x_build_info gauge\n\
             x_build_info{version=\"0.1.0a2\",revision=\"2d6a97d1f00b\"} 1\n"
        );
        assert!(metric("x", "1.0.0", Some("a\"} 1\nevil 1")).contains("revision=\"unknown\""));
    }
}
