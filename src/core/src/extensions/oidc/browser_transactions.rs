// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use anyhow::Result;
use config::oidc::Oidc;
use http::{HeaderMap, header};

use super::transaction_cookie_name;

pub const MAX_BROWSER_TRANSACTIONS: usize = 8;

pub fn marker(binding: &str) -> String {
    super::compact_key("oidc_tx_", binding)
}

pub async fn register(binding: &str) -> Result<()> {
    super::session_store::start_transaction(
        &marker(binding),
        chrono::Utc::now().timestamp_micros() + 300_000_000,
    )
    .await?;
    Ok(())
}

fn valid_state(state: &str) -> bool {
    (1..=128).contains(&state.len())
        && state
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// The public state selects the cookie. Its independent, secret value binds the browser.
pub fn cookie_for_state(cfg: &Oidc, state: &str) -> Option<String> {
    valid_state(state).then(|| format!("{}-{state}", transaction_cookie_name(cfg)))
}

pub fn pending_cookie_names<'a>(headers: &'a HeaderMap, cfg: &Oidc) -> Vec<&'a str> {
    pending_cookies(headers, cfg)
        .map(|(name, _)| name)
        .collect()
}

pub(super) fn pending_markers(headers: &HeaderMap, cfg: &Oidc) -> Vec<String> {
    pending_cookies(headers, cfg)
        .map(|(_, binding)| marker(binding))
        .collect()
}

fn pending_cookies<'a>(
    headers: &'a HeaderMap,
    cfg: &Oidc,
) -> impl Iterator<Item = (&'a str, &'a str)> {
    let prefix = transaction_cookie_name(cfg);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|line| line.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .filter(move |(name, _)| {
            name.strip_prefix(prefix)
                .and_then(|suffix| suffix.strip_prefix('-'))
                .is_some_and(valid_state)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_does_not_contain_browser_secret() {
        assert!(!marker("browser-secret").contains("browser-secret"));
        assert_ne!(marker("one"), marker("two"));
        assert!(marker("one").starts_with("oidc_tx_"));
        assert!(marker("one").len() <= 36);
    }

    #[test]
    fn oidc_cookie_names_only_match_state_for_configured_prefix() {
        let cfg = Oidc::default();
        let name = cookie_for_state(&cfg, "A_2-Z").unwrap();
        assert!(cookie_for_state(&cfg, "a;b").is_none());
        assert!(cookie_for_state(&cfg, "").is_none());
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!("{name}=secret; other=value").parse().unwrap(),
        );
        headers.append(header::COOKIE, "unrelated-cookie=test".parse().unwrap());
        assert_eq!(pending_cookie_names(&headers, &cfg), [name]);
    }
}
