// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

mod provider;
mod transactions;

use std::fmt;

pub use provider::{AuthorizationRequest, OidcProvider, ProviderSettings, VerifiedIdentity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Configuration,
    ProviderUnavailable,
    InvalidResponse,
    TransactionRejected,
    Capacity,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid OIDC configuration",
            Self::ProviderUnavailable => "identity provider unavailable",
            Self::InvalidResponse => "identity provider response rejected",
            Self::TransactionRejected => "login transaction rejected or expired",
            Self::Capacity => "too many pending login requests",
        })
    }
}

impl std::error::Error for Error {}

pub fn random_secret() -> String {
    openidconnect::CsrfToken::new_random_len(32)
        .secret()
        .to_owned()
}
