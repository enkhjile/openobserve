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

use super::*;

#[test]
fn metrics_search_denials_are_forbidden_and_syntax_errors_remain_bad_requests() {
    let denial = errors::ErrorCodes::AuthorizationDenied("metric access denied".into());
    assert!(infra::rbac::is_denied(&errors::Error::ErrorCode(denial)));
    let syntax = errors::ErrorCodes::InvalidParams("invalid expression".into());
    assert!(!infra::rbac::is_denied(&errors::Error::ErrorCode(syntax)));
}
