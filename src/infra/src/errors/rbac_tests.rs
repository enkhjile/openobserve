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

#[test]
fn authorization_denial_preserves_http_status_across_rpc() {
    let denial = super::ErrorCodes::AuthorizationDenied("not permitted".into());
    assert_eq!(denial.http_status(), 403);
    let decoded = super::ErrorCodes::from_json(&denial.to_json()).unwrap();
    assert_eq!(decoded.http_status(), 403);
    assert_eq!(decoded.get_code(), 20015);
}
