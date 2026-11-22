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
fn rbac_password_changes_cannot_cross_identity_boundaries() {
    use UserUpdateMode::{CliUpdate, OtherUpdate, SelfUpdate};
    for (enabled, initiator, target, mode, password, denied) in [
        (
            true,
            "alice@example.com",
            "bob@example.com",
            OtherUpdate,
            Some("new"),
            true,
        ),
        (
            true,
            "root@example.com",
            "bob@example.com",
            OtherUpdate,
            Some("new"),
            true,
        ),
        (
            true,
            "alice@example.com",
            "bob@example.com",
            SelfUpdate,
            Some("new"),
            true,
        ),
        (
            true,
            "alice@example.com",
            "alice@example.com",
            OtherUpdate,
            Some("new"),
            true,
        ),
        (
            true,
            "alice@example.com",
            "alice@example.com",
            CliUpdate,
            Some("new"),
            true,
        ),
        (
            true,
            "alice@example.com",
            "alice@example.com",
            SelfUpdate,
            Some("new"),
            false,
        ),
        (
            false,
            "alice@example.com",
            "bob@example.com",
            OtherUpdate,
            Some("new"),
            false,
        ),
        (
            true,
            "alice@example.com",
            "bob@example.com",
            OtherUpdate,
            None,
            false,
        ),
    ] {
        assert_eq!(
            enabled
                && infra::rbac::password_change_denied(
                    initiator,
                    target,
                    mode.is_self_update(),
                    password.is_some()
                ),
            denied,
            "{enabled} {initiator} -> {target} {mode:?}"
        );
    }
}
