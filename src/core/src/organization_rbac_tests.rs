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

use sea_orm::ConnectionTrait;

#[tokio::test]
async fn rbac_service_account_target_requires_nonroot_membership_and_exact_role() {
    let database = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
    database
        .execute_unprepared("CREATE TABLE users (email TEXT PRIMARY KEY, is_root BOOLEAN NOT NULL)")
        .await
        .unwrap();
    database.execute_unprepared("CREATE TABLE org_users (email TEXT NOT NULL, org_id TEXT NOT NULL, role SMALLINT NOT NULL)").await.unwrap();
    database.execute_unprepared("INSERT INTO users VALUES ('root@example.test',true),('human@example.test',false),('service@example.test',false),('other@example.test',false),('duplicate@example.test',false),('DUPLICATE@example.test',true)").await.unwrap();
    database.execute_unprepared("INSERT INTO org_users VALUES ('root@example.test','a',5),('human@example.test','a',1),('service@example.test','a',5),('other@example.test','b',5),('duplicate@example.test','a',5)").await.unwrap();

    for (org, target, allowed) in [
        ("a", "root@example.test", false),
        ("a", "human@example.test", false),
        ("a", "service@example.test", true),
        ("a", "SERVICE@example.test", true),
        ("b", "service@example.test", false),
        ("a", "other@example.test", false),
        ("a", "missing@example.test", false),
        ("a", "duplicate@example.test", false),
    ] {
        assert_eq!(
            infra::rbac::validate_service_account_target_on(&database, org, target)
                .await
                .is_ok(),
            allowed,
            "target {target} in organization {org}",
        );
    }
    database
        .execute_unprepared("DROP TABLE users")
        .await
        .unwrap();
    assert!(
        infra::rbac::validate_service_account_target_on(&database, "a", "service@example.test")
            .await
            .is_err()
    );
}
