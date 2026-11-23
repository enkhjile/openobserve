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

use axum::{Extension, Json, extract::Path, response::Response};
use infra::rbac;
use serde::Deserialize;

use super::rbac::{VerifiedUser, json_or_forbidden};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalUpdate {
    expected_version: u64,
    approvals: Vec<rbac::DestinationApprovalRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AvailableRequest {
    sql: String,
    stream_type: config::meta::stream::StreamType,
    alert_id: Option<String>,
}

pub(super) async fn available(
    Path(org): Path<String>,
    Extension(user): Extension<VerifiedUser>,
    Json(request): Json<AvailableRequest>,
) -> Response {
    let result = async {
        anyhow::ensure!(rbac::enabled(), "RBAC is disabled");
        let subject = rbac::user_subject(&user.0).await?;
        let sources =
            search::rbac::authorize_subject(&request.sql, &org, request.stream_type, &subject)
                .await?;
        rbac::available_alert_destinations(
            &subject,
            &org,
            request.alert_id.as_deref().unwrap_or("*"),
            &sources,
        )
        .await
    }
    .await;
    json_or_forbidden(result.map(|names| {
        names
            .into_iter()
            .map(|name| serde_json::json!({"name":name}))
            .collect::<Vec<_>>()
    }))
}

pub(super) async fn put(
    Path(org): Path<String>,
    Extension(user): Extension<VerifiedUser>,
    Json(update): Json<ApprovalUpdate>,
) -> Response {
    json_or_forbidden(
        rbac::replace_destination_approvals(
            &user.0,
            &org,
            update.expected_version,
            update.approvals,
        )
        .await,
    )
}
