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

use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait,
    sea_query::{Expr, OnConflict},
};

use super::entity::sessions::{ActiveModel, Column, Entity, Model};
use crate::{
    db::{get_orm_client_ro, get_orm_client_rw},
    errors,
};

/// Gets a session by session_id
pub async fn get(session_id: &str) -> Result<Option<Model>, errors::Error> {
    let client = get_orm_client_ro().await;
    let session = Entity::find()
        .filter(Column::SessionId.eq(session_id))
        .one(client)
        .await?;
    Ok(session)
}

/// Creates or updates a session with expiration
///
/// # Arguments
/// * `session_id` - Unique session identifier
/// * `access_token` - Access token to store
/// * `expires_at` - Expiration timestamp (microseconds since epoch) All sessions must have an
///   expiry - either from JWT or default 24 hours
pub async fn set_with_expiry(
    session_id: &str,
    access_token: &str,
    expires_at: i64,
) -> Result<(), errors::Error> {
    let client = get_orm_client_rw().await;
    let result = Entity::insert(session_model(session_id, access_token, expires_at))
        .on_conflict(
            OnConflict::column(Column::SessionId)
                .update_columns([Column::AccessToken, Column::UpdatedAt, Column::ExpiresAt])
                .to_owned(),
        )
        .exec(client)
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            log::error!("[DB] Failed to insert/update session: id={session_id}, error={e}");
            Err(e.into())
        }
    }
}

pub async fn start_oidc_transaction(marker: &str, expires_at: i64) -> Result<(), errors::Error> {
    Entity::insert(session_model(marker, "", expires_at))
        .exec(get_orm_client_rw().await)
        .await?;
    Ok(())
}

/// Keep the marker on failure so a retried logout can revoke the issued session. [strong]
pub async fn revoke_oidc_sessions(
    markers: Vec<String>,
    current: Option<String>,
) -> Result<(), errors::Error> {
    if markers.is_empty() {
        if let Some(current) = current {
            delete(&current).await?;
        }
        return Ok(());
    }
    let transaction = get_orm_client_rw().await.begin().await?;
    let marker_rows = Entity::delete_many().filter(Column::SessionId.is_in(markers));
    let mut issued: Vec<String> =
        super::delete_returning(&transaction, marker_rows, &[Column::AccessToken]).await?;
    issued.retain(|session_id| !session_id.is_empty());
    issued.extend(current);
    if !issued.is_empty() {
        Entity::delete_many()
            .filter(Column::SessionId.is_in(issued))
            .exec(&transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

/// The previous session remains valid if storing the replacement fails. [strong]
pub async fn rotate_oidc_session(
    marker: &str,
    previous_id: Option<&str>,
    session_id: &str,
    access_token: &str,
    expires_at: i64,
) -> Result<(), errors::Error> {
    let transaction = get_orm_client_rw().await.begin().await?;
    // Take the marker's write lock before touching session rows, in the same order as logout.
    let claimed = Entity::update_many()
        .col_expr(Column::AccessToken, Expr::value(session_id))
        .filter(Column::SessionId.eq(marker))
        .filter(Column::AccessToken.eq(""))
        .exec(&transaction)
        .await?;
    if claimed.rows_affected != 1 {
        return Err(errors::Error::Message(
            "OIDC login cancelled or already completed".into(),
        ));
    }
    Entity::insert(session_model(session_id, access_token, expires_at))
        .exec(&transaction)
        .await?;
    if let Some(previous_id) = previous_id {
        Entity::delete_by_id(previous_id).exec(&transaction).await?;
    }
    // Check both deadlines after any wait for the writer, then keep the revocation handle as long
    // as the session.
    let now = chrono::Utc::now().timestamp_micros();
    let published = Entity::update_many()
        .col_expr(Column::ExpiresAt, Expr::value(expires_at))
        .filter(Column::SessionId.eq(marker))
        .filter(Column::ExpiresAt.gt(now))
        .exec(&transaction)
        .await?;
    if published.rows_affected != 1 || expires_at <= now {
        return Err(errors::Error::Message("OIDC login expired".into()));
    }
    transaction.commit().await?;
    Ok(())
}

/// Deletes a session by session_id
pub async fn delete(session_id: &str) -> Result<(), errors::Error> {
    let client = get_orm_client_rw().await;
    Entity::delete_many()
        .filter(Column::SessionId.eq(session_id))
        .exec(client)
        .await?;
    Ok(())
}

/// Lists all sessions
pub async fn list() -> Result<Vec<Model>, errors::Error> {
    let client = get_orm_client_ro().await;
    let sessions = Entity::find().all(client).await?;
    Ok(sessions)
}

/// Deletes all expired sessions from the database
/// This is more efficient than deleting one at a time
pub async fn delete_expired() -> Result<u64, errors::Error> {
    let client = get_orm_client_rw().await;
    let now = chrono::Utc::now().timestamp_micros();

    let result = Entity::delete_many()
        .filter(Column::ExpiresAt.lt(now))
        .exec(client)
        .await?;

    Ok(result.rows_affected)
}

fn session_model(session_id: &str, access_token: &str, expires_at: i64) -> ActiveModel {
    let now = chrono::Utc::now().timestamp_micros();

    ActiveModel {
        session_id: Set(session_id.to_string()),
        access_token: Set(access_token.to_string()),
        created_at: Set(now),
        updated_at: Set(now),
        expires_at: Set(expires_at),
    }
}
