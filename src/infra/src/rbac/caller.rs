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

use std::future::Future;

use anyhow::{Result, bail};

tokio::task_local! {
    static CALLER: Caller;
}

/// Who the current task searches as; only a verified boundary sets it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// An authenticated user or service account, by its verified email.
    User(String),
    /// A stable policy subject a trusted boundary already resolved.
    Subject(String),
}

/// Runs `fut` as `caller`; a nested scope may only repeat the current caller.
pub async fn scope<F: Future>(caller: Caller, fut: F) -> Result<F::Output> {
    if !super::enabled() {
        return Ok(fut.await);
    }
    match current() {
        Some(existing) if existing != caller => bail!("RBAC caller cannot change within a request"),
        _ => Ok(CALLER.scope(caller, fut).await),
    }
}

/// [`scope`] for a verified user; with RBAC disabled it runs `fut` without copying `email`.
pub async fn scope_user<F: Future>(email: &str, fut: F) -> Result<F::Output> {
    if !super::enabled() {
        return Ok(fut.await);
    }
    scope(Caller::User(email.to_owned()), fut).await
}

/// `fut` carrying the caller of the task that creates it, for work handed to `tokio::spawn`.
pub fn inherit<F: Future>(fut: F) -> impl Future<Output = F::Output> {
    let caller = current();
    async move {
        match caller {
            Some(caller) => CALLER.scope(caller, fut).await,
            None => fut.await,
        }
    }
}

/// `tokio::spawn` for search work that must keep the spawning task's caller.
pub fn spawn<F>(fut: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(inherit(fut))
}

pub fn current() -> Option<Caller> {
    CALLER.try_with(Clone::clone).ok()
}

/// The current caller's subject when a trusted boundary already resolved it.
pub fn subject() -> Option<String> {
    match current()? {
        Caller::Subject(subject) => Some(subject),
        Caller::User(_) => None,
    }
}

/// The current caller's stable policy subject; no caller denies.
pub async fn current_subject() -> Result<String> {
    match current() {
        Some(Caller::Subject(subject)) => Ok(subject),
        Some(Caller::User(email)) => super::user_subject(&email).await,
        None => bail!("RBAC execution identity required"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn caller_scope_and_inheritance() {
        if std::env::var_os("O2_RBAC_CALLER_CHILD").is_none() {
            let inside = scope(Caller::User("a@example.test".into()), async { current() });
            assert_eq!(inside.await.unwrap(), None);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "rbac::caller::tests::caller_scope_and_inheritance",
                    "--nocapture",
                ])
                .env("O2_RBAC_CALLER_CHILD", "1")
                .env("ZO_RBAC_ENABLED", "true")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        assert!(super::super::enabled());
        assert!(current_subject().await.is_err());
        let user = Caller::User("a@example.test".into());
        let delegated = Caller::Subject("subject-id".into());
        let nested = scope(user.clone(), async {
            let same = scope(user.clone(), async { current() }).await.unwrap();
            let other = scope(delegated.clone(), async { current() }).await;
            let lost = tokio::spawn(async { current() }).await.unwrap();
            let kept = tokio::spawn(inherit(async { current() })).await.unwrap();
            (same, other.is_err(), lost, kept)
        });
        let (same, switched, lost, kept) = nested.await.unwrap();
        assert_eq!(same, Some(user.clone()));
        assert!(switched, "a nested scope must not switch callers");
        assert_eq!(lost, None);
        assert_eq!(kept, Some(user));
        let resolved = scope(delegated, async { (subject(), current_subject().await) });
        let (carried, resolved) = resolved.await.unwrap();
        assert_eq!(carried.as_deref(), Some("subject-id"));
        assert_eq!(resolved.unwrap(), "subject-id");
    }
}
