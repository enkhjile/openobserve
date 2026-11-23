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

use std::task::{Context, Poll};

use futures::future::{Either, Ready, ready};
use http::{Request, Response};
use tonic::{Status, body::Body};
use tower::{Layer, Service};

/// The RPCs that keep working while RBAC is on; each checks its own caller. See docs/rbac/rpc.md.
const ALLOWED: &[&str] = &[
    "/cluster.Search/Search",
    "/cluster.Search/GetLicenseUsageInfo",
    "/cluster.Metrics/Query",
    "/cluster.Event/SendFileList",
    "/cluster.ClusterInfoService/GetClusterInfo",
    "/cluster.NodeService/GetNodes",
    "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
    "/arrow.flight.protocol.FlightService/DoGet",
];

/// Refuses every RPC outside [`ALLOWED`] while RBAC is on, including ones added upstream later.
#[derive(Clone, Copy, Debug)]
pub struct GateLayer {
    enabled: bool,
}

impl GateLayer {
    pub fn new() -> Self {
        Self {
            enabled: super::enabled(),
        }
    }
}

impl Default for GateLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for GateLayer {
    type Service = Gate<S>;

    fn layer(&self, inner: S) -> Gate<S> {
        Gate {
            inner,
            enabled: self.enabled,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Gate<S> {
    inner: S,
    enabled: bool,
}

impl<S, B> Service<Request<B>> for Gate<S>
where
    S: Service<Request<B>, Response = Response<Body>>,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Either<Ready<Result<Response<Body>, S::Error>>, S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        if self.enabled && !allowed(request.uri().path()) {
            let refusal = Status::permission_denied("RPC is not available while RBAC is enabled");
            return Either::Left(ready(Ok(refusal.into_http())));
        }
        Either::Right(self.inner.call(request))
    }
}

pub fn allowed(path: &str) -> bool {
    ALLOWED.contains(&path)
}

#[cfg(test)]
mod tests {
    use proto::cluster_rpc::{
        self,
        metrics_client::MetricsClient,
        metrics_server::{Metrics, MetricsServer},
    };
    use tokio::net::TcpListener;
    use tonic::{
        Code, Request as RpcRequest, Response as RpcResponse, transport::server::TcpIncoming,
    };

    use super::*;

    struct Echo;

    #[tonic::async_trait]
    impl Metrics for Echo {
        type DataStream = futures::stream::Empty<Result<cluster_rpc::MetricsQueryResponse, Status>>;

        async fn query(
            &self,
            _: RpcRequest<cluster_rpc::MetricsQueryRequest>,
        ) -> Result<RpcResponse<cluster_rpc::MetricsQueryResponse>, Status> {
            Ok(RpcResponse::new(Default::default()))
        }

        async fn data(
            &self,
            _: RpcRequest<cluster_rpc::MetricsQueryRequest>,
        ) -> Result<RpcResponse<Self::DataStream>, Status> {
            Ok(RpcResponse::new(futures::stream::empty()))
        }

        async fn wal_min_ts(
            &self,
            _: RpcRequest<cluster_rpc::WalMinTsRequest>,
        ) -> Result<RpcResponse<cluster_rpc::WalMinTsResponse>, Status> {
            Ok(RpcResponse::new(Default::default()))
        }
    }

    #[test]
    fn only_rpcs_with_their_own_checks_pass_and_new_ones_are_refused() {
        for path in ALLOWED {
            assert!(allowed(path), "{path}");
        }
        for path in [
            "/cluster.Search/SearchMulti",
            "/cluster.Search/SearchPartition",
            "/cluster.Search/GetTable",
            "/cluster.Metrics/Data",
            "/cluster.Metrics/WalMinTs",
            "/cluster.Event/GetFiles",
            "/cluster.QueryCache/DeleteResultCache",
            "/cluster.ClusterInfoService/GetDeleteJobStatus",
            "/cluster.Ingest/Ingest",
            "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
            "/cluster.Search/AnRpcUpstreamAddsLater",
        ] {
            assert!(!allowed(path), "{path}");
        }
    }

    #[test]
    fn every_allowed_cluster_rpc_exists_in_the_protos() {
        let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/../proto/proto/cluster");
        let mut declared = Vec::new();
        for entry in std::fs::read_dir(directory).unwrap() {
            let mut service = String::new();
            for line in std::fs::read_to_string(entry.unwrap().path())
                .unwrap()
                .lines()
            {
                let words: Vec<_> = line
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .filter(|w| !w.is_empty())
                    .collect();
                match words.as_slice() {
                    ["service", name, ..] => service = (*name).to_owned(),
                    ["rpc", name, ..] => declared.push(format!("/cluster.{service}/{name}")),
                    _ => {}
                }
            }
        }
        for path in ALLOWED.iter().filter(|path| path.starts_with("/cluster.")) {
            assert!(
                declared.iter().any(|rpc| rpc == path),
                "{path} is not a declared RPC"
            );
        }
    }

    #[tokio::test]
    async fn the_gate_answers_permission_denied_before_the_handler_runs() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .layer(GateLayer { enabled: true })
                .add_service(MetricsServer::new(Echo))
                .serve_with_incoming(TcpIncoming::from(listener)),
        );
        let channel = tonic::transport::Channel::from_shared(address)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = MetricsClient::new(channel);
        assert!(
            client
                .query(cluster_rpc::MetricsQueryRequest::default())
                .await
                .is_ok()
        );
        let refused = client
            .wal_min_ts(cluster_rpc::WalMinTsRequest::default())
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::PermissionDenied);
        server.abort();
    }
}
