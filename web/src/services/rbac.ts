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

import http from "./http";

export type Role = "admin" | "editor" | "viewer" | "ingester" | "exporter";
export type ResourceKind =
  | "organization"
  | "stream"
  | "dashboard"
  | "alert"
  | "pipeline"
  | "report"
  | "saved_query"
  | "service_account"
  | "user";
export interface Resource {
  kind: ResourceKind;
  stream_type: string;
  name: string;
}
export interface Grant {
  subject: string;
  role: Role;
  resources: Resource[];
}
export interface DestinationApproval {
  destination_id?: string;
  destination_name: string;
  target_fingerprint?: string;
  sources: Resource[];
}
export interface Policy {
  schema_version: number;
  version: number;
  organization: string;
  grants: Grant[];
  destination_approvals?: DestinationApproval[];
}
export interface Membership {
  enabled: boolean;
  subject?: string;
  can_manage: boolean;
  grants: Grant[];
}
export interface Subject {
  subject: string;
  email?: string;
  name?: string;
  kind?: "user" | "ingestion_token";
}
const base = (org: string) => `/api/${encodeURIComponent(org)}/rbac`;
export default {
  me: (org: string) => http().get<Membership>(`${base(org)}/me`, { silentForbidden: true }),
  policy: (org: string) => http().get<Policy>(`${base(org)}/policy`),
  subjects: (org: string) => http().get<Subject[]>(`${base(org)}/subjects`),
  availableDestinations: (org: string, sql: string, streamType: string, alertId?: string) =>
    http().post<{ name: string }[]>(
      `${base(org)}/destinations/available`,
      { sql, stream_type: streamType, alert_id: alertId },
      { silentForbidden: true },
    ),
  saveDestinations: (org: string, policy: Policy) =>
    http().put<Policy>(`${base(org)}/destinations`, {
      expected_version: policy.version,
      approvals: (policy.destination_approvals ?? []).map((approval) => ({
        destination_name: approval.destination_name,
        expected_target_fingerprint: approval.target_fingerprint,
        sources: approval.sources,
      })),
    }),
  save: (org: string, policy: Policy) =>
    http().put<Policy>(`${base(org)}/policy`, {
      expected_version: policy.version,
      grants: policy.grants,
    }),
};
