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

import { computed, shallowRef, watch, type Ref } from "vue";
import rbac, { type Membership } from "@/services/rbac";

/** Only RBAC answers 403 from `me`, so that means on with no grants; other failures stay unknown. */
export async function readMembership(org: string): Promise<Membership | undefined> {
  try {
    return (await rbac.me(org)).data;
  } catch (error) {
    const status = (error as { response?: { status?: number } })?.response?.status;
    return status === 403 ? { enabled: true, can_manage: false, grants: [] } : undefined;
  }
}

export function useDashboardRbac(
  organization: Ref<string>,
  dashboard: Ref<string>,
  enterprise: boolean,
) {
  const canMutate = useDashboardPermissions(organization, enterprise);
  return computed(() => canMutate(dashboard.value));
}

export function useDashboardPermissions(organization: Ref<string>, enterprise: boolean) {
  const membership = shallowRef<Membership>();
  watch(
    organization,
    async (org, _, onCleanup) => {
      membership.value = undefined;
      if (enterprise || !org) return;
      let current = true;
      onCleanup(() => {
        current = false;
      });
      const member = await readMembership(org);
      if (current) membership.value = member;
    },
    { immediate: true },
  );
  // Until RBAC is known to be on, controls stay as upstream shows them; the server still decides.
  return (dashboard: string | null) => {
    const member = membership.value;
    if (enterprise || member?.enabled !== true) return true;
    if (dashboard === null) return false;
    return member.grants.some(
      (grant) =>
        grant.subject === member.subject &&
        (grant.role === "admin" || grant.role === "editor") &&
        grant.resources.some(
          (resource) =>
            (grant.role === "admin" && resource.kind === "organization") ||
            (resource.kind === "dashboard" &&
              (resource.name === "*" || resource.name === dashboard)),
        ),
    );
  };
}
