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
      try {
        const { data } = await rbac.me(org);
        if (current) membership.value = data;
      } catch {
        // Failed permission reads must not expose mutation controls.
        if (current) membership.value = undefined;
      }
    },
    { immediate: true },
  );
  return (dashboard: string | null) => {
    if (enterprise || membership.value?.enabled === false) return true;
    if (dashboard === null) return false;
    const member = membership.value;
    return !!member?.grants.some(
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
