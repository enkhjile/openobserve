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

export function useApprovedAlertDestinations(
  organization: Ref<string>,
  sql: Ref<string>,
  streamType: Ref<string>,
  alertId: Ref<string | undefined>,
  legacy: Ref<{ name: string }[]>,
  enterprise: boolean,
) {
  const membership = shallowRef<Membership>();
  const approved = shallowRef<{ name: string }[]>([]);
  watch(
    organization,
    async (org, _, onCleanup) => {
      membership.value = undefined;
      if (enterprise || !org) return;
      let active = true;
      onCleanup(() => {
        active = false;
      });
      try {
        const response = await rbac.me(org);
        if (active) membership.value = response.data;
      } catch {
        if (active) membership.value = undefined;
      }
    },
    { immediate: true, flush: "sync" },
  );
  watch(
    [organization, sql, streamType, alertId, membership],
    ([org, query, type, id, member], _, onCleanup) => {
      approved.value = [];
      if (enterprise || !member?.enabled || !query.trim()) return;
      let active = true;
      const timeout = setTimeout(async () => {
        try {
          const response = await rbac.availableDestinations(org, query, type, id);
          if (active) approved.value = response.data.map(({ name }) => ({ name }));
        } catch {
          if (active) approved.value = [];
        }
      }, 250);
      onCleanup(() => {
        active = false;
        clearTimeout(timeout);
      });
    },
    { immediate: true, flush: "sync" },
  );
  const requiresApproval = computed(() => !enterprise && membership.value?.enabled !== false);
  return {
    destinations: computed(() => (requiresApproval.value ? approved.value : legacy.value)),
    requiresApproval,
  };
}
