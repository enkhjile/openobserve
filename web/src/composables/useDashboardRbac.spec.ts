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

import { effectScope, nextTick, ref } from "vue";
import { flushPromises } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import rbac from "@/services/rbac";
import { useDashboardRbac, useDashboardPermissions } from "./useDashboardRbac";

vi.mock("@/services/rbac", () => ({ default: { me: vi.fn() } }));

describe("dashboard mutation permissions", () => {
  it("follows upstream until RBAC is known; denies Viewer and no-grant callers; allows scoped Editor", async () => {
    const org = ref("first");
    const dashboard = ref("dashboard-a");
    const me = vi.mocked(rbac.me);
    me.mockResolvedValueOnce({
      data: {
        enabled: true,
        subject: "u",
        grants: [{ subject: "u", role: "viewer", resources: [{ kind: "dashboard", name: "*" }] }],
      },
    } as any);
    const scope = effectScope();
    const permission = scope.run(() => useDashboardRbac(org, dashboard, false))!;
    expect(permission.value).toBe(true);
    await flushPromises();
    expect(permission.value).toBe(false);
    me.mockResolvedValueOnce({
      data: {
        enabled: true,
        subject: "u",
        grants: [
          { subject: "u", role: "editor", resources: [{ kind: "dashboard", name: "dashboard-a" }] },
        ],
      },
    } as any);
    org.value = "second";
    await flushPromises();
    expect(permission.value).toBe(true);
    dashboard.value = "dashboard-b";
    expect(permission.value).toBe(false);
    expect(me).toHaveBeenCalledTimes(2);
    me.mockRejectedValueOnce(new Error("offline"));
    org.value = "third";
    await flushPromises();
    expect(permission.value).toBe(true);
    me.mockRejectedValueOnce({ response: { status: 403 } });
    org.value = "denied";
    await flushPromises();
    expect(permission.value).toBe(false);
    me.mockResolvedValueOnce({ data: { enabled: false, grants: [] } } as any);
    org.value = "fourth";
    await flushPromises();
    expect(permission.value).toBe(true);
    scope.stop();
  });

  it("uses a single membership for row scopes and requires wildcard grants for creation", async () => {
    const me = vi.mocked(rbac.me);
    me.mockClear();
    me.mockResolvedValueOnce({
      data: {
        enabled: true,
        subject: "u",
        grants: [{ subject: "u", role: "editor", resources: [{ kind: "dashboard", name: "one" }] }],
      },
    } as any);
    const scope = effectScope();
    const allowed = scope.run(() => useDashboardPermissions(ref("org"), false))!;
    await flushPromises();
    expect(allowed("one")).toBe(true);
    expect(allowed("two")).toBe(false);
    expect(allowed("*")).toBe(false);
    expect(allowed(null)).toBe(false);
    expect(me).toHaveBeenCalledTimes(1);
    scope.stop();
  });

  it("preserves Enterprise behavior without an OSS request", async () => {
    vi.mocked(rbac.me).mockClear();
    const scope = effectScope();
    const permission = scope.run(() => useDashboardRbac(ref("org"), ref("dash"), true))!;
    await nextTick();
    expect(permission.value).toBe(true);
    expect(rbac.me).not.toHaveBeenCalled();
    scope.stop();
  });
});
