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

import { effectScope, ref } from "vue";
import { flushPromises } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import rbac from "@/services/rbac";
import { useApprovedAlertDestinations } from "./useApprovedAlertDestinations";

vi.mock("@/services/rbac", () => ({ default: { me: vi.fn(), availableDestinations: vi.fn() } }));
afterEach(() => {
  vi.useRealTimers();
  vi.resetAllMocks();
});

describe("approved alert destination picker", () => {
  it("never exposes legacy configs while loading or for unresolved queries", async () => {
    vi.useFakeTimers();
    vi.mocked(rbac.me).mockResolvedValue({ data: { enabled: true } } as never);
    vi.mocked(rbac.availableDestinations).mockResolvedValue({
      data: [
        { name: "approved", url: "https://private.example", headers: { Authorization: "secret" } },
      ],
    } as never);
    const scope = effectScope();
    const sql = ref("");
    const result = scope.run(() =>
      useApprovedAlertDestinations(
        ref("org"),
        sql,
        ref("logs"),
        ref(undefined),
        ref([{ name: "secret-config" }]),
        false,
      ),
    )!;
    expect(result.destinations.value).toEqual([]);
    await flushPromises();
    await vi.advanceTimersByTimeAsync(300);
    expect(rbac.availableDestinations).not.toHaveBeenCalled();
    sql.value = "select * from allowed";
    await vi.advanceTimersByTimeAsync(300);
    await flushPromises();
    expect(result.destinations.value).toEqual([{ name: "approved" }]);
    sql.value = "invalid query";
    vi.mocked(rbac.availableDestinations).mockRejectedValueOnce(new Error("denied"));
    expect(result.destinations.value).toEqual([]);
    await vi.advanceTimersByTimeAsync(300);
    await flushPromises();
    expect(result.destinations.value).toEqual([]);
    scope.stop();
  });

  it("discards stale destination results after switching organizations", async () => {
    vi.useFakeTimers();
    vi.mocked(rbac.me).mockResolvedValue({ data: { enabled: true } } as never);
    let resolveOld!: (value: any) => void;
    vi.mocked(rbac.availableDestinations)
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveOld = resolve;
          }) as never,
      )
      .mockResolvedValueOnce({ data: [{ name: "new-org" }] } as never);
    const org = ref("first");
    const scope = effectScope();
    const result = scope.run(() =>
      useApprovedAlertDestinations(
        org,
        ref("select * from allowed"),
        ref("logs"),
        ref(undefined),
        ref([]),
        false,
      ),
    )!;
    await flushPromises();
    await vi.advanceTimersByTimeAsync(300);
    org.value = "second";
    expect(result.destinations.value).toEqual([]);
    await flushPromises();
    await vi.advanceTimersByTimeAsync(300);
    await flushPromises();
    resolveOld({ data: [{ name: "old-org" }] });
    await flushPromises();
    expect(result.destinations.value).toEqual([{ name: "new-org" }]);
    scope.stop();
  });

  it("ignores an old organization's permission response", async () => {
    vi.useFakeTimers();
    let resolveOldProfile!: (value: any) => void;
    vi.mocked(rbac.me)
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveOldProfile = resolve;
          }) as never,
      )
      .mockResolvedValueOnce({ data: { enabled: true } } as never);
    vi.mocked(rbac.availableDestinations).mockResolvedValue({
      data: [{ name: "new-org" }],
    } as never);
    const org = ref("first");
    const scope = effectScope();
    const result = scope.run(() =>
      useApprovedAlertDestinations(
        org,
        ref("select * from allowed"),
        ref("logs"),
        ref(undefined),
        ref([{ name: "legacy-config" }]),
        false,
      ),
    )!;
    org.value = "second";
    await flushPromises();
    await vi.advanceTimersByTimeAsync(300);
    resolveOldProfile({ data: { enabled: false } });
    await flushPromises();
    expect(result.requiresApproval.value).toBe(true);
    expect(result.destinations.value).toEqual([{ name: "new-org" }]);
    scope.stop();
  });

  it("retains disabled and Enterprise behavior without filtering legacy choices", async () => {
    vi.mocked(rbac.me).mockResolvedValue({ data: { enabled: false } } as never);
    const scope = effectScope();
    const legacy = ref([{ name: "legacy" }]);
    const disabled = scope.run(() =>
      useApprovedAlertDestinations(ref("org"), ref(""), ref("logs"), ref(undefined), legacy, false),
    )!;
    await flushPromises();
    expect(disabled.destinations.value).toEqual(legacy.value);
    vi.mocked(rbac.me).mockClear();
    const enterprise = scope.run(() =>
      useApprovedAlertDestinations(ref("org"), ref(""), ref("logs"), ref(undefined), legacy, true),
    )!;
    expect(enterprise.destinations.value).toEqual(legacy.value);
    expect(rbac.me).not.toHaveBeenCalled();
    scope.stop();
  });
});
