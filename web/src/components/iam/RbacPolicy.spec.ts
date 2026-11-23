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

import { mount, flushPromises } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createStore } from "vuex";
import i18n from "@/locales";
import RbacPolicy from "./RbacPolicy.vue";
import rbac from "@/services/rbac";

vi.mock("@/services/rbac", () => ({
  default: {
    me: vi.fn(),
    policy: vi.fn(),
    subjects: vi.fn(),
    save: vi.fn(),
    saveDestinations: vi.fn(),
  },
}));

function render() {
  return mount(RbacPolicy, {
    global: {
      plugins: [createStore({ state: { selectedOrganization: { identifier: "org-a" } } }), i18n],
      stubs: {
        OPageHeader: true,
        OCard: { template: "<div><slot /></div>" },
        OCardSection: { template: "<div><slot /></div>" },
        OButton: { template: "<button><slot /></button>" },
        OSelect: true,
        OInput: true,
      },
    },
  });
}

describe("organization RBAC panel", () => {
  beforeEach(() => vi.resetAllMocks());
  it("shows viewer roles without administration controls or policy requests", async () => {
    vi.mocked(rbac.me).mockResolvedValue({
      data: {
        enabled: true,
        subject: "uuid-a",
        can_manage: false,
        grants: [{ subject: "uuid-a", role: "viewer", resources: [] }],
      },
    } as never);
    const wrapper = render();
    await flushPromises();
    expect(wrapper.get('[data-test="iam-rbac-roles"]').text()).toContain("Viewer");
    expect(wrapper.find('[data-test="iam-rbac-save"]').exists()).toBe(false);
    expect(rbac.policy).not.toHaveBeenCalled();
    wrapper.unmount();
  });
  it("hides the panel when RBAC is disabled", async () => {
    vi.mocked(rbac.me).mockResolvedValue({
      data: { enabled: false, can_manage: false, grants: [] },
    } as never);
    const wrapper = render();
    await flushPromises();
    expect(wrapper.find('[data-test="iam-rbac-panel"]').exists()).toBe(false);
    expect(wrapper.emitted("enabled")).toEqual([[false]]);
    wrapper.unmount();
  });
  it("displays a meaningful access denial and offers reload", async () => {
    vi.mocked(rbac.me).mockRejectedValue({ isAxiosError: true, response: { status: 403 } });
    const wrapper = render();
    await flushPromises();
    expect(wrapper.get('[data-test="iam-rbac-error"]').text()).toContain("Access denied");
    expect(wrapper.find('[data-test="iam-rbac-retry"]').exists()).toBe(true);
    expect(wrapper.find('[data-test="iam-rbac-save"]').exists()).toBe(false);
    wrapper.unmount();
  });
  it("labels token subjects and only offers explicit-stream Ingester grants", async () => {
    const token = "org-token:000000000000000000000000001";
    const policy = { schema_version: 1, version: 1, organization: "org-a", grants: [] };
    vi.mocked(rbac.me).mockResolvedValue({
      data: { enabled: true, can_manage: true, grants: [] },
    } as never);
    vi.mocked(rbac.policy).mockResolvedValue({ data: policy } as never);
    vi.mocked(rbac.subjects).mockResolvedValue({
      data: [{ subject: token, name: "collector", kind: "ingestion_token" }],
    } as never);
    vi.mocked(rbac.save).mockResolvedValue({ data: policy } as never);
    const wrapper = render();
    await flushPromises();
    const member = wrapper.findComponent('[data-test="iam-rbac-member"]');
    expect(member.props("options")).toEqual([
      { value: token, label: "Ingestion token: collector" },
    ]);
    member.vm.$emit("update:modelValue", token);
    await flushPromises();
    const role = wrapper.findComponent('[data-test="iam-rbac-role"]');
    expect(role.attributes("modelvalue")).toBe("ingester");
    wrapper
      .findComponent('[data-test="iam-rbac-resource-name"]')
      .vm.$emit("update:modelValue", "api");
    await flushPromises();
    await wrapper.get('[data-test="iam-rbac-add"]').trigger("click");
    await wrapper.get('[data-test="iam-rbac-save"]').trigger("click");
    expect(rbac.save).toHaveBeenCalledWith(
      "org-a",
      expect.objectContaining({
        grants: [
          {
            subject: token,
            role: "ingester",
            resources: [{ kind: "stream", stream_type: "logs", name: "api" }],
          },
        ],
      }),
    );
    wrapper.unmount();
  });

  it("saves destination approvals with the current revision and preserves the prior binding", async () => {
    const approval = {
      destination_name: "ops",
      target_fingerprint: "a".repeat(64),
      sources: [{ kind: "stream", stream_type: "logs", name: "api" }],
    };
    const policy = {
      schema_version: 1,
      version: 4,
      organization: "org-a",
      grants: [],
      destination_approvals: [approval],
    };
    vi.mocked(rbac.me).mockResolvedValue({
      data: { enabled: true, can_manage: true, grants: [] },
    } as never);
    vi.mocked(rbac.policy).mockResolvedValue({ data: policy } as never);
    vi.mocked(rbac.subjects).mockResolvedValue({ data: [] } as never);
    vi.mocked(rbac.saveDestinations).mockResolvedValue({
      data: { ...policy, version: 5 },
    } as never);
    const wrapper = render();
    await flushPromises();
    await wrapper.get('[data-test="iam-rbac-destinations-save"]').trigger("click");
    await flushPromises();
    expect(rbac.saveDestinations).toHaveBeenCalledWith(
      "org-a",
      expect.objectContaining({ version: 4, destination_approvals: [approval] }),
    );
    wrapper.unmount();
  });

  it("saves a structured member grant with the policy revision", async () => {
    const initial = {
      schema_version: 1,
      version: 7,
      organization: "org-a",
      grants: [
        {
          subject: "root-id",
          role: "admin",
          resources: [{ kind: "organization", stream_type: "", name: "organization" }],
        },
      ],
    };
    vi.mocked(rbac.me).mockResolvedValue({
      data: { enabled: true, subject: "root-id", can_manage: true, grants: initial.grants },
    } as never);
    vi.mocked(rbac.policy).mockResolvedValue({ data: initial } as never);
    vi.mocked(rbac.subjects).mockResolvedValue({
      data: [{ subject: "member-id", email: "member@example.test" }],
    } as never);
    vi.mocked(rbac.save).mockResolvedValue({ data: initial } as never);
    const wrapper = render();
    await flushPromises();
    wrapper
      .findComponent('[data-test="iam-rbac-member"]')
      .vm.$emit("update:modelValue", "member-id");
    wrapper
      .findComponent('[data-test="iam-rbac-resource-name"]')
      .vm.$emit("update:modelValue", "api");
    await flushPromises();
    await wrapper.get('[data-test="iam-rbac-add"]').trigger("click");
    await wrapper.get('[data-test="iam-rbac-save"]').trigger("click");
    await flushPromises();
    expect(rbac.save).toHaveBeenCalledWith(
      "org-a",
      expect.objectContaining({
        version: 7,
        grants: expect.arrayContaining([
          {
            subject: "member-id",
            role: "viewer",
            resources: [{ kind: "stream", stream_type: "logs", name: "api" }],
          },
        ]),
      }),
    );
    wrapper.unmount();
  });
});
