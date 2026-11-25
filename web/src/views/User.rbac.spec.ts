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

import { describe, expect, it, vi } from "vitest";
import { mount } from "@vue/test-utils";
import { nextTick } from "vue";
import { createStore } from "vuex";
import User from "./User.vue";

vi.mock("@/types/i18n", () => ({ useI18nTyped: () => ({ t: (key: string) => key }) }));
vi.mock("@/components/iam/RbacPolicy.vue", () => ({
  default: { name: "RbacPolicy", emits: ["enabled", "permissions"], template: "<div />" },
}));
vi.mock("@/components/iam/users/User.vue", () => ({
  default: { name: "Users", template: '<div data-test="legacy-users" />' },
}));

function fixture() {
  const store = createStore({ state: { selectedOrganization: { identifier: "org-a" } } });
  const wrapper = mount(User, { global: { plugins: [store] } });
  return { store, wrapper, policy: wrapper.findComponent({ name: "RbacPolicy" }) };
}

describe("Users RBAC administration", () => {
  it.each([
    [false, false, true],
    [true, false, false],
    [true, true, true],
  ])("enabled=%s manage=%s shows Users=%s", async (enabled, canManage, visible) => {
    const { wrapper, policy } = fixture();
    expect(wrapper.find('[data-test="legacy-users"]').exists()).toBe(true);
    policy.vm.$emit("permissions", { organization: "org-a", enabled, canManage });
    await nextTick();
    expect(wrapper.find('[data-test="legacy-users"]').exists()).toBe(visible);
    wrapper.unmount();
  });

  it("re-checks after an org switch and ignores late old-org grants", async () => {
    const { wrapper, policy, store } = fixture();
    policy.vm.$emit("permissions", { organization: "org-a", enabled: true, canManage: true });
    await nextTick();
    expect(wrapper.find('[data-test="legacy-users"]').exists()).toBe(true);
    policy.vm.$emit("permissions", { organization: "org-a", enabled: true, canManage: false });
    await nextTick();
    expect(wrapper.find('[data-test="legacy-users"]').exists()).toBe(false);
    store.state.selectedOrganization.identifier = "org-b";
    await nextTick();
    expect(wrapper.find('[data-test="legacy-users"]').exists()).toBe(true);
    policy.vm.$emit("permissions", { organization: "org-a", enabled: true, canManage: false });
    await nextTick();
    expect(wrapper.find('[data-test="legacy-users"]').exists()).toBe(true);
    policy.vm.$emit("permissions", { organization: "org-b", enabled: true, canManage: false });
    await nextTick();
    expect(wrapper.find('[data-test="legacy-users"]').exists()).toBe(false);
    wrapper.unmount();
  });
});
