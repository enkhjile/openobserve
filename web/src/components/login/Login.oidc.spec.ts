// Copyright 2026 OpenObserve Inc.
import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { createStore } from "vuex";
import { createMemoryHistory, createRouter } from "vue-router";
import i18n from "@/locales";
import Login from "@/components/login/Login.vue";

vi.mock("@/services/oidc", () => ({ default: { loginUrl: () => "/auth/oidc/login" } }));
vi.mock("@/aws-exports", () => ({ default: { isCloud: "false", isEnterprise: "false" } }));
vi.mock("@/lib/feedback/Toast/useToast", () => ({ toast: vi.fn() }));
vi.mock("@openobserve/browser-rum", () => ({
  openobserveRum: { setUser: vi.fn(), startSessionReplayRecording: vi.fn() },
}));

describe("Login with OSS OIDC", () => {
  it("shows SSO and offers local login only when the server allows it", async () => {
    const store = createStore({
      state: {
        zoConfig: { oidc_enabled: true, native_login_enabled: false },
        userInfo: {},
      },
    });
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/:path(.*)*", component: { template: "<div />" } }],
    });
    const wrapper: any = mount(Login, { global: { plugins: [i18n, store, router] } });
    expect(wrapper.vm.showSSO).toBe(true);
    expect(wrapper.vm.showInternalLogin).toBe(false);
    expect(wrapper.find("#login-internal-form").exists()).toBe(false);
    store.state.zoConfig.native_login_enabled = true;
    await flushPromises();
    expect(wrapper.vm.showInternalLogin).toBe(true);
    wrapper.unmount();
  });
});
