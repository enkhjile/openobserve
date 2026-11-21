// Copyright 2026 OpenObserve Inc.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { createStore } from "vuex";
import { createMemoryHistory, createRouter } from "vue-router";
import i18n from "@/locales";
import oidc from "@/services/oidc";
import organizationsService from "@/services/organizations";
import { purgeAllPersisted } from "@/composables/query/persisters";
import { redirectUser } from "@/utils/common";
import { expireSession } from "@/utils/sessionServices";
import OidcCallback from "./OidcCallback.vue";

vi.mock("@/services/oidc", () => ({ default: { session: vi.fn(), logout: vi.fn() } }));
vi.mock("@/services/organizations", () => ({ default: { list: vi.fn() } }));
vi.mock("@/composables/query/persisters", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/composables/query/persisters")>()),
  purgeAllPersisted: vi.fn(() => Promise.resolve()),
}));
vi.mock("@/utils/common", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/utils/common")>()),
  redirectUser: vi.fn(),
}));
vi.mock("@/utils/sessionServices", () => ({ expireSession: vi.fn() }));

const profile = {
  email: "second@example.test",
  name: "Second",
  given_name: "Second",
  family_name: "",
  exp: 12345,
};
const organizations = (data: unknown[]) => ({ data: { data } }) as any;

describe("OidcCallback", () => {
  let store: ReturnType<typeof createStore>;
  let router: ReturnType<typeof createRouter>;

  const mountView = async () => {
    const wrapper = mount(OidcCallback, { global: { plugins: [i18n, store, router] } });
    await flushPromises();
    return wrapper;
  };

  beforeEach(() => {
    store = createStore({ state: { zoConfig: {} } });
    store.dispatch = vi.fn() as any;
    router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/:path(.*)*", component: { template: "<div />" } }],
    });
    vi.mocked(oidc.session).mockResolvedValue(profile);
    vi.mocked(organizationsService.list).mockResolvedValue(organizations([{ id: "1" }]));
  });

  afterEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
  });

  it("installs the server session's profile and redirects to the saved page", async () => {
    sessionStorage.setItem("redirectURI", "/web/logs");
    await mountView();
    expect(store.dispatch).toHaveBeenCalledWith("login", { loginState: true, userInfo: profile });
    expect(redirectUser).toHaveBeenCalledWith("/web/logs");
    expect(sessionStorage.getItem("redirectURI")).toBeNull();
  });

  it("removes a replaced account's persisted results before installing the new identity", async () => {
    let finishPurge = () => {};
    vi.mocked(purgeAllPersisted).mockImplementation(
      () => new Promise<void>((resolve) => (finishPurge = resolve)),
    );
    try {
      await mountView();
      expect(purgeAllPersisted).toHaveBeenCalled();
      expect(store.dispatch).not.toHaveBeenCalledWith("setCurrentUser", expect.anything());
      expect(store.dispatch).not.toHaveBeenCalledWith("login", expect.anything());
      finishPurge();
      await flushPromises();
      expect(store.dispatch).toHaveBeenCalledWith("login", { loginState: true, userInfo: profile });
    } finally {
      vi.mocked(purgeAllPersisted).mockImplementation(() => Promise.resolve());
    }
  });

  it("explains a missing organization membership instead of entering the app", async () => {
    vi.mocked(organizationsService.list).mockResolvedValue(organizations([]));
    const wrapper = await mountView();
    expect(wrapper.find('[data-test="oidc-no-organization"]').exists()).toBe(true);
    expect(redirectUser).not.toHaveBeenCalled();
  });

  it.each(["organization", "session"])(
    "lets the user retry a temporary %s lookup failure",
    async (failure) => {
      if (failure === "session") {
        vi.mocked(oidc.session).mockRejectedValueOnce({
          isAxiosError: true,
          response: { status: 503 },
        });
      } else {
        vi.mocked(organizationsService.list).mockRejectedValueOnce(new Error("network failure"));
      }
      const wrapper = await mountView();
      expect(store.dispatch).not.toHaveBeenCalledWith("logout");
      expect(redirectUser).not.toHaveBeenCalled();
      await wrapper.get('[data-test="oidc-retry-callback"]').trigger("click");
      await flushPromises();
      expect(redirectUser).toHaveBeenCalledTimes(1);
    },
  );

  it("does not authenticate a refused session and shows the generic login error", async () => {
    vi.mocked(oidc.session).mockRejectedValue({ isAxiosError: true, response: { status: 401 } });
    const replace = vi.spyOn(router, "replace");
    await mountView();
    expect(store.dispatch).not.toHaveBeenCalledWith("login", expect.anything());
    expect(replace).toHaveBeenCalledWith({ path: "/login", query: { oidc_error: "1" } });
  });

  it("revokes the session before leaving when the organizations are refused", async () => {
    vi.mocked(organizationsService.list).mockRejectedValue({
      isAxiosError: true,
      response: { status: 403 },
    });
    vi.mocked(oidc.logout).mockResolvedValue();
    await mountView();
    expect(oidc.logout).toHaveBeenCalledTimes(1);
    expect(expireSession).toHaveBeenCalledWith(store, { toLogin: true });
  });

  it("stays on the page when sign-out cannot revoke the session", async () => {
    vi.mocked(organizationsService.list).mockResolvedValue(organizations([]));
    vi.mocked(oidc.logout).mockRejectedValue(new Error("unavailable"));
    const wrapper = await mountView();
    await wrapper.get('[data-test="oidc-sign-out"]').trigger("click");
    await flushPromises();
    expect(expireSession).not.toHaveBeenCalled();
    expect(wrapper.find('[data-test="oidc-no-organization"]').exists()).toBe(true);
  });
});
