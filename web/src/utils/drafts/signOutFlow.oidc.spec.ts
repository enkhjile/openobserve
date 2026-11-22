// Copyright 2026 OpenObserve Inc.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { defineComponent, h } from "vue";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import { resumeDraftSession } from "@/utils/drafts/draftSession";
import { readEditorDraft, writeEditorDraft } from "@/utils/drafts/editorDraftStore";
import { getDecodedUserInfo, invalidateLoginData } from "@/utils/zincutils";
import oidc from "@/services/oidc";
import userService from "@/services/users";
import { endSignedInSession, signOutThroughLeaveGuards } from "./signOutFlow";

const authClient = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock("@/services/oidc", () => ({ default: { logout: vi.fn() }, authClient: () => authClient }));
vi.mock("@/services/users", () => ({ default: { logout: vi.fn() } }));
vi.mock("@/utils/sessionServices", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/utils/sessionServices")>()),
  stopSessionServices: vi.fn(),
}));
vi.mock("@/utils/zincutils", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/utils/zincutils")>()),
  invalidateLoginData: vi.fn(),
}));

const Blank = defineComponent({ setup: () => () => h("div") });
const email = "me@x.io";
const realLocation = window.location;

const makeStore = () => ({
  state: { userInfo: { email }, zoConfig: { oidc_enabled: false, rum: { enabled: true } } },
  dispatch: vi.fn(),
});

describe("sign-out that revokes the server session first", () => {
  let router: Router;
  let assign: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    router = createRouter({
      history: createMemoryHistory(),
      routes: ["/", "/editor", "/login", "/logout"].map((path) => ({ path, component: Blank })),
    });
    await router.push("/editor");
  });

  afterEach(() => {
    vi.stubGlobal("location", realLocation);
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    resumeDraftSession();
  });

  it("keeps drafts and clears the previous user's browser state after a confirmed direct sign-out", async () => {
    const { rememberLinkRequest, recallLinkRequest } = await import("@/utils/slackLink");
    const store = makeStore();
    const scope = { kind: "function" as const, org: "o", entityId: "f", userEmail: email };
    writeEditorDraft(scope, { data: {} });
    rememberLinkRequest("req-1.sig", null);
    localStorage.setItem("userInfo", "old-profile");
    localStorage.setItem("currentuser", JSON.stringify("old-user"));
    await endSignedInSession(store, { keepDrafts: true });
    expect(store.dispatch).toHaveBeenCalledWith("logout");
    expect(readEditorDraft(scope)).not.toBeNull();
    expect(recallLinkRequest()).toBeNull();
    expect(localStorage.getItem("userInfo")).toBeNull();
    expect(localStorage.getItem("currentuser")).toBeNull();
  });

  it("awaits OIDC revocation before clearing state or navigating", async () => {
    let revoke = () => {};
    vi.mocked(oidc.logout).mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          revoke = resolve;
        }),
    );
    const store = {
      ...makeStore(),
      state: { ...makeStore().state, zoConfig: { oidc_enabled: true } },
    };
    const result = signOutThroughLeaveGuards(router, store);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(oidc.logout).toHaveBeenCalledTimes(1);
    expect(store.dispatch).not.toHaveBeenCalled();
    expect(assign).not.toHaveBeenCalled();
    revoke();
    expect(await result).toBe(true);
    expect(store.dispatch).toHaveBeenCalled();
    expect(assign).toHaveBeenCalled();
  });

  it.each(["isFirstTimeLogin", "o2_sample_tour", "userInfo"])(
    "continues cleanup and navigation when storage removal fails for %s after revocation",
    async (blockedKey) => {
      const { rememberLinkRequest, recallLinkRequest } = await import("@/utils/slackLink");
      rememberLinkRequest("req-1.sig", null);
      localStorage.setItem("currentuser", JSON.stringify("old-user"));
      vi.mocked(oidc.logout).mockResolvedValue();
      const store = makeStore();
      store.state.zoConfig.oidc_enabled = true;
      const removeItem = Storage.prototype.removeItem;
      const removal = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(function (key) {
        if (key === blockedKey) throw new DOMException("Storage blocked", "SecurityError");
        removeItem.call(this, key);
      });
      try {
        await expect(signOutThroughLeaveGuards(router, store)).resolves.toBe(true);
        expect(store.dispatch).toHaveBeenCalledWith("logout", { draftsOf: email });
        expect(localStorage.getItem("currentuser")).toBeNull();
        expect(recallLinkRequest()).toBeNull();
        expect(assign).toHaveBeenCalledTimes(1);
      } finally {
        removal.mockRestore();
      }
    },
  );

  it("confirms a native logout without the global session handler and keeps drafts", async () => {
    vi.mocked(userService.logout).mockResolvedValue({} as any);
    const store = makeStore();
    await endSignedInSession(store, { keepDrafts: true, awaitNativeLogout: true });
    expect(userService.logout).toHaveBeenCalledWith(authClient);
    expect(invalidateLoginData).not.toHaveBeenCalled();
    expect(store.dispatch).toHaveBeenCalledWith("logout");
  });

  it.each([401, 503])(
    "keeps the native session for a retry when confirmed logout gets %i",
    async (status) => {
      vi.mocked(userService.logout).mockRejectedValue({ response: { status } });
      localStorage.setItem("userInfo", btoa(JSON.stringify({ email })));
      const store = makeStore();
      await expect(
        endSignedInSession(store, { keepDrafts: true, awaitNativeLogout: true }),
      ).rejects.toEqual({ response: { status } });
      expect(store.dispatch).not.toHaveBeenCalled();
      expect(getDecodedUserInfo()).toBe(JSON.stringify({ email }));
    },
  );

  it("never restores a signed-out profile that storage refused to delete", async () => {
    vi.mocked(oidc.logout).mockResolvedValue();
    const stale = btoa(JSON.stringify({ email }));
    localStorage.setItem("userInfo", stale);
    const store = makeStore();
    store.state.zoConfig.oidc_enabled = true;
    const removeItem = Storage.prototype.removeItem;
    const removal = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(function (key) {
      if (key === "userInfo") throw new DOMException("Storage blocked", "SecurityError");
      removeItem.call(this, key);
    });
    try {
      await endSignedInSession(store, { keepDrafts: true });
    } finally {
      removal.mockRestore();
    }
    expect(localStorage.getItem("userInfo")).toBe(stale);
    expect(getDecodedUserInfo()).toBeNull();
    const next = JSON.stringify({ email: "next@x.io" });
    localStorage.setItem("userInfo", btoa(next));
    expect(getDecodedUserInfo()).toBe(next);
  });

  it("keeps an OIDC session visible when revocation fails", async () => {
    vi.mocked(oidc.logout).mockRejectedValue(new Error("network failure"));
    const store = {
      ...makeStore(),
      state: { ...makeStore().state, zoConfig: { oidc_enabled: true } },
    };
    expect(await signOutThroughLeaveGuards(router, store)).toBe(false);
    expect(store.dispatch).not.toHaveBeenCalled();
    expect(assign).not.toHaveBeenCalled();
  });
});
