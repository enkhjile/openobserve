// Copyright 2026 OpenObserve Inc.
import { describe, expect, it, vi } from "vitest";
import { expireSession } from "./sessionServices";

vi.mock("@openobserve/browser-rum", () => ({
  openobserveRum: {
    stopSessionReplayRecording: vi.fn(),
    clearUser: vi.fn(),
    clearAccount: vi.fn(),
  },
}));
vi.mock("@/composables/useSearchWebSocket", () => ({ closeSearchSocket: vi.fn() }));
vi.mock("@/lib/feedback/Toast/useToast", () => ({ dismissAll: vi.fn() }));

describe("expireSession after an OIDC session ends", () => {
  it("navigates even when session storage is blocked", () => {
    const realLocation = window.location;
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    const store = { state: { zoConfig: { rum: { enabled: false } } }, dispatch: vi.fn() };
    const clear = vi.spyOn(Storage.prototype, "clear").mockImplementation(() => {
      throw new DOMException("Storage blocked", "SecurityError");
    });
    try {
      expect(() => expireSession(store, { toLogin: true })).not.toThrow();
      expect(store.dispatch).toHaveBeenCalledWith("logout");
      expect(assign).toHaveBeenCalledTimes(1);
    } finally {
      clear.mockRestore();
      vi.stubGlobal("location", realLocation);
    }
  });
});
