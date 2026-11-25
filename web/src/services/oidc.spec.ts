// Copyright 2026 OpenObserve Inc.
import { beforeEach, describe, expect, it, vi } from "vitest";
import oidc from "./oidc";
const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock("axios", () => ({ default: { create: () => mocks } }));
vi.mock("@/stores", () => ({ default: { state: { API_ENDPOINT: "https://observe.test/base" } } }));
describe("OIDC browser adapter", () => {
  beforeEach(() => vi.resetAllMocks());
  it("uses a fixed login endpoint under the API base", () => {
    expect(oidc.loginUrl()).toBe("https://observe.test/base/auth/oidc/login");
  });
  it("gets the profile from the session rather than URL claims", async () => {
    const profile = {
      email: "user@example.test",
      name: "User",
      given_name: "User",
      family_name: "",
      exp: 123,
    };
    mocks.get.mockResolvedValue({ data: profile });
    expect(await oidc.session()).toEqual(profile);
    expect(mocks.get).toHaveBeenCalledWith("/auth/oidc/session");
  });
  it("does not swallow session or logout failure", async () => {
    mocks.get.mockRejectedValue(new Error("unavailable"));
    mocks.post.mockRejectedValue(new Error("unavailable"));
    await expect(oidc.session()).rejects.toThrow();
    await expect(oidc.logout()).rejects.toThrow();
    expect(mocks.post).toHaveBeenCalledWith("/auth/oidc/logout");
  });
});
