// Copyright 2026 OpenObserve Inc.
describe("OSS OIDC login", () => {
  const openLogin = (overrides = {}, query = "") => {
    cy.intercept("GET", "**/config", {
      oidc_enabled: true,
      oidc_only: true,
      oidc_emergency_login_enabled: false,
      native_login_enabled: true,
      sso_enabled: false,
      telemetry_enabled: false,
      ...overrides,
    });
    cy.visit(`/web/login${query}`);
  };

  it("shows SSO and hides native login in OIDC-only mode", () => {
    openLogin();
    cy.get('[data-test="sso-login-btn"]').should("be.visible").and("contain", "Sign in with SSO");
    cy.get('[data-test="login-user-id"]').should("not.exist");
    cy.get('[data-test="login-as-internal-user"]').should("not.exist");
    cy.screenshot("oidc-only-login");
  });

  it("allows explicitly enabled emergency login", () => {
    openLogin({ oidc_emergency_login_enabled: true });
    cy.get('[data-test="login-as-internal-user"]').click();
    cy.get('[data-test="login-user-id"]').should("be.visible");
    cy.get('[data-test="login-password"]').should("be.visible");
  });

  it("preserves local login when OIDC is disabled", () => {
    openLogin({ oidc_enabled: false });
    cy.get('[data-test="sso-login-btn"]').should("not.exist");
    cy.get('[data-test="login-user-id"]').should("be.visible");
  });

  it("explains missing organization membership and signs out", () => {
    cy.intercept("GET", "**/config", {
      oidc_enabled: true,
      oidc_only: true,
      telemetry_enabled: false,
    });
    cy.intercept("GET", "**/auth/oidc/session", {
      email: "new@example.test",
      name: "New",
      given_name: "New",
      family_name: "",
      exp: Math.floor(Date.now() / 1000) + 600,
    });
    cy.intercept("GET", "**/api/organizations?*", { data: [] });
    cy.intercept("POST", "**/auth/oidc/logout", { statusCode: 204, delay: 200 }).as("logout");
    cy.visit("/web/cb?oidc=1");
    cy.get('[data-test="oidc-no-organization"]')
      .should("be.visible")
      .and("contain", "Ask your OpenObserve administrator");
    cy.screenshot("oidc-no-organization");
    cy.contains("button", "Sign Out").click();
    cy.wait("@logout");
    cy.location("pathname").should("eq", "/web/login");
  });

  it("requires confirmation for a direct native logout", () => {
    cy.intercept("GET", "**/config", { oidc_enabled: false });
    let attempts = 0;
    cy.intercept("GET", "**/config/logout", (request) => {
      attempts += 1;
      request.reply({ statusCode: [503, 401, 200][attempts - 1] });
    }).as("nativeLogout");
    cy.visit("/web/logout", {
      onBeforeLoad(win) {
        win.localStorage.setItem(
          "userInfo",
          win.btoa(JSON.stringify({ email: "native@example.test" })),
        );
      },
    });
    cy.get('[data-test="confirm-sign-out"]')
      .should("be.visible")
      .then(() => {
        expect(attempts).to.equal(0);
      });
    [503, 401].forEach((status) => {
      cy.get('[data-test="confirm-sign-out"]').click();
      cy.wait("@nativeLogout").its("response.statusCode").should("eq", status);
      cy.contains("Sign-out failed").should("be.visible");
      cy.location("pathname").should("eq", "/web/logout");
      cy.window().then((win) => expect(win.localStorage.getItem("userInfo")).not.to.be.null);
    });
    cy.get('[data-test="confirm-sign-out"]').click();
    cy.wait("@nativeLogout");
    cy.location("pathname").should("eq", "/web/login");
  });

  [false, true].forEach((cachedProfile) => {
    it(`requires confirmation for direct logout with ${cachedProfile ? "a cached" : "no cached"} profile`, () => {
      cy.intercept("GET", "**/config", { oidc_enabled: true, oidc_only: true });
      let attempts = 0;
      cy.intercept("POST", "**/auth/oidc/logout", (request) => {
        attempts += 1;
        request.reply({ statusCode: attempts === 1 ? 503 : 204 });
      }).as("revoke");
      cy.visit("/web/logout", {
        onBeforeLoad(win) {
          if (cachedProfile) {
            win.localStorage.setItem(
              "userInfo",
              win.btoa(
                JSON.stringify({
                  email: "member@example.test",
                  exp: Math.floor(Date.now() / 1000) + 600,
                }),
              ),
            );
          } else {
            win.localStorage.removeItem("userInfo");
          }
        },
      });
      cy.get('[data-test="confirm-sign-out"]')
        .should("be.visible")
        .then(() => {
          expect(attempts).to.equal(0);
        });
      cy.get('[data-test="confirm-sign-out"]').click();
      cy.wait("@revoke");
      cy.contains("Sign-out failed").should("be.visible");
      cy.location("pathname").should("eq", "/web/logout");
      cy.get('[data-test="confirm-sign-out"]').click();
      cy.wait("@revoke");
      cy.location("pathname").should("eq", "/web/login");
    });
  });

  it("finishes confirmed logout when browser storage cleanup is blocked", () => {
    cy.intercept("GET", "**/config", { oidc_enabled: true, oidc_only: true });
    cy.intercept("POST", "**/auth/oidc/logout", { statusCode: 204 }).as("revoke");
    cy.visit("/web/logout");
    cy.window().then((win) => {
      const removeItem = win.Storage.prototype.removeItem;
      cy.stub(win.Storage.prototype, "removeItem").callsFake(function (key) {
        if (key === "isFirstTimeLogin")
          throw new win.DOMException("Storage blocked", "SecurityError");
        removeItem.call(this, key);
      });
    });
    cy.get('[data-test="confirm-sign-out"]').click();
    cy.wait("@revoke");
    cy.location("pathname").should("eq", "/web/login");
    cy.get('[data-test="sso-login-btn"]').should("be.visible");
  });

  it("shows a generic failure without echoing provider error details", () => {
    openLogin({}, "?oidc_error=1&error_description=private-provider-details");
    cy.get('[data-test="oidc-error"]').should("be.visible").and("contain", "SSO sign-in failed");
    cy.get("body").should("not.contain", "private-provider-details");
  });
});
