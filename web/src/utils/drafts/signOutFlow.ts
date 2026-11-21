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

import type { Router } from "vue-router";
import { queryClient } from "@/composables/query/queryClient";
import { configQuery } from "@/services/config.queries";
import oidc from "@/services/oidc";
import { toast } from "@/lib/feedback/Toast/useToast";
import { gt } from "@/types/i18n";
import {
  getPath,
  useLocalCurrentUser,
  useLocalUserInfo,
  invalidateLoginData,
} from "@/utils/zincutils";
import { forgetLinkRequest } from "@/utils/slackLink";
import {
  beginDraftSignOut,
  cancelDraftSignOut,
  signOutLeaveWillAsk,
} from "@/utils/drafts/draftSession";
import { countAllDraftsFor, endEditorDraftSession } from "@/utils/drafts/editorDraftStore";
import {
  silenceUnloadPrompts,
  stopSessionServices,
  type SessionServicesStore,
} from "@/utils/sessionServices";

interface SignOutStore extends SessionServicesStore {
  state: SessionServicesStore["state"] & {
    userInfo?: { email?: string };
    zoConfig?: { oidc_enabled?: boolean };
  };
  dispatch: (type: "logout", payload?: { draftsOf?: string }) => unknown;
}

interface SignOutOptions {
  /** The session can no longer save (forced password reset), so the leave dialogs offer only Discard. */
  discardOnly?: boolean;
  /** The old session is already dead (the user's own password changed): no guard can keep the user in it, and the drafts stay as after an expired session. */
  forced?: boolean;
}

/** A full load, as the /logout route does, so nothing of the previous user's session stays in memory. */
export const reloadToLogin = (): void => {
  // The guards have already been answered, so no editor's own "leave site?" prompt may ask again on the way out.
  silenceUnloadPrompts();
  window.location.assign(`${getPath()}login`);
};

/** Ends the signed-in session here: services stopped, login data gone and, unless kept, this user's drafts gone with no draft written after. */
export const endSignedInSession = (
  store: SignOutStore,
  {
    keepDrafts = false,
    awaitNativeLogout = false,
  }: { keepDrafts?: boolean; awaitNativeLogout?: boolean } = {},
): void | Promise<void> => {
  const finish = (oidcEnabled: boolean) => {
    const request = oidcEnabled ? oidc.logout() : invalidateLoginData(awaitNativeLogout);
    if (oidcEnabled || awaitNativeLogout) {
      return request.then(() => clearSignedInSession(store, keepDrafts));
    }
    clearSignedInSession(store, keepDrafts);
  };
  const enabled = store.state.zoConfig?.oidc_enabled;
  // A direct /logout navigation can run before main.ts has stored the bootstrap config.
  if (enabled === undefined) {
    return queryClient.fetchQuery(configQuery()).then((config) => finish(config.oidc_enabled));
  }
  return finish(enabled);
};

const clearSignedInSession = (store: SignOutStore, keepDrafts: boolean): void => {
  const userEmail = String(store.state.userInfo?.email ?? "");
  stopSessionServices(store);
  // A deep-link first login keeps the flag for a later Home visit; it must not pass to the next user.
  localStorage.removeItem("isFirstTimeLogin");
  // the open sample tour is this user's; the full reload that follows drops its in-memory copy
  localStorage.removeItem("o2_sample_tour");
  if (keepDrafts) store.dispatch("logout");
  else {
    store.dispatch("logout", { draftsOf: userEmail });
    endEditorDraftSession(userEmail);
  }
  useLocalCurrentUser("", true);
  useLocalUserInfo("", true);
  forgetLinkRequest();
};

/** How many of the user's drafts a sign-out must confirm before it runs: 0 when there are none, or when an open editor's leave dialog tells about them itself. */
export const signOutDraftsToConfirm = (store: SignOutStore): number => {
  const count = countAllDraftsFor(String(store.state.userInfo?.email ?? ""));
  return count > 0 && !signOutLeaveWillAsk() ? count : 0;
};

/** Signs out through the open editors' leave guards, so their Save still has a session, then reloads to login; resolves false when one of them keeps the user. */
export const signOutThroughLeaveGuards = (
  router: Router,
  store: SignOutStore,
  { discardOnly = false, forced = false }: SignOutOptions = {},
): Promise<boolean> => {
  beginDraftSignOut({ discardOnly, forced });
  let signedOut = false;
  let ending: void | Promise<void>;
  const endSession = () => {
    if (signedOut) return ending;
    signedOut = true;
    ending = endSignedInSession(store, { keepDrafts: forced });
    return ending;
  };
  const removeGuard = router.beforeEach((to) => {
    removeGuard();
    if (to.path !== "/logout") return true;
    const pending = endSession();
    return pending ? pending.then(() => false) : false;
  });
  const finish = (refused: boolean): boolean | Promise<boolean> => {
    removeGuard();
    if (refused && !forced && !signedOut) {
      cancelDraftSignOut();
      return false;
    }
    const pending = endSession();
    if (pending) {
      return pending
        .then(() => {
          reloadToLogin();
          return true;
        })
        .catch(() => {
          cancelDraftSignOut();
          reportSignOutFailure();
          return false;
        });
    }
    reloadToLogin();
    return true;
  };
  return router.push("/logout").then(
    (failure) => finish(!!failure),
    () => finish(true),
  );
};

export const reportSignOutFailure = (): void => {
  toast({ variant: "error", message: gt("login.oidcLogoutError") });
};
