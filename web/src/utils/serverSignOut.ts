// Copyright 2026 OpenObserve Inc.
import { queryClient } from "@/composables/query/queryClient";
import { toast } from "@/lib/feedback/Toast/useToast";
import { configQuery } from "@/services/config.queries";
import oidc, { authClient } from "@/services/oidc";
import userService from "@/services/users";
import { gt } from "@/types/i18n";
import { invalidateLoginData } from "@/utils/zincutils";

interface ConfigStore {
  state: { zoConfig?: { oidc_enabled?: boolean } };
}

/** Revokes the server session ahead of browser cleanup; an unconfirmed native logout is only started. */
export const revokeServerSession = async (
  store: ConfigStore,
  { confirmNative }: { confirmNative: boolean },
): Promise<void> => {
  // A direct /logout navigation can run before main.ts has stored the bootstrap config.
  const enabled =
    store.state.zoConfig?.oidc_enabled ??
    (await queryClient.fetchQuery(configQuery())).oidc_enabled;
  // The caller reports a failed revocation, so the global 401 handler must not reload first.
  if (enabled) await oidc.logout();
  else if (confirmNative) await userService.logout(authClient());
  else invalidateLoginData();
};

export const reportSignOutFailure = (): void => {
  toast({ variant: "error", message: gt("login.oidcLogoutError") });
};
