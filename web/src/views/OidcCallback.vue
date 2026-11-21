<!-- Copyright 2026 OpenObserve Inc. -->
<template>
  <main class="bg-card-glass-bg flex min-h-dvh items-center justify-center p-6">
    <div
      v-if="state === 'loading'"
      data-test="oidc-callback-loading"
      class="flex flex-col items-center gap-4"
    >
      <OSpinner size="lg" />
      <div class="text-text-secondary text-base">{{ t("login.signingIn") }}</div>
    </div>
    <div v-else class="flex max-w-lg flex-col gap-4">
      <OBanner
        v-if="state === 'no-organization'"
        variant="info"
        :content="t('login.oidcNoOrganization')"
        data-test="oidc-no-organization"
      />
      <template v-else>
        <OBanner variant="error" :content="t('login.oidcError')" />
        <OButton variant="primary" data-test="oidc-retry-callback" @click="load">
          {{ t("common.retry") }}
        </OButton>
      </template>
      <OButton variant="primary" data-test="oidc-sign-out" @click="signOut">
        {{ t("menu.signOut") }}
      </OButton>
    </div>
  </main>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { isAxiosError } from "axios";
import { useRouter } from "vue-router";
import { useStore } from "vuex";
import OButton from "@/lib/core/Button/OButton.vue";
import OBanner from "@/lib/feedback/Banner/OBanner.vue";
import OSpinner from "@/lib/feedback/Spinner/OSpinner.vue";
import { purgeAllQueries } from "@/composables/query/queryClient";
import { purgeAllPersisted } from "@/composables/query/persisters";
import oidc, { type OidcSessionProfile } from "@/services/oidc";
import organizationsService from "@/services/organizations";
import { useI18nTyped } from "@/types/i18n";
import { redirectUser } from "@/utils/common";
import { reportSignOutFailure } from "@/utils/serverSignOut";
import { b64EncodeStandard } from "@/utils/formatters";
import { expireSession } from "@/utils/sessionServices";
import { useLocalCurrentUser, useLocalUserInfo } from "@/utils/storage";

const { t } = useI18nTyped();
const router = useRouter();
const store = useStore();
const state = ref<"loading" | "no-organization" | "failed">("loading");

const statusOf = (error: unknown) => (isAxiosError(error) ? error.response?.status : undefined);

async function load() {
  state.value = "loading";
  let profile: OidcSessionProfile;
  try {
    // Only the server session supplies identity; nothing in the URL is trusted.
    profile = await oidc.session();
  } catch (error) {
    const status = statusOf(error);
    if (!status || status >= 500) {
      state.value = "failed";
      return;
    }
    useLocalUserInfo("", true);
    useLocalCurrentUser("", true);
    store.dispatch("logout");
    router.replace({ path: "/login", query: { oidc_error: "1" } });
    return;
  }
  // Cached results carry no user in their keys, so a replaced account's must be gone first;
  // purgeAllQueries only starts the disk purge, so await it before the new identity loads.
  purgeAllQueries();
  await purgeAllPersisted();
  useLocalUserInfo(b64EncodeStandard(JSON.stringify(profile)));
  useLocalCurrentUser(JSON.stringify(profile));
  store.dispatch("setCurrentUser", profile);
  store.dispatch("login", { loginState: true, userInfo: profile });
  let organizations: unknown[] | undefined;
  try {
    // One row answers whether any membership exists; the main layout loads the full list.
    organizations = (await organizationsService.list(0, 1, "id", false, "")).data.data;
  } catch (error) {
    if (statusOf(error) === 403) return signOut();
    state.value = "failed";
    return;
  }
  if (!organizations?.length) {
    state.value = "no-organization";
    return;
  }
  const redirectURI = sessionStorage.getItem("redirectURI");
  sessionStorage.removeItem("redirectURI");
  // A full load lets the main layout choose the organization as it does after any reload.
  redirectUser(redirectURI);
}

async function signOut() {
  try {
    await oidc.logout();
  } catch {
    reportSignOutFailure();
    return;
  }
  // A reload here would re-run the callback, so this goes to the login page instead.
  expireSession(store, { toLogin: true });
}

void load();
</script>
