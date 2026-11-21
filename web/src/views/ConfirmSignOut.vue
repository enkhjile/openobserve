<!-- Copyright 2026 OpenObserve Inc. -->
<template>
  <main class="bg-card-glass-bg flex min-h-dvh items-center justify-center p-6">
    <div class="flex max-w-lg flex-col gap-4">
      <h1 class="text-lg font-semibold">{{ t("login.confirmSignOut") }}</h1>
      <OBanner v-if="failed" variant="error" :content="t('login.oidcLogoutError')" />
      <div class="flex gap-2">
        <OButton variant="secondary" :disabled="pending" @click="router.replace('/')">
          {{ t("common.cancel") }}
        </OButton>
        <OButton
          variant="primary"
          :disabled="pending"
          data-test="confirm-sign-out"
          @click="confirm"
        >
          {{ t("menu.signOut") }}
        </OButton>
      </div>
    </div>
  </main>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";
import OButton from "@/lib/core/Button/OButton.vue";
import OBanner from "@/lib/feedback/Banner/OBanner.vue";
import store from "@/stores";
import { useI18nTyped } from "@/types/i18n";
import { endSignedInSession, reloadToLogin } from "@/utils/drafts/signOutFlow";

const { t } = useI18nTyped();
const router = useRouter();
const pending = ref(false);
const failed = ref(false);

async function confirm() {
  if (pending.value) return;
  pending.value = true;
  failed.value = false;
  try {
    await endSignedInSession(store, { keepDrafts: true, awaitNativeLogout: true });
    reloadToLogin();
  } catch {
    failed.value = true;
    pending.value = false;
  }
}
</script>
