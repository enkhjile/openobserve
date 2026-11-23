<!-- Copyright 2026 OpenObserve Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->

<template>
  <section v-if="enabled" data-test="iam-rbac-panel">
    <OPageHeader :title="t('ossRbac.title')" icon="person" :subtitle="t('ossRbac.subtitle')" />
    <OCard>
      <OCardSection role="body">
        <p v-if="error" role="alert" data-test="iam-rbac-error">{{ error }}</p>
        <OButton
          v-if="error"
          variant="outline"
          :disabled="busy"
          data-test="iam-rbac-retry"
          @click="load"
          >{{ t("ossRbac.reload") }}</OButton
        >
        <p v-if="busy" role="status">{{ t("ossRbac.loading") }}</p>
        <template v-if="membership">
          <p data-test="iam-rbac-roles">
            {{
              t("ossRbac.yourRoles", {
                roles:
                  membership.grants.map((g) => t(`ossRbac.roles.${g.role}`)).join(", ") ||
                  t("ossRbac.none"),
              })
            }}
          </p>
          <p data-test="iam-rbac-subject">
            {{ t("ossRbac.identity", { subject: membership.subject }) }}
          </p>
          <p v-if="!membership.can_manage">{{ t("ossRbac.readOnly") }}</p>
        </template>
        <template v-if="membership?.can_manage && policy">
          <div
            v-for="(grant, index) in policy.grants"
            :key="index"
            class="my-4"
            data-test="iam-rbac-grant"
          >
            <p>{{ subjectLabel(grant.subject) }} — {{ t(`ossRbac.roles.${grant.role}`) }}</p>
            <ul>
              <li v-for="(resource, resourceIndex) in grant.resources" :key="resourceIndex">
                {{ t(`ossRbac.kinds.${resource.kind}`) }} · {{ resource.stream_type }} ·
                {{ resource.name }}
              </li>
            </ul>
            <OButton
              variant="outline"
              size="sm"
              :disabled="busy"
              data-test="iam-rbac-remove"
              @click="policy.grants.splice(index, 1)"
              >{{ t("ossRbac.remove") }}</OButton
            >
          </div>
          <div class="grid grid-cols-2 gap-4 max-md:grid-cols-1">
            <OSelect
              v-model="subject"
              :label="t('ossRbac.member')"
              :options="subjectOptions"
              :disabled="busy"
              data-test="iam-rbac-member"
            />
            <OSelect
              v-model="role"
              :label="t('ossRbac.role')"
              :options="roleOptions"
              :disabled="busy"
              data-test="iam-rbac-role"
            />
            <OSelect
              v-model="kind"
              :label="t('ossRbac.resource')"
              :options="kindOptions"
              :disabled="busy"
              data-test="iam-rbac-kind"
            />
            <OSelect
              v-if="kind === 'stream'"
              v-model="streamType"
              :label="t('ossRbac.streamType')"
              :options="streamOptions"
              :disabled="busy"
              data-test="iam-rbac-stream-type"
            />
            <OInput
              v-if="kind !== 'organization'"
              v-model="resourceName"
              :label="t('ossRbac.resourceName')"
              :help-text="t('ossRbac.scopeHelp')"
              :disabled="busy"
              data-test="iam-rbac-resource-name"
            />
          </div>
          <OButton
            variant="outline"
            :disabled="busy || !canAdd"
            class="my-4"
            data-test="iam-rbac-add"
            @click="addGrant"
            >{{ t("ossRbac.add") }}</OButton
          >
          <OButton
            variant="primary"
            :loading="busy"
            :disabled="busy"
            data-test="iam-rbac-save"
            @click="save"
            >{{ t("ossRbac.save") }}</OButton
          >
          <OCard class="mt-4">
            <OCardSection>
              <p>{{ t("ossRbac.deliveryApprovals") }}</p>
              <p>{{ t("ossRbac.deliveryHelp") }}</p>
              <div
                v-for="(approval, index) in policy.destination_approvals ?? []"
                :key="index"
                class="my-4"
              >
                <p>
                  {{ approval.destination_name }}:
                  {{
                    approval.sources
                      .map((source) => `${source.stream_type}/${source.name}`)
                      .join(", ")
                  }}
                </p>
                <OButton
                  variant="outline"
                  :disabled="busy"
                  @click="policy.destination_approvals?.splice(index, 1)"
                  >{{ t("ossRbac.remove") }}</OButton
                >
              </div>
              <OInput
                v-model="destinationName"
                :label="t('ossRbac.destinationName')"
                :disabled="busy"
              />
              <OSelect
                v-model="destinationStreamType"
                :label="t('ossRbac.streamType')"
                :options="streamOptions"
                :disabled="busy"
              />
              <OInput
                v-model="destinationStream"
                :label="t('ossRbac.resourceName')"
                :disabled="busy"
              />
              <OButton
                variant="outline"
                class="my-4"
                :disabled="
                  busy ||
                  !destinationName.trim() ||
                  !destinationStream.trim() ||
                  destinationStream.includes('*')
                "
                data-test="iam-rbac-destination-add"
                @click="addDestinationApproval"
                >{{ t("ossRbac.add") }}</OButton
              >
              <OButton
                variant="primary"
                :disabled="busy"
                data-test="iam-rbac-destinations-save"
                @click="saveDestinationApprovals"
                >{{ t("ossRbac.saveDelivery") }}</OButton
              >
            </OCardSection>
          </OCard>
          <p v-if="saved" role="status" data-test="iam-rbac-saved">{{ t("ossRbac.saved") }}</p>
        </template>
      </OCardSection>
    </OCard>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useStore } from "vuex";
import { isAxiosError } from "axios";
import { useI18nTyped, raw, type I18nText } from "@/types/i18n";
import OPageHeader from "@/lib/core/PageHeader/OPageHeader.vue";
import OCard from "@/lib/core/Card/OCard.vue";
import OCardSection from "@/lib/core/Card/OCardSection.vue";
import OButton from "@/lib/core/Button/OButton.vue";
import OInput from "@/lib/forms/Input/OInput.vue";
import OSelect from "@/lib/forms/Select/OSelect.vue";
import rbac, {
  type Membership,
  type Policy,
  type Subject,
  type Role,
  type ResourceKind,
} from "@/services/rbac";

const emit = defineEmits<{
  enabled: [value: boolean];
  permissions: [value: { organization: string; enabled: boolean | null; canManage: boolean }];
}>();
const { t } = useI18nTyped();
const store = useStore();
const organization = computed(
  () => store.state.selectedOrganization?.identifier as string | undefined,
);
const membership = ref<Membership>();
const policy = ref<Policy>();
const subjects = ref<Subject[]>([]);
const enabled = ref(false);
const busy = ref(false);
const error = ref<I18nText>();
const saved = ref(false);
const subject = ref("");
const role = ref<Role>("viewer");
const kind = ref<ResourceKind>("stream");
const streamType = ref("logs");
const resourceName = ref("");
const destinationName = ref("");
const destinationStreamType = ref("logs");
const destinationStream = ref("");
function addDestinationApproval() {
  if (!policy.value || !membership.value?.can_manage || busy.value) return;
  const name = destinationName.value.trim();
  const stream = destinationStream.value.trim();
  if (!name || !stream || stream.includes("*")) return;
  const approvals = (policy.value.destination_approvals ??= []);
  const existing = approvals.find((approval) => approval.destination_name === name);
  const resource = {
    kind: "stream" as const,
    stream_type: destinationStreamType.value,
    name: stream,
  };
  if (existing) existing.sources.push(resource);
  else approvals.push({ destination_name: name, sources: [resource] });
  destinationStream.value = "";
}

async function saveDestinationApprovals() {
  if (!organization.value || !policy.value || !membership.value?.can_manage || busy.value) return;
  const current = generation;
  busy.value = true;
  error.value = undefined;
  try {
    const response = await rbac.saveDestinations(organization.value, policy.value);
    if (current !== generation || !policy.value) return;
    // Keep unsaved grant edits; this save only changes delivery approvals.
    policy.value = { ...response.data, grants: policy.value.grants };
    saved.value = true;
  } catch {
    if (current === generation) error.value = t("ossRbac.deliveryFailed");
  } finally {
    if (current === generation) busy.value = false;
  }
}

let generation = 0;
const tokenSelected = computed(() => subject.value.startsWith("org-token:"));
watch(subject, () => {
  if (tokenSelected.value) {
    role.value = "ingester";
    kind.value = "stream";
  }
});
const roleOptions = computed(() =>
  (tokenSelected.value
    ? ["ingester" as const]
    : (["admin", "editor", "viewer", "ingester", "exporter"] as const)
  ).map((value) => ({
    value,
    label: t(`ossRbac.roles.${value}`),
  })),
);
const kindOptions = computed(() =>
  (tokenSelected.value
    ? ["stream" as const]
    : ([
        "organization",
        "stream",
        "dashboard",
        "alert",
        "report",
        "pipeline",
        "saved_query",
      ] as const)
  ).map((value) => ({
    value,
    label: t(`ossRbac.kinds.${value}`),
  })),
);
const streamOptions = ["logs", "metrics", "traces"].map((value) => ({ value, label: raw(value) }));
const subjectOptions = computed(() =>
  subjects.value.map((member) => ({
    value: member.subject,
    label:
      member.kind === "ingestion_token"
        ? t("ossRbac.tokenLabel", { name: member.name ?? member.subject })
        : raw(member.email ?? member.subject),
  })),
);
const canAdd = computed(
  () =>
    subject.value &&
    (!tokenSelected.value || (role.value === "ingester" && kind.value === "stream")) &&
    (kind.value === "organization" || resourceName.value.trim()) &&
    (!["ingester", "exporter"].includes(role.value) ||
      (kind.value === "stream" && resourceName.value.trim() !== "*")),
);
const subjectLabel = (id: string) =>
  subjectOptions.value.find((option) => option.value === id)?.label ?? id;
const failure = (cause: unknown) =>
  isAxiosError(cause) && cause.response?.status === 403 ? t("ossRbac.denied") : t("ossRbac.failed");

let loadedOrganization: string | undefined;

async function load() {
  const org = organization.value;
  const run = ++generation;
  // Reloading the same organization keeps the Users list mounted.
  if (org !== loadedOrganization) {
    emit("permissions", { organization: org ?? "", enabled: null, canManage: false });
  }
  loadedOrganization = org;
  membership.value = undefined;
  policy.value = undefined;
  subjects.value = [];
  subject.value = "";
  error.value = undefined;
  saved.value = false;
  if (!org) return;
  busy.value = true;
  try {
    const { data } = await rbac.me(org);
    if (run !== generation) return;
    membership.value = data;
    enabled.value = data.enabled;
    emit("enabled", data.enabled);
    emit("permissions", {
      organization: org,
      enabled: typeof data.enabled === "boolean" ? data.enabled : null,
      canManage: data.can_manage === true,
    });
    if (data.can_manage) {
      const [document, members] = await Promise.all([rbac.policy(org), rbac.subjects(org)]);
      if (run !== generation) return;
      policy.value = document.data;
      subjects.value = members.data;
    }
  } catch (cause) {
    if (run === generation) {
      // Only RBAC answers 403 here; any other failure leaves the page as upstream shows it.
      const denied = isAxiosError(cause) && cause.response?.status === 403;
      enabled.value = denied || enabled.value;
      error.value = failure(cause);
      emit("permissions", { organization: org, enabled: denied ? true : null, canManage: false });
    }
  } finally {
    if (run === generation) busy.value = false;
  }
}

function addGrant() {
  if (!canAdd.value || !membership.value?.can_manage || !policy.value) return;
  policy.value.grants.push({
    subject: subject.value,
    role: role.value,
    resources: [
      {
        kind: kind.value,
        stream_type: kind.value === "stream" ? streamType.value : "",
        name: kind.value === "organization" ? "organization" : resourceName.value.trim(),
      },
    ],
  });
  saved.value = false;
}

async function save() {
  const org = organization.value;
  if (!org || !policy.value || !membership.value?.can_manage || busy.value) return;
  const run = generation;
  busy.value = true;
  error.value = undefined;
  saved.value = false;
  try {
    const { data } = await rbac.save(org, policy.value);
    if (run !== generation || !policy.value) return;
    // Keep unsaved approval edits; this save only changes grants.
    policy.value = { ...data, destination_approvals: policy.value.destination_approvals };
    saved.value = true;
  } catch (cause) {
    if (run === generation) error.value = failure(cause);
  } finally {
    if (run === generation) busy.value = false;
  }
}
watch(organization, load, { immediate: true });
</script>
