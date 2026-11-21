<template>
  <RbacPolicy @permissions="acceptPermissions" />
  <component v-if="loadComponent && canShowUsers" :is="componentName" />
</template>

<script lang="ts">
import { defineComponent, ref, computed, watch, onBeforeMount } from "vue";
import { useStore } from "vuex";
import { useI18nTyped } from "@/types/i18n";
import RbacPolicy from "@/components/iam/RbacPolicy.vue";
import Users from "@/components/iam/users/User.vue";

interface Permissions {
  organization: string;
  enabled: boolean | null;
  canManage: boolean;
}

export default defineComponent({
  name: "UserPage",
  components: {
    Users,
    RbacPolicy,
  },
  setup() {
    const store = useStore();
    const permissions = ref<Permissions>();
    const organization = computed(() => store.state.selectedOrganization?.identifier);
    watch(
      organization,
      () => {
        permissions.value = undefined;
      },
      { flush: "sync" },
    );
    const acceptPermissions = (value: Permissions) => {
      if (value.organization === organization.value) permissions.value = value;
    };
    const canShowUsers = computed(() => {
      const current = permissions.value;
      return (
        current?.organization === organization.value &&
        (current?.enabled === false || (current?.enabled === true && current.canManage))
      );
    });
    const { t } = useI18nTyped();

    const componentName = ref("");

    const loadComponent = ref(false);

    onBeforeMount(() => {
      componentName.value = "Users";
      loadComponent.value = true;
    });

    return { store, t, componentName, loadComponent, acceptPermissions, canShowUsers };
  },
});
</script>
