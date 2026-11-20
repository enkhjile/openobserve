// Copyright 2026 OpenObserve Inc.
import axios from "axios";
import store from "@/stores";

export interface OidcSessionProfile {
  email: string;
  name: string;
  given_name: string;
  family_name: string;
  exp: number;
}

// Auth failures must reach the login UI without the global 401 reload interceptor.
const client = () => axios.create({ baseURL: store.state.API_ENDPOINT, withCredentials: true });
const oidc = {
  loginUrl: () => `${store.state.API_ENDPOINT.replace(/\/$/, "")}/auth/oidc/login`,
  session: async (): Promise<OidcSessionProfile> =>
    (await client().get<OidcSessionProfile>("/auth/oidc/session")).data,
  logout: async (): Promise<void> => {
    await client().post("/auth/oidc/logout");
  },
};
export default oidc;
