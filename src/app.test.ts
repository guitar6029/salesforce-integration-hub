import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SalesforceConfig } from "./config.js";
import { createApp } from "./app.js";

const config: SalesforceConfig = {
    loginUrl: "https://login.salesforce.com",
    clientId: "fake-client-id",
    clientSecret: "fake-client-secret",
    callbackUrl: "https://hub.example.invalid/oauth/callback",
};

describe("HTTP application", () => {
    afterEach(() => {
        vi.unstubAllEnvs();
    });

    it("returns a minimal health response", async () => {
        const response = await request(createApp()).get("/health");

        expect(response.status).toBe(200);
        expect(response.body).toEqual({ status: "ok" });
    });

    it("redirects to Salesforce with the required OAuth and S256 PKCE parameters", async () => {
        const loadConfig = vi.fn(() => config);
        const response = await request(createApp({ loadConfig })).get("/oauth/authorize");
        const location = new URL(response.headers.location as string);

        expect(response.status).toBe(302);
        expect(location.origin).toBe("https://login.salesforce.com");
        expect(location.pathname).toBe("/services/oauth2/authorize");
        expect(location.searchParams.get("response_type")).toBe("code");
        expect(location.searchParams.get("client_id")).toBe(config.clientId);
        expect(location.searchParams.get("redirect_uri")).toBe(config.callbackUrl);
        expect(location.searchParams.get("code_challenge_method")).toBe("S256");
        expect(location.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(location.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(response.headers["set-cookie"]).toBeDefined();
        expect(response.headers.location).not.toContain(config.clientSecret);
        expect(loadConfig).toHaveBeenCalledOnce();
    });

    it("rejects a repeated authorization request without replacing the pending transaction", async () => {
        vi.stubEnv("NODE_ENV", "development");
        const loadConfig = vi.fn(() => config);
        const app = createApp({ loadConfig });
        const browser = request.agent(app);
        const first = await browser.get("/oauth/authorize");
        const originalState = new URL(first.headers.location as string).searchParams.get("state");

        const second = await browser.get("/oauth/authorize");
        const third = await browser.get("/oauth/authorize");

        expect(first.status).toBe(302);
        expect(originalState).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(second.status).toBe(409);
        expect(second.body).toEqual({
            error: "An OAuth authorization is already in progress for this session.",
        });
        expect(second.headers.location).toBeUndefined();
        expect(second.headers["set-cookie"]).toBeUndefined();
        expect(third.status).toBe(409);
        expect(loadConfig).toHaveBeenCalledOnce();
    });

    it("sets HttpOnly and SameSite=Lax without Secure for local HTTP development", async () => {
        vi.stubEnv("NODE_ENV", "development");
        const response = await request(createApp({ loadConfig: () => config }))
            .get("/oauth/authorize");
        const setCookie = response.headers["set-cookie"];
        const cookie = Array.isArray(setCookie) ? setCookie.join("; ") : setCookie ?? "";

        expect(cookie).toContain("HttpOnly");
        expect(cookie).toContain("SameSite=Lax");
        expect(cookie).not.toContain("Secure");
    });

    it("sets Secure for production requests received over trusted HTTPS", async () => {
        vi.stubEnv("NODE_ENV", "production");
        const app = createApp({ loadConfig: () => config });
        app.set("trust proxy", 1);
        const response = await request(app)
            .get("/oauth/authorize")
            .set("X-Forwarded-Proto", "https");
        const setCookie = response.headers["set-cookie"];
        const cookie = Array.isArray(setCookie) ? setCookie.join("; ") : setCookie ?? "";

        expect(cookie).toContain("HttpOnly");
        expect(cookie).toContain("SameSite=Lax");
        expect(cookie).toContain("Secure");
    });

    it("returns a generic error when configuration cannot be loaded", async () => {
        const response = await request(createApp({
            loadConfig: () => { throw new Error("configuration unavailable"); },
        })).get("/oauth/authorize");

        expect(response.status).toBe(503);
        expect(response.body).toEqual({ error: "OAuth authorization is unavailable." });
    });
});
