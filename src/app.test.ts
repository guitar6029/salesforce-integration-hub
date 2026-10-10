import { createHmac } from "node:crypto";
import session from "express-session";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SalesforceConfig } from "./config.js";
import { createApp } from "./app.js";

const config: SalesforceConfig = {
    loginUrl: "https://login.salesforce.com",
    clientId: "fake-client-id",
    clientSecret: "fake-client-secret",
    callbackUrl: "https://hub.example.invalid/oauth/callback",
    sessionSecret: "b".repeat(64),
};

describe("HTTP application", () => {
    afterEach(() => {
        vi.unstubAllEnvs();
        vi.restoreAllMocks();
    });

    it("returns a minimal health response", async () => {
        const response = await request(createApp({ loadConfig: () => config })).get("/health");

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

    it("fails app creation when configuration cannot be loaded", async () => {
        expect(() => createApp({
            loadConfig: () => { throw new Error("configuration unavailable"); },
        })).toThrow("configuration unavailable");
    });

    it("uses the configured session secret to sign cookies without exposing it", async () => {
        const app = createApp({ loadConfig: () => config });
        const response = await request(app).get("/oauth/authorize");
        const setCookie = response.headers["set-cookie"];
        const cookies = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
        const signedCookie = decodeURIComponent(cookies[0]?.split(";", 1)[0] ?? "");
        const signature = signedCookie.slice(signedCookie.lastIndexOf(".") + 1);
        const sessionId = signedCookie.slice("connect.sid=s:".length, signedCookie.lastIndexOf("."));
        const expectedSignature = createHmac("sha256", config.sessionSecret)
            .update(sessionId)
            .digest("base64")
            .replace(/=+$/, "");

        expect(signedCookie).toContain("connect.sid=s:");
        expect(signature).toBe(expectedSignature);
        expect(cookies.join("; ")).not.toContain(config.sessionSecret);
        expect(response.headers.location).not.toContain(config.sessionSecret);
    });

    it("accepts a matching callback once and does not expose callback secrets", async () => {
        const app = createApp({ loadConfig: () => config });
        const browser = request.agent(app);
        const authorization = await browser.get("/oauth/authorize");
        const state = new URL(authorization.headers.location as string).searchParams.get("state");
        const code = "fake-authorization-code";
        const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
        const errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined);

        const callback = await browser.get("/oauth/callback")
            .query({ state, code });

        expect(callback.status).toBe(200);
        expect(callback.body).toEqual({
            status: "Authorization received. Token exchange is not implemented.",
        });
        expect(JSON.stringify(callback.body)).not.toContain(code);
        expect(JSON.stringify(callback.body)).not.toContain(config.clientSecret);
        expect(log).not.toHaveBeenCalled();
        expect(errorLog).not.toHaveBeenCalled();
        log.mockRestore();
        errorLog.mockRestore();

        const replay = await browser.get("/oauth/callback").query({ state, code });
        expect(replay.status).toBe(400);
        expect(JSON.stringify(replay.body)).not.toContain(code);
    });

    it("rejects callbacks with missing state or missing authorization code", async () => {
        const app = createApp({ loadConfig: () => config });
        const missingStateBrowser = request.agent(app);
        const first = await missingStateBrowser.get("/oauth/authorize");
        const firstState = new URL(first.headers.location as string).searchParams.get("state");
        const missingState = await missingStateBrowser.get("/oauth/callback").query({ code: "fake-code" });
        expect(missingState.status).toBe(400);

        const missingCodeBrowser = request.agent(app);
        const second = await missingCodeBrowser.get("/oauth/authorize");
        const secondState = new URL(second.headers.location as string).searchParams.get("state");
        const missingCode = await missingCodeBrowser.get("/oauth/callback").query({ state: secondState });
        expect(missingCode.status).toBe(400);
        expect(firstState).not.toBe(secondState);
    });

    it("rejects a mismatched state without consuming the pending transaction", async () => {
        const browser = request.agent(createApp({ loadConfig: () => config }));
        const authorization = await browser.get("/oauth/authorize");
        const state = new URL(authorization.headers.location as string).searchParams.get("state");
        const mismatched = await browser.get("/oauth/callback")
            .query({ state: "A".repeat(43), code: "fake-code" });
        const valid = await browser.get("/oauth/callback").query({ state, code: "fake-code" });

        expect(mismatched.status).toBe(400);
        expect(valid.status).toBe(200);
    });

    it("rejects callbacks without a pending transaction", async () => {
        const response = await request(createApp({ loadConfig: () => config }))
            .get("/oauth/callback")
            .query({ state: "A".repeat(43), code: "fake-code" });

        expect(response.status).toBe(400);
        expect(response.body).toEqual({ error: "OAuth callback is invalid or expired." });
    });

    it("rejects a callback after the five-minute transaction lifetime", async () => {
        let now = Date.now();
        vi.spyOn(Date, "now").mockImplementation(() => now);
        const browser = request.agent(createApp({ loadConfig: () => config }));
        const authorization = await browser.get("/oauth/authorize");
        const state = new URL(authorization.headers.location as string).searchParams.get("state");

        now += 5 * 60 * 1000;
        const callback = await browser.get("/oauth/callback").query({ state, code: "fake-code" });

        expect(callback.status).toBe(400);
        expect(callback.body).toEqual({ error: "OAuth callback is invalid or expired." });
    });

    it("does not process a callback after its session save fails", async () => {
        const app = createApp({ loadConfig: () => config });
        const originalSet = session.MemoryStore.prototype.set;
        let failNextSave = false;
        vi.spyOn(session.MemoryStore.prototype, "set").mockImplementation(function (
            this: InstanceType<typeof session.MemoryStore>,
            sessionId,
            data,
            callback,
        ) {
            if (failNextSave) {
                failNextSave = false;
                callback?.(new Error("synthetic session save failure"));
                return;
            }
            originalSet.call(this, sessionId, data, callback);
        });
        const browser = request.agent(app);
        const authorization = await browser.get("/oauth/authorize");
        const state = new URL(authorization.headers.location as string).searchParams.get("state");

        failNextSave = true;
        const failedSave = await browser.get("/oauth/callback").query({ state, code: "fake-code" });
        const retry = await browser.get("/oauth/callback").query({ state, code: "fake-code" });

        expect(failedSave.status).toBe(503);
        expect(failedSave.body).toEqual({ error: "OAuth callback could not be processed." });
        expect(retry.status).toBe(400);
        expect(retry.body).toEqual({ error: "OAuth callback is invalid or expired." });
    });

    it("consumes a pending transaction for Salesforce authorization errors without reflecting descriptions", async () => {
        const browser = request.agent(createApp({ loadConfig: () => config }));
        const authorization = await browser.get("/oauth/authorize");
        const state = new URL(authorization.headers.location as string).searchParams.get("state");
        const description = "<script>secret-looking untrusted content</script>";
        const callback = await browser.get("/oauth/callback")
            .query({ state, error: "access_denied", error_description: description });
        const replay = await browser.get("/oauth/callback").query({ state, code: "fake-code" });

        expect(callback.status).toBe(400);
        expect(callback.body).toEqual({ error: "Salesforce authorization was not completed." });
        expect(JSON.stringify(callback.body)).not.toContain(description);
        expect(replay.status).toBe(400);
    });
});
