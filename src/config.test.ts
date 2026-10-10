import { describe, expect, it } from "vitest";
import { ConfigValidationError, loadConfig } from "./config.js";

const validValues = {
    SALESFORCE_LOGIN_URL: "https://login.salesforce.com",
    SALESFORCE_CLIENT_ID: "fake-client-id",
    SALESFORCE_CLIENT_SECRET: "fake-client-secret",
    SALESFORCE_CALLBACK_URL: "http://localhost:3000/oauth/callback",
    SESSION_SECRET: "a".repeat(64),
};

describe("loadConfig", () => {
    it.each([
        "https://login.salesforce.com",
        "https://test.salesforce.com/",
    ])("accepts the approved Salesforce login URL %s", (loginUrl) => {
        expect(loadConfig({ ...validValues, SALESFORCE_LOGIN_URL: loginUrl }).loginUrl)
            .toBe(loginUrl);
    });

    it("returns typed configuration for valid values", () => {
        expect(loadConfig(validValues)).toEqual({
            loginUrl: "https://login.salesforce.com",
            clientId: "fake-client-id",
            clientSecret: "fake-client-secret",
            callbackUrl: "http://localhost:3000/oauth/callback",
            sessionSecret: "a".repeat(64),
        });
    });

    it("reports every missing and whitespace-only variable by name", () => {
        expect(() => loadConfig({
            SALESFORCE_LOGIN_URL: " ",
            SALESFORCE_CLIENT_ID: "fake-client-id",
            SALESFORCE_CLIENT_SECRET: "\t",
            SALESFORCE_CALLBACK_URL: "",
            SESSION_SECRET: " ",
        })).toThrow(
            "Missing required Salesforce configuration: SALESFORCE_LOGIN_URL, SALESFORCE_CLIENT_SECRET, SALESFORCE_CALLBACK_URL, SESSION_SECRET",
        );
    });

    it("requires a session secret", () => {
        expect(() => loadConfig({ ...validValues, SESSION_SECRET: undefined }))
            .toThrow("Missing required Salesforce configuration: SESSION_SECRET");
    });

    it("rejects a blank session secret", () => {
        expect(() => loadConfig({ ...validValues, SESSION_SECRET: "  " }))
            .toThrow("Missing required Salesforce configuration: SESSION_SECRET");
    });

    it("rejects a session secret with fewer than 32 bytes of hex material", () => {
        const secret = "ab".repeat(31);
        expect(() => loadConfig({ ...validValues, SESSION_SECRET: secret }))
            .toThrow("SESSION_SECRET must be at least 64 hexadecimal characters (32 random bytes).");
    });

    it("does not reflect session secret values in validation errors", () => {
        const secret = "not-a-secure-session-secret";
        let thrown: unknown;
        expect(() => {
            try {
                loadConfig({ ...validValues, SESSION_SECRET: secret });
            } catch (error) {
                thrown = error;
                throw error;
            }
        }).toThrow();
        expect((thrown as Error).message).not.toContain(secret);
    });

    it.each([
        "not a URL",
        "https://login.salesforce.com:bad-port",
    ])("rejects malformed login URLs without reflecting the value", (loginUrl) => {
        expect(() => loadConfig({ ...validValues, SALESFORCE_LOGIN_URL: loginUrl }))
            .toThrow("SALESFORCE_LOGIN_URL must be a valid HTTPS URL.");
    });

    it("rejects non-HTTPS login URLs", () => {
        expect(() => loadConfig({
            ...validValues,
            SALESFORCE_LOGIN_URL: "http://login.salesforce.com",
        })).toThrow("SALESFORCE_LOGIN_URL must use HTTPS.");
    });

    it.each([
        "https://login.salesforce.com.attacker.invalid",
        "https://my-domain.my.salesforce.com",
        "https://login.salesforce.com/oauth",
        "https://login.salesforce.com?next=/oauth",
        "https://login.salesforce.com?",
        "https://login.salesforce.com#fragment",
    ])("rejects unapproved login hosts or URL components", (loginUrl) => {
        expect(() => loadConfig({ ...validValues, SALESFORCE_LOGIN_URL: loginUrl }))
            .toThrow(ConfigValidationError);
    });

    it.each([
        "https://user@login.salesforce.com",
        "https://user:fake-secret@login.salesforce.com",
        "https://@login.salesforce.com",
    ])("rejects credentials in login URLs", (loginUrl) => {
        expect(() => loadConfig({ ...validValues, SALESFORCE_LOGIN_URL: loginUrl }))
            .toThrow("SALESFORCE_LOGIN_URL must not contain credentials.");
    });

    it.each([
        "not a URL",
        "/relative/callback",
        "http://[invalid/callback",
    ])("rejects malformed or relative callback URLs", (callbackUrl) => {
        expect(() => loadConfig({ ...validValues, SALESFORCE_CALLBACK_URL: callbackUrl }))
            .toThrow("SALESFORCE_CALLBACK_URL must be a valid URL.");
    });

    it.each([
        "https://partner.example.invalid/oauth/callback",
        "https://localhost/oauth/callback",
    ])("accepts HTTPS callback URLs: %s", (callbackUrl) => {
        expect(loadConfig({ ...validValues, SALESFORCE_CALLBACK_URL: callbackUrl }).callbackUrl)
            .toBe(callbackUrl);
    });

    it.each([
        "http://localhost:3000/oauth/callback",
        "http://127.0.0.1:3000/oauth/callback",
        "http://[::1]:3000/oauth/callback",
    ])("accepts local HTTP callback URLs: %s", (callbackUrl) => {
        expect(loadConfig({ ...validValues, SALESFORCE_CALLBACK_URL: callbackUrl }).callbackUrl)
            .toBe(callbackUrl);
    });

    it("rejects HTTP callback URLs on non-loopback hosts", () => {
        expect(() => loadConfig({
            ...validValues,
            SALESFORCE_CALLBACK_URL: "http://partner.example.invalid/callback",
        })).toThrow(
            "SALESFORCE_CALLBACK_URL must use HTTPS, except on localhost or a loopback IP.",
        );
    });

    it.each([
        "https://user@partner.example.invalid/callback",
        "https://user:fake-secret@partner.example.invalid/callback",
        "https://@partner.example.invalid/callback",
    ])("rejects credentials in callback URLs", (callbackUrl) => {
        expect(() => loadConfig({ ...validValues, SALESFORCE_CALLBACK_URL: callbackUrl }))
            .toThrow("SALESFORCE_CALLBACK_URL must not contain credentials.");
    });

    it("rejects callback URL fragments", () => {
        expect(() => loadConfig({
            ...validValues,
            SALESFORCE_CALLBACK_URL: "https://partner.example.invalid/callback#fragment",
        })).toThrow("SALESFORCE_CALLBACK_URL must not contain a fragment.");
    });

    it.each([
        {
            name: "login URL",
            variable: "SALESFORCE_LOGIN_URL" as const,
            invalidValue: "https://login.salesforce.com.attacker.invalid/fake-secret",
        },
        {
            name: "callback URL",
            variable: "SALESFORCE_CALLBACK_URL" as const,
            invalidValue: "http://partner.example.invalid/fake-secret",
        },
    ])("does not include invalid $name input in error messages", ({ variable, invalidValue }) => {
        let thrown: unknown;
        expect(() => {
            try {
                loadConfig({ ...validValues, [variable]: invalidValue });
            } catch (error) {
                thrown = error;
                throw error;
            }
        }).toThrow();
        expect(thrown).toBeInstanceOf(ConfigValidationError);
        expect((thrown as Error).message).not.toContain(invalidValue);
        expect((thrown as Error).message).not.toContain("fake-secret");
    });
});
