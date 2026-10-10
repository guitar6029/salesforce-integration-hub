import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { SalesforceConfig } from "./config.js";
import { buildAuthorizationUrl, createOAuthTransaction } from "./oauth.js";

const config: SalesforceConfig = {
    loginUrl: "https://test.salesforce.com",
    clientId: "fake-client-id",
    clientSecret: "fake-client-secret",
    callbackUrl: "http://localhost:3000/oauth/callback",
};

describe("OAuth authorization helpers", () => {
    it("creates unique cryptographically random state and a valid PKCE verifier", () => {
        const first = createOAuthTransaction();
        const second = createOAuthTransaction();

        expect(first.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(first.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(first.state).not.toBe(second.state);
        expect(first.verifier).not.toBe(second.verifier);
    });

    it("uses the verifier only to derive the S256 challenge", () => {
        const transaction = createOAuthTransaction();
        const url = buildAuthorizationUrl(config, transaction);
        const expectedChallenge = createHash("sha256")
            .update(transaction.verifier)
            .digest("base64url");

        expect(url.searchParams.get("code_challenge")).toBe(expectedChallenge);
        expect(url.searchParams.get("state")).toBe(transaction.state);
        expect(url.searchParams.get("code_challenge_method")).toBe("S256");
        expect(url.toString()).not.toContain(transaction.verifier);
        expect(url.toString()).not.toContain(config.clientSecret);
    });
});
