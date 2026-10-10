import express, { type Express } from "express";
import session from "express-session";
import { loadConfig, type SalesforceConfig } from "./config.js";
import { buildAuthorizationUrl, createOAuthTransaction } from "./oauth.js";

declare module "express-session" {
    interface SessionData {
        oauthTransaction?: ReturnType<typeof createOAuthTransaction>;
    }
}

export interface AppOptions {
    loadConfig?: () => SalesforceConfig;
}

const transactionLifetimeMs = 5 * 60 * 1000;
const consumedTransactions = new Map<string, number>();

function isValidTransaction(value: unknown): value is ReturnType<typeof createOAuthTransaction> {
    if (!value || typeof value !== "object") return false;
    const transaction = value as Partial<ReturnType<typeof createOAuthTransaction>>;
    return typeof transaction.state === "string" &&
        /^[A-Za-z0-9_-]{43}$/.test(transaction.state) &&
        typeof transaction.verifier === "string" &&
        /^[A-Za-z0-9_-]{43}$/.test(transaction.verifier) &&
        typeof transaction.createdAt === "number" && Number.isFinite(transaction.createdAt);
}

function queryValue(value: unknown): string | undefined {
    return typeof value === "string" ? value : undefined;
}

export function createApp(options: AppOptions = {}): Express {
    const app = express();
    const getConfig = options.loadConfig ?? loadConfig;
    const config = getConfig();

    app.disable("x-powered-by");
    app.use(session({
        // Keep the signing key stable across restarts. OAuth data is stored server-side.
        secret: config.sessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: transactionLifetimeMs,
        },
    }));

    app.get("/health", (_request, response) => {
        response.json({ status: "ok" });
    });

    app.get("/oauth/authorize", (request, response) => {
        if (request.session.oauthTransaction) {
            response.status(409).json({
                error: "An OAuth authorization is already in progress for this session.",
            });
            return;
        }

        try {
            const transaction = createOAuthTransaction();
            request.session.oauthTransaction = transaction;
            response.redirect(buildAuthorizationUrl(config, transaction).toString());
        } catch {
            response.status(503).json({ error: "OAuth authorization is unavailable." });
        }
    });

    app.get("/oauth/callback", (request, response) => {
        const transaction = request.session.oauthTransaction;
        const state = queryValue(request.query.state);
        const code = queryValue(request.query.code);
        const error = queryValue(request.query.error);
        const now = Date.now();

        // Keep consumed session IDs briefly so simultaneous requests carrying a stale
        // session snapshot cannot process the same transaction twice.
        for (const [transactionKey, consumedAt] of consumedTransactions) {
            if (now - consumedAt >= transactionLifetimeMs) consumedTransactions.delete(transactionKey);
        }

        const transactionKey = `${request.sessionID}:${state ?? ""}`;
        if (consumedTransactions.has(transactionKey)) {
            response.status(400).json({ error: "OAuth callback is invalid or expired." });
            return;
        }
        if (!isValidTransaction(transaction) ||
            now - transaction.createdAt < 0 ||
            now - transaction.createdAt >= transactionLifetimeMs ||
            !state || !/^[A-Za-z0-9_-]{43}$/.test(state) || state !== transaction.state) {
            response.status(400).json({ error: "OAuth callback is invalid or expired." });
            return;
        }

        // Reserve synchronously and persist removal before accepting any callback
        // outcome. This makes accepted callbacks single-use within this process.
        consumedTransactions.set(transactionKey, now);
        delete request.session.oauthTransaction;
        request.session.save((saveError) => {
            if (saveError) {
                response.status(503).json({ error: "OAuth callback could not be processed." });
                return;
            }
            if (error) {
                response.status(400).json({ error: "Salesforce authorization was not completed." });
                return;
            }
            if (!code || code.length === 0) {
                response.status(400).json({ error: "OAuth callback is invalid or expired." });
                return;
            }

            response.json({ status: "Authorization received. Token exchange is not implemented." });
        });
    });

    return app;
}
