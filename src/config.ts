import "dotenv/config";

export interface SalesforceConfig {
    loginUrl: string;
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
    sessionSecret: string;
}

export class ConfigValidationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "ConfigValidationError";
    }
}

const requiredVariables = [
    "SALESFORCE_LOGIN_URL",
    "SALESFORCE_CLIENT_ID",
    "SALESFORCE_CLIENT_SECRET",
    "SALESFORCE_CALLBACK_URL",
    "SESSION_SECRET",
] as const;

type SalesforceVariable = (typeof requiredVariables)[number];
type ConfigSource = Partial<Record<SalesforceVariable, string | undefined>>;
const approvedLoginHosts = new Set(["login.salesforce.com", "test.salesforce.com"]);

function getRequiredValue(source: ConfigSource, name: SalesforceVariable): string {
    const value = source[name]?.trim();
    if (!value) {
        throw new ConfigValidationError(`Missing required Salesforce configuration: ${name}`);
    }
    return value;
}

/** Validate Salesforce settings without including their values in errors. */
export function loadConfig(source: ConfigSource = process.env): SalesforceConfig {
    const missing = requiredVariables.filter((name) => !source[name]?.trim());
    if (missing.length > 0) {
        throw new ConfigValidationError(
            `Missing required Salesforce configuration: ${missing.join(", ")}`,
        );
    }

    const loginUrl = getRequiredValue(source, "SALESFORCE_LOGIN_URL");
    let parsedLoginUrl: URL;
    try {
        parsedLoginUrl = new URL(loginUrl);
    } catch {
        throw new ConfigValidationError("SALESFORCE_LOGIN_URL must be a valid HTTPS URL.");
    }

    if (parsedLoginUrl.protocol !== "https:") {
        throw new ConfigValidationError("SALESFORCE_LOGIN_URL must use HTTPS.");
    }
    const loginAuthority = loginUrl
        .slice(loginUrl.indexOf("://") + 3)
        .split(/[/?#]/, 1)[0] ?? "";
    if (parsedLoginUrl.username || parsedLoginUrl.password || loginAuthority.includes("@")) {
        throw new ConfigValidationError("SALESFORCE_LOGIN_URL must not contain credentials.");
    }
    if (!approvedLoginHosts.has(parsedLoginUrl.hostname)) {
        throw new ConfigValidationError(
            "SALESFORCE_LOGIN_URL host must be login.salesforce.com or test.salesforce.com.",
        );
    }
    if (parsedLoginUrl.port || parsedLoginUrl.pathname !== "/" ||
        loginUrl.includes("?") || loginUrl.includes("#")) {
        throw new ConfigValidationError(
            "SALESFORCE_LOGIN_URL must not contain a port, path, query, or fragment.",
        );
    }

    const callbackUrl = getRequiredValue(source, "SALESFORCE_CALLBACK_URL");
    let parsedCallbackUrl: URL;
    try {
        parsedCallbackUrl = new URL(callbackUrl);
    } catch {
        throw new ConfigValidationError("SALESFORCE_CALLBACK_URL must be a valid URL.");
    }

    if (parsedCallbackUrl.protocol !== "https:" &&
        !(parsedCallbackUrl.protocol === "http:" &&
            (parsedCallbackUrl.hostname === "localhost" ||
                parsedCallbackUrl.hostname === "127.0.0.1" ||
                parsedCallbackUrl.hostname === "[::1]"))) {
        throw new ConfigValidationError(
            "SALESFORCE_CALLBACK_URL must use HTTPS, except on localhost or a loopback IP.",
        );
    }
    const callbackAuthority = callbackUrl
        .slice(callbackUrl.indexOf("://") + 3)
        .split(/[/?#]/, 1)[0] ?? "";
    if (parsedCallbackUrl.username || parsedCallbackUrl.password || callbackAuthority.includes("@")) {
        throw new ConfigValidationError("SALESFORCE_CALLBACK_URL must not contain credentials.");
    }
    if (callbackUrl.includes("#")) {
        throw new ConfigValidationError("SALESFORCE_CALLBACK_URL must not contain a fragment.");
    }

    const sessionSecret = getRequiredValue(source, "SESSION_SECRET");
    if (!/^(?:[A-Fa-f0-9]{2}){32,}$/.test(sessionSecret)) {
        throw new ConfigValidationError(
            "SESSION_SECRET must be at least 64 hexadecimal characters (32 random bytes).",
        );
    }

    return {
        loginUrl,
        clientId: getRequiredValue(source, "SALESFORCE_CLIENT_ID"),
        clientSecret: getRequiredValue(source, "SALESFORCE_CLIENT_SECRET"),
        callbackUrl,
        sessionSecret,
    };
}
