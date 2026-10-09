import { describe, expect, it } from "vitest";
import { getStartupMessage } from "./index.js";

describe("getStartupMessage", () => {
    it("returns the message displayed when the hub starts", () => {
        expect(getStartupMessage()).toBe("Salesforce Integration Hub starting...");
    });
});
