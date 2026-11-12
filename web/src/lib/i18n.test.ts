import { describe, expect, it } from "vitest";
import { initialLang, translate } from "./i18n";

describe("i18n", () => {
  it("fills slots and falls back to the key", () => {
    expect(translate("en", "overview.stale", 7)).toBe("Hosts not reporting for 7 days");
    expect(translate("ko", "ago.hours", 3)).toBe("3시간 전");
    expect(translate("en", "host.waived", { reason: "legacy", expires: "2027-01-01" })).toBe("Waived: legacy (until 2027-01-01)");
    expect(translate("en", "no.such.key")).toBe("no.such.key");
  });
  it("uses the singular for exactly one in English", () => {
    expect(translate("en", "profile.hosts", 1)).toBe("1 host");
    expect(translate("en", "profile.hosts", 12)).toBe("12 hosts");
    expect(translate("en", "overview.stale", 1)).toBe("Hosts not reporting for 1 day");
    expect(translate("ko", "profile.hosts", 1)).toBe("호스트 1대");
  });
  it("picks the language from the stored choice, then the browser", () => {
    expect(initialLang("ko", "en-US")).toBe("ko");
    expect(initialLang(null, "ko-KR")).toBe("ko");
    expect(initialLang("fr", "en-US")).toBe("en");
  });
});
