import { beforeEach, describe, expect, it } from "vitest";
import { lastListAddress, rememberListAddress, resetListAddresses } from "./listAddress";

describe("the remembered address of a list", () => {
  beforeEach(resetListAddresses);
  it("starts at the plain list and remembers each list apart", () => {
    expect(lastListAddress("hosts")).toBe("#/hosts");
    expect(lastListAddress("controls")).toBe("#/controls");
    rememberListAddress("hosts", "#/hosts?status=failing");
    expect(lastListAddress("hosts")).toBe("#/hosts?status=failing");
    expect(lastListAddress("controls")).toBe("#/controls");
  });
  it("is forgotten on reset", () => {
    rememberListAddress("controls", "#/controls?q=ssh");
    resetListAddresses();
    expect(lastListAddress("controls")).toBe("#/controls");
  });
});
