import { describe, expect, it } from "vitest";
import type { VaultInfo } from "../vault/store";
import { settingsContentFor, showSettingsButton } from "./sharing-settings";

// Fixtures mirror store.vaults() shapes: personal first, roles from the latest grant
// (roleFor returns null when no grant carried one — the row tag falls back to "member").
const personal: VaultInfo = { vaultId: "vp", type: "personal", name: "Personal", role: "owner" };
const personalNullRole: VaultInfo = { vaultId: "vp0", type: "personal", name: "Personal", role: null };
const owned: VaultInfo = { vaultId: "vo", type: "shared", name: "Family", role: "owner" };
const writer: VaultInfo = { vaultId: "vw", type: "shared", name: "Household", role: "writer" };
const reader: VaultInfo = { vaultId: "vr", type: "shared", name: "Kids", role: "reader" };
const sharedNullRole: VaultInfo = { vaultId: "vn", type: "shared", name: "Grants", role: null };
const vaults = [personal, personalNullRole, owned, writer, reader, sharedNullRole];

describe("showSettingsButton (DN-1 row affordance)", () => {
  it("personal vaults get NO button — regardless of role value", () => {
    expect(showSettingsButton(personal)).toBe(false);
    expect(showSettingsButton(personalNullRole)).toBe(false);
  });

  it("shared vaults get the button, owner and member alike", () => {
    expect(showSettingsButton(owned)).toBe(true);
    expect(showSettingsButton(writer)).toBe(true);
    expect(showSettingsButton(reader)).toBe(true);
    expect(showSettingsButton(sharedNullRole)).toBe(true);
  });
});

describe("settingsContentFor (DN-1 layer branch)", () => {
  it("owner vault → owner content (MemberPanel)", () => {
    expect(settingsContentFor("vo", vaults)).toBe("owner");
  });

  it("member vault → member content (roster + leave), for every non-owner role", () => {
    expect(settingsContentFor("vw", vaults)).toBe("member");
    expect(settingsContentFor("vr", vaults)).toBe("member");
    expect(settingsContentFor("vn", vaults)).toBe("member"); // null role tags as "member" too
  });

  it("missing id → null (vault vanished mid-view — A2 clears, render falls back)", () => {
    expect(settingsContentFor("gone", vaults)).toBe(null);
  });

  it("null id → null (layer closed)", () => {
    expect(settingsContentFor(null, vaults)).toBe(null);
  });

  it("personal id → null (defensive — rows never offer it, but no lifecycle page exists)", () => {
    expect(settingsContentFor("vp", vaults)).toBe(null);
  });

  it("empty vaults list → null for any id (pre-sync frame)", () => {
    expect(settingsContentFor("vo", [])).toBe(null);
  });
});
