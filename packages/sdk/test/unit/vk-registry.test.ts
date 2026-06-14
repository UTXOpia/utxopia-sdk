import { describe, it, expect } from "bun:test";
import {
  vkeyJsonToVkMaterial,
  buildVkRegistryData,
  parseVkRegistry,
  assertVkRegistryForShape,
  isVkRegistryReady,
  computeVkHash,
  joinSplitNumPublicInputs,
  INIT_VK_REGISTRY_DISCRIMINATOR,
  UPDATE_VK_REGISTRY_DISCRIMINATOR,
  VK_REGISTRY_LEN,
  VK_REGISTRY_DISCRIMINATOR,
  type SnarkjsVkeyJson,
} from "../../src/vk-registry";

// Synthetic but structurally valid 1x2 vkey: nPublic = 2+1+2 = 5, IC = nPublic+1 = 6.
function makeVkey(): SnarkjsVkeyJson {
  const g1 = (a: string, b: string): [string, string, string] => [a, b, "1"];
  const g2 = (): [[string, string], [string, string], [string, string]] => [
    ["11", "12"],
    ["13", "14"],
    ["1", "0"],
  ];
  return {
    nPublic: 5,
    vk_alpha_1: g1("100", "101"),
    vk_beta_2: g2(),
    vk_gamma_2: g2(),
    vk_delta_2: [["201", "202"], ["203", "204"], ["1", "0"]],
    IC: Array.from({ length: 6 }, (_, i) => g1(String(1000 + i * 2), String(1001 + i * 2))),
  };
}

describe("vk-registry", () => {
  it("derives public input / IC counts per shape", () => {
    expect(joinSplitNumPublicInputs(1, 2)).toBe(5);
    expect(joinSplitNumPublicInputs(2, 2)).toBe(6);
  });

  it("converts a vkey into material with correct shapes", () => {
    const mat = vkeyJsonToVkMaterial(makeVkey(), 1, 2);
    expect(mat.vkHash.length).toBe(32);
    expect(mat.deltaG2.length).toBe(128);
    expect(mat.ic.length).toBe(6);
    expect(mat.ic.every((p) => p.length === 64)).toBe(true);
  });

  it("encodes delta_g2 in Ethereum order (x_imag||x_real||y_imag||y_real)", () => {
    const mat = vkeyJsonToVkMaterial(makeVkey(), 1, 2);
    const f = (n: bigint) => n.toString(16).padStart(2, "0");
    // x_imag=202 (0xca) at byte 31, x_real=201 (0xc9) at byte 63
    expect(mat.deltaG2[31]).toBe(202);
    expect(mat.deltaG2[63]).toBe(201);
    expect(mat.deltaG2[95]).toBe(204); // y_imag
    expect(mat.deltaG2[127]).toBe(203); // y_real
    void f;
  });

  it("rejects mismatched IC length for the shape", () => {
    const vk = makeVkey();
    vk.IC = vk.IC.slice(0, 5);
    expect(() => vkeyJsonToVkMaterial(vk, 1, 2)).toThrow(/IC length/);
  });

  it("rejects out-of-range dimensions", () => {
    expect(() => vkeyJsonToVkMaterial(makeVkey(), 6, 6)).toThrow(/dimensions/);
  });

  it("builds init/update payloads with the documented layout", () => {
    const mat = vkeyJsonToVkMaterial(makeVkey(), 1, 2);
    const data = buildVkRegistryData(INIT_VK_REGISTRY_DISCRIMINATOR, mat);
    expect(data.length).toBe(1 + 2 + 32 + 128 + 1 + 6 * 64); // 548
    expect(data[0]).toBe(INIT_VK_REGISTRY_DISCRIMINATOR);
    expect(data[1]).toBe(1);
    expect(data[2]).toBe(2);
    expect(data[3 + 32 + 128]).toBe(6); // ic_len byte

    const upd = buildVkRegistryData(UPDATE_VK_REGISTRY_DISCRIMINATOR, mat);
    expect(upd[0]).toBe(UPDATE_VK_REGISTRY_DISCRIMINATOR);
  });

  it("parses a 1060-byte account and round-trips fields", () => {
    const mat = vkeyJsonToVkMaterial(makeVkey(), 1, 2);
    const acct = new Uint8Array(VK_REGISTRY_LEN);
    acct[0] = VK_REGISTRY_DISCRIMINATOR;
    acct[2] = 1;
    acct[3] = 2;
    acct.set(mat.vkHash, 36);
    acct.set(mat.deltaG2, 68);
    acct[196] = mat.ic.length;
    mat.ic.forEach((p, i) => acct.set(p, 228 + i * 64));

    const parsed = parseVkRegistry(acct);
    expect(parsed.nInputs).toBe(1);
    expect(parsed.nOutputs).toBe(2);
    expect(parsed.icLen).toBe(6);
    expect(Buffer.from(parsed.vkHash).equals(Buffer.from(mat.vkHash))).toBe(true);
    expect(Buffer.from(parsed.deltaG2).equals(Buffer.from(mat.deltaG2))).toBe(true);
    expect(Buffer.from(parsed.ic[0]).equals(Buffer.from(mat.ic[0]))).toBe(true);

    expect(() => assertVkRegistryForShape(acct, 1, 2)).not.toThrow();
    expect(() => assertVkRegistryForShape(acct, 2, 2)).toThrow(/shape mismatch/);
    expect(isVkRegistryReady(acct, 1, 2)).toBe(true);
    expect(isVkRegistryReady(null, 1, 2)).toBe(false);
  });

  it("computeVkHash is deterministic", () => {
    const a = computeVkHash(makeVkey());
    const b = computeVkHash(makeVkey());
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
    expect(a.length).toBe(32);
  });
});
