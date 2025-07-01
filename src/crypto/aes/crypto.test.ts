import { describe, test } from "node:test";
import { expect } from "expect";

import {
	calcSessionKeys,
	decryptCbc,
	encryptCbc,
	encryptEcb,
} from "./crypto.ts";
import { validateAndDecryptPicc, validatePlainPiccMac } from "./validation.ts";

describe("crypto module", async () => {
	test("session key derivation works", async () => {
		const key = Buffer.alloc(0x10);
		const RndA = Buffer.from("b98f4c50cf1c2e084fd150e33992b048", "hex");
		const RndB = Buffer.from("91517975190dcea6104948efa3085c1b", "hex");

		const { sessionEncryptionKey, sessionMacKey } = calcSessionKeys(
			key,
			RndA,
			RndB,
		);

		expect(sessionEncryptionKey).toStrictEqual(
			Buffer.from("7a93d6571e4b180fca6ac90c9a7488d4", "hex"),
		);
		expect(sessionMacKey).toStrictEqual(
			Buffer.from("fc4af159b62e549b5812394cab1918cc", "hex"),
		);
	});

	test("aes-128-cbc full roundtrip with padding, full block width", async () => {
		const plaintextExpected = Buffer.alloc(16, 69);
		const iv = Buffer.alloc(16, 23);

		const key = Buffer.alloc(16, 42);

		const encrypted = encryptCbc(key, plaintextExpected, iv, true);
		expect(encrypted.length).toBe(2 * 16); // there has to be a padding block starting with 0x80
		expect(encrypted).not.toEqual(plaintextExpected);

		const decrypted = decryptCbc(key, encrypted, iv, true);
		expect(decrypted).toStrictEqual(plaintextExpected);

		const decryptedWithPadding = decryptCbc(key, encrypted, iv, false);
		expect(decryptedWithPadding).toStrictEqual(
			Buffer.alloc(32, 69).fill(0x80, 16, 17).fill(0, 17),
		);
	});

	test("aes-128-cbc full roundtrip with padding, actual used padding", async () => {
		const plaintextExpected = Buffer.alloc(15, 69);
		const iv = Buffer.alloc(16, 23);

		const key = Buffer.alloc(16, 42);

		const encrypted = encryptCbc(key, plaintextExpected, iv, true);
		expect(encrypted.length).toBe(1 * 16);
		expect(encrypted).not.toEqual(plaintextExpected);

		const decrypted = decryptCbc(key, encrypted, iv, true);
		expect(decrypted).toStrictEqual(plaintextExpected);

		const decryptedWithPadding = decryptCbc(key, encrypted, iv, false);
		expect(decryptedWithPadding).toStrictEqual(
			Buffer.alloc(16, 69).fill(0x80, 15, 16),
		);
	});

	test("aes-128-cbc full roundtrip without padding", async () => {
		const plaintextExpected = Buffer.alloc(16, 69);
		const iv = Buffer.alloc(16, 23);

		const key = Buffer.alloc(16, 42);

		const encrypted = encryptCbc(key, plaintextExpected, iv, false);
		expect(encrypted.length).toBe(1 * 16);
		expect(encrypted).not.toEqual(plaintextExpected);

		const decrypted = decryptCbc(key, encrypted, iv, false);
		expect(decrypted).toStrictEqual(plaintextExpected);

		const decryptedWithPadding = decryptCbc(key, encrypted, iv, false);
		expect(decryptedWithPadding).toStrictEqual(plaintextExpected);
	});

	test("aes-128-cbc full roundtrip without padding, uneven blocks", async () => {
		expect(() => {
			const plaintextExpected = Buffer.alloc(18, 69);
			const iv = Buffer.alloc(16, 23);
			const key = Buffer.alloc(16, 42);

			encryptCbc(key, plaintextExpected, iv, false);
		}).toThrow(
			new Error(
				"`dataToEncrypt` is not a multiple of the block length and there is no padding to be applied. This can not happen.",
			),
		);

		expect(() => {
			const plaintextExpected = Buffer.alloc(18, 69);
			const iv = Buffer.alloc(16, 23);
			const key = Buffer.alloc(16, 42);

			decryptCbc(key, plaintextExpected, iv, false);
		}).toThrow(new Error("`data` is not a multiple of blockSize long."));

		expect(() => {
			const plaintextExpected = Buffer.alloc(13, 69);
			const iv = Buffer.alloc(16, 23);
			const key = Buffer.alloc(16, 42);

			decryptCbc(key, plaintextExpected, iv, false);
		}).toThrow(new Error("`data` is not a multiple of blockSize long."));
	});

	test("aes-128-ecb invalid size", async () => {
		const plaintextExpected = Buffer.alloc(16, 69);
		const key = Buffer.alloc(16, 42);

		const encrypted = encryptEcb(key, plaintextExpected);
		expect(encrypted.length).toBe(16);
		expect(encrypted).not.toEqual(plaintextExpected);
	});

	test("aes-128-ecb invalid size", async () => {
		expect(() => {
			const plaintext = Buffer.alloc(15, 69);
			const key = Buffer.alloc(16, 42);

			encryptEcb(key, plaintext);
		}).toThrow(new Error("`data` is not a multiple of blockSize long."));

		expect(() => {
			const plaintext = Buffer.alloc(17, 69);
			const key = Buffer.alloc(16, 42);

			encryptEcb(key, plaintext);
		}).toThrow(new Error("`data` is not a multiple of blockSize long."));
	});
});

describe("picc + cmac validation", async () => {
	const macKey = Buffer.alloc(16);
	const encryptionKey = Buffer.alloc(16);
	const uid = Buffer.from("049d98f20b1090", "hex");

	describe("mac validation", async () => {
		test("positive case", async () => {
			const actual = validatePlainPiccMac(
				macKey,
				uid,
				0x000026,
				Buffer.from("71fd0299f6a6f742", "hex"),
			);
			expect(actual).toBe(true);
		});

		test("negative case - wrong signature", async () => {
			const actual = validatePlainPiccMac(
				macKey,
				uid,
				0x000026,
				Buffer.from("71fd0299f6a6f743", "hex"),
			);
			expect(actual).toBe(false);
		});

		test("negative case - wrong counter", async () => {
			const actual = validatePlainPiccMac(
				macKey,
				uid,
				0x000027,
				Buffer.from("71fd0299f6a6f743", "hex"),
			);
			expect(actual).toBe(false);
		});
	});

	describe("decrypt and validate picc data", async () => {
		test("positive case", async () => {
			const piccData = validateAndDecryptPicc(
				encryptionKey,
				macKey,
				Buffer.from("1cc49b9aa47d2837e5f1a1b5deae811c", "hex"),
				Buffer.from("6488aeba44044cbf", "hex"),
			);

			expect(piccData).toStrictEqual({
				uid,
				counter: 56,
			});
		});

		test("negative case - wrong encrypted data", async () => {
			const piccData = validateAndDecryptPicc(
				encryptionKey,
				macKey,
				Buffer.from("1cc49b9aa47d2837e5f1a1b5deae811d", "hex"),
				Buffer.from("6488aeba44044cbf", "hex"),
			);

			expect(piccData).toBeNull();
		});

		test("negative case - wrong mac", async () => {
			const piccData = validateAndDecryptPicc(
				encryptionKey,
				macKey,
				Buffer.from("1cc49b9aa47d2837e5f1a1b5deae811c", "hex"),
				Buffer.from("6488aeba44044cbe", "hex"),
			);

			expect(piccData).toBeNull();
		});
	});
});
