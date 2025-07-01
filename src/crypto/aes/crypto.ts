import * as crypto from "node:crypto";

import aesCmac from "@nikeee/aes-cmac";

export { default as MAC } from "@nikeee/aes-cmac";
export { crcjam as crc } from "crc";

const blockSize = 16;

export function calcSessionKeys(key: Buffer, RndA: Buffer, RndB: Buffer) {
	const xor = Buffer.alloc(6);
	for (let i = 0; i < 6; i++) {
		xor[i] = RndA[2 + i] ^ RndB[i];
	}

	const sv1 = Buffer.concat([
		Buffer.from("a55a00010080", "hex"),
		RndA.subarray(0, 2),
		xor,
		RndB.subarray(6),
		RndA.subarray(8),
	]);

	const sv2 = Buffer.concat([
		Buffer.from("5aa500010080", "hex"),
		RndA.subarray(0, 2),
		xor,
		RndB.subarray(6),
		RndA.subarray(8),
	]);

	return {
		sessionEncryptionKey: aesCmac(key, sv1),
		sessionMacKey: aesCmac(key, sv2),
	};
}

export function decryptCbc(
	key: Buffer,
	data: Buffer,
	iv: Buffer,
	removePadding: boolean,
): Buffer {
	if (data.byteLength % blockSize !== 0) {
		throw new Error("`data` is not a multiple of blockSize long.");
	}

	const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
	decipher.setAutoPadding(false);

	const plaintextWithPadding = decipher.update(data);
	if (plaintextWithPadding.byteLength !== data.byteLength) {
		throw new Error(
			"`decipher.update` should return the same number as output as it received",
		);
	}

	if (decipher.final().byteLength !== 0) {
		throw new Error(
			"`decryptCbc` should not return any last block when doing manual padding",
		);
	}

	if (!removePadding) {
		return plaintextWithPadding;
	}

	const paddingStart = plaintextWithPadding.lastIndexOf(0x80);
	if (paddingStart < 0) {
		throw new Error("Could not find any padding");
	}

	return plaintextWithPadding.subarray(0, paddingStart);
}

export const createEmptyIv = () => Buffer.alloc(blockSize);

export function encryptEcb(key: Buffer, data: Buffer) {
	if (data.byteLength % blockSize !== 0) {
		throw new Error("`data` is not a multiple of blockSize long.");
	}

	const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
	cipher.setAutoPadding(false);
	const res = cipher.update(data);

	if (cipher.final().byteLength !== 0) {
		throw new Error("ECB mode should not return anything in `cipher.final()`");
	}

	return res;
}

/**
 * @param addPadding If true, adds padding according to ISO IEC 9797-1 Method 2. See: https://en.wikipedia.org/wiki/ISO/IEC_9797-1
 *
 * @remarks Section 9.1.4 requires ISO 9797-1 M/2 padding on some operations.
 */
export function encryptCbc(
	key: Buffer,
	data: Buffer,
	iv: Buffer,
	addPadding: boolean,
): Buffer<ArrayBuffer> {
	const cipher = crypto.createCipheriv("aes-128-cbc", key, iv);
	cipher.setAutoPadding(false);

	let dataToEncrypt = data;

	if (addPadding) {
		const dataToPad = Buffer.concat([data, Buffer.of(0x80)]);
		const paddingLength = blockSize - (dataToPad.byteLength % blockSize);
		dataToEncrypt =
			paddingLength === blockSize
				? dataToPad
				: Buffer.concat([dataToPad, Buffer.alloc(paddingLength)]);
	} else {
		if (dataToEncrypt.byteLength % blockSize !== 0) {
			throw new Error(
				"`dataToEncrypt` is not a multiple of the block length and there is no padding to be applied. This can not happen.",
			);
		}
	}

	return Buffer.concat([cipher.update(dataToEncrypt), cipher.final()]);
}

/**
 * @remarks - documentation not clear if this is supposed to be evens (zero-indexed) or evens (one-indexed)
 *          - AN12196 page 21 indicates that it is one-indexed evens
 */
export function reduceMac(mac: Buffer) {
	const mact = Buffer.alloc(8);
	for (let i = 0; i < mac.length; i++) {
		if (i % 2 === 1) {
			mact[(i / 2) >>> 0] = mac[i];
		}
	}
	return mact;
}
