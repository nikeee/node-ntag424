import * as ntagCrypto from "./crypto.ts";

import MAC from "@nikeee/aes-cmac";

/**
 * @param decryptionKey Usually the key of metaRead
 * @param macKey Usually the key of fileRead
 */
export function validateAndDecryptPicc(
	decryptionKey: Buffer,
	macKey: Buffer,
	encryptedPicc: Buffer,
	signatureMac: Buffer,
): { uid: Buffer | null; counter: number | null } | null {
	const decrypted = ntagCrypto.decryptCbc(
		decryptionKey,
		encryptedPicc,
		ntagCrypto.createEmptyIv(),
		false,
	);
	const tag = decrypted[0];

	let index = 1;

	const hasUid = (tag & 0b1000_0000) !== 0;
	let uid = null;
	if (hasUid) {
		uid = decrypted.subarray(index, index + 7);
		index += 7;
	}

	const hasCounter = (tag & 0b0100_0000) !== 0;
	let counter = null;
	if (hasCounter) {
		counter = decrypted.readUintLE(index, 3);
		index += 3;
	}

	const isValid = validatePlainPiccMac(macKey, uid, counter, signatureMac);

	return isValid ? { uid, counter } : null;
}

export function validatePlainPiccMac(
	fileReadKey: Buffer,
	nfcUid: Buffer | null,
	counter: number | null,
	signatureMac: Buffer,
) {
	const sv2 = createSessionVector(
		Buffer.from("3cc300010080", "hex"),
		nfcUid,
		counter,
	);

	const SesSDMFileReadMAC = MAC(fileReadKey, sv2);

	const expectedMac = MAC(SesSDMFileReadMAC, Buffer.alloc(0));

	return Buffer.compare(ntagCrypto.reduceMac(expectedMac), signatureMac) === 0;
}

function createSessionVector(
	prefix: Buffer,
	uid: Buffer | null,
	counter: number | null,
) {
	if (prefix.byteLength + (uid?.byteLength ?? 0) + 3 > 16) {
		throw new Error(
			"Session vectors with multiple block size not supported yet.",
		);
	}

	let offset = 0;

	// Section 9.3.9.1
	const sessionVector = Buffer.alloc(16);
	offset += prefix.copy(sessionVector);
	if (uid) {
		offset += uid.copy(sessionVector, offset);
	}

	if (counter) {
		offset = sessionVector.writeUintLE(counter, offset, 3);
	}

	console.assert(offset === sessionVector.length);
	console.assert(sessionVector.length % 16 === 0);

	return sessionVector;
}
