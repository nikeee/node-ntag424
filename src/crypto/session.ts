import * as ntagCrypto from "./aes/crypto.ts";

import { rotateRight } from "../buffer.ts";

export type EncryptionParams = Readonly<{
	TI: Buffer;
	sessionEncryptionKey: Buffer;
	sessionMacKey: Buffer;
}>;

export function deriveSessionKeys(
	key: Buffer,
	ecRndAp: Buffer,
	rndA: Buffer,
	rndB: Buffer,
): EncryptionParams {
	const TiRndAPDcap2PCDcap2 = ntagCrypto.decryptCbc(
		key,
		ecRndAp,
		ntagCrypto.createEmptyIv(),
		false,
	);
	const TI = TiRndAPDcap2PCDcap2.subarray(0, 4);
	const rndAp = TiRndAPDcap2PCDcap2.subarray(4, 20);

	// TODO: What is this?
	// const PDcap2 = TiRndAPDcap2PCDcap2.subarray(20, 26);
	// const PCDcap2 = TiRndAPDcap2PCDcap2.subarray(26);

	const rndA2 = rotateRight(rndAp);

	if (Buffer.compare(rndA, rndA2) !== 0) {
		throw new Error("error in match rndA random bytes");
	}

	const keys = ntagCrypto.calcSessionKeys(key, rndA, rndB);
	return {
		TI,
		...keys,
	};
}
