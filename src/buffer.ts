export function rotateLeft(b: Buffer) {
	return Buffer.concat([b.subarray(1), b.subarray(0, 1)]);
}

export function rotateRight(b: Buffer) {
	return Buffer.concat([b.subarray(-1), b.subarray(0, -1)]);
}

export function hex(hex: string): Buffer {
	return Buffer.from(hex, "hex");
}

export function format(buffer: Buffer): string {
	const a = buffer.toString("hex").match(/.{2}/g);
	return a ? a.join(" ") : "<null>";
}

export const create = Object.freeze({
	u8le: (n: number) => Buffer.of(n & 0xff),
	u16le: (n: number) => Buffer.of(n & 0xff, (n >> 8) & 0xff),
	u24le: (n: number) => Buffer.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff),
	u32le: (n: number) =>
		Buffer.of(
			(n >> 0) & 0xff,
			(n >> 8) & 0xff,
			(n >> 16) & 0xff,
			(n >> 24) & 0xff,
		),
});

export function xor(a: Buffer, b: Buffer): Buffer {
	if (a.length !== b.length) {
		throw new Error("`a` does not have the same length as `b`");
	}
	const keyXor = Buffer.allocUnsafe(a.length);
	for (let i = 0; i < keyXor.length; ++i) {
		keyXor[i] = a[i] ^ b[i];
	}
	return keyXor;
}
