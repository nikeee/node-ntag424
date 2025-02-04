import { type CommMode, commModeLookup, commModes } from "./commMode.ts";

export type KeyNumber = 0 | 1 | 2 | 3 | 4;
export type FreeAccess = 0xe;
export type NoAccess = 0xf;
export type AccessCondition = KeyNumber | FreeAccess | NoAccess;

export type FileAccessRights = Readonly<{
	read: AccessCondition;
	write: AccessCondition;
	readWrite: AccessCondition;
	change: AccessCondition;
}>;

export type SDMAccessRights = Readonly<{
	/**
	 * 0-4: encrypted using targeted app key number
	 * 0xe: plain
	 * 0xf: disabled
	 */
	metaRead: AccessCondition;
	fileRead: KeyNumber | NoAccess;
	counterRetrieval: AccessCondition;
}>;

export type EncryptedFileSettings = {
	offset: number;
	/** Must be multiple of 32 */
	length: number;
};

export type SdmOptions = {
	uidOffset: number | null;
	readCounterOffset: number | null;
	/** Only possible if accessRights.metaRead is a key number */
	piccDataOffset: number | null;
	macInputOffset: number | null;
	/** Must be present if `accessRights.fileRead` !== `0xf` */
	macOffset: number | null;

	encryptedFileData: null | EncryptedFileSettings;

	readCounterLimit: number | null;
	encodingMode: "ascii";
	accessRights: SDMAccessRights;
};

export type FileSettings = {
	sdmOptions: null | SdmOptions;
	commMode: CommMode;
	access: FileAccessRights;
};

export type TagParams = {
	fileSize: number;
	encodedUidLength: number;
	encodedReadCounterLength: number;
	piccDataLength: number;
};

/**
 * @param {TagParams} tagParams Needed for validation.
 * @see Section 10.7.1
 */
export function serializeForChangeFileSettings(
	{ sdmOptions, commMode, access }: FileSettings,
	tagParams: TagParams,
) {
	const result = Buffer.alloc(1000);
	let index = 0;

	index = result.writeUint8(
		// fileOption
		(sdmOptions !== null ? 0b0_1_0000_00 : 0) | commModes[commMode],
		index,
	);

	index = result.writeUint8(
		// access rights part 1
		((access.readWrite & 0xf) << 4) | ((access.change & 0xf) << 0),
		index,
	);
	index = result.writeUint8(
		// access rights part 2
		((access.read & 0xf) << 4) | ((access.write & 0xf) << 0),
		index,
	);

	if (sdmOptions !== null) {
		index = result.writeUint8(
			// intSdmOptions
			(sdmOptions.uidOffset !== null ? 0b1_0_0_0_000_0 : 0) |
				(sdmOptions.readCounterOffset !== null ? 0b0_1_0_0_000_0 : 0) |
				(sdmOptions.readCounterLimit !== null ? 0b0_0_1_0_000_0 : 0) |
				(sdmOptions.encryptedFileData !== null ? 0b0_0_0_1_000_0 : 0) |
				// [3 bits RFU left out]
				(sdmOptions.encodingMode === "ascii" ? 0b0_0_0_0_000_1 : 0),
			index,
		);

		const ar = sdmOptions.accessRights;
		index = result.writeUint8(
			0xf0 | // RFU that must be 0xF
				ar.counterRetrieval,
			index,
		);

		index = result.writeUint8((ar.metaRead << 4) | ar.fileRead, index);

		if (ar.metaRead === 0xe) {
			if (sdmOptions.uidOffset !== null) {
				ensureInRange.exclusive(
					0,
					sdmOptions.uidOffset,
					tagParams.fileSize - tagParams.encodedUidLength,
					"sdmOptions.uidOffset",
				);

				index = result.writeUintLE(sdmOptions.uidOffset, index, 3);
			}

			if (sdmOptions.readCounterOffset !== null) {
				ensureInRange.exclusive(
					0,
					sdmOptions.readCounterOffset,
					tagParams.fileSize - tagParams.encodedReadCounterLength,
					"sdmOptions.readCounterOffset",
				);

				index = result.writeUintLE(sdmOptions.readCounterOffset, index, 3);
			}
		} else if (ar.metaRead !== 0xf) {
			if (sdmOptions.piccDataOffset === null) {
				throw new Error(
					"`piccDataOffset` must be set when `accessRights.metaRead` is a key id.",
				);
			}

			ensureInRange.exclusive(
				0,
				sdmOptions.piccDataOffset,
				tagParams.fileSize - tagParams.piccDataLength,
				"sdmOptions.piccDataOffset",
			);

			index = result.writeUintLE(sdmOptions.piccDataOffset, index, 3);
		} else if (sdmOptions.piccDataOffset !== null) {
			throw new Error(
				"`piccDataOffset` cannot be set when `accessRights.metaRead` is not a key id.",
			);
		}

		if (ar.fileRead !== 0xf) {
			if (sdmOptions.macInputOffset === null) {
				throw new Error(
					"`sdmOptions.macInputOffset` must be set if `accessRights.fileRead` !== 0xf.",
				);
			}

			if (sdmOptions.macOffset === null) {
				throw new Error(
					"`sdmOptions.macOffset` must be set if `accessRights.fileRead` !== 0xf.",
				);
			}

			ensureInRange.inclusive(
				0,
				sdmOptions.macInputOffset,
				sdmOptions.macOffset,
				"sdmOptions.macInputOffset",
			);

			index = result.writeUintLE(sdmOptions.macInputOffset, index, 3);

			if (sdmOptions.encryptedFileData !== null) {
				ensureInRange.exclusive(
					sdmOptions.macInputOffset,
					sdmOptions.encryptedFileData.offset,
					sdmOptions.macOffset - 32,
					"sdmOptions.encryptedFileData.offset",
				);

				ensureInRange.exclusive(
					32,
					sdmOptions.encryptedFileData.length,
					sdmOptions.macOffset - sdmOptions.encryptedFileData.offset,
					"sdmOptions.encryptedFileData.length",
				);
				if (sdmOptions.encryptedFileData.length % 32 !== 0) {
					throw new Error(
						"`sdmOptions.encryptedFileData.length` must be a multiple of 32.",
					);
				}

				index = result.writeUintLE(
					sdmOptions.encryptedFileData.offset,
					index,
					3,
				);

				index = result.writeUintLE(
					sdmOptions.encryptedFileData.length,
					index,
					3,
				);
			}

			if (sdmOptions.encryptedFileData === null) {
				ensureInRange.exclusive(
					sdmOptions.macInputOffset,
					sdmOptions.macOffset,
					tagParams.fileSize - 16,
					"sdmOptions.macOffset",
				);
			} else {
				ensureInRange.fullExclusive(
					sdmOptions.encryptedFileData.offset +
						sdmOptions.encryptedFileData.length,
					sdmOptions.macOffset,
					tagParams.fileSize - 16,
					"sdmOptions.macOffset",
				);
			}

			index = result.writeUintLE(sdmOptions.macOffset, index, 3);
		}

		if (sdmOptions.readCounterLimit !== null) {
			index = result.writeUintLE(sdmOptions.readCounterLimit, index, 3);
		}
	}
	return result.subarray(0, index);
}

export type GetFileSettings = {
	fileType: 0;
	accessRights: FileAccessRights;
	fileSize: number;
	commMode: CommMode;
	sdmOptions: null | SdmOptions;
};

/**
 * @see Section 10.7.2
 */
export function parseFromGetFileSettings(buffer: Buffer): GetFileSettings {
	let index = 0;

	const fileType = buffer.readUint8(index);
	index += 1;

	if (fileType !== 0) {
		throw new Error(`Unsupported fileType: ${fileType}`);
	}

	const fileOption = buffer.readUint8(index);
	index += 1;

	// bit 7 RFU
	const sdmEnabled = !!(fileOption & 0b0100_0000);
	console.assert((fileOption & 0b0011_1100) === 0); // RFU + must be 0
	const commMode = commModeLookup[(fileOption & 0b11) as 0 | 1 | 3];

	const intAccessRights = buffer.readUint16LE(index);
	index += 2;

	const accessRights = {
		read: (intAccessRights >> 12) & 0xf,
		write: (intAccessRights >> 8) & 0xf,
		readWrite: (intAccessRights >> 4) & 0xf,
		change: (intAccessRights >> 0) & 0xf,
	} as FileAccessRights;

	const fileSize = buffer.readUintLE(index, 3);
	index += 3;

	let sdmFlags = null;
	let sdmOptions: null | SdmOptions = null;
	if (sdmEnabled) {
		const intSdmOptions = buffer.readUint8(index);
		index += 1;

		sdmFlags = {
			mirrorUid: !!(intSdmOptions & 0b1000_0000),
			mirrorReadCounter: !!(intSdmOptions & 0b0100_0000),
			hasReadCounterLimit: !!(intSdmOptions & 0b0010_0000),
			encFileData: !!(intSdmOptions & 0b0001_0000),
			encoding:
				(intSdmOptions & 1) === 1
					? "ascii"
					: (() => {
							throw new Error("Unsupported encoding");
						})(),
		};

		const intAccessRights = buffer.readUint16LE(index);
		index += 2;

		const sdmAccessRights = {
			metaRead: ((intAccessRights >> 12) & 0xf) as AccessCondition,
			fileRead: ((intAccessRights >> 8) & 0xf) as KeyNumber | NoAccess,
			counterRetrieval: ((intAccessRights >> 0) & 0xf) as AccessCondition,
		} satisfies SDMAccessRights;

		let uidOffset: number | null = null;
		let readCounterOffset: number | null = null;
		if (sdmAccessRights.metaRead === 0xe) {
			if (sdmFlags.mirrorUid) {
				uidOffset = buffer.readUintLE(index, 3);
				index += 3;
			}

			if (sdmFlags.mirrorReadCounter) {
				readCounterOffset = buffer.readUintLE(index, 3);
				index += 3;
			}
		}

		let piccDataOffset: number | null = null;
		if (0x0 <= sdmAccessRights.metaRead && sdmAccessRights.metaRead <= 0x4) {
			piccDataOffset = buffer.readUintLE(index, 3);
			index += 3;
		}

		let macInputOffset: number | null = null;
		let encryptedFileData: EncryptedFileSettings | null = null;
		let macOffset: number | null = null;
		let readCounterLimit: number | null = null;

		if (sdmAccessRights.fileRead !== 0xf) {
			macInputOffset = buffer.readUintLE(index, 3);
			index += 3;

			if (sdmFlags.encFileData) {
				const offset = buffer.readUintLE(index, 3);
				index += 3;
				const length = buffer.readUintLE(index, 3);
				index += 3;
				encryptedFileData = { offset, length };
			}

			macOffset = buffer.readUintLE(index, 3);
			index += 3;

			if (sdmFlags.hasReadCounterLimit) {
				readCounterLimit = buffer.readUintLE(index, 3);
				index += 3;
			}
		}

		sdmOptions = {
			accessRights: sdmAccessRights,
			encodingMode: "ascii",
			encryptedFileData,
			macInputOffset,
			macOffset,
			piccDataOffset,
			readCounterLimit,
			readCounterOffset,
			uidOffset,
		};
	}

	if (index !== buffer.length) {
		throw new Error(
			"Did not consume entire buffer input. Something is wrong with the buffer.",
		);
	}

	return {
		fileType,
		accessRights,
		fileSize,
		commMode,
		sdmOptions,
	};
}

const ensureInRange = {
	inclusive: (lower: number, value: number, upper: number, name: string) => {
		if (!(lower <= value && value <= upper)) {
			throw new Error(
				`"${name}" must be in the range [${lower}, ${upper}], but got ${value}`,
			);
		}
	},

	exclusive: (lower: number, value: number, upper: number, name: string) => {
		if (!(lower <= value && value < upper)) {
			throw new Error(
				`"${name}" must be in the range [${lower}, ${upper}), but got ${value}`,
			);
		}
	},

	fullExclusive: (
		lower: number,
		value: number,
		upper: number,
		name: string,
	) => {
		if (!(lower < value && value < upper)) {
			throw new Error(
				`"${name}" must be in the range [${lower}, ${upper}), but got ${value}`,
			);
		}
	},
};
