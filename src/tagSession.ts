import * as buffer from "./buffer.ts";
import * as ntagCrypto from "./crypto/aes/crypto.ts";
import { deriveSessionKeys, type EncryptionParams } from "./crypto/session.ts";
import { CommandResponse } from "./response.ts";
import type { CommMode } from "./serializer/commMode.ts";
import type { ConfigurationUpdate } from "./serializer/configuration.ts";
import * as configuration from "./serializer/configuration.ts";
import type {
	FileSettings,
	GetFileSettings,
	TagParams,
} from "./serializer/fileSettings.ts";
import * as fileSettings from "./serializer/fileSettings.ts";

export type Reader = {
	transmit(
		data: Buffer,
		responseMaxLength: number,
	): Promise<Buffer<ArrayBuffer>>;
};

type LogParams = Parameters<(typeof console)["log"]>;
export type LogFunction = (...args: LogParams) => void;
export type Logger = {
	trace: LogFunction;
	debug: LogFunction;
	info: LogFunction;
	warn: LogFunction;
	success: LogFunction;
	error: LogFunction;
};

export type TagSessionOptions = {
	authentication: EncryptionParams;
	logger: Logger;
	initialCommandCounter: number;
};

export type TagSession = {
	isAuthenticated: () => boolean;

	getUid: () => Promise<Buffer>;

	getFileSettings: (fileId: number) => Promise<GetFileSettings>;
	getFileSettingsRaw: (fileId: number) => Promise<Buffer>;

	/**
	 * ISOSelectFile
	 * @param {number} mode See {@link isoSelectFileMode}.
	 * @see Section 10.9.1
	 */
	selectFile: (fileId: Buffer, mode: number) => Promise<void>;

	readStandardFile: () => Promise<Buffer>;
	// readNdefRecords: () => Promise<NDefRecord[]>;
	writeStandardFile: (contents: Buffer) => Promise<void>;
	// writeNdefRecords: (records: NDefRecord[]) => Promise<void>;

	/**
	 * `getCardUid` command is required to get the 7-byte UID from the card. In case "Random ID" at activation is configured,
	 * encrypted secure messaging is applied for this command and response.
	 * An authentication with any key needs to be performed prior to the command `getCardUid`.
	 * This command returns the UID and gives the opportunity to retrieve the UID, even if the Random ID is used.
	 */
	getCardUid(commMode: CommMode): Promise<Buffer>;

	/**
	 * @remarks Requires CommMode full (an authenticated session).
	 * @param config
	 */
	setConfiguration(config: ConfigurationUpdate): Promise<void>;

	/**
	 * The `getKeyVersion` command retrieves the current key version of any key.
	 * Key version can be changed with the {@link changeKey} command together with the key.
	 * @param keyNumber Must be in the range `[0, 4]`.
	 *
	 * @returns {number} Key version. `0x00` if requesting key version of disabled keys or originality keys.
	 */
	getKeyVersion(keyNumber: number): Promise<number>;

	/**
	 * The `getFileCounters` command supports retrieving of the current values associated with
	 * the SDMReadCtr related with a StandardData file after enabling Secure Dynamic Messaging.
	 *
	 * @remarks Requires CommMode "full" (authenticated session).
	 *
	 * @param {number} fileNumber
	 */
	getFileCounters(fileNumber: number): Promise<number>;

	writeData(
		commMode: CommMode,
		fileNumber: number,
		data: Buffer,
		offset?: number,
	): Promise<void>;

	authenticate: (keyNumber: number, key: Buffer) => Promise<void>;

	setFileSettings: (
		fileId: number,
		value: FileSettings,
		tagParams: TagParams,
	) => Promise<void>;
	setFileSettingsRaw: (fileId: number, value: Buffer) => Promise<void>;

	changeKey: (
		keyNumber: number,
		oldKey: Buffer,
		newKey: Buffer,
		newKeyVersion: number,
	) => Promise<void>;
};

/**
 * Terms:
 * - Elementary File (EF)
 * - Dedicated File (DF)
 * - Master File (MF)
 *
 * Table 39, ISO IEC 7816-4-1
 */
export const isoSelectFileMode = Object.freeze({
	MF_DF_EF: 0b0,
	CHILD_DF: 0b1,
	EF_UNDER_CURRENT_DF: 0b10,
	PARENT_DF_OF_CURRENT_DF: 0b11,

	/** Eg, application identifier */
	BY_DF_NAME: 0b100,

	/** Path without the MF identifier */
	FROM_MF: 0b1000,
	/** Path without the MF identifier */
	FROM_CURRENT_DF: 0b1001,
});

/**
 * Section 8.2.3 NT4H2421Gx.pdf
 */
const standardFileIds = {
	/** Capability Container */
	cc: Buffer.of(0xe1, 0x03),
	ndef: Buffer.of(0xe1, 0x04),
	raw: Buffer.of(0xe1, 0x05),
};

/**
 * Section 8.2.3 NT4H2421Gx.pdf
 */
// biome-ignore lint/correctness/noUnusedVariables: maybe used some day :harold:
const standardFileNumbers = {
	/** Capability Container */
	cc: 1,
	ndef: 2,
	raw: 3,
};

export function createTagSession(
	reader: Reader,
	options?: Partial<TagSessionOptions>,
): TagSession {
	let commandCounter = options?.initialCommandCounter ?? 0;

	const log = options?.logger ?? undefined;
	let authentication = options?.authentication ?? undefined;

	return {
		isAuthenticated: () => !!authentication,
		getUid,
		getFileSettings,
		getFileSettingsRaw,
		selectFile,
		readStandardFile,
		writeStandardFile,
		getCardUid,
		setConfiguration,
		getKeyVersion,
		getFileCounters,
		writeData,
		authenticate,
		setFileSettings,
		setFileSettingsRaw,
		changeKey,
	} as const;

	// #region Raw sending + Packing/unpacking commands

	/**
	 * Runs a basic framed NXP native command.
	 * **Does not affect the command counter**.
	 */
	async function sendNativeCommand(
		command: number,
		header: Buffer,
		data: Buffer | null,
		macData: Buffer | null,
		comment: string,
	) {
		const buffers = [header];
		if (data) {
			buffers.push(data);
		}
		if (macData) {
			buffers.push(macData);
		}

		return sendIsoCommand(
			0x90,
			command,
			0x00,
			0x00,
			Buffer.concat(buffers),
			0x00, // all
			comment,
		);
	}

	/**
	 * Runs a standard ISO/IEC7816-4 communication frame.
	 * **Does not affect the command counter**.
	 */
	async function sendIsoCommand(
		instructionClass: number,
		instruction: number,
		param1: number,
		param2: number,
		data: Buffer | null,
		expectedResponseLength: number | null,
		comment: string,
	): Promise<CommandResponse> {
		const arr = [instructionClass, instruction, param1, param2];

		if (data !== null) {
			arr.push(data.length & 0xff);
			arr.push(...data);
		}

		if (expectedResponseLength !== null) {
			arr.push(expectedResponseLength & 0xff);
		}

		const commandBuffer = Buffer.from(arr);

		log?.debug(`[${comment}]`, "-> %s", buffer.format(commandBuffer));

		const response = await reader.transmit(
			commandBuffer,
			0x80,
			/*
			expectedResponseLength === null
				? 0
				: expectedResponseLength + 2, // Probably + 2 to get the response status
			*/
		);

		log?.debug(`[${comment}]`, "<- %s", buffer.format(response));

		if (response.length < 2) {
			throw new Error("Got malformed response.");
		}

		return CommandResponse.create(
			response.subarray(-2),
			response.length > 2 ? response.subarray(0, -2) : null,
		);
	}

	// #endregion

	/** @deprecated */
	async function send(
		value: Buffer,
		comment: string | null,
		responseMaxLength = 40,
	) {
		const b = value instanceof Buffer ? value : Buffer.from(value);
		log?.debug(`[${comment}]`, "-> %s", buffer.format(b));
		const data = await reader.transmit(b, responseMaxLength);
		log?.debug(`[${comment}]`, "<- %s", buffer.format(data));
		return data;
	}

	async function authenticate(keyNumber: number, key: Buffer) {
		const ecRndB = await authStep1(keyNumber);
		const [ecRndAp, rndA, rndB] = await authStep2(key, ecRndB);

		const newAuthentication = deriveSessionKeys(key, ecRndAp, rndA, rndB);

		log?.debug(`Authenticated with key ${keyNumber}`);

		commandCounter = 0;
		authentication = newAuthentication;
	}

	/**
	 * @see AuthenticateEV2First - Part1
	 * @returns {Buffer} ecRndB
	 */
	async function authStep1(keyNumber: number): Promise<Buffer> {
		const result = await sendNativeCommand(
			0x71,
			Buffer.of(
				keyNumber,
				0x00, // Length of the PCD capability vector (NT4H2421Gx.pdf 10.4.1)
			),
			null,
			null,
			authStep1.name,
		);

		return result.getDataOrThrow(authStep1.name);
	}

	/**
	 * @see AuthenticateEV2First - Part2
	 * @returns {Buffer} ecRndB
	 */
	async function authStep2(
		key: Buffer,
		ecRndB: Buffer,
	): Promise<[Buffer, Buffer, Buffer]> {
		const rndB = ntagCrypto.decryptCbc(
			key,
			ecRndB,
			ntagCrypto.createEmptyIv(),
			false,
		);
		const rndBp = buffer.rotateLeft(rndB);

		const nodeCrypto = await import("node:crypto");
		const rndA = nodeCrypto.randomBytes(rndB.length);

		// If keySize === blockSize, this would actually be the same as an ECB pass
		// But the spec states that it needs to be CBC (which is only relevant if keySize > blockSize)
		const message = ntagCrypto.encryptCbc(
			key,
			Buffer.concat([rndA, rndBp]),
			ntagCrypto.createEmptyIv(),
			false,
		);

		const result = await sendNativeCommand(
			0xaf,
			message,
			null,
			null,
			authStep2.name,
		);

		return [result.getDataOrThrow(authStep2.name), rndA, rndB];
	}

	async function getUid() {
		// TODO: Find this in the docs and replace it with some iso command
		const res = await send(
			Buffer.of(0xff, 0xca, 0x00, 0x00, 0x00),
			getUid.name,
		);
		if (res.at(-1) !== 0x00) {
			throw new Error("Error getting UID");
		}

		return res.subarray(0, -2);
	}

	/**
	 * Performs GetFileSettings
	 * @see Section 10.7.2
	 * @returns Something
	 */
	async function getFileSettings(fileNumber: number): Promise<GetFileSettings> {
		const res = await getFileSettingsRaw(fileNumber);
		return fileSettings.parseFromGetFileSettings(res);
	}
	/**
	 * Performs GetFileSettings
	 * @see Section 10.7.2
	 * @returns Something
	 */
	async function getFileSettingsRaw(fileNumber: number): Promise<Buffer> {
		if (fileNumber < 0 || fileNumber > 0b0000_1111) {
			throw new Error("fileNumber must fit into 4 bits");
		}

		const result = await sendWithMac(
			0xf5,
			Buffer.of(fileNumber & 0xf),
			null,
			getFileSettingsRaw.name,
		);

		return result.getDataOrThrow(getFileSettingsRaw.name);
	}

	async function setFileSettings(
		fileNumber: number,
		value: FileSettings,
		tagParams: TagParams,
	): Promise<void> {
		const serialized = fileSettings.serializeForChangeFileSettings(
			value,
			tagParams,
		);
		return await setFileSettingsRaw(fileNumber, serialized);
	}

	/**
	 * Performs ChangeFileSettings
	 * @See Section 10.7.1
	 */
	async function setFileSettingsRaw(
		fileNumber: number,
		value: Buffer,
	): Promise<void> {
		if (fileNumber < 0 || fileNumber > 0b0000_1111) {
			throw new Error("fileNumber must fit into 4 bits");
		}

		const command = 0x5f;
		const header = Buffer.of(fileNumber & 0b0000_1111);

		if (!authentication) {
			const result = await sendPlainCommand(
				command,
				header,
				value,
				setFileSettings.name,
			);
			result.throwIfError(setFileSettingsRaw.name);
			return;
		}

		const result = await sendEncrypted(
			command,
			header,
			value,
			setFileSettings.name,
		);

		result.throwIfError(setFileSettings.name);
	}

	async function selectFile(fileId: Buffer, mode: number): Promise<void> {
		if (fileId.length > 16) {
			throw new Error("fileId cannot be larger than 16 bytes");
		}

		const result = await sendIsoCommand(
			0x00,
			0xa4,
			mode,
			0x0c, // Don't return FCI (No response data if L_e field absent, or proprietary if L_e field present)
			fileId,
			0x80, // Largest supported value by our reader. Found out by trail&error
			selectFile.name,
		);

		result.throwIfError(getFileSettingsRaw.name);
	}

	/**
	 * Performs ISOReadBinary on the StandardDataFile.
	 *
	 * @see Section 10.9.2
	 */
	async function readStandardFile(): Promise<Buffer> {
		await selectFile(standardFileIds.ndef, isoSelectFileMode.MF_DF_EF);

		const result = await sendIsoCommand(
			0x00,
			0xb0,
			0x00,
			0x00,
			null,
			0x80 - 2,
			readStandardFile.name,
		);
		return result.getDataOrThrow(readStandardFile.name);
	}

	/** Performs ISOUpdateBinary on the StandardDataFile.
	 *
	 * @see Section 10.9.3
	 */
	async function writeStandardFile(contents: Buffer): Promise<void> {
		if (contents.length > 255) {
			throw new Error(
				"Buffer is too large. StandardDataFile can hold a maximum of 255 bytes.",
			);
		}

		await selectFile(standardFileIds.ndef, isoSelectFileMode.MF_DF_EF);

		const result = await sendIsoCommand(
			0x00,
			0xd6,
			0x00,
			0x00,
			contents.length === 0 ? null : contents,
			null,
			writeStandardFile.name,
		);

		result.throwIfError(writeStandardFile.name);
	}

	async function getCardUid(commMode: CommMode): Promise<Buffer> {
		const result = await sendSwitchedCommand(
			commMode,
			0x51,
			Buffer.alloc(0),
			null,
			getCardUid.name,
		);
		return result.getDataOrThrow(getCardUid.name);
	}

	async function writeData(
		commMode: CommMode,
		fileNumber: number,
		data: Buffer,
		offset = 0,
	): Promise<void> {
		const header = Buffer.alloc(7);
		header.writeUint8(fileNumber);
		header.writeUintLE(offset, 1, 3);
		header.writeUintLE(data.byteLength, 4, 3);

		const result = await sendSwitchedCommand(
			commMode,
			0x8d,
			header,
			data,
			writeData.name,
		);
		result.throwIfError(writeData.name);
	}

	async function changeKey(
		keyNumber: number,
		oldKey: Buffer,
		newKey: Buffer,
		newKeyVersion: number,
	): Promise<void> {
		if (oldKey.byteLength !== 16) {
			throw new Error("`oldKey` must be 16 bytes long");
		}
		if (newKey.byteLength !== 16) {
			throw new Error("`newKey` must be 16 bytes long");
		}

		let keyData: Buffer;
		if (keyNumber === 0) {
			keyData = Buffer.from([...newKey, newKeyVersion & 0xff]);
		} else {
			keyData = Buffer.from([
				...buffer.xor(oldKey, newKey),
				newKeyVersion & 0xff,
				...buffer.create.u32le(ntagCrypto.crc(newKey)),
			]);
		}

		const result = await sendEncrypted(
			0xc4,
			Buffer.of(keyNumber),
			keyData,
			changeKey.name,
		);

		result.throwIfError(changeKey.name);
	}

	async function setConfiguration(config: ConfigurationUpdate): Promise<void> {
		const [header, data] = configuration.serializeConfigurationUpdate(config);

		const result = await sendEncrypted(
			0x5c,
			Buffer.of(header),
			data,
			setConfiguration.name,
		);
		result.throwIfError();
	}

	async function getKeyVersion(keyNumber: number): Promise<number> {
		if (keyNumber < 0 || keyNumber > 4) {
			throw new Error("`keyNumber` must be in the range `[0, 4]`");
		}

		const res = await sendWithMac(
			0x64,
			Buffer.of(keyNumber & 0b111),
			null,
			getKeyVersion.name,
		);

		const data = res.getDataOrThrow(getKeyVersion.name);
		if (data.length !== 1) {
			throw new Error("Returned data has unsupported length");
		}

		return data[0];
	}

	/**
	 * The `getFileCounters` command supports retrieving of the current values associated with
	 * the SDMReadCtr related with a StandardData file after enabling Secure Dynamic Messaging.
	 *
	 * @remarks Requires CommMode "full" (authenticated session).
	 *
	 * @param {number} fileNumber
	 */
	async function getFileCounters(fileNumber: number): Promise<number> {
		if (fileNumber < 0 || fileNumber > 0b11111) {
			throw new Error("`fileNumber` must be in the range `[0, 0b11111]`");
		}

		const res = await sendEncrypted(
			0xf6,
			Buffer.of(fileNumber & 0b11111),
			null,
			getFileCounters.name,
		);

		const counters = res.getDataOrThrow(getFileCounters.name);
		if (counters.byteLength !== 5) {
			throw new Error("Expected the response to have exactly 5 bytes");
		}

		const sdmReadCounter = counters.readUintLE(0, 3);
		const rfu0 = counters.readUintLE(3, 2);
		if (rfu0 !== 0) {
			throw new Error("Expected RFU counters to be `0x0000`.");
		}
		return sdmReadCounter;
	}

	//#region Command Dispatch

	async function sendSwitchedCommand(
		commMode: CommMode,
		command: number,
		header: Buffer,
		data: Buffer | null,
		comment: string,
	) {
		switch (commMode) {
			case "plain":
				return sendPlainCommand(command, header, data, comment);
			case "mac":
				return sendWithMac(command, header, data, comment);
			case "full":
				return sendEncrypted(command, header, data, comment);
			default:
				throw new Error("Unsupported commMode");
		}
	}

	async function sendPlainCommand(
		command: number,
		header: Buffer,
		data: Buffer | null,
		comment: string,
	): Promise<CommandResponse> {
		++commandCounter;
		return await sendNativeCommand(command, header, data, null, comment);
	}

	async function sendWithMac(
		command: number,
		header: Buffer,
		data: Buffer | null,
		comment: string,
	): Promise<CommandResponse> {
		if (!authentication) {
			return await sendPlainCommand(command, header, data, comment);
		}

		const macIn = Buffer.of(
			command,
			0x00,
			0x00,
			...authentication.TI,
			...header,
			...(data ?? []),
		);
		macIn.writeUInt16LE(commandCounter, 1);

		const longMac = ntagCrypto.MAC(authentication.sessionMacKey, macIn);
		const macData = ntagCrypto.reduceMac(longMac);

		const macedResult = await sendNativeCommand(
			command,
			header,
			data,
			macData,
			comment,
		);
		++commandCounter; // sendNativeCommand can throw, we only want to increment successful commands

		if (macedResult.isError()) {
			return macedResult;
		}

		const macedPayload = macedResult.data;
		if (macedPayload === null) {
			// there is no additional data to be checked
			return new CommandResponse(macedResult.status, null);
		}

		const actualResponseMac = macedPayload.subarray(-8);
		const responseData = macedPayload.subarray(0, -8);

		const resultMacInputHeader = Buffer.of(
			macedResult.status.status2,
			0x00,
			0x00, // counter
			...authentication.TI,
		);
		resultMacInputHeader.writeUInt16LE(commandCounter, 1);

		const resultMacInput = Buffer.concat([resultMacInputHeader, responseData]);
		const expectedResponseMac = ntagCrypto.reduceMac(
			ntagCrypto.MAC(authentication.sessionMacKey, resultMacInput),
		);
		if (Buffer.compare(expectedResponseMac, actualResponseMac) !== 0) {
			throw new Error(
				`Expected response MAC and actual response MAC did not match. Expected: ${expectedResponseMac.toString("hex")}, actual: ${actualResponseMac.toString("hex")}`,
			);
		}

		return new CommandResponse(macedResult.status, responseData);
	}

	function encryptData(
		params: EncryptionParams,
		commandCounter: number,
		data: Buffer,
	): Buffer {
		// Section 9.1.4
		const ivInput = Buffer.alloc(16);
		ivInput.writeUint8(0xa5, 0);
		ivInput.writeUint8(0x5a, 1);
		params.TI.copy(ivInput, 2, 0); // 2, 3, 4, 5
		ivInput.writeUInt16LE(commandCounter, 6);
		// 8 bytes kept to 0

		const iv = ntagCrypto.encryptEcb(params.sessionEncryptionKey, ivInput);

		return ntagCrypto.encryptCbc(params.sessionEncryptionKey, data, iv, true);
	}
	function decryptData(params: EncryptionParams, data: Buffer): Buffer {
		// Section 9.1.4
		const ivInput = Buffer.alloc(16);
		ivInput.writeUint8(0x5a, 0);
		ivInput.writeUint8(0xa5, 1);
		params.TI.copy(ivInput, 2, 0); // 2, 3, 4, 5
		ivInput.writeUInt16LE(commandCounter, 6);
		// 8 bytes kept to 0

		const iv = ntagCrypto.encryptEcb(params.sessionEncryptionKey, ivInput);

		return ntagCrypto.decryptCbc(params.sessionEncryptionKey, data, iv, true);
	}

	async function sendEncrypted(
		command: number,
		header: Buffer,
		data: Buffer | null,
		comment: string,
	): Promise<CommandResponse> {
		if (!authentication) {
			throw new Error("You should not be able to do this");
		}

		const encryptedData =
			data !== null && data.length > 0
				? encryptData(authentication, commandCounter, data)
				: data;

		const result = await sendWithMac(command, header, encryptedData, comment);

		if (result.isError() || result.data === null || result.data.length === 0) {
			return new CommandResponse(result.status, null);
		}

		const decryptedData = decryptData(authentication, result.getDataOrThrow());
		return new CommandResponse(result.status, decryptedData);
	}

	//#endregion
}
