import { describe, test } from "node:test";
import { expect } from "expect";

import * as fileSettings from "./fileSettings.ts";

describe("`parseFromGetFileSettings`", async () => {
	describe("smoke test", async () => {
		test("factory settings 0", async () => {
			const settings = Buffer.from("0000e0ee000100", "hex");
			const actual = fileSettings.parseFromGetFileSettings(settings);

			expect(actual).toStrictEqual({
				fileType: 0,
				accessRights: { read: 14, write: 14, readWrite: 14, change: 0 },
				fileSize: 256,
				commMode: "plain",
				sdmOptions: null,
			});
		});

		test("doc settings 0", async () => {
			// Taken from application notes:
			// https://www.nxp.com/docs/en/application-note/AN12196.pdf
			// Section 4.3
			// Table 7. Example of CommMode.MAC on Cmd.GetFileSettings command

			const docSettings = Buffer.from(
				"0040eeee000100d1fe001f00004400004400002000006a0000",
				"hex",
			);
			const actual = fileSettings.parseFromGetFileSettings(docSettings);

			expect(actual).toStrictEqual({
				fileType: 0,
				accessRights: { read: 14, write: 14, readWrite: 14, change: 14 },
				fileSize: 256,
				commMode: "plain",
				sdmOptions: {
					accessRights: { metaRead: 0, fileRead: 0, counterRetrieval: 14 },
					encodingMode: "ascii",
					encryptedFileData: { offset: 68, length: 32 },
					macInputOffset: 68,
					macOffset: 106,
					piccDataOffset: 31,
					readCounterLimit: null,
					readCounterOffset: null,
					uidOffset: null,
				},
			});
		});

		test("actual data", async () => {
			// Settings retrieved from an actual tag
			const factorySettings = Buffer.from(
				"0040eeee000100c1f121200000430000430000",
				"hex",
			);
			const actual = fileSettings.parseFromGetFileSettings(factorySettings);

			expect(actual).toStrictEqual({
				fileType: 0,
				accessRights: { read: 14, write: 14, readWrite: 14, change: 14 },
				fileSize: 256,
				commMode: "plain",
				sdmOptions: {
					accessRights: { metaRead: 2, fileRead: 1, counterRetrieval: 1 },
					encodingMode: "ascii",
					encryptedFileData: null,
					macInputOffset: 67,
					macOffset: 67,
					piccDataOffset: 32,
					readCounterLimit: null,
					readCounterOffset: null,
					uidOffset: null,
				},
			});
		});
	});
});

describe("`serializeForChangeFileSettings`", async () => {
	function runTest(settings: fileSettings.FileSettings, expected: string) {
		const actual = fileSettings.serializeForChangeFileSettings(settings, {
			fileSize: 256,
			piccDataLength: 0,
			encodedReadCounterLength: 3 * 2,
			encodedUidLength: 7 * 2,
		});

		expect(actual).toBeDefined();
		expect(actual).not.toBeNull();
		expect(actual).toBeInstanceOf(Buffer);
		expect(actual.length).toBeGreaterThan(0);

		expect(actual).toStrictEqual(Buffer.from(expected, "hex"));
	}

	function runExpectError(settings: fileSettings.FileSettings, error: Error) {
		expect(() =>
			fileSettings.serializeForChangeFileSettings(settings, {
				fileSize: 256,
				piccDataLength: 0,
				encodedReadCounterLength: 3 * 2,
				encodedUidLength: 7 * 2,
			}),
		).toThrow(error);
	}

	test("smoke test", async () => {
		runTest(
			{
				access: {
					read: 0xe,
					write: 0xe,
					readWrite: 0xe,
					change: 0xe,
				},
				commMode: "plain",
				sdmOptions: null,
			},
			"00eeee",
		);
		runTest(
			{
				access: {
					read: 1,
					write: 2,
					readWrite: 3,
					change: 4,
				},
				commMode: "plain",
				sdmOptions: null,
			},
			"003412",
		);
	});

	test("comm modes", async () => {
		runTest(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "plain",
				sdmOptions: null,
			},
			"000000",
		);
		runTest(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "mac",
				sdmOptions: null,
			},
			"010000",
		);
		runTest(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "full",
				sdmOptions: null,
			},
			"030000",
		);
	});

	test("sdm", async () => {
		runTest(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "full",
				sdmOptions: {
					accessRights: {
						fileRead: 0xf,
						metaRead: 0xe,
						counterRetrieval: 0xe,
					},
					uidOffset: 0,
					piccDataOffset: null,
					encodingMode: "ascii",
					encryptedFileData: null,
					macInputOffset: null,
					macOffset: null,
					readCounterLimit: null,
					readCounterOffset: null,
				},
			},
			"43000081feef000000",
		);

		runTest(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "full",
				sdmOptions: {
					accessRights: {
						fileRead: 0xf,
						metaRead: 0x0,
						counterRetrieval: 0xe,
					},
					uidOffset: null,
					piccDataOffset: 0,
					encodingMode: "ascii",
					encryptedFileData: null,
					macInputOffset: null,
					macOffset: null,
					readCounterLimit: null,
					readCounterOffset: null,
				},
			},
			"43000001fe0f000000",
		);

		runExpectError(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "full",
				sdmOptions: {
					accessRights: {
						fileRead: 0xf,
						metaRead: 0xf,
						counterRetrieval: 0xe,
					},
					uidOffset: null,
					piccDataOffset: 0,
					encodingMode: "ascii",
					encryptedFileData: null,
					macInputOffset: null,
					macOffset: null,
					readCounterLimit: null,
					readCounterOffset: null,
				},
			},
			new Error(
				"`piccDataOffset` cannot be set when `accessRights.metaRead` is not a key id.",
			),
		);

		runExpectError(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "full",
				sdmOptions: {
					accessRights: {
						fileRead: 0xf,
						metaRead: 0x0,
						counterRetrieval: 0xe,
					},
					uidOffset: null,
					piccDataOffset: null,
					encodingMode: "ascii",
					encryptedFileData: null,
					macInputOffset: null,
					macOffset: null,
					readCounterLimit: null,
					readCounterOffset: null,
				},
			},
			new Error(
				"`piccDataOffset` must be set when `accessRights.metaRead` is a key id.",
			),
		);

		runExpectError(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "full",
				sdmOptions: {
					accessRights: {
						fileRead: 0x0,
						metaRead: 0xf,
						counterRetrieval: 0xe,
					},
					uidOffset: null,
					piccDataOffset: null,
					encodingMode: "ascii",
					encryptedFileData: null,
					macInputOffset: null,
					macOffset: null,
					readCounterLimit: null,
					readCounterOffset: null,
				},
			},
			new Error(
				"`sdmOptions.macInputOffset` must be set if `accessRights.fileRead` !== 0xf.",
			),
		);

		runExpectError(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "full",
				sdmOptions: {
					accessRights: {
						fileRead: 0x0,
						metaRead: 0xf,
						counterRetrieval: 0xe,
					},
					uidOffset: null,
					piccDataOffset: null,
					encodingMode: "ascii",
					encryptedFileData: null,
					macInputOffset: 0,
					macOffset: null,
					readCounterLimit: null,
					readCounterOffset: null,
				},
			},
			new Error(
				"`sdmOptions.macOffset` must be set if `accessRights.fileRead` !== 0xf.",
			),
		);

		runTest(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "full",
				sdmOptions: {
					accessRights: {
						fileRead: 0x2,
						metaRead: 0xe,
						counterRetrieval: 0xe,
					},
					uidOffset: 0,
					piccDataOffset: null,
					encodingMode: "ascii",
					encryptedFileData: null,
					macInputOffset: 7,
					macOffset: 7,
					readCounterLimit: null,
					readCounterOffset: null,
				},
			},
			"43000081fee2000000070000070000",
		);

		runTest(
			{
				access: {
					read: 0,
					write: 0,
					readWrite: 0,
					change: 0,
				},
				commMode: "full",
				sdmOptions: {
					accessRights: {
						fileRead: 0x2,
						metaRead: 0xe,
						counterRetrieval: 0xe,
					},
					uidOffset: 0,
					piccDataOffset: null,
					encodingMode: "ascii",
					encryptedFileData: null,
					macInputOffset: 4,
					macOffset: 7,
					readCounterLimit: null,
					readCounterOffset: null,
				},
			},
			"43000081fee2000000040000070000",
		);
	});
});
