import { createTagSession, isoSelectFileMode, type TagSession } from "ntag424";
import { NFC, TAG_ISO_14443_4 } from "nfc-pcsc";

const nfc = new NFC();

nfc.on("error", err => console.error(err, "an error occurred"));

nfc.on("reader", async reader => {
	console.info(`Card reader attached: "${reader.name}"`);
	reader.autoProcessing = false;

	reader.on("error", err => console.error(err, "An error occurred"));
	reader.on("end", () => console.info("Reader detached"));

	reader.on("card.off", () => console.info("Tag removed"));
	reader.on("card", async tag => {
		console.debug("Tag detected");
		if (tag.type !== TAG_ISO_14443_4) {
			console.info("Tag unsupported, skipping");
			return;
		}
		await processTag(createTagSession(reader));
	});
});

const ndefAid = Buffer.from("d2760000850101", "hex");

const factoryKey = Buffer.from("00000000000000000000000000000000", "hex");

async function processTag(session: TagSession) {
	const uid = await session.getUid();
	console.info("UID:", uid);

	await session.selectFile(ndefAid, isoSelectFileMode.BY_DF_NAME);
	await session.authenticate(0, factoryKey);

	const actualUid = await session.getCardUid("full");
	console.info("Actual UID: ", actualUid);

	const ndefFileSettings = await session.getFileSettings(0x02);

	console.log("NDEF file settings:");
	console.table(ndefFileSettings.accessRights);
	console.table(ndefFileSettings?.sdmOptions?.accessRights);
}
