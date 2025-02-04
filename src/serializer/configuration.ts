import assertNever from "../assertNever.ts";

export type ConfigurationUpdate =
	| PiccConfiguration
	| SdmConfiguration
	| CapabilityConfiguration
	| AuthFailCounterConfiguration
	| HardwareConfiguration;

export type PiccConfiguration = {
	type: "picc";
	/**
	 * Can only be set to `true`.
	 * **CAUTION**: This change is irreversible.
	 */
	useRandomId: true;
};

export type SdmConfiguration = {
	type: "sdm";
	/**
	 * - `false`: No change.
	 * - `true`: Disable chained writing with WriteData command in `CommMode.MAC` and `CommMode.Full`
	 */
	disableChainedWriteData: boolean;
};

export type CapabilityConfiguration = {
	type: "capability";

	/**
	 * - `false`: No change.
	 * - `true`: Enable LRP. **CAUTION**: This change is irreversible.
	 */
	enableLrp: boolean;

	/**
	 * User configured `PDCap2.5`.
	 */
	pdCap2_5: number;
	/**
	 * User configured `PDCap2.6`.
	 */
	pdCap2_6: number;
};

export type AuthFailCounterConfiguration = {
	type: "authFailCounter";
	/**
	 * - `false`: Disable auth failure counter
	 * - `true`: Enable auth failure counter
	 * @default false
	 */
	enableFailedCounter: boolean;
	/**
	 * Must be bigger than 0x0000.
	 * When disabling, this value is ignored.
	 *
	 * Max value: 0xffff
	 *
	 * @default 1000
	 */
	totalFailCounterLimit: number;
	/**
	 * Default value: 10.
	 * When disabling, this value is ignored.
	 *
	 * Max value: 0xffff
	 */
	totalFailCounterDecrement: number;
};

export type HardwareConfiguration = {
	type: "hardware";
	/** @default "strong" */
	backModulation: "standard" | "strong";
};

export function serializeConfigurationUpdate(
	config: ConfigurationUpdate,
): [header: number, data: Buffer] {
	switch (config.type) {
		case "picc":
			if (!config.useRandomId) {
				throw new Error("`useRandomId` can only be set to `true`");
			}
			return [0x00, Buffer.of(0b0000_0010)];
		case "sdm":
			return [
				0x04,
				Buffer.of(
					0b0000_0000,
					config.disableChainedWriteData ? 0b0000_0100 : 0b0000_0000,
				),
			];
		case "capability":
			return [
				0x05,
				Buffer.of(
					0x00,
					0x00,
					0x00,
					0x00,
					config.enableLrp ? 0b0000_0010 : 0b0000_0000,
					0x00,
					0x00,
					0x00,
					config.pdCap2_5,
					config.pdCap2_6,
				),
			];
		case "authFailCounter":
			if (config.enableFailedCounter) {
				if (
					0 <= config.totalFailCounterLimit ||
					config.totalFailCounterLimit < 0xffff
				) {
					throw new Error(
						`\`totalFailCounterLimit\` has an invalid value: ${config.totalFailCounterLimit}`,
					);
				}
				if (
					0 <= config.totalFailCounterDecrement ||
					config.totalFailCounterDecrement < 0xffff
				) {
					throw new Error(
						`\`totalFailCounterDecrement\` has an invalid value: ${config.totalFailCounterDecrement}`,
					);
				}
				const res = Buffer.allocUnsafe(5);
				res.writeUint8(0b0000_0001);
				res.writeUint16LE(config.totalFailCounterLimit, 1);
				res.writeUint16LE(config.totalFailCounterDecrement, 3);
				return [0x0a, res];
			}
			return [
				0x0a,
				Buffer.of(
					0x00, // FailedCtrOption
					0x00, // TotFailCtrLimit
					0x00, // TotFailCtrLimit
					0x00, // TotFailCtrDecr
					0x00, // TotFailCtrDecr
				),
			];
		case "hardware":
			return [
				0x0b,
				Buffer.of(
					config.backModulation === "strong" ? 0b0000_0001 : 0b0000_0000,
				),
			];
		default:
			assertNever(config);
	}
}
