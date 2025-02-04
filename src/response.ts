export class ResponseStatus {
	#status: Buffer;

	get status1() {
		return this.#status[0];
	}
	get status2() {
		return this.#status[1];
	}

	constructor(status: Buffer) {
		if (status.length !== 2) {
			throw new Error(`Status has invalid length: ${status.length}`);
		}
		this.#status = status;
	}

	throwIfError(step?: string) {
		if (!this.isOk()) {
			throw new Error(
				step
					? `Error in step "${step}": ${this.toString()}`
					: `Some error happened: ${this.toString()}`,
			);
		}
	}
	isOk() {
		if (
			(this.#status[0] !== 0x90 && // PLAIN_OK
				this.#status[0] !== 0x91) || // MAC_OK
			(this.#status[1] !== 0 && // SUCCESS
				this.#status[1] !== 0xaf) // ADDITIONAL_FRAME_EXPECTED
		) {
			return false;
		}
		return true;
	}
	toString() {
		return `<Status: ${this.#status.toString("hex")}>`;
	}
}

export class CommandResponse {
	readonly status: ResponseStatus;
	readonly data: Buffer | null;
	constructor(status: ResponseStatus, data: Buffer | null) {
		this.status = status;
		this.data = data;
	}

	static create(status: Buffer, data: Buffer | null) {
		return new CommandResponse(new ResponseStatus(status), data);
	}

	throwIfError(this: this, step?: string) {
		this.status.throwIfError(step);
	}
	isError() {
		return !this.status.isOk();
	}
	getDataOrThrow(step?: string): Buffer | never {
		this.throwIfError();
		const d = this.data;
		if (d === null) {
			throw new Error(
				step
					? `Expected to have data in step "${step}": ${this.toString()}`
					: "Expected to have data, but there was none",
			);
		}
		return d;
	}
}
