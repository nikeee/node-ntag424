export const commModes = {
	__proto__: null,
	plain: 0b00,
	mac: 0b01,
	full: 0b11,
} as const;

export type CommMode = Exclude<keyof typeof commModes, "__proto__">;

export const commModeLookup = {
	__proto__: null,
	// biome-ignore lint/complexity/useSimpleNumberKeys: same as above
	0b00: "plain",
	// biome-ignore lint/complexity/useSimpleNumberKeys: same as above
	0b01: "mac",
	// biome-ignore lint/complexity/useSimpleNumberKeys: same as above
	0b11: "full",
} as const;
