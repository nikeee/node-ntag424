export default function assertNever(type: never): never {
	throw new Error("This code should never be reached");
}
