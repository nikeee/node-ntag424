export default function assertNever(_: never): never {
	throw new Error("This code should never be reached");
}
