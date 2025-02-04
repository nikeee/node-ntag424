import { validationAes } from "ntag424";

const fileReadKey = Buffer.from("...", "hex"); // your key
const uid = Buffer.from("11223344556677", "hex"); // The UID in your validation request
const counter = 123;
const signatureMac = Buffer.from("", "hex");

const signatureValid = validationAes.validatePlainPiccMac(
    fileReadKey,
    uid,
    counter,
    signatureMac,
);
console.log("Provided signature was valid?", signatureValid);
