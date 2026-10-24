const { privateKey, publicKey } = await crypto.subtle.generateKey(
	{
		hash: "SHA-256",
		modulusLength: 4096,
		name: "RSASSA-PKCS1-v1_5",
		publicExponent: new Uint8Array([1, 0, 1]),
	},
	true,
	["sign", "verify"],
);

export const publicJwk = await crypto.subtle.exportKey("jwk", publicKey);
export const privateJwk = await crypto.subtle.exportKey("jwk", privateKey);
