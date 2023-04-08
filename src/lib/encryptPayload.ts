/* Copyright © 2023 Exact Realty Limited.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

const encryptPayload = async (
	payload: ArrayBuffer,
	apvCK: CryptoKey,
	aad?: ArrayBufferView,
) => {
	const ephemeralKeyPair = (await globalThis.crypto.subtle.generateKey(
		apvCK.algorithm,
		false,
		['deriveKey'],
	)) as CryptoKeyPair;

	const derivedKey = await globalThis.crypto.subtle.deriveKey(
		{
			['name']: 'ECDH',
			['public']: apvCK,
		},
		ephemeralKeyPair.privateKey,
		{
			['name']: 'AES-GCM',
			['length']: 256,
		},
		false,
		['encrypt'],
	);

	const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));

	const encryptedPayload = await globalThis.crypto.subtle.encrypt(
		{ ['name']: 'AES-GCM', ['iv']: iv, ['additionalData']: aad },
		derivedKey,
		payload,
	);

	const rawPublicEphemeralKey = await globalThis.crypto.subtle.exportKey(
		'raw',
		ephemeralKeyPair.publicKey,
	);

	const publicKeyLengthBuffer = new Uint8Array([
		(rawPublicEphemeralKey.byteLength >> 8) & 0xff,
		rawPublicEphemeralKey.byteLength & 0xff,
	]);

	const result = new Uint8Array(
		publicKeyLengthBuffer.byteLength +
			rawPublicEphemeralKey.byteLength +
			iv.byteLength +
			encryptedPayload.byteLength,
	);

	result.set(publicKeyLengthBuffer, 0);
	result.set(
		new Uint8Array(rawPublicEphemeralKey),
		publicKeyLengthBuffer.length,
	);
	result.set(
		iv,
		publicKeyLengthBuffer.length + rawPublicEphemeralKey.byteLength,
	);
	result.set(
		new Uint8Array(encryptedPayload),
		publicKeyLengthBuffer.length +
			rawPublicEphemeralKey.byteLength +
			iv.byteLength,
	);

	return result.buffer;
};

const decryptPayload = async (
	payload: ArrayBuffer,
	key: CryptoKey,
	aad?: ArrayBufferView,
): Promise<ArrayBuffer> => {
	const publicKeyLengthBuffer = new Uint8Array(payload.slice(0, 2));
	const publicKeyLength =
		publicKeyLengthBuffer[1] + (publicKeyLengthBuffer[0] << 8);

	const publicEphemeralKey = await globalThis.crypto.subtle.importKey(
		'raw',
		payload.slice(2, 2 + publicKeyLength),
		key.algorithm,
		false,
		[],
	);

	const derivedKey = await globalThis.crypto.subtle.deriveKey(
		{
			['name']: 'ECDH',
			['public']: publicEphemeralKey,
		},
		key,
		{
			['name']: 'AES-GCM',
			['length']: 256,
		},
		false,
		['decrypt'],
	);

	const iv = payload.slice(2 + publicKeyLength, 14 + publicKeyLength);

	return globalThis.crypto.subtle.decrypt(
		{ ['name']: 'AES-GCM', ['iv']: iv, ['additionalData']: aad },
		derivedKey,
		payload.slice(14 + publicKeyLength),
	);
};

export { encryptPayload, decryptPayload };
