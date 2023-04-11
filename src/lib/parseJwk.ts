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

import deriveKeyId from './deriveKeyId';

const parseJwk = async (
	jwk: string,
): Promise<{ ['CKP']: CryptoKeyPair; ['kId']: string }> => {
	const jwkObj = JSON.parse(jwk);

	const CK = await globalThis.crypto.subtle.importKey(
		'jwk',
		jwkObj,
		{ ['name']: 'ECDH', ['namedCurve']: jwkObj['crv'] },
		false,
		['deriveKey'],
	);

	// To get the KID, we need an extractable
	// public key.
	// We delete all the secret values from JwkObj
	// For ECDH / OKP keys, this is only 'd', but if we happened
	// to have an RSA key, we'd have some additional secret values
	delete jwkObj['d'];
	delete jwkObj['p'];
	delete jwkObj['q'];
	delete jwkObj['qi'];
	delete jwkObj['dp'];
	delete jwkObj['dq'];

	const pubCK = await globalThis.crypto.subtle.importKey(
		'jwk',
		jwkObj,
		{ ['name']: 'ECDH', ['namedCurve']: jwkObj['crv'] },
		true,
		[],
	);

	const kId = await deriveKeyId(pubCK);

	return {
		['CKP']: {
			['privateKey']: CK,
			['publicKey']: pubCK,
		},
		['kId']: kId,
	};
};

export default parseJwk;
