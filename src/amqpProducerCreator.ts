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

import type amqplib from 'amqplib';
import { btoau } from './lib/base64url';
import { encryptPayload } from './lib/encryptPayload';
import normalizeHeaders from './lib/normalizeHeaders';

export type TAmqpProducerParams = {
	queue: string;
	apv: string;
	schemaId: string;
	payload: ArrayBuffer;
	correlationId: string;
	replyTo?: string;
	headers?: Record<string, string>;
};

const amqpProducerCreator = (
	ch: amqplib.Channel,
	apuKid: string,
	apuCK: CryptoKey,
) => {
	const textEncoder = new TextEncoder();

	return async (outgoingMessage: TAmqpProducerParams) => {
		const {
			queue: outgoingQueue,
			apv: apvJwkS,
			schemaId: outgoingSchemaId,
			payload: encodedOutgoingMessage,
			correlationId: correlationId,
			replyTo: replyTo,
			headers: headers,
		} = outgoingMessage;

		const apvJwkObj = JSON.parse(apvJwkS);

		const apvCK = await globalThis.crypto.subtle.importKey(
			'jwk',
			apvJwkObj,
			{
				['name']: 'ECDH',
				['namedCurve']: apvJwkObj['crv'],
			},
			false,
			[],
		);

		const outgoingOptions = {
			['contentType']: 'application/octet-stream',
			['correlationId']: correlationId,
			['replyTo']: replyTo,
			['headers']: {
				...headers,
				['date']: new Date().toUTCString(),
				['x-protected-headers']: '',
				['x-request-integrity']: '',
				['x-schema-id']: outgoingSchemaId,
				['x-sender-key-id']: apuKid,
			},
		};

		outgoingOptions['headers']['x-protected-headers'] = Object.keys(
			outgoingOptions['headers'],
		)
			.sort()
			.map((k) => k.toLowerCase())
			.join(':');

		const derivedOutgoingKey = await globalThis.crypto.subtle.deriveKey(
			{
				['name']: 'ECDH',
				['public']: apvCK,
			},
			apuCK,
			{
				['name']: 'HMAC',
				['hash']: 'SHA-256',
				['length']: 256,
			},
			false,
			['sign'],
		);

		const normalisedOutgoingOptions = {
			...outgoingOptions,
			['headers']: normalizeHeaders(outgoingOptions['headers']),
		};

		const encryptedEncodedOutgoingMessage = await encryptPayload(
			encodedOutgoingMessage,
			apvCK,
			textEncoder.encode(JSON.stringify(normalisedOutgoingOptions)),
		);

		outgoingOptions.headers['x-request-integrity'] += btoau(
			new Uint8Array(
				await globalThis.crypto.subtle.sign(
					{
						['name']: 'HMAC',
					},
					derivedOutgoingKey,
					encryptedEncodedOutgoingMessage,
				),
			),
		);

		ch.sendToQueue(
			outgoingQueue,
			Buffer.from(encryptedEncodedOutgoingMessage),
			outgoingOptions,
		);
	};
};

export default amqpProducerCreator;
