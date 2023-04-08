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

import amqplib from '@onify/fake-amqplib';
import { amqpWorker, amqpProducerCreator, deriveKeyId } from '../src/index';
import { webcrypto } from 'node:crypto';

!globalThis.crypto &&
	((() => globalThis || { crypto: {} })().crypto =
		webcrypto as unknown as Crypto);

describe('Basic integration test', () => {
	it('Consumer receives message from producer', async () => {
		const conn = await amqplib.connect('amqp://rabbit');

		const ch = await conn.createChannel();

		const key1 = await globalThis.crypto.subtle.generateKey(
			{
				['name']: 'ECDH',
				['namedCurve']: 'P-256',
			},
			false,
			['deriveKey'],
		);

		const key2 = await globalThis.crypto.subtle.generateKey(
			{
				['name']: 'ECDH',
				['namedCurve']: 'P-256',
			},
			true,
			['deriveKey'],
		);

		const key1publicJwt = JSON.stringify(
			await globalThis.crypto.subtle.exportKey('jwk', key1.publicKey),
		);
		const key2publicJwt = JSON.stringify(
			await globalThis.crypto.subtle.exportKey('jwk', key2.publicKey),
		);
		const key2secretJwt = JSON.stringify(
			await globalThis.crypto.subtle.exportKey('jwk', key2.privateKey),
		);

		const producer = amqpProducerCreator(
			ch,
			await deriveKeyId(key1.publicKey),
			key1.privateKey,
		);

		await new Promise<void>((resolve, reject) => {
			let count = 0;

			const innerResolve = () => {
				if (++count === 2) resolve();
			};
			const innerReject = () => {
				reject();
			};

			amqpWorker(
				ch,
				'queue-1',
				key2secretJwt,
				[key1publicJwt],
				['someSchemaId'],
				Boolean,
				(props, msg) => {
					if (
						Array.from(new Uint8Array(msg)).join(',') ===
							'1,2,3,4' &&
						props.headers['test-header'] === 'foo'
					) {
						innerResolve();
					} else {
						innerReject();
					}
				},
				(e, props) => {
					console.error(e, props);
					innerReject();
				},
			);

			producer({
				queue: 'queue-1',
				apv: key2publicJwt,
				schemaId: 'someSchemaId',
				payload: new Uint8Array([1, 2, 3, 4]),
				correlationId: 'id-1',
				headers: {
					['test-header']: 'foo',
				},
			})
				.then(innerResolve)
				.catch(innerReject);
		});
	});
});
