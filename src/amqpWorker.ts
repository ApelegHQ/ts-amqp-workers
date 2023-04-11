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
import amqpProducerCreator from './amqpProducerCreator';
import type { TAmqpProducerParams } from './amqpProducerCreator';
import {
	ConsumerCancelledError,
	DecryptionError,
	MessageHandlerError,
	MessageIntegrityError,
	OutgoingMessageError,
	ProcessingError,
	RequeuableSoftError,
	UnsupportedMessageWarning,
} from './Errors';
import { autobb } from './lib/base64url';
import deriveKeyId from './lib/deriveKeyId';
import { decryptPayload } from './lib/encryptPayload';
import normalizeHeaders from './lib/normalizeHeaders';
import parseJwk from './lib/parseJwk';

export type TAmqpWorkerContext = {
	['ap$selfPub$CK']: CryptoKey;
	['ap$self$Kid']: string;
};

const amqpWorker = async (
	ch: amqplib.Channel,
	inputQueue: string,
	// Our own key
	ap$self$: string,
	sourceJwkPublicKeys: string[],
	incomingSchemaIds: string[],
	propertiesValidator: {
		(props: amqplib.MessageProperties, ctx: TAmqpWorkerContext):
			| Promise<boolean>
			| boolean;
	},
	messageHandler: {
		(
			props: amqplib.MessageProperties,
			msg: ArrayBuffer,
			ctx: TAmqpWorkerContext,
		): Promise<TAmqpProducerParams[] | void> | TAmqpProducerParams[] | void;
	},
	errorHandler?: {
		(e: Error, props: amqplib.MessageProperties, ctx: TAmqpWorkerContext):
			| TAmqpProducerParams[]
			| void;
	},
) => {
	const textEncoder = new TextEncoder();

	const {
		['CKP']: { ['privateKey']: ap$self$CK, ['publicKey']: ap$selfPub$CK },
		['kId']: ap$self$Kid,
	} = await parseJwk(ap$self$);
	// Clear ap$self$
	ap$self$ = undefined as unknown as string;

	const ctx = {
		['ap$selfPub$CK']: ap$selfPub$CK,
		['ap$self$Kid']: ap$self$Kid,
	};

	const derivedIncomingKeys = Object.fromEntries(
		await Promise.all(
			sourceJwkPublicKeys.map(async (apuJwkS) => {
				const apuJwkObj = JSON.parse(apuJwkS);

				const apuCK = await globalThis.crypto.subtle.importKey(
					'jwk',
					apuJwkObj,
					{ ['name']: 'ECDH', ['namedCurve']: apuJwkObj['crv'] },
					true,
					[],
				);

				const apuKid = await deriveKeyId(apuCK);

				const derivedIncomingKey =
					await globalThis.crypto.subtle.deriveKey(
						{
							['name']: 'ECDH',
							['public']: apuCK,
						},
						ap$self$CK,
						{
							['name']: 'HMAC',
							['hash']: 'SHA-256',
							['length']: 256,
						},
						false,
						['verify'],
					);

				return [apuKid, derivedIncomingKey];
			}),
		),
	);

	await ch.assertQueue(inputQueue, { durable: true });

	const outgoingMessageHelper = amqpProducerCreator(
		ch,
		ap$self$Kid,
		ap$self$CK,
	);

	await ch.consume(
		inputQueue,
		(msg: Readonly<amqplib.ConsumeMessage | null>) => {
			if (msg === null) {
				throw new ConsumerCancelledError();
			}

			if (
				msg.properties.contentType !== 'application/octet-stream' ||
				!incomingSchemaIds.includes(
					msg.properties.headers['x-schema-id'],
				) ||
				!msg.properties.headers['date'] ||
				!msg.properties.headers['x-protected-headers'] ||
				!msg.properties.headers['x-request-integrity'] ||
				!/^[0-9a-zA-Z_-]+$/.test(
					msg.properties.headers['x-request-integrity'],
				) ||
				!msg.properties.headers['x-sender-key-id']
			) {
				errorHandler &&
					typeof errorHandler === 'function' &&
					Promise.all(
						errorHandler(
							new UnsupportedMessageWarning(),
							msg.properties,
							ctx,
						)?.map(outgoingMessageHelper) ?? [],
					).catch(Boolean);

				ch.reject(msg, false);
			}

			Promise.resolve(propertiesValidator(msg.properties, ctx))
				.then(async () => {
					const encodedVerificationTag =
						msg.properties.headers['x-request-integrity'];

					const incomingKeyId =
						msg.properties.headers['x-sender-key-id'];

					const derivedIncomingKey =
						derivedIncomingKeys[incomingKeyId];

					const verificationResult =
						await globalThis.crypto.subtle.verify(
							{
								['name']: 'HMAC',
							},
							derivedIncomingKey,
							autobb(encodedVerificationTag),
							msg.content,
						);

					if (!verificationResult) {
						throw new MessageIntegrityError();
					}

					const incomingOptions = {
						['contentType']: msg.properties.contentType,
						['correlationId']: msg.properties.correlationId,
						['replyTo']: msg.properties.replyTo,
						['headers']: normalizeHeaders(
							msg.properties.headers,
							msg.properties.headers['x-protected-headers'].split(
								':',
							),
						),
					};

					incomingOptions['headers']['x-request-integrity'] = '';

					try {
						const decryptedPayload = await decryptPayload(
							msg.content,
							ap$self$CK,
							textEncoder.encode(JSON.stringify(incomingOptions)),
						);

						return decryptedPayload;
					} catch (e) {
						throw new DecryptionError(e);
					}
				})
				.then(async (decryptedPayload) => {
					try {
						const result = await messageHandler(
							msg.properties,
							decryptedPayload,
							ctx,
						);

						return result;
					} catch (e) {
						if (e && e instanceof RequeuableSoftError) {
							throw e;
						}

						throw new MessageHandlerError(e);
					}
				})
				.then(async (result) => {
					if (Array.isArray(result)) {
						try {
							await Promise.all(
								result.map(outgoingMessageHelper),
							);
						} catch (e) {
							throw new OutgoingMessageError(e);
						}
					}
				})
				.then(() => ch.ack(msg))
				.catch((e) => {
					try {
						errorHandler &&
							typeof errorHandler === 'function' &&
							Promise.all(
								errorHandler(
									e && e instanceof ProcessingError
										? e
										: new ProcessingError(e),
									msg.properties,
									ctx,
								)?.map(outgoingMessageHelper) ?? [],
							).catch(Boolean);
					} catch (e) {
						// empty
					}

					ch.reject(msg, e && e instanceof RequeuableSoftError);
				});
		},
		{ noAck: false },
	);
};

export default amqpWorker;
