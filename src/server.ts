import { cors } from "@elysiajs/cors";
import swagger from "@elysiajs/swagger";
import { Elysia, t } from "elysia";
import { type JWTPayload, SignJWT, importJWK } from "jose";
import { privateJwk, publicJwk } from "./jwks";



export interface CreateServerOptions {
	issuer?: string;
}

export async function createServer({
	issuer = "http://localhost:4220",
}: CreateServerOptions) {
	return new Elysia()
		.use(cors())
		.use(swagger())
		.decorate("publicJwk", publicJwk)
		.decorate("privateJwk", privateJwk)
		.decorate("privateKey", await importJWK(privateJwk))
		.derive(({ headers }) => ({
			bearer: headers.authorization?.split(" ")[1],
		}))
		.get("/.well-known/openid-configuration", () => ({
			issuer: issuer,
			token_endpoint: `${issuer}/token`,
			authorization_endpoint: `${issuer}/authorize`,
			userinfo_endpoint: `${issuer}/userinfo`,
			token_endpoint_auth_methods_supported: ["none"],
			jwks_uri: `${issuer}/jwks`,
			response_types_supported: ["code"],
			grant_types_supported: [
				"client_credentials",
				"authorization_code",
				"refresh_token",
			],
			token_endpoint_auth_signing_alg_values_supported: ["RS256"],
			response_modes_supported: ["query"],
			id_token_signing_alg_values_supported: ["RS256"],
			revocation_endpoint: `${issuer}/revoke`,
			subject_types_supported: ["public"],
			end_session_endpoint: `${issuer}/endsession`,
			introspection_endpoint: `${issuer}/introspect`,
		}))
		.get("/jwks", () => ({
			keys: [publicJwk],
		}))
		.post(
			"/token",
			async ({ body, cookie: { nonces }, privateJwk, privateKey }) => {
				const payload: JWTPayload = {
					scope: body.scope,
					iss: issuer,
					aud: body.grant_type === "client_credentials" ? body.aud : undefined,
					sub: body.grant_type !== "client_credentials" ? "johndoe" : undefined,
				};

				const token = await new SignJWT(payload)
					.setProtectedHeader({ typ: "JWT", alg: privateJwk.alg ?? "RS256" })
					.sign(privateKey);

				const responseBody: Record<string, unknown> = {
					access_token: token,
					token_type: "Bearer",
					expires_in: 3600,
					scope: payload.scope,
				};

				if (body.grant_type !== "client_credentials") {
					const idTokenPayload: JWTPayload = {
						iss: issuer,
						sub: "johndoe",
						aud: body.client_id,
					};

					if (body.code !== undefined) {
						const nonce = nonces.value?.find(
							(nonce) => nonce.code === body.code,
						);
						if (nonce) {
							idTokenPayload.nonce = nonce.value;
							nonces.value = (nonces.value ?? []).filter(
								(nonce) => nonce.code !== body.code,
							);
							nonces.sameSite = "none";
						}
					}

					responseBody.id_token = await new SignJWT(idTokenPayload)
						.setProtectedHeader({ typ: "JWT", alg: privateJwk.alg ?? "RS256" })
						.sign(privateKey);
					responseBody.refresh_token = crypto.randomUUID();
				}

				return responseBody;
			},
			{
				body: t.Object({
					scope: t.Optional(t.String()),
					grant_type: t.Union([
						t.Literal("client_credentials"),
						t.Literal("authorization_code"),
						t.Literal("refresh_token"),
					]),
					client_id: t.Optional(t.String()),
					code: t.Optional(t.String()),
					aud: t.Optional(t.Union([t.String(), t.Array(t.String())])),
					username: t.Optional(t.String()),
				}),
				cookie: t.Cookie({
					nonces: t.Optional(
						t.Array(t.Object({ value: t.String(), code: t.String() })),
					),
				}),
			},
		)
		.get(
			"/authorize",
			({
				query: { redirect_uri, response_type, nonce, state },
				cookie,
				redirect,
			}) => {
				const code = crypto.randomUUID();

				const url = new URL(redirect_uri);

				if (nonce !== undefined) {
					cookie.nonces.value = (cookie.nonces.value ?? []).concat({
						value: nonce,
						code,
					});
				}
				url.searchParams.set("code", code);

				if (state) {
					url.searchParams.set("state", state);
				}

				return redirect(url.href);
			},
			{
				query: t.Object({
					response_type: t.Literal("code", {
						examples: ["code"],
					}),
					client_id: t.String({
						examples: ["client_id"],
					}),
					redirect_uri: t.String({
						examples: ["https://example.com/callback"],
					}),
					scope: t.Optional(
						t.String({
							examples: ["openid"],
						}),
					),
					state: t.Optional(
						t.String({
							examples: ["state"],
						}),
					),
					nonce: t.Optional(
						t.String({
							examples: ["nonce"],
						}),
					),
				}),
				cookie: t.Cookie({
					nonces: t.Optional(
						t.Array(t.Object({ value: t.String(), code: t.String() })),
					),
				}),
			},
		)
		.get(
			"/userinfo",
			() => ({
				sub: "johndoe",
				name: "John Doe",
			}),
			{
				headers: t.Object({
					authorization: t.String(),
				}),
			},
		)
		.post(
			"/revoke",
			() => {
				return {};
			},
			{
				body: t.Object({
					token: t.String(),
				}),
			},
		)
		.get(
			"/endsession",
			({ query: { post_logout_redirect_uri }, redirect }) => {
				return redirect(post_logout_redirect_uri);
			},
			{
				query: t.Object({
					post_logout_redirect_uri: t.String(),
				}),
			},
		)
		.post(
			"/introspect",
			() => {
				return {
					active: true,
				};
			},
			{
				body: t.Object({
					token: t.String(),
				}),
			},
		);
}
