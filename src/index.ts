import { cors } from "@elysiajs/cors";
import { Elysia, t } from "elysia";
import { parseBasicAuth } from "./basic-auth";
import { privateJwk, publicJwk } from "./jwks";
import { type JwtPayload, sign } from "./jwt";

const issuer = "http://localhost:4220";

const app = new Elysia({
	serve: {
		port: 4220,
	},
})
	.use(cors())
	.decorate("publicJwk", publicJwk)
	.decorate("privateJwk", privateJwk)
	.derive(({ headers }) => ({
		basicAuth: headers.authorization && parseBasicAuth(headers.authorization),
	}))
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
			"password",
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
		async ({ body, error, basicAuth, cookie: { nonces } }) => {
			const payload: JwtPayload = {
				scope: body.scope,
				iss: issuer,
			};
			switch (body.grant_type) {
				case "client_credentials": {
					payload.aud = body.aud;
					break;
				}
				case "password": {
					payload.sub = body.username;
					break;
				}

				case "authorization_code": {
					payload.sub = "johndoe";
					break;
				}
				case "refresh_token": {
					payload.sub = "johndoe";
					break;
				}
				default: {
					return error(400, {
						error: "unsupported_grant_type",
						error_description: "The provided grant type is not supported",
					});
				}
			}

			const token = await sign(payload, privateJwk, "RS256");

			const responseBody: Record<string, unknown> = {
				access_token: token,
				token_type: "Bearer",
				expires_in: 3600,
				scope: payload.scope,
			};

			if (body.grant_type !== "client_credentials") {
				const clientId = basicAuth ? basicAuth.name : body.client_id;

				const idTokenPayload: JwtPayload = {
					iss: issuer,
					sub: "johndoe",
					aud: clientId,
				};

				if (body.code !== undefined) {
					const nonce = nonces.value?.find((nonce) => nonce.code === body.code);
					if (nonce) {
						idTokenPayload.nonce = nonce.value;
						nonces.value = (nonces.value ?? []).filter(
							(nonce) => nonce.code !== body.code,
						);
						nonces.sameSite = "none";
					}
				}

				responseBody.id_token = await sign(idTokenPayload, privateJwk, "RS256");
				responseBody.refresh_token = crypto.randomUUID();
			}

			return responseBody;
		},
		{
			body: t.Object({
				scope: t.Optional(t.String()),
				grant_type: t.String(),
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

			if (response_type === "code") {
				if (nonce !== undefined) {
					cookie.nonces.value = (cookie.nonces.value ?? []).concat({
						value: nonce,
						code,
					});
				}
				url.searchParams.set("code", code);
			} else {
				url.searchParams.set("error", "unsupported_response_type");
				url.searchParams.set(
					"error_description",
					"The authorization server does not support obtaining an access token using this response_type.",
				);
			}

			if (state) {
				url.searchParams.set("state", state);
			}

			return redirect(url.href);
		},
		{
			query: t.Object({
				response_type: t.String(),
				client_id: t.String(),
				redirect_uri: t.String(),
				scope: t.Optional(t.String()),
				state: t.Optional(t.String()),
				nonce: t.Optional(t.String()),
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
	)
	.listen({});

console.log(
	`🦊 Elysia is running at http://${app.server?.hostname}:${app.server?.port}`,
);
