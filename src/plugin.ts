import { createMiddleware } from "@universal-middleware/express";
import type { Plugin } from "vite";
import { type CreateServerOptions, createServer } from "./server";

export function mockOidcPlugin(options: CreateServerOptions): Plugin {
	return {
		name: "vite-plugin-oidc-mock-server",
		async configureServer(server) {
			const s = await createServer(options);

			server.middlewares.use(createMiddleware(() => s.handle));
		},
	};
}
