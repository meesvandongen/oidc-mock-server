# Elysia with Bun runtime

## Getting Started
Install dependencies with pnpm (pinned through corepack in `package.json`; pnpm 12 needs corepack 0.36 or newer):
```bash
npm install -g corepack@latest && corepack enable
pnpm install
```

## Development
The server runs on [Bun](https://bun.sh). To start the development server run:
```bash
pnpm run dev
```

Open http://localhost:3000/ with your browser to see the result.

Lint and format with Vite+:
```bash
pnpm run lint
pnpm run fmt
```
