import { readFileSync } from 'node:fs';
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vitest/config';

// `bun run dev` serves the interface and hands the server's paths to a controller
// running beside it. The prefixes come from the document, so a route added under a new
// one reaches the controller without anyone editing this file.
const controller = process.env.HLB_CONTROLLER ?? 'http://127.0.0.1:8420';
const document = JSON.parse(readFileSync('openapi.json', 'utf8')) as { paths: object };
const prefixes = new Set(Object.keys(document.paths).map((p) => '/' + p.split('/')[1]));

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			compilerOptions: { runes: true },
			// The controller answers `index.html` for any path that is neither a file nor
			// one of its own routes, so a reload on `/apps/gitea` lands here.
			adapter: adapter({ fallback: 'index.html' })
		}),
		paraglideVitePlugin({
			project: './project.inlang',
			outdir: './src/lib/paraglide',
			// The language a person picked, else the browser's, else English. No URL
			// strategy: the controller routes no `/fr/` prefix, and a cookie would be sent
			// to the API on every request for nothing.
			strategy: ['localStorage', 'preferredLanguage', 'baseLocale']
		})
	],
	server: {
		proxy: Object.fromEntries([...prefixes].map((p) => [p, controller]))
	},
	test: {
		environment: 'node',
		include: ['src/**/*.test.ts'],
		expect: { requireAssertions: true }
	}
});
