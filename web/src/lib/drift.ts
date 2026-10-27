import type { Schemas } from '#lib/api/client.ts';

/**
 * What tells one gap from another on the drift page.
 *
 * 🔴 Not the target alone: one application can be off on its replicas AND its image at
 * once, and a keyed `{#each}` meeting a key twice throws — in production too — and takes
 * the page with it. Each kind of gap has its own sentence, so the two together are unique.
 */
export function gap(d: Schemas['DriftSummary']): string {
	return `${d.target}\n${d.description}`;
}
