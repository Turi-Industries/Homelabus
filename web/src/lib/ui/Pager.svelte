<script lang="ts">
	import { number } from '#lib/format.ts';
	import { m } from '#lib/paraglide/messages.js';
	import { button } from './styles.ts';

	/** Previous, where we are, next — drawn only when there is more than one page. */
	let { page, pages, onpage }: { page: number; pages: number; onpage: (page: number) => void } = $props();
</script>

{#if pages > 1}
	<nav aria-label={m.table_pages()} class="flex flex-wrap items-center gap-3 text-sm">
		<button type="button" class={button} disabled={page === 1} onclick={() => onpage(page - 1)}>{m.table_previous()}</button>
		<span class="text-muted-text tabular-nums">{m.table_page({ page: number(page), pages: number(pages) })}</span>
		<button type="button" class={button} disabled={page === pages} onclick={() => onpage(page + 1)}>{m.table_next()}</button>
	</nav>
{/if}
