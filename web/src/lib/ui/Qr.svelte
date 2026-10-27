<script lang="ts">
	import { encode } from 'uqr';

	/**
	 * A QR code, painted: an SVG of whole modules with `crispEdges`, so no smoothing
	 * blends two squares into something a scanner cannot read. The 4-module quiet zone
	 * is part of the code — without it, it "only works on some phones".
	 */
	let { value, label }: { value: string; label: string } = $props();

	// Dark modules on a light ground, whatever the theme: an inverted code is one some
	// scanners refuse. The theme's lighter role is the ground.
	const dark = document.documentElement.style.colorScheme === 'dark';
	const qr = $derived(encode(value, { border: 4 }));
	const path = $derived(
		qr.data
			.flatMap((row, y) => row.map((on, x) => (on ? `M${x} ${y}h1v1h-1z` : '')))
			.join('')
	);
</script>

<svg
	role="img"
	aria-label={label}
	viewBox="0 0 {qr.size} {qr.size}"
	shape-rendering="crispEdges"
	class={['size-48 rounded', dark ? 'bg-text' : 'bg-background']}
>
	<path d={path} class={dark ? 'fill-background' : 'fill-text'} />
</svg>
