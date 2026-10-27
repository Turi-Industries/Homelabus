// The few shapes every page repeats, named once so a button looks like a button
// everywhere. Colours are palette roles only.
export const button =
	'inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm hover:bg-raised-surface disabled:opacity-50';
export const primary =
	'inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-on-accent disabled:opacity-50';
export const danger =
	'inline-flex items-center gap-1.5 rounded-md border border-critical px-3 py-1.5 text-sm text-critical hover:bg-raised-surface disabled:opacity-50';
// Red once the person has typed something the field refuses, not before: an empty
// form opened in red reads as a mistake nobody made.
export const input =
	'min-w-0 rounded-md border border-border bg-background px-3 py-1.5 text-sm user-invalid:border-critical';
export const code = 'rounded-md bg-raised-surface px-3 py-2 font-mono text-xs wrap-anywhere';
export const muted = 'text-sm text-muted-text';
