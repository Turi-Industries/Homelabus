/**
 * The longest text a field read only by the page takes — a search, a filter, a value
 * pasted into a command. A field whose value reaches the controller takes its bound
 * from `#lib/api/limits.ts` instead, which the controller refuses past.
 */
export const TYPED = 200;
