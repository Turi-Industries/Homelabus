/**
 * Copies `text`, or selects `shown` for the person to copy themselves.
 *
 * ⚠️ `navigator.clipboard` exists only in a secure context: on a controller reached over
 * plain HTTP by its LAN address it is `undefined`, and a copy button calling it threw
 * where nobody saw, leaving the button saying nothing. A browser may also refuse the
 * write. Either way the text is selected, and the caller says so.
 */
export async function copy(text: string, shown: Element | null): Promise<'copied' | 'selected'> {
	try {
		if (navigator.clipboard !== undefined) {
			await navigator.clipboard.writeText(text);
			return 'copied';
		}
	} catch {
		// Refused: selecting it is all that is left.
	}
	if (shown !== null) {
		const range = document.createRange();
		range.selectNodeContents(shown);
		const selection = getSelection();
		selection?.removeAllRanges();
		selection?.addRange(range);
	}
	return 'selected';
}
