import { describe, expect, it } from 'vitest';
import { mobileconfig } from './mobileconfig.ts';

const setup = { device: 'Lena’s phone', user: 'lena@home.example', password: 'a&b<c>"d', server: 'mail.home.example' };

describe('a device profile', () => {
	it('sets up calendars, contacts and mail with the one password', () => {
		const xml = mobileconfig(setup, () => 'u');
		for (const type of ['com.apple.caldav.account', 'com.apple.carddav.account', 'com.apple.mail.managed']) {
			expect(xml).toContain(`<string>${type}</string>`);
		}
		// Four places take the password: CalDAV, CardDAV, IMAP and SMTP.
		expect(xml.split('<string>a&amp;b&lt;c&gt;&quot;d</string>').length - 1).toBe(4);
	});

	it('is well-formed XML whatever the name and password hold', () => {
		const xml = mobileconfig({ ...setup, device: 'R&D <laptop>' }, () => 'u');
		// The unit tests run without a DOM: what is left between the tags is text, where
		// an `&` must open an entity and no `<` or `>` may stand.
		const text = xml.replace(/<[^<>]*>/g, '');
		expect(text).not.toMatch(/[<>]|&(?!amp;|lt;|gt;|quot;)/);
		expect(xml).toContain('<string>R&amp;D &lt;laptop&gt; — lena@home.example</string>');
	});

	it('gives every payload a UUID of its own, as iOS requires', () => {
		let n = 0;
		const xml = mobileconfig(setup, () => `uuid-${n++}`);
		expect(n).toBe(4);
		expect(new Set(xml.match(/uuid-\d/g)).size).toBe(4);
	});
});
