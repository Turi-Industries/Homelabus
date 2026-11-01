import type { Schemas } from './api/client';

/**
 * An Apple configuration profile setting a device up with its password: calendars
 * (CalDAV), contacts (CardDAV) and mail (IMAP, SMTP) on Stalwart's public name.
 *
 * Built here, in the browser, from the answer shown once: the controller never writes
 * the password into a file of its own, and a profile served from a URL would be a
 * second place to fetch it from.
 *
 * Ports are Stalwart's published ones — 993 and 465, TLS from the first byte — and
 * 443 for DAV, which iOS finds through `/.well-known/caldav` behind the ingress.
 */
export function mobileconfig(
	setup: Schemas['DeviceSetup'],
	uuid: () => string = () => crypto.randomUUID()
): string {
	const id = `homelabus.device.${setup.server}.${setup.user}`;
	const description = `${setup.device} — ${setup.user}`;
	const payload = (type: string, suffix: string, fields: Record<string, string | number | boolean>) => ({
		PayloadType: type,
		PayloadVersion: 1,
		PayloadIdentifier: `${id}.${suffix}`,
		PayloadUUID: uuid(),
		PayloadDisplayName: description,
		...fields
	});
	const profile = {
		PayloadType: 'Configuration',
		PayloadVersion: 1,
		PayloadIdentifier: id,
		PayloadUUID: uuid(),
		PayloadDisplayName: description,
		PayloadRemovalDisallowed: false,
		PayloadContent: [
			payload('com.apple.caldav.account', 'caldav', {
				CalDAVAccountDescription: description,
				CalDAVHostName: setup.server,
				CalDAVPort: 443,
				CalDAVUseSSL: true,
				CalDAVUsername: setup.user,
				CalDAVPassword: setup.password
			}),
			payload('com.apple.carddav.account', 'carddav', {
				CardDAVAccountDescription: description,
				CardDAVHostName: setup.server,
				CardDAVPort: 443,
				CardDAVUseSSL: true,
				CardDAVUsername: setup.user,
				CardDAVPassword: setup.password
			}),
			payload('com.apple.mail.managed', 'mail', {
				EmailAccountDescription: description,
				EmailAccountType: 'EmailTypeIMAP',
				EmailAddress: setup.user,
				IncomingMailServerHostName: setup.server,
				IncomingMailServerPortNumber: 993,
				IncomingMailServerUseSSL: true,
				IncomingMailServerAuthentication: 'EmailAuthPassword',
				IncomingMailServerUsername: setup.user,
				IncomingPassword: setup.password,
				OutgoingMailServerHostName: setup.server,
				OutgoingMailServerPortNumber: 465,
				OutgoingMailServerUseSSL: true,
				OutgoingMailServerAuthentication: 'EmailAuthPassword',
				OutgoingMailServerUsername: setup.user,
				OutgoingPassword: setup.password
			})
		]
	};
	return [
		'<?xml version="1.0" encoding="UTF-8"?>',
		'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
		'<plist version="1.0">',
		plist(profile),
		'</plist>',
		''
	].join('\n');
}

type Value = string | number | boolean | Value[] | { [key: string]: Value };

function plist(v: Value): string {
	if (typeof v === 'string') return `<string>${escaped(v)}</string>`;
	if (typeof v === 'number') return `<integer>${Math.trunc(v)}</integer>`;
	if (typeof v === 'boolean') return v ? '<true/>' : '<false/>';
	if (Array.isArray(v)) return `<array>${v.map(plist).join('')}</array>`;
	return `<dict>${Object.entries(v)
		.map(([k, x]) => `<key>${escaped(k)}</key>${plist(x)}`)
		.join('')}</dict>`;
}

// A device's name is the person's own text, and a password may hold `&` or `<`: either
// unescaped makes the whole profile one iOS refuses to install, saying only "invalid".
function escaped(s: string): string {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
