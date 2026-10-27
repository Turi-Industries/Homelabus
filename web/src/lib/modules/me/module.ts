import User from '@lucide/svelte/icons/user';
import { m } from '#lib/paraglide/messages.js';
import type { Module } from '../module';

export const module: Module = {
	id: 'me',
	area: 'me',
	order: 0,
	label: m.nav_me,
	icon: User,
	pages: [
		{ path: '/me', label: m.page_me_home, reads: ['/api/portal'] },
		{ path: '/me/mailbox', label: m.page_me_mailbox, reads: ['/api/me', '/api/me/aliases'] },
		{ path: '/me/status', label: m.page_me_status, reads: ['/api/status'] },
		{ path: '/me/preferences', label: m.page_me_preferences, reads: ['/api/preferences', '/api/themes'] },
		{ path: '/me/account', label: m.page_me_account, reads: ['/api/me', '/api/me/identity', '/api/me/sessions'] }
	]
};
