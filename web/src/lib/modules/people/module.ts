import Users from '@lucide/svelte/icons/users';
import { m } from '#lib/paraglide/messages.js';
import type { Module } from '../module';

export const module: Module = {
	id: 'people',
	area: 'console',
	order: 60,
	label: m.nav_people,
	icon: Users,
	details: ['/accounts/[name]'],
	pages: [
		{ path: '/accounts', label: m.page_people_accounts, reads: ['/api/accounts'] },
		{ path: '/invitations', label: m.page_people_invitations, reads: ['/api/invitations'] },
		{ path: '/roles', label: m.page_people_roles, reads: ['/api/access'] },
		{
			path: '/announcements',
			label: m.page_people_announcements,
			reads: ['/api/announcements'],
			writes: [['POST', '/api/announcements']]
		},
		{ path: '/recovery', label: m.page_people_recovery, reads: ['/api/recovery'] }
	],
	causes: ['account_without_mailbox', 'account_without_identity', 'account_empty', 'alias_still_receiving', 'safeguard'],
};
