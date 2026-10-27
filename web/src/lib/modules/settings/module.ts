import Settings from '@lucide/svelte/icons/settings';
import { m } from '#lib/paraglide/messages.js';
import type { Module } from '../module';

export const module: Module = {
	id: 'settings',
	area: 'console',
	order: 70,
	label: m.nav_settings,
	icon: Settings,
	pages: [
		{
			path: '/settings',
			label: m.page_settings_appearance,
			reads: ['/api/appearance', '/api/themes'],
			writes: [['PUT', '/api/appearance']]
		},
		{ path: '/settings/exports', label: m.page_settings_exports, reads: ['/api/runbook'] }
	]
};
