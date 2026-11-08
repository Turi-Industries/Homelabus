import LayoutGrid from '@lucide/svelte/icons/layout-grid';
import { m } from '#lib/paraglide/messages.js';
import type { Module } from '../module';

export const module: Module = {
	id: 'apps',
	area: 'console',
	order: 10,
	label: m.nav_apps,
	icon: LayoutGrid,
	pages: [
		{ path: '/apps', label: m.page_apps_installed, reads: ['/api/apps'] },
		{ path: '/catalog', label: m.page_apps_catalog, reads: ['/api/catalog'] },
		{ path: '/todo', label: m.page_apps_todo, reads: ['/api/todo'] },
		{ path: '/updates', label: m.page_apps_updates, reads: ['/api/updates'] },
		{ path: '/plans', label: m.page_apps_plans, reads: ['/api/plans'] }
	],
	details: ['/apps/[name]/[[tab]]'],
	causes: ['app_failed', 'app_partial', 'guide_blocking', 'guide_pending', 'catalog_changed', 'version_revoked', 'job_failed', 'mail_waiting', 'update_needs_approval', 'update_needs_hands', 'update_refused'],
	search: {
		path: '/api/apps',
		entries: (apps) =>
			(apps as { name: string; domain: string | null }[]).map((a) => ({
				label: a.name,
				hint: a.domain ?? m.nav_apps(),
				href: `/apps/${a.name}`
			}))
	}
};
