import Activity from '@lucide/svelte/icons/activity';
import { m } from '#lib/paraglide/messages.js';
import type { Module } from '../module';

export const module: Module = {
	id: 'activity',
	area: 'console',
	order: 50,
	label: m.nav_activity,
	icon: Activity,
	pages: [
		{ path: '/alerts', label: m.page_activity_alerts, reads: ['/api/alerts'] },
		{ path: '/timeline', label: m.page_activity_timeline, reads: ['/api/timeline'] },
		{ path: '/audit', label: m.page_activity_audit, reads: ['/api/audit'] },
		{ path: '/tasks', label: m.page_activity_tasks, reads: ['/api/tasks'] }
	],
	causes: ['alert'],
};
