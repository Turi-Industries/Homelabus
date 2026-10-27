import type { Component } from 'svelte';
import type { Schemas } from '#lib/api/client.ts';
import { m } from '#lib/paraglide/messages.js';
import type { Readable } from '#lib/resource.svelte.ts';
import ActivityWidget from './modules/activity/ActivityWidget.svelte';
import TasksWidget from './modules/activity/TasksWidget.svelte';
import AppsWidget from './modules/apps/AppsWidget.svelte';
import BackupsWidget from './modules/data/BackupsWidget.svelte';
import CpuWidget from './modules/infra/CpuWidget.svelte';
import DisksWidget from './modules/infra/DisksWidget.svelte';
import MemoryWidget from './modules/infra/MemoryWidget.svelte';
import NetworkWidget from './modules/infra/NetworkWidget.svelte';
import NodesWidget from './modules/infra/NodesWidget.svelte';
import ResilienceWidget from './modules/infra/ResilienceWidget.svelte';
import UptimeWidget from './modules/me/UptimeWidget.svelte';
import AccountsWidget from './modules/people/AccountsWidget.svelte';
import AnnouncementsWidget from './modules/people/AnnouncementsWidget.svelte';
import ExposureWidget from './modules/security/ExposureWidget.svelte';
import ProblemsWidget from './home/ProblemsWidget.svelte';
import SummaryWidget from './home/SummaryWidget.svelte';

export type HomeWidget = Schemas['HomeWidget'];
export type HomeTile = Schemas['HomeTile'];

/**
 * Every card the home can pin. 🔴 A `Record` over the server's enum: a card named in
 * `hlb_api::HomeWidget` without a component here — or the reverse — does not compile.
 */
export const widgets: Record<HomeWidget, { label: () => string; reads: Readable; component: Component }> = {
	problems: { label: m.widget_problems, reads: '/api/issues', component: ProblemsWidget },
	summary: { label: m.widget_summary, reads: '/api/nodes', component: SummaryWidget },
	apps: { label: m.widget_apps, reads: '/api/apps', component: AppsWidget },
	cpu: { label: m.widget_cpu, reads: '/api/nodes', component: CpuWidget },
	memory: { label: m.widget_memory, reads: '/api/nodes', component: MemoryWidget },
	disks: { label: m.widget_disks, reads: '/api/nodes', component: DisksWidget },
	network: { label: m.widget_network, reads: '/api/history', component: NetworkWidget },
	nodes: { label: m.widget_nodes, reads: '/api/nodes', component: NodesWidget },
	uptime: { label: m.widget_uptime, reads: '/api/status', component: UptimeWidget },
	backups: { label: m.widget_backups, reads: '/api/backups', component: BackupsWidget },
	exposure: { label: m.widget_exposure, reads: '/api/exposure', component: ExposureWidget },
	tasks: { label: m.widget_tasks, reads: '/api/tasks', component: TasksWidget },
	activity: { label: m.widget_activity, reads: '/api/timeline', component: ActivityWidget },
	announcements: { label: m.widget_announcements, reads: '/api/announcements', component: AnnouncementsWidget },
	resilience: { label: m.widget_resilience, reads: '/api/topology', component: ResilienceWidget },
	accounts: { label: m.widget_accounts, reads: '/api/accounts', component: AccountsWidget }
};
