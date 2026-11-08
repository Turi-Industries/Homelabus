import Server from '@lucide/svelte/icons/server';
import { m } from '#lib/paraglide/messages.js';
import type { Module } from '../module';

export const module: Module = {
	id: 'infra',
	area: 'console',
	order: 20,
	label: m.nav_infra,
	icon: Server,
	pages: [
		{ path: '/nodes', label: m.page_infra_nodes, reads: ['/api/nodes'] },
		{ path: '/resilience', label: m.page_infra_resilience, reads: ['/api/topology'] },
		{ path: '/drift', label: m.page_infra_drift, reads: ['/api/drift'] },
		{ path: '/health', label: m.page_infra_health, reads: ['/api/health'] },
		{ path: '/storage', label: m.page_infra_storage, reads: ['/api/nodes'] }
	],
	details: ['/nodes/[address]'],
	causes: ['node_unreachable', 'node_disk_full', 'node_disk_filling', 'node_swapping', 'node_load', 'node_reboot_pending', 'host_flaw_exploitable', 'host_flaws_unknown', 'topology', 'drift', 'deadman_absent', 'deadman_silent', 'admin_tokens', 'admin_unknown', 'audit_broken', 'audit_unreadable'],
	search: {
		path: '/api/nodes',
		entries: (nodes) =>
			(nodes as { address: string; hostname: string | null }[]).map((n) => ({
				label: n.hostname ?? n.address,
				hint: n.address,
				href: `/nodes/${encodeURIComponent(n.address)}`
			}))
	}
};
