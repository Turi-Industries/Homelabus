import { spawn, type ChildProcess } from 'node:child_process';
import { join } from 'node:path';

export const POPULATED = '127.0.0.1:8431';
export const EMPTY = '127.0.0.1:8432';
/** The demonstration at scale: what a list has to survive. */
export const LARGE = '127.0.0.1:8435';
/** The same demonstration again, for the tests that open the home and its modals: on
 * `large` they spent the read budget its walk of every page needs. */
export const SCREENS = '127.0.0.1:8436';

/** The controller's arguments, serving the built interface beside its API. */
function args(address: string, extra: string[], open = true): string[] {
	// ⚠️ A real state opens the vault, creating its key where it is told — by default in
	// the working directory, which here is `web/`. Only `--demo` holds its key in memory.
	const key = extra.includes('--master-key') ? [] : ['--master-key', join(run(), `${address.replace(/\W/g, '-')}.key`)];
	return [
		'--listen', address,
		'--ui-dir', 'build',
		'--catalog', '../catalog',
		'--themes', '../themes',
		...(open ? ['--insecure-no-auth'] : []),
		...key,
		...extra
	];
}

/** The run's own directory, made by `playwright.config.ts`. */
export function run(): string {
	const dir = process.env.HLB_E2E_DIR;
	if (dir === undefined) throw new Error('HLB_E2E_DIR is set by playwright.config.ts');
	return dir;
}

// A socket that does not exist: the empty controller is not a demonstration, and on a
// machine running Docker it would otherwise connect and start reconciling against it.
const env = { ...process.env, DOCKER_HOST: 'unix:///nonexistent/hlb-e2e.sock', HLB_LOG: 'warn' } as Record<string, string>;

/**
 * A controller for Playwright's `webServer`. Through `cargo run`, so a run never tests
 * a binary older than the source — the one failure that would make every test here lie.
 */
export function controller(address: string, extra: string[]) {
	return {
		command: ['cargo', 'run', '-q', '-p', 'hlb-controller', '--', ...args(address, extra)].join(' '),
		env,
		// The first run compiles the controller.
		timeout: 600_000,
		reuseExistingServer: false,
		stdout: 'ignore' as const,
		stderr: 'pipe' as const
	};
}

/** A controller a test owns, to kill it. */
export interface Owned {
	address: string;
	process: ChildProcess;
	kill(): Promise<void>;
}

/**
 * Starts a controller only this test reads. The binary itself, not `cargo run`: killing
 * cargo would leave the controller it started serving. `webServer` has built it by now.
 */
export async function start(address: string, extra: string[], { open = true } = {}): Promise<Owned> {
	const child = spawn(join('..', 'target', 'debug', 'hlb-controller'), args(address, extra, open), {
		env,
		stdio: ['ignore', 'ignore', 'pipe']
	});
	let said = '';
	child.stderr?.on('data', (chunk: Buffer) => (said += chunk.toString()));
	// Killed by a signal, a process has no exit code: `signalCode` is what says it is gone.
	const gone = () => child.exitCode !== null || child.signalCode !== null;
	const deadline = Date.now() + 30_000;
	for (;;) {
		try {
			if ((await fetch(`http://${address}/api/themes`)).ok) break;
		} catch {
			// Not listening yet.
		}
		if (gone()) throw new Error(`the controller on ${address} exited with ${child.exitCode}:\n${said}`);
		if (Date.now() > deadline) throw new Error(`the controller on ${address} never answered`);
		await new Promise((r) => setTimeout(r, 100));
	}
	return {
		address,
		process: child,
		kill: () =>
			new Promise((resolve) => {
				if (gone()) return resolve();
				child.once('exit', () => resolve());
				child.kill('SIGKILL');
			})
	};
}
