import { createSubscriber } from 'svelte/reactivity';

/**
 * The time, ticking every few seconds while something reads it — so "updated 40 s ago"
 * keeps counting while the controller stays silent, which is the whole point of it.
 */
class Clock {
	#subscribe = createSubscriber((update) => {
		const timer = setInterval(update, 5_000);
		return () => clearInterval(timer);
	});

	get now(): number {
		this.#subscribe();
		return Date.now();
	}
}

export const clock = new Clock();
