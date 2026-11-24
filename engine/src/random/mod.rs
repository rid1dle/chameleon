//! Seeded randomization for testing: seeds, schedules with bounded jitter, randomized scenarios
//! served by a local fault-injecting mock server, and the `fuzz` driver that checks each one.
//!
//! Reproducibility: every run has a seed (given, or drawn from the OS and recorded). Scenario `i` is
//! generated from ChaCha8 stream `i` of that seed, so it is the same whatever else runs, and
//! `cfprobe fuzz --seed S --only i` rebuilds it alone. ChaCha8 output is fixed by its algorithm, so
//! sequences do not change with the `rand` version (StdRng does not promise that).
//!
//! Randomization varies **test conditions** only. It never varies the client's identity or
//! fingerprint, and nothing here is pointed at third-party sites: the mock server listens on
//! loopback, and real-world runs only get bounded delays and a shuffled order.

pub mod fuzz;
pub mod mock;
pub mod scenario;

use std::time::Duration;

use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::Serialize;

/// Stream ids reserved for things that are not scenarios.
const SCHEDULE_STREAM: u64 = u64::MAX;
const JITTER_STREAM: u64 = u64::MAX - 1;

/// The seed to use: the given one, or a fresh one from the OS. Always recorded by callers.
pub fn seed_or_new(seed: Option<u64>) -> u64 {
    seed.unwrap_or_else(|| rand::rng().random())
}

/// The generator for one stream of a seed.
pub fn stream(seed: u64, stream: u64) -> ChaCha8Rng {
    let mut r = ChaCha8Rng::seed_from_u64(seed);
    r.set_stream(stream);
    r
}

/// RNG for retry jitter in a session.
pub fn jitter_rng(seed: u64) -> ChaCha8Rng {
    stream(seed, JITTER_STREAM)
}

/// Order and pauses for a run of `n` items.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Schedule {
    pub seed: u64,
    /// Item indexes in run order.
    pub order: Vec<usize>,
    /// Pause before each item in run order (the first is 0).
    pub delays_ms: Vec<u64>,
}

impl Schedule {
    /// `shuffle`: random order. Delays are uniform in `min_ms..=max_ms` (bounded jitter).
    pub fn new(seed: u64, n: usize, shuffle: bool, min_ms: u64, max_ms: u64) -> Self {
        let (min_ms, max_ms) = (min_ms.min(max_ms), min_ms.max(max_ms));
        let mut r = stream(seed, SCHEDULE_STREAM);
        let mut order: Vec<usize> = (0..n).collect();
        if shuffle {
            order.shuffle(&mut r);
        }
        let delays_ms = (0..n).map(|i| if i == 0 { 0 } else { r.random_range(min_ms..=max_ms) }).collect();
        Self { seed, order, delays_ms }
    }

    pub fn delay(&self, position: usize) -> Duration {
        Duration::from_millis(self.delays_ms[position])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_schedule_other_seed_other_schedule() {
        let a = Schedule::new(9, 50, true, 100, 900);
        assert_eq!(a, Schedule::new(9, 50, true, 100, 900));
        assert_ne!(a.order, Schedule::new(10, 50, true, 100, 900).order);
        let mut sorted = a.order.clone();
        sorted.sort();
        assert_eq!(sorted, (0..50).collect::<Vec<_>>(), "a permutation");
        assert_eq!(a.delays_ms[0], 0);
        assert!(a.delays_ms[1..].iter().all(|d| (100..=900).contains(d)));
    }

    #[test]
    fn unshuffled_keeps_order_and_reversed_bounds_are_fixed() {
        let s = Schedule::new(1, 5, false, 50, 10);
        assert_eq!(s.order, [0, 1, 2, 3, 4]);
        assert!(s.delays_ms[1..].iter().all(|d| (10..=50).contains(d)));
    }

    #[test]
    fn streams_are_independent_of_each_other() {
        let a: Vec<u32> = (0..4).map(|_| stream(5, 3).random()).collect();
        let mut r = stream(5, 3);
        let b: Vec<u32> = (0..4).map(|_| r.random()).collect();
        assert_eq!(a[0], b[0]);
        let other: u32 = stream(5, 4).random();
        assert_ne!(b[0], other);
    }
}
