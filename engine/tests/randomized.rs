//! The randomization subsystem: reproducibility of seeds and scenarios, and a fixed-seed fuzz run
//! against the loopback mock server as part of the normal suite.

use cfprobe::random::fuzz::{self, FuzzOptions};
use cfprobe::random::{Schedule, scenario, stream};

fn opts(seed: Option<u64>, count: u64) -> FuzzOptions {
    FuzzOptions { seed, count, only: None, concurrency: 8 }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_seed_fuzz_run_passes_and_records_its_seed() {
    let r = fuzz::run(&opts(Some(1), 150)).await.unwrap();
    let failed: Vec<_> = r.results.iter().filter(|x| !x.pass).map(|x| (x.index, x.checks.iter().filter(|c| !c.ok).map(|c| c.detail.clone()).collect::<Vec<_>>())).collect();
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!((r.seed, r.seed_given, r.count), (1, true, 150));
    assert!(r.results.iter().all(|x| x.reproduce == format!("cfprobe fuzz --seed 1 --only {}", x.index)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_seed_same_outcomes_and_a_missing_seed_is_generated_and_recorded() {
    let a = fuzz::run(&opts(Some(99), 60)).await.unwrap();
    let b = fuzz::run(&opts(Some(99), 60)).await.unwrap();
    let key = |r: &fuzz::FuzzReport| r.results.iter().map(|x| (x.index, serde_json::to_string(&x.scenario).unwrap(), x.verdict)).collect::<Vec<_>>();
    assert_eq!(key(&a), key(&b));
    let fresh = fuzz::run(&opts(None, 5)).await.unwrap();
    assert!(!fresh.seed_given);
    // The recorded seed rebuilds the same scenarios.
    let again = fuzz::run(&opts(Some(fresh.seed), 5)).await.unwrap();
    assert_eq!(key(&fresh).iter().map(|k| k.1.clone()).collect::<Vec<_>>(), key(&again).iter().map(|k| k.1.clone()).collect::<Vec<_>>());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_scenario_reruns_alone_identically() {
    let all = fuzz::run(&opts(Some(7), 40)).await.unwrap();
    let pick = &all.results[17];
    let one = fuzz::run(&FuzzOptions { seed: Some(7), count: 0, only: Some(17), concurrency: 1 }).await.unwrap();
    assert_eq!(serde_json::to_string(&one.results[0].scenario).unwrap(), serde_json::to_string(&pick.scenario).unwrap());
    assert_eq!(one.results[0].verdict, pick.verdict);
}

#[test]
fn different_seeds_give_different_sequences() {
    let make = |seed| (0..20).map(|i| serde_json::to_string(&scenario::generate(&mut stream(seed, i), i)).unwrap()).collect::<Vec<_>>();
    assert_eq!(make(5), make(5));
    assert_ne!(make(5), make(6));
    assert_ne!(Schedule::new(5, 30, true, 0, 10).order, Schedule::new(6, 30, true, 0, 10).order);
}
