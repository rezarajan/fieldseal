//! The event wrappers around the landing (INT-011).

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use fieldseal_adapters_memory::intake::MemoryDataPlatform;
use fieldseal_intake::contract::sample_observation;
use fieldseal_intake::ports::{DataPlatform, LandingBatch};
use fieldseal_intake_app::wiring::EventPlatform;

// covers: INT-091
#[test]
fn int_011_the_event_platform_satisfies_the_data_platform_contract() {
    fieldseal_intake::contract::data_platform_contract(|| EventPlatform::new(Box::new(MemoryDataPlatform::new()), Arc::new(AtomicBool::new(false))));
}

// covers: INT-091
#[test]
fn int_011_the_event_platform_prints_one_event_per_landing_and_none_for_instruments() {
    let lines = Rc::new(RefCell::new(Vec::<String>::new()));
    let mut p = EventPlatform::new(Box::new(MemoryDataPlatform::new()), Arc::new(AtomicBool::new(false)));
    let sink = lines.clone();
    p.sink = Box::new(move |l| sink.borrow_mut().push(l.to_owned()));
    p.land(&LandingBatch { observations: vec![sample_observation(1, 1)], ..LandingBatch::default() }).expect("lands");
    let _ = p.instruments().expect("instruments");
    let _ = p.observations(&sample_observation(1, 1).instrument).expect("reads");
    assert_eq!(lines.borrow().len(), 1, "{:?}", lines.borrow());
    assert!(lines.borrow()[0].contains("\"event\":\"landed\"") && lines.borrow()[0].contains("\"observations\":1"));
    // While replay runs, nothing is printed.
    p.replaying.store(true, std::sync::atomic::Ordering::SeqCst);
    p.land(&LandingBatch { observations: vec![sample_observation(1, 2)], ..LandingBatch::default() }).expect("lands");
    assert_eq!(lines.borrow().len(), 1);
}
