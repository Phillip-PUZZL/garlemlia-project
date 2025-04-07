use garlemlia::time_hash::time_based_hash::RotatingHash;

#[tokio::test]
async fn hash_test() {
    let mut test_hash = RotatingHash::new(1.0);
    test_hash.store();
    
    let locations = test_hash.get_next(24, 1.0);
    
    assert!(locations.is_some(), "No locations found");
    let locations = locations.unwrap();
    println!("SEED: {}\nSTORED ON: {}\nLOCATIONS:", test_hash.get_seed(), test_hash.get_stored_on().unwrap());

    for location in locations {
        println!("TIME: {}, ID: {}", location.time, location.id);
    }
}