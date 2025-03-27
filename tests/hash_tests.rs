use garlemlia::time_hash::time_based_hash::RotatingHash;

#[tokio::test]
async fn hash_test() {
    let mut test_hash = RotatingHash::new(1.0);
    test_hash.store();
    
    let locations = test_hash.get_next(9, 0.25);
    
    assert!(locations.is_some(), "No locations found");
    let locations = locations.unwrap();
    println!("{:#?}", locations);
}