use garlemlia_structs::GarlicMessage;
use garlic_cast::GarlicCast;

#[tokio::test]
async fn test_erasure_code_striping() {
    let msg = GarlicMessage::SearchOverlay {
        search_term: "Will proxy?".to_string(),
    };

    let cloves = GarlicCast::generate_cloves(msg.clone(), 30, rand::random::<u128>()).await;

    let decrypted = GarlicCast::get_message_from_cloves(cloves[0].clone(), cloves[2].clone()).await;

    println!("{:?}, {:?}", msg, decrypted);

    assert_eq!(msg, decrypted, "Messages not the same");
}