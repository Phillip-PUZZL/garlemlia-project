use garlemlia::file_utils::garlemlia_files::{FileInfo, FileUpload};
use garlemlia::garlemlia_structs::garlemlia_structs::SOCKET_FILE_DATA_MAX;
use std::path::Path;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST_FILE_NAME: &str = "JWST.tif";
const TEST_OUTPUT_FOLDER: &str = "./test_file_methods";
const CHUNKS_FOLDER: &str = "temp_chunks";
const DOWNLOADS_FOLDER: &str = "downloads";
const FILE_UPLOAD_FILE: &str = "file_upload.json";

#[tokio::test]
async fn file_encryption_and_split_test() {
    let file_name = TEST_FILE_NAME;
    let test_file = format!("./{}", file_name);
    let test_output_folder = TEST_OUTPUT_FOLDER;

    let test_dir_path = Path::new(test_output_folder);
    if test_dir_path.exists() && test_dir_path.is_dir() {
        fs::remove_dir_all(test_dir_path).await.unwrap();
        println!("Old Test Output Folder Removed!");
    }

    fs::create_dir(test_dir_path).await.unwrap();

    let test_chunks_output_folder = format!("{}/{}", test_output_folder, CHUNKS_FOLDER);

    fs::create_dir(Path::new(&test_chunks_output_folder)).await.unwrap();

    let info = FileUpload::encrypt_file(Box::from(Path::new(&test_file)), Box::from(Path::new(&test_chunks_output_folder))).await;

    assert!(info.is_ok(), "Did not successfully encrypt!");

    let file_information = info.unwrap();

    let encrypted_file_name = format!("{}/{}.enc", test_chunks_output_folder, file_name);

    assert!(File::open(encrypted_file_name.clone()).await.is_ok(), "Did not save encrypted file!");

    let chunks_info = FileUpload::split_into_chunks(Box::from(Path::new(&encrypted_file_name)), 150).await;

    assert!(chunks_info.is_ok(), "Did not split file into chunks!");
    assert!(File::open(encrypted_file_name.clone()).await.is_err(), "Did not delete encrypted file!");

    let chunks = chunks_info.unwrap();

    let file_upload = FileUpload::new(file_information, chunks, 1.0);

    let json_string = serde_json::to_string_pretty(&file_upload).unwrap();
    let mut file = File::create(format!("{}/{}", test_output_folder, FILE_UPLOAD_FILE)).await.unwrap();
    file.write_all(json_string.as_bytes()).await.unwrap();
}

#[tokio::test]
async fn split_chunk_into_pieces() {
    let test_output_folder = TEST_OUTPUT_FOLDER;

    let test_chunks_output_folder = format!("{}/{}", test_output_folder, CHUNKS_FOLDER);
    let chunk_id = "00e4364ad9c049b48de35056b5e07d3f636b3ebe6ce69ba13b19c25dee7055e4";
    
    let mut chunk_file = File::open(format!("{}/{}", test_chunks_output_folder, chunk_id)).await.unwrap();

    let mut chunk_data = Vec::new();
    chunk_file.read_to_end(&mut chunk_data).await.unwrap();

    let part_size = SOCKET_FILE_DATA_MAX;

    let mut total_parts = 0;
    while chunk_data.len() > 0 {
        let part_data: Vec<u8>;
        if part_size > chunk_data.len() {
            part_data = chunk_data.drain(..).collect();
        } else {
            part_data = chunk_data.drain(0..part_size).collect();
        }

        let mut piece_file = File::create(format!("{}/{}_{}", test_chunks_output_folder, chunk_id, total_parts)).await.unwrap();
        piece_file.write_all(&*part_data).await.unwrap();

        total_parts += 1;
    }
}

#[tokio::test]
async fn file_assembly_and_decryption_test() {
    let test_output_folder = TEST_OUTPUT_FOLDER;
    let test_chunks_output_folder = format!("{}/{}", test_output_folder, CHUNKS_FOLDER);

    let test_dir_path = Path::new(test_output_folder);
    if !test_dir_path.exists() && !test_dir_path.is_dir() {
        assert!(false, "No test directory exists!");
    }

    let test_downloads_folder = format!("{}/{}", test_output_folder, DOWNLOADS_FOLDER);

    let test_downloads_dir = Path::new(&test_downloads_folder);
    if test_downloads_dir.exists() && test_downloads_dir.is_dir() {
        fs::remove_dir_all(test_downloads_dir).await.unwrap();
        println!("Old Test Downloads Folder Removed!");
    }

    fs::create_dir(test_downloads_dir).await.unwrap();

    let mut file = File::open(format!("{}/{}", test_output_folder, FILE_UPLOAD_FILE)).await.unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).await.unwrap();
    let file_upload: FileUpload = serde_json::from_str(&contents).unwrap();

    let mut file_info = FileInfo::new(file_upload.name, file_upload.file_type, file_upload.size, file_upload.categories);

    file_info.set_file_id(file_upload.file_id);
    file_info.set_enc_file_id(file_upload.enc_file_id);
    file_info.set_decryption_key(file_upload.decryption_key);
    file_info.set_chunk_info(file_upload.chunks.clone());
    for chunk in file_upload.chunks {
        file_info.add_downloaded(chunk.chunk_id);
    }

    let assemble_res = file_info.assemble(Box::from(Path::new(&test_chunks_output_folder))).await;

    assert!(assemble_res.is_ok(), "{}", assemble_res.err().unwrap().1);

    let decrypt_res = file_info.decrypt(Box::from(Path::new(&assemble_res.unwrap())), Box::from(test_downloads_dir)).await;

    assert!(decrypt_res.is_ok(), "{}", decrypt_res.err().unwrap().1);

    println!("Decrypted file created at {}", decrypt_res.unwrap());
}