use crate::data::garlemlia_protocol::GarlemliaStoreRequest;
use crate::routing::dispatcher::garlemlia_dispatch::GarlemliaContext;

pub struct LocalStore;
impl LocalStore {
    async fn store_chunk_part(context: &GarlemliaContext, request: &GarlemliaStoreRequest) {
        let chunk_id = request.get_id();
        let mut cpa = context.chunk_part_associations.lock().await;

        if !cpa.am_storing_chunk(chunk_id) {
            return;
        }

        let chunk_info = cpa.get_mut_chunk_stored(chunk_id).unwrap();
        chunk_info
            .parts_info
            .push(request.get_chunk_part_info().unwrap());

        let index = request.get_chunk_part_index().unwrap();
        let chunk_part_data = request.get_chunk_part_data().unwrap();

        let _ = context
            .file_storage
            .lock()
            .await
            .store_chunk_part(chunk_id, index, chunk_part_data)
            .await;

        if chunk_info.parts_info.len() == chunk_info.parts_count {
            let assembled = context
                .file_storage
                .lock()
                .await
                .assemble_chunk(chunk_id, chunk_info.parts_count)
                .await;

            if assembled.is_ok() {
                cpa.remove_from_chunk_storage(chunk_id);
            }
        }
    }

    pub(crate) async fn store_value(context: &GarlemliaContext, request: &GarlemliaStoreRequest) {
        let mut store_val = request.to_store_data();

        if request.is_chunk_info() {
            context
                .chunk_part_associations
                .lock()
                .await
                .add_to_chunk_storage(request.get_file_chunk_info().unwrap());
            return;
        }

        if request.is_chunk_part() {
            Self::store_chunk_part(context, request).await;
            return;
        }

        if let Some(mut value) = store_val.take() {
            value.store();
            context
                .data_store
                .lock()
                .await
                .insert(request.get_id(), value);
        }
    }
}
