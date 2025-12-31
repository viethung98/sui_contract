module medical_vault::export {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use std::string::{Self, String};
    use std::vector;
    use sui::event;
    use sui::clock::{Self, Clock};
    use medical_vault::seal_whitelist::{Self, SealWhitelist};

    /// Error codes
    const E_NOT_OWNER: u64 = 1;
    const E_EXPORT_EXPIRED: u64 = 2;

    /// Export format types
    const FORMAT_ENCRYPTED_ZIP: u8 = 0;
    const FORMAT_DECRYPTED_BUNDLE: u8 = 1;

    /// Export manifest with signed list of files and proof-of-existence
    public struct ExportManifest has key, store {
        id: UID,
        /// Whitelist ID being exported (replaces folder_id)
        whitelist_id: ID,
        /// Owner/requester
        requester: address,
        /// List of record IDs included
        record_ids: vector<ID>,
        /// List of Walrus CIDs
        walrus_cids: vector<vector<u8>>,
        /// Export format
        format: u8,
        /// Signed manifest hash (for legal proof)
        manifest_signature: vector<u8>,
        /// Timestamp of export creation
        created_at: u64,
        /// Expiration timestamp (download link validity)
        expires_at: u64,
        /// Download URL (Walrus gateway or IPFS)
        download_url: String,
    }

    /// Events
    public struct ExportCreated has copy, drop {
        export_id: ID,
        whitelist_id: ID,
        requester: address,
        record_count: u64,
        format: u8,
        timestamp: u64,
        expires_at: u64,
    }

    public struct ExportDownloaded has copy, drop {
        export_id: ID,
        downloader: address,
        timestamp: u64,
    }

    /// Create an export manifest for self-service data download
    public entry fun create_export(
        whitelist: &SealWhitelist,
        record_ids: vector<ID>,
        walrus_cids: vector<vector<u8>>,
        format: u8,
        manifest_signature: vector<u8>,
        download_url: vector<u8>,
        validity_duration_ms: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Only whitelist owner can export
        assert!(seal_whitelist::owner(whitelist) == sender, E_NOT_OWNER);

        let export_uid = object::new(ctx);
        let export_id = object::uid_to_inner(&export_uid);
        let current_time = clock::timestamp_ms(clock);

        let export = ExportManifest {
            id: export_uid,
            whitelist_id: object::id(whitelist),
            requester: sender,
            record_ids,
            walrus_cids,
            format,
            manifest_signature,
            created_at: current_time,
            expires_at: current_time + validity_duration_ms,
            download_url: string::utf8(download_url),
        };

        event::emit(ExportCreated {
            export_id,
            whitelist_id: object::id(whitelist),
            requester: sender,
            record_count: vector::length(&export.record_ids),
            format,
            timestamp: current_time,
            expires_at: export.expires_at,
        });

        transfer::share_object(export);
    }

    /// Log download event
    public entry fun log_download(
        export: &ExportManifest,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let current_time = clock::timestamp_ms(clock);
        
        // Check if export has expired
        assert!(current_time <= export.expires_at, E_EXPORT_EXPIRED);

        event::emit(ExportDownloaded {
            export_id: object::uid_to_inner(&export.id),
            downloader: sender,
            timestamp: current_time,
        });
    }

    /// Getter functions
    public fun whitelist_id(export: &ExportManifest): ID {
        export.whitelist_id
    }

    public fun requester(export: &ExportManifest): address {
        export.requester
    }

    public fun record_ids(export: &ExportManifest): &vector<ID> {
        &export.record_ids
    }

    public fun walrus_cids(export: &ExportManifest): &vector<vector<u8>> {
        &export.walrus_cids
    }

    public fun format(export: &ExportManifest): u8 {
        export.format
    }

    public fun manifest_signature(export: &ExportManifest): &vector<u8> {
        &export.manifest_signature
    }

    public fun download_url(export: &ExportManifest): String {
        export.download_url
    }

    public fun is_expired(export: &ExportManifest, clock: &Clock): bool {
        clock::timestamp_ms(clock) > export.expires_at
    }

    public fun created_at(export: &ExportManifest): u64 {
        export.created_at
    }

    public fun expires_at(export: &ExportManifest): u64 {
        export.expires_at
    }
}
