module medical_vault::medical_record {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use std::string::{Self, String};
    use std::vector;
    use sui::event;
    use sui::clock::{Self, Clock};
    use medical_vault::seal_whitelist::{Self, SealWhitelist, WhitelistAdminCap};

    /// Error codes
    const E_NO_WHITELIST_ACCESS: u64 = 1;
    const E_NOT_UPLOADER: u64 = 2;
    const E_WHITELIST_REVOKED: u64 = 3;
    const E_RECORD_REVOKED: u64 = 4;
    const E_NOT_DOCTOR: u64 = 5;
    const E_NO_VIEW_ACCESS: u64 = 6;

    /// Document types
    const DOC_TYPE_LAB_RESULT: u8 = 0;
    const DOC_TYPE_IMAGING: u8 = 1;
    const DOC_TYPE_DOCTOR_NOTES: u8 = 2;
    const DOC_TYPE_PRESCRIPTION: u8 = 3;
    const DOC_TYPE_OTHER: u8 = 4;

    /// Represents a medical record stored on Walrus
    public struct Record has key, store {
        id: UID,
        /// Record identifier
        record_id: String,
        /// Parent whitelist ID (replaces folder_id)
        whitelist_id: ID,
        /// Uploader address (doctor/hospital)
        uploader: address,
        /// Walrus blob IDs (multiple files can be associated)
        walrus_cid: vector<vector<u8>>,
        /// Sealed key references for Seal encryption
        sealed_key_ref: vector<vector<u8>>,
        /// Document type (lab, imaging, notes, etc.)
        doc_type: vector<u8>,
        /// Upload timestamp
        timestamp: u64,
        /// Revoked status
        revoked: bool,
    }

    /// --- Events ---
    public struct RecordCreated has copy, drop {
        record_id: ID,
        whitelist_id: ID,
        uploader: address,
        doc_type_count: u64,
        timestamp: u64,
    }

    public struct RecordUpdated has copy, drop {
        record_id: ID,
        uploader: address,
        timestamp: u64,
    }

    public struct RecordRevoked has copy, drop {
        record_id: ID,
        timestamp: u64,
    }

    public struct RecordAccessed has copy, drop {
        record_id: ID,
        accessor: address,
        timestamp: u64,
    }

    /// --- Entry functions ---

    /// Create a medical record (only doctors can create)
    /// Automatically adds the record to the whitelist
    public entry fun create_record(
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        record_id_bytes: vector<u8>,
        walrus_cid: vector<vector<u8>>,
        sealed_key_ref: vector<vector<u8>>,
        doc_type: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Check: Must be an authorized doctor (writer) to add records
        assert!(seal_whitelist::can_write(whitelist, sender, clock), E_NOT_DOCTOR);

        let record_uid = object::new(ctx);
        let record_obj_id = object::uid_to_inner(&record_uid);

        let record = Record {
            id: record_uid,
            record_id: string::utf8(record_id_bytes),
            whitelist_id: object::id(whitelist),
            uploader: sender,
            walrus_cid,
            sealed_key_ref,
            doc_type,
            timestamp: clock::timestamp_ms(clock),
            revoked: false,
        };

        // Add record to whitelist
        seal_whitelist::add_record(whitelist, cap, record_obj_id);

        event::emit(RecordCreated {
            record_id: record_obj_id,
            whitelist_id: object::id(whitelist),
            uploader: sender,
            doc_type_count: (vector::length(&record.doc_type) as u64),
            timestamp: record.timestamp,
        });

        transfer::share_object(record);
    }

    /// Add files to existing record (only the original uploader doctor can add)
    public entry fun add_files_to_record(
        whitelist: &SealWhitelist,
        record: &mut Record,
        walrus_cid: vector<u8>,
        sealed_key_ref: vector<u8>,
        doc_type: u8,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Check: Must be the original uploader (doctor)
        assert!(record.uploader == sender, E_NOT_UPLOADER);
        // Also verify still has doctor access to whitelist
        assert!(seal_whitelist::can_write(whitelist, sender, clock), E_NOT_DOCTOR);
        assert!(!record.revoked, E_RECORD_REVOKED);

        vector::push_back(&mut record.walrus_cid, walrus_cid);
        vector::push_back(&mut record.sealed_key_ref, sealed_key_ref);
        vector::push_back(&mut record.doc_type, doc_type);

        event::emit(RecordUpdated {
            record_id: object::uid_to_inner(&record.id),
            uploader: sender,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    /// Revoke a record (only the uploader doctor can revoke)
    public entry fun revoke_record(
        record: &mut Record,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        assert!(record.uploader == sender, E_NOT_UPLOADER);

        record.revoked = true;

        event::emit(RecordRevoked {
            record_id: object::uid_to_inner(&record.id),
            timestamp: clock::timestamp_ms(clock),
        });
    }

    /// Log access to a record (anyone with view access can log their access)
    /// This is for audit trail purposes
    public entry fun log_access(
        whitelist: &SealWhitelist,
        record: &Record,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Check: Must have read access (owner, doctors, or members)
        assert!(seal_whitelist::can_read(whitelist, sender, clock), E_NO_VIEW_ACCESS);
        assert!(!record.revoked, E_RECORD_REVOKED);

        event::emit(RecordAccessed {
            record_id: object::uid_to_inner(&record.id),
            accessor: sender,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    /// --- Getter functions ---

    public fun record_id(record: &Record): &String {
        &record.record_id
    }

    public fun whitelist_id(record: &Record): ID {
        record.whitelist_id
    }

    public fun uploader(record: &Record): address {
        record.uploader
    }

    public fun walrus_cids(record: &Record): &vector<vector<u8>> {
        &record.walrus_cid
    }

    public fun sealed_key_refs(record: &Record): &vector<vector<u8>> {
        &record.sealed_key_ref
    }

    public fun doc_types(record: &Record): &vector<u8> {
        &record.doc_type
    }

    public fun timestamp(record: &Record): u64 {
        record.timestamp
    }

    public fun is_revoked(record: &Record): bool {
        record.revoked
    }
}
