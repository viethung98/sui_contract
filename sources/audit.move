module medical_vault::audit {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use std::string::{Self, String};
    use std::vector;
    use sui::event;
    use sui::clock::{Self, Clock};

    /// Action types
    const ACTION_CREATE_WHITELIST: u8 = 0;
    const ACTION_ADD_MEMBER: u8 = 1;
    const ACTION_REMOVE_MEMBER: u8 = 2;
    const ACTION_REVOKE_WHITELIST: u8 = 3;
    const ACTION_CREATE_RECORD: u8 = 4;
    const ACTION_UPDATE_RECORD: u8 = 5;
    const ACTION_ACCESS_RECORD: u8 = 6;
    const ACTION_REVOKE_RECORD: u8 = 7;
    const ACTION_EXPORT_DATA: u8 = 8;
    const ACTION_GRANT_ACCESS: u8 = 9;
    const ACTION_REVOKE_ACCESS: u8 = 10;

    /// Audit event log stored on-chain
    public struct AuditEvent has key, store {
        id: UID,
        /// Event identifier
        event_id: String,
        /// Actor who performed the action
        actor: address,
        /// Action type
        action: u8,
        /// Target resource ID (whitelist, record)
        target_id: ID,
        /// Transaction digest for verification
        tx_digest: vector<u8>,
        /// Timestamp
        timestamp: u64,
        /// Additional metadata (JSON-encoded)
        metadata: String,
    }

    /// Event emitted for each audit log
    public struct AuditEventEmitted has copy, drop {
        event_id: ID,
        actor: address,
        action: u8,
        target_id: ID,
        timestamp: u64,
    }

    /// Create a new audit event
    public entry fun log_event(
        event_id: vector<u8>,
        action: u8,
        target_id: ID,
        tx_digest: vector<u8>,
        metadata: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let audit_uid = object::new(ctx);
        let audit_obj_id = object::uid_to_inner(&audit_uid);

        let audit = AuditEvent {
            id: audit_uid,
            event_id: string::utf8(event_id),
            actor: sender,
            action,
            target_id,
            tx_digest,
            timestamp: clock::timestamp_ms(clock),
            metadata: string::utf8(metadata),
        };

        event::emit(AuditEventEmitted {
            event_id: audit_obj_id,
            actor: sender,
            action,
            target_id,
            timestamp: audit.timestamp,
        });

        transfer::share_object(audit);
    }

    /// Batch log multiple events (for export operations)
    public entry fun log_batch_events(
        event_ids: vector<vector<u8>>,
        actions: vector<u8>,
        target_ids: vector<ID>,
        tx_digest: vector<u8>,
        metadata: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let len = vector::length(&event_ids);
        let mut i = 0;

        while (i < len) {
            let event_id = *vector::borrow(&event_ids, i);
            let action = *vector::borrow(&actions, i);
            let target_id = *vector::borrow(&target_ids, i);

            log_event(
                event_id,
                action,
                target_id,
                tx_digest,
                metadata,
                clock,
                ctx
            );

            i = i + 1;
        };
    }

    /// Getter functions
    public fun event_id(audit: &AuditEvent): String {
        audit.event_id
    }

    public fun actor(audit: &AuditEvent): address {
        audit.actor
    }

    public fun action(audit: &AuditEvent): u8 {
        audit.action
    }

    public fun target_id(audit: &AuditEvent): ID {
        audit.target_id
    }

    public fun timestamp(audit: &AuditEvent): u64 {
        audit.timestamp
    }

    public fun metadata(audit: &AuditEvent): String {
        audit.metadata
    }

    public fun tx_digest(audit: &AuditEvent): &vector<u8> {
        &audit.tx_digest
    }
}
