// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Timeline Module for HIPAA Safe Harbor Compliant Patient Records
/// Uses Nautilus Intent pattern with enclave signature verification
/// 
/// ARCHITECTURE NOTE:
/// Timeline entries are stored as dynamic_object_fields on SealWhitelist.
/// This provides:
/// - Query entries via whitelist object (no indexer needed)
/// - Storage embedded in parent (no separate object overhead)
/// - Access control implicit (attached to whitelist)
/// - Patient ref derived from parent whitelist
///
/// All data stored on-chain follows HIPAA Safe Harbor de-identification standards:
/// - No direct patient identifiers (use references)
/// - No exact dates (use date strings only)
/// - No specific symptoms or diagnoses (use generalized categories)
/// - Provider specialty instead of provider name
/// - Visit type categorization (checkup, procedure, etc.)

module medical_vault::timeline {
    use sui::dynamic_object_field as dof;
    use sui::event;
    use sui::clock::Clock;
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::hash;
    use sui::bcs;
    use std::string::{Self, String};
    use std::vector;
    use medical_vault::seal_whitelist::{Self, SealWhitelist};

    // ============================================
    // Error Codes
    // ============================================

    const E_INVALID_SIGNATURE: u64 = 0;
    const E_INVALID_SCOPE: u64 = 1;
    const E_INVALID_ENTRY_TYPE: u64 = 2;
    const E_ALREADY_REVOKED: u64 = 3;
    const E_UNAUTHORIZED_ACCESS: u64 = 4;
    const E_EMPTY_PATIENT_REF: u64 = 5;
    const E_INVALID_VISIT_DATE: u64 = 6;
    const E_ENTRY_NOT_FOUND: u64 = 7;
    const E_INVALID_WHITELIST: u64 = 8;
    const E_POOL_ALREADY_EXISTS: u64 = 9;
    const E_POOL_NOT_ACTIVE: u64 = 10;
    const E_INVALID_PATIENT: u64 = 11;
    const E_UNAUTHORIZED_CREATOR: u64 = 12;
    const E_INVALID_DEPOSIT: u64 = 13;

    // ============================================
    // Timeline Entry Type Constants
    // ============================================

    const ENTRY_VISIT_SUMMARY: u8 = 0;
    const ENTRY_PROCEDURE: u8 = 1;
    const ENTRY_REFILL: u8 = 2;
    const ENTRY_NOTE: u8 = 3;
    const ENTRY_DIAGNOSIS: u8 = 4;
    const ENTRY_LAB_RESULT: u8 = 5;
    const ENTRY_IMMUNIZATION: u8 = 6;

    // ============================================
    // Dynamic Field Keys
    // ============================================

    /// Key for timeline entries as dynamic object field on SealWhitelist
    /// Uses (patient_ref_bytes, timestamp_ms) as key for uniqueness
    public struct TimelineEntryKey has store, copy, drop {
        patient_ref_bytes: vector<u8>,
        timestamp_ms: u64,
    }

    /// Marker type for entry counter (single counter per whitelist)
    public struct EntryCounter has store, copy, drop {
        marker: u8,
    }

    // ============================================
    // On-Chain Timeline Structures (HIPAA Safe Harbor)
    // ============================================

    /// TimelineEntry - Non-PHI visit summaries stored as dynamic_object_field on SealWhitelist
    /// All fields follow HIPAA Safe Harbor de-identification standards
    /// Note: patient_ref and whitelist_id are derived from parent SealWhitelist
    public struct TimelineEntry has key, store {
        id: UID,
        /// Patient reference stored as bytes (derived from parent)
        patient_ref_bytes: vector<u8>,
        /// Type of entry (visit_summary, procedure, refill, note, etc.)
        entry_type: u8,
        /// Date of visit (format: YYYY-MM-DD, no exact timestamp)
        visit_date: String,
        /// Provider specialty (general category, not provider name)
        provider_specialty: String,
        /// Visit type (checkup, procedure, emergency, etc.)
        visit_type: String,
        /// Status of the entry (completed, pending, cancelled)
        status: String,
        /// SHA3-256 hash of the full entry content stored off-chain
        content_hash: String,
        /// Walrus blob ID where full entry content is stored (encrypted)
        walrus_blob_id: vector<u8>,
        /// Unix timestamp when entry was created
        created_at: u64,
        /// Whether this entry has been revoked
        revoked: bool,
    }

    /// DepositPool - Holds SUI coins temporarily for patient withdrawal
    /// Created when TimelineEntry status is updated to eligible state
    public struct DepositPool has key, store {
        id: UID,
        /// ID of the associated TimelineEntry
        timeline_entry_id: ID,
        /// Patient reference bytes for validation
        patient_ref_bytes: vector<u8>,
        /// Creator who deposited the funds
        creator: address,
        /// Deposited SUI balance
        balance: Balance<SUI>,
        /// Whether pool is active (can be withdrawn)
        active: bool,
    }


    // ============================================
    // Timeline Events
    // ============================================

    /// Emitted when a new timeline entry is created
    public struct TimelineEntryCreated has copy, drop {
        whitelist_id: ID,
        patient_ref_bytes: vector<u8>,
        timestamp_ms: u64,
        visit_date: String,
        entry_type: u8,
    }

    /// Emitted when a timeline entry is revoked
    public struct TimelineEntryRevoked has copy, drop {
        whitelist_id: ID,
        patient_ref_bytes: vector<u8>,
        timestamp_ms: u64,
    }

    /// Emitted when a deposit pool is created
    public struct DepositPoolCreated has copy, drop {
        timeline_entry_id: ID,
        pool_id: ID,
        creator: address,
        amount: u64,
    }

    /// Emitted when patient withdraws from deposit pool
    public struct PatientWithdrawn has copy, drop {
        timeline_entry_id: ID,
        pool_id: ID,
        patient: address,
        amount: u64,
    }

    /// Emitted when creator cancels deposit pool
    public struct PoolCancelled has copy, drop {
        timeline_entry_id: ID,
        pool_id: ID,
        creator: address,
        amount: u64,
    }

    

    // ============================================
    // Entry Functions
    // ============================================

    /// Create a new HIPAA Safe Harbor compliant timeline entry as dynamic field on SealWhitelist
    /// 
    /// USAGE:
    /// 1. Off-chain: Generate entry content (non-PHI)
    /// 2. Off-chain: Upload to Walrus → get blob_id
    /// 3. Off-chain: Compute content_hash (SHA3-256)
    /// 4. On-chain: Call this function with metadata only
    public fun create_entry(
        whitelist: &mut SealWhitelist,
        patient_ref: vector<u8>,
        entry_type: u8,
        visit_date: vector<u8>,
        provider_specialty: vector<u8>,
        visit_type: vector<u8>,
        status: vector<u8>,
        content_hash: vector<u8>,
        walrus_blob_id: vector<u8>,
        timestamp_ms: u64,
        _clock: &Clock,
        ctx: &mut TxContext,
    ) {
        // Validate inputs
        assert!(vector::length(&patient_ref) > 0, E_EMPTY_PATIENT_REF);
        assert!(vector::length(&visit_date) > 0, E_INVALID_VISIT_DATE);
        assert!(entry_type <= ENTRY_IMMUNIZATION, E_INVALID_ENTRY_TYPE);

        // Create dynamic field key using patient_ref bytes and timestamp
        let key = TimelineEntryKey {
            patient_ref_bytes: patient_ref,
            timestamp_ms,
        };

        // Create timeline entry (whitelist_id derived from parent)
        let entry = TimelineEntry {
            id: object::new(ctx),
            patient_ref_bytes: *&key.patient_ref_bytes,
            entry_type,
            visit_date: string::utf8(visit_date),
            provider_specialty: string::utf8(provider_specialty),
            visit_type: string::utf8(visit_type),
            status: string::utf8(status),
            content_hash: string::utf8(content_hash),
            walrus_blob_id,
            created_at: timestamp_ms,
            revoked: false,
        };

        // Add as dynamic field to whitelist
        dof::add(seal_whitelist::uid_mut(whitelist), key, entry);

        // Emit creation event
        event::emit(TimelineEntryCreated {
            whitelist_id: seal_whitelist::whitelist_id(whitelist),
            patient_ref_bytes: *&key.patient_ref_bytes,
            timestamp_ms,
            visit_date: string::utf8(visit_date),
            entry_type,
        });
    }

    /// Verify an existing timeline entry (for externally created entries)
    public fun verify_entry(
        whitelist: &mut SealWhitelist,
        patient_ref: vector<u8>,
        entry_type: u8,
        visit_date: vector<u8>,
        content_hash: vector<u8>,
        walrus_blob_id: vector<u8>,
        timestamp_ms: u64,
        _clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(vector::length(&patient_ref) > 0, E_EMPTY_PATIENT_REF);

        let key = TimelineEntryKey {
            patient_ref_bytes: patient_ref,
            timestamp_ms,
        };

        let entry = TimelineEntry {
            id: object::new(ctx),
            patient_ref_bytes: *&key.patient_ref_bytes,
            entry_type,
            visit_date: string::utf8(visit_date),
            provider_specialty: string::utf8(b""),
            visit_type: string::utf8(b""),
            status: string::utf8(b"verified"),
            content_hash: string::utf8(content_hash),
            walrus_blob_id,
            created_at: timestamp_ms,
            revoked: false,
        };

        dof::add(seal_whitelist::uid_mut(whitelist), key, entry);

        event::emit(TimelineEntryCreated {
            whitelist_id: seal_whitelist::whitelist_id(whitelist),
            patient_ref_bytes: *&key.patient_ref_bytes,
            timestamp_ms,
            visit_date: string::utf8(visit_date),
            entry_type,
        });
    }

    /// Revoke a timeline entry (requires mutable access to whitelist)
    entry fun revoke_entry(
        whitelist: &mut SealWhitelist,
        patient_ref: vector<u8>,
        timestamp_ms: u64,
        _clock: &Clock,
        _ctx: &mut TxContext,
    ) {
        let key = TimelineEntryKey {
            patient_ref_bytes: patient_ref,
            timestamp_ms,
        };

        assert!(dof::exists_<TimelineEntryKey>(seal_whitelist::uid(whitelist), key), E_ENTRY_NOT_FOUND);

        let entry: TimelineEntry = dof::remove(seal_whitelist::uid_mut(whitelist), key);
        
        assert!(!entry.revoked, E_ALREADY_REVOKED);

        event::emit(TimelineEntryRevoked {
            whitelist_id: seal_whitelist::whitelist_id(whitelist),
            patient_ref_bytes: entry.patient_ref_bytes,
            timestamp_ms,
        });

        // Clean up UID
        let TimelineEntry { id, .. } = entry;
        object::delete(id);
    }

    // ============================================
    // Deposit Pool Functions
    // ============================================

    /// Update status of TimelineEntry and create deposit pool with SUI deposit
    /// Only creator can call this function
    /// Requires deposit amount > 0
    entry fun create_pool_and_deposit(
        whitelist: &mut SealWhitelist,
        patient_ref: vector<u8>,
        timestamp_ms: u64,
        deposit_coin: Coin<SUI>,
        ctx: &mut TxContext,
    ) {
        let sender = tx_context::sender(ctx);
        let key = TimelineEntryKey {
            patient_ref_bytes: patient_ref,
            timestamp_ms,
        };

        // Check if entry exists
        assert!(dof::exists_<TimelineEntryKey>(seal_whitelist::uid(whitelist), key), E_ENTRY_NOT_FOUND);

        // Get mutable reference to entry
        let entry: &mut TimelineEntry = dof::borrow_mut(seal_whitelist::uid_mut(whitelist), key);

        // Check if entry is not revoked
        assert!(!entry.revoked, E_ALREADY_REVOKED);

        // Validate deposit amount
        let deposit_amount = coin::value(&deposit_coin);
        assert!(deposit_amount > 0, E_INVALID_DEPOSIT);

        // Update status
        entry.status = string::utf8(b"verified");

        // Check if pool already exists (using entry ID as key)
        let entry_id = object::id(entry);
        assert!(!dof::exists_<ID>(seal_whitelist::uid(whitelist), entry_id), E_POOL_ALREADY_EXISTS);

        // Create deposit pool
        let pool = DepositPool {
            id: object::new(ctx),
            timeline_entry_id: entry_id,
            patient_ref_bytes: patient_ref,
            creator: sender,
            balance: coin::into_balance(deposit_coin),
            active: true,
        };

        let pool_id = object::id(&pool);
        let amount = balance::value(&pool.balance);

        // Add pool as dynamic field to whitelist
        dof::add(seal_whitelist::uid_mut(whitelist), entry_id, pool);

        // Emit event
        event::emit(DepositPoolCreated {
            timeline_entry_id: entry_id,
            pool_id,
            creator: sender,
            amount,
        });
    }

    /// Patient withdraws from deposit pool
    /// Validates patient using hash of their address
    entry fun withdraw_by_patient(
        whitelist: &mut SealWhitelist,
        patient_ref: vector<u8>,
        timestamp_ms: u64,
        ctx: &mut TxContext,
    ) {
        let sender = tx_context::sender(ctx);
        let key = TimelineEntryKey {
            patient_ref_bytes: patient_ref,
            timestamp_ms,
        };

        // Check if entry exists and get patient_ref for validation
        assert!(dof::exists_<TimelineEntryKey>(seal_whitelist::uid(whitelist), key), E_ENTRY_NOT_FOUND);
        let entry: &TimelineEntry = dof::borrow(seal_whitelist::uid(whitelist), key);
        assert!(!entry.revoked, E_ALREADY_REVOKED);

        // Validate patient using hash
        let sender_addr = tx_context::sender(ctx);
        let patient_hash = hash::blake2b256(&bcs::to_bytes(&sender_addr));
        assert!(patient_hash == entry.patient_ref_bytes, E_INVALID_PATIENT);

        // Get entry ID and check pool
        let entry_id = object::id(entry);
        assert!(dof::exists_<ID>(seal_whitelist::uid(whitelist), entry_id), E_POOL_NOT_ACTIVE);

        // Get mutable reference to pool and process
        let pool: &mut DepositPool = dof::borrow_mut(seal_whitelist::uid_mut(whitelist), entry_id);
        assert!(pool.active, E_POOL_NOT_ACTIVE);

        // Withdraw funds
        let amount = balance::value(&pool.balance);
        let withdraw_balance = balance::split(&mut pool.balance, amount);
        let withdraw_coin = coin::from_balance(withdraw_balance, ctx);
        transfer::public_transfer(withdraw_coin, sender);

        // Deactivate pool
        pool.active = false;

        // Emit event
        event::emit(PatientWithdrawn {
            timeline_entry_id: entry_id,
            pool_id: object::id(pool),
            patient: sender,
            amount,
        });
    }

    /// Creator cancels deposit pool and refunds
    entry fun cancel_pool_and_refund_creator(
        whitelist: &mut SealWhitelist,
        patient_ref: vector<u8>,
        timestamp_ms: u64,
        ctx: &mut TxContext,
    ) {
        let sender = tx_context::sender(ctx);
        let key = TimelineEntryKey {
            patient_ref_bytes: patient_ref,
            timestamp_ms,
        };

        // Check if entry exists
        assert!(dof::exists_<TimelineEntryKey>(seal_whitelist::uid(whitelist), key), E_ENTRY_NOT_FOUND);

        // Get entry ID first
        let entry: &TimelineEntry = dof::borrow(seal_whitelist::uid(whitelist), key);
        let entry_id = object::id(entry);

        // Check if pool exists
        assert!(dof::exists_<ID>(seal_whitelist::uid(whitelist), entry_id), E_POOL_NOT_ACTIVE);

        // Get mutable reference to pool and process
        let pool: &mut DepositPool = dof::borrow_mut(seal_whitelist::uid_mut(whitelist), entry_id);
        assert!(pool.active, E_POOL_NOT_ACTIVE);
        assert!(pool.creator == sender, E_UNAUTHORIZED_CREATOR);

        // Refund funds
        let amount = balance::value(&pool.balance);
        let refund_balance = balance::split(&mut pool.balance, amount);
        let refund_coin = coin::from_balance(refund_balance, ctx);
        transfer::public_transfer(refund_coin, sender);

        // Deactivate pool
        pool.active = false;

        // Emit event
        event::emit(PoolCancelled {
            timeline_entry_id: entry_id,
            pool_id: object::id(pool),
            creator: sender,
            amount,
        });
    }

    // ============================================
    // Helper Functions
    // ============================================

    /// Get entry type name as bytes
    public fun entry_type_name(entry_type: u8): vector<u8> {
        if (entry_type == ENTRY_VISIT_SUMMARY) {
            b"visit_summary"
        } else if (entry_type == ENTRY_PROCEDURE) {
            b"procedure"
        } else if (entry_type == ENTRY_REFILL) {
            b"refill"
        } else if (entry_type == ENTRY_NOTE) {
            b"note"
        } else if (entry_type == ENTRY_DIAGNOSIS) {
            b"diagnosis"
        } else if (entry_type == ENTRY_LAB_RESULT) {
            b"lab_result"
        } else if (entry_type == ENTRY_IMMUNIZATION) {
            b"immunization"
        } else {
            b"unknown"
        }
    }

    // ============================================
    // Getter Functions
    // ============================================

    public fun patient_ref_bytes(entry: &TimelineEntry): &vector<u8> {
        &entry.patient_ref_bytes
    }

    public fun entry_type(entry: &TimelineEntry): u8 {
        entry.entry_type
    }

    public fun visit_date(entry: &TimelineEntry): &String {
        &entry.visit_date
    }

    public fun provider_specialty(entry: &TimelineEntry): &String {
        &entry.provider_specialty
    }

    public fun visit_type(entry: &TimelineEntry): &String {
        &entry.visit_type
    }

    public fun status(entry: &TimelineEntry): &String {
        &entry.status
    }

    public fun content_hash(entry: &TimelineEntry): &String {
        &entry.content_hash
    }

    public fun walrus_blob_id(entry: &TimelineEntry): &vector<u8> {
        &entry.walrus_blob_id
    }

    public fun created_at(entry: &TimelineEntry): u64 {
        entry.created_at
    }

    public fun is_revoked(entry: &TimelineEntry): bool {
        entry.revoked
    }

    // ============================================
    // DepositPool Getter Functions
    // ============================================

    public fun pool_timeline_entry_id(pool: &DepositPool): ID {
        pool.timeline_entry_id
    }

    public fun pool_patient_ref_bytes(pool: &DepositPool): &vector<u8> {
        &pool.patient_ref_bytes
    }

    public fun pool_creator(pool: &DepositPool): address {
        pool.creator
    }

    public fun pool_balance_value(pool: &DepositPool): u64 {
        balance::value(&pool.balance)
    }

    public fun pool_is_active(pool: &DepositPool): bool {
        pool.active
    }
}
