module medical_vault::seal_whitelist {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use std::string::{Self, String};
    use std::vector;
    use sui::event;
    use sui::clock::{Self, Clock};

    /// Error codes
    const E_INVALID_CAP: u64 = 0;
    const E_NO_ACCESS: u64 = 1;
    const E_DUPLICATE: u64 = 2;
    const E_NOT_OWNER: u64 = 4;
    const E_NO_WRITE_ACCESS: u64 = 5;
    const E_NO_READ_ACCESS: u64 = 6;

    /// Access roles
    const ROLE_OWNER: u8 = 0;      // Read/write access
    const ROLE_DOCTOR: u8 = 1;     // Read/write access
    const ROLE_MEMBER: u8 = 2;     // Read-only access

    /// Whitelist types
    const POLICY_TYPE_FOLDER: u8 = 0;
    const POLICY_TYPE_RECORD: u8 = 1;

    /// Seal whitelist allowlist for fine-grained access control
    /// Implements two-level access pattern:
    /// - Writers (owner + doctors): Can encrypt AND decrypt data  
    /// - Readers (members): Can ONLY decrypt data
    /// 
    /// Key format: [package_id]::[whitelist_id][optional_nonce]
    /// This follows the Seal allowlist pattern from:
    /// https://github.com/MystenLabs/seal/blob/main/examples/move/sources/allowlist.move
    public struct SealWhitelist has key {
        id: UID,
        /// Whitelist name/description (e.g., "Personal Medical Records", "Family Health")
        name: String,
        /// Owner (patient) - read/write access
        owner: address,
        /// Authorized doctors - read/write access (can encrypt & decrypt)
        doctors: vector<address>,
        /// Authorized members (family, viewers) - read-only access (can only decrypt)
        members: vector<address>,
        /// List of medical record IDs in this whitelist
        records: vector<ID>,
        /// Record of revoked users
        revoked: vector<address>,
        /// Created timestamp
        created_at: u64,
    }

    /// Capability to manage policies - owned by folder owner
    public struct WhitelistAdminCap has key, store {
        id: UID,
        whitelist_id: ID,
    }

    /// Events
    public struct WhitelistCreated has copy, drop {
        whitelist_id: ID,
        target_id: ID,
        whitelist_type: u8,
        creator: address,
        timestamp: u64,
    }

    public struct AccessGranted has copy, drop {
        whitelist_id: ID,
        user: address,
        role: u8,
        timestamp: u64,
    }

    public struct AccessRevoked has copy, drop {
        whitelist_id: ID,
        user: address,
        timestamp: u64,
    }

    /// Create a new Seal whitelist allowlist
    /// Sender becomes the owner with read/write access
    /// This replaces the folder creation - whitelists are now the main organizational unit
    public entry fun create_whitelist(
        name: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let whitelist_uid = object::new(ctx);
        let whitelist_id = object::uid_to_inner(&whitelist_uid);

        let whitelist = SealWhitelist {
            id: whitelist_uid,
            name: string::utf8(name),
            owner: sender,
            doctors: vector::empty(),
            members: vector::empty(),
            records: vector::empty(),
            revoked: vector::empty(),
            created_at: clock::timestamp_ms(clock),
        };

        let cap = WhitelistAdminCap {
            id: object::new(ctx),
            whitelist_id,
        };

        event::emit(WhitelistCreated {
            whitelist_id,
            target_id: whitelist_id,
            whitelist_type: 0,
            creator: sender,
            timestamp: whitelist.created_at,
        });

        transfer::share_object(whitelist);
        transfer::transfer(cap, sender);
    }

    /// Add a doctor to the allowlist (read/write access)
    public entry fun add_doctor(
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        doctor: address,
        clock: &Clock,
        _ctx: &mut TxContext
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        assert!(!whitelist.doctors.contains(&doctor), E_DUPLICATE);
        
        whitelist.doctors.push_back(doctor);

        event::emit(AccessGranted {
            whitelist_id: object::uid_to_inner(&whitelist.id),
            user: doctor,
            role: ROLE_DOCTOR,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    /// Add a member to the allowlist (read-only access)
    public entry fun add_member(
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        member: address,
        clock: &Clock,
        _ctx: &mut TxContext
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        assert!(!whitelist.members.contains(&member), E_DUPLICATE);
        
        whitelist.members.push_back(member);

        event::emit(AccessGranted {
            whitelist_id: object::uid_to_inner(&whitelist.id),
            user: member,
            role: ROLE_MEMBER,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    /// Remove a doctor from the allowlist
    public entry fun remove_doctor(
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        doctor: address,
        clock: &Clock,
        _ctx: &mut TxContext
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        
        whitelist.doctors = whitelist.doctors.filter!(|x| x != doctor);

        event::emit(AccessRevoked {
            whitelist_id: object::uid_to_inner(&whitelist.id),
            user: doctor,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    /// Remove a member from the allowlist
    public entry fun remove_member(
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        member: address,
        clock: &Clock,
        _ctx: &mut TxContext
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        
        whitelist.members = whitelist.members.filter!(|x| x != member);

        event::emit(AccessRevoked {
            whitelist_id: object::uid_to_inner(&whitelist.id),
            user: member,
            timestamp: clock::timestamp_ms(clock),
        });
    }


    ////////////////////////////////////////////////////////////
    // Access control functions following Seal allowlist pattern
    ////////////////////////////////////////////////////////////

    /// Get namespace for Seal key-id generation
    /// Key format: [package_id]::[whitelist_id][optional_nonce]
    /// The whitelist ID bytes serve as the namespace prefix
    public fun namespace(whitelist: &SealWhitelist): vector<u8> {
        object::uid_to_bytes(&whitelist.id)
    }

    /// Internal function to check if key ID matches this whitelist
    /// Verifies that the key ID has the correct whitelist namespace prefix
    fun is_prefix(namespace: vector<u8>, id: vector<u8>): bool {
        let namespace_len = vector::length(&namespace);
        let id_len = vector::length(&id);
        
        if (id_len < namespace_len) {
            return false
        };
        
        let mut i = 0;
        while (i < namespace_len) {
            if (*vector::borrow(&namespace, i) != *vector::borrow(&id, i)) {
                return false
            };
            i = i + 1;
        };
        
        true
    }

    /// Check if a user can WRITE (encrypt) data
    /// Only owner and doctors have write access
    public fun can_write(
        whitelist: &SealWhitelist,
        user: address,
        _clock: &Clock,
    ): bool {
        user == whitelist.owner || whitelist.doctors.contains(&user)
    }

    /// Check if a user can READ (decrypt) data  
    /// Owner, doctors, and members can all read
    public fun can_read(
        whitelist: &SealWhitelist,
        user: address,
        _clock: &Clock,
    ): bool {
        user == whitelist.owner || 
        whitelist.doctors.contains(&user) || 
        whitelist.members.contains(&user)
    }

    /// Internal approval check for writers (encrypt/decrypt access)
    /// Verifies: 1) Key ID has correct namespace, 2) User is owner or doctor
    fun approve_write_internal(
        caller: address, 
        id: vector<u8>, 
        whitelist: &SealWhitelist
    ): bool {
        // Check if the id has the right prefix
        let ns = namespace(whitelist);
        if (!is_prefix(ns, id)) {
            return false
        };
        
        // Check if user is owner or doctor (write access)
        caller == whitelist.owner || whitelist.doctors.contains(&caller)
    }

    /// Internal approval check for readers (decrypt-only access)
    /// Verifies: 1) Key ID has correct namespace, 2) User is owner, doctor, or member
    fun approve_read_internal(
        caller: address,
        id: vector<u8>,
        whitelist: &SealWhitelist
    ): bool {
        // Check if the id has the right prefix
        let ns = namespace(whitelist);
        if (!is_prefix(ns, id)) {
            return false
        };
        
        // Check if user has read access (owner, doctor, or member)
        caller == whitelist.owner || 
        whitelist.doctors.contains(&caller) || 
        whitelist.members.contains(&caller)
    }

    /// Seal approve entry for WRITE operations (encryption)
    /// This is called by Seal service when encrypting data
    /// Only owner and doctors can encrypt
    public entry fun seal_approve_write(
        id: vector<u8>,
        whitelist: &SealWhitelist,
        _clock: &Clock,
        ctx: &TxContext
    ) {
        assert!(approve_write_internal(tx_context::sender(ctx), id, whitelist), E_NO_WRITE_ACCESS);
    }

    /// Seal approve entry for READ operations (decryption)
    /// This is called by Seal service when decrypting data
    /// Owner, doctors, and members can all decrypt
    public entry fun seal_approve_read(
        id: vector<u8>,
        whitelist: &SealWhitelist,
        _clock: &Clock,
        ctx: &TxContext
    ) {
        assert!(approve_read_internal(tx_context::sender(ctx), id, whitelist), E_NO_READ_ACCESS);
    }

    /// Legacy seal_approve function for backward compatibility
    /// Defaults to read access check
    entry fun seal_approve(
        whitelist: &SealWhitelist,
        clock: &Clock,
        ctx: &TxContext
    ) {
        let sender = tx_context::sender(ctx);
        assert!(can_read(whitelist, sender, clock), E_NO_ACCESS);
    }

    /// Getter functions
    public fun name(whitelist: &SealWhitelist): String {
        whitelist.name
    }

    public fun owner(whitelist: &SealWhitelist): address {
        whitelist.owner
    }

    public fun doctors(whitelist: &SealWhitelist): &vector<address> {
        &whitelist.doctors
    }

    public fun members(whitelist: &SealWhitelist): &vector<address> {
        &whitelist.members
    }

    /// Check if address is owner
    public fun is_owner(whitelist: &SealWhitelist, user: address): bool {
        whitelist.owner == user
    }

    /// Check if address is doctor
    public fun is_doctor(whitelist: &SealWhitelist, user: address): bool {
        whitelist.doctors.contains(&user)
    }

    /// Check if address is member
    public fun is_member(whitelist: &SealWhitelist, user: address): bool {
        whitelist.members.contains(&user)
    }

    /// Add a record to the whitelist
    public fun add_record(
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        record_id: ID,
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        whitelist.records.push_back(record_id);
    }

    /// Remove a record from the whitelist
    public fun remove_record(
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        record_id: ID,
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        whitelist.records = whitelist.records.filter!(|x| x != &record_id);
    }

    /// Get records list
    public fun records(whitelist: &SealWhitelist): &vector<ID> {
        &whitelist.records
    }

    /// Check if a record is in the whitelist
    public fun has_record(whitelist: &SealWhitelist, record_id: ID): bool {
        whitelist.records.contains(&record_id)
    }
}
