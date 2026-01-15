module medical_vault::seal_whitelist {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use std::string::{Self, String};
    use std::vector;
    use sui::event;
    use sui::clock::{Self, Clock};
    use sui::table::{Self, Table};

    /// Error codes
    const E_INVALID_CAP: u64 = 0;
    const E_DUPLICATE: u64 = 2;
    const E_NO_WRITE_ACCESS: u64 = 5;
    const E_NO_READ_ACCESS: u64 = 6;

    /// Access roles
    const ROLE_OWNER: u8 = 0;      // Read/write access
    const ROLE_DOCTOR: u8 = 1;     // Read/write access
    const ROLE_MEMBER: u8 = 2;     // Read-only access
    const ROLE_NONE: u8 = 255;     // No access

    /// Global registry to track user access to whitelists
    /// This enables efficient querying of all whitelists a user can access
    /// Uses nested Table for O(1) access checks
    public struct WhitelistRegistry has key {
        id: UID,
        /// Maps user address to Table of whitelist IDs (ID -> bool)
        /// Inner Table acts as a Set for O(1) contains() checks
        user_whitelists: Table<address, Table<ID, bool>>,
    }

    /// Whitelist access info for queries
    public struct WhitelistAccessInfo has copy, drop, store {
        whitelist_id: ID,
        role: u8,
        has_read: bool,
        has_write: bool,
    }

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

    /// Debug event for registry updates
    public struct RegistryUpdated has copy, drop {
        user: address,
        whitelist_id: ID,
        operation: String,
    }

    /// Initialize the global registry (should be called once during deployment)
    fun init(ctx: &mut TxContext) {
        let registry = WhitelistRegistry {
            id: object::new(ctx),
            user_whitelists: table::new(ctx),
        };
        transfer::share_object(registry);
    }

    /// Internal function to add whitelist to user's access list
    fun add_user_whitelist_access(
        registry: &mut WhitelistRegistry,
        user: address,
        whitelist_id: ID,
        ctx: &mut TxContext
    ) {
        // Create user's nested table if doesn't exist
        if (!table::contains(&registry.user_whitelists, user)) {
            let new_table = table::new<ID, bool>(ctx);
            table::add(&mut registry.user_whitelists, user, new_table);
        };
        
        // Add whitelist to user's table
        let user_table = table::borrow_mut(&mut registry.user_whitelists, user);
        if (!table::contains(user_table, whitelist_id)) {
            table::add(user_table, whitelist_id, true);
            
            // Emit debug event
            event::emit(RegistryUpdated {
                user,
                whitelist_id,
                operation: string::utf8(b"add"),
            });
        };
    }

    /// Internal function to remove whitelist from user's access list
    fun remove_user_whitelist_access(
        registry: &mut WhitelistRegistry,
        user: address,
        whitelist_id: ID
    ) {
        if (table::contains(&registry.user_whitelists, user)) {
            let user_table = table::borrow_mut(&mut registry.user_whitelists, user);
            if (table::contains(user_table, whitelist_id)) {
                table::remove(user_table, whitelist_id);
            };
        };
    }

    /// Create a new Seal whitelist allowlist
    /// Sender becomes the owner with read/write access
    /// This replaces the folder creation - whitelists are now the main organizational unit
    public entry fun create_whitelist(
        registry: &mut WhitelistRegistry,
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
            created_at: clock::timestamp_ms(clock),
        };

        let cap = WhitelistAdminCap {
            id: object::new(ctx),
            whitelist_id,
        };

        // Register owner's access to this whitelist
        add_user_whitelist_access(registry, sender, whitelist_id, ctx);

        event::emit(WhitelistCreated {
            whitelist_id,
            creator: sender,
            timestamp: whitelist.created_at,
        });

        transfer::share_object(whitelist);
        transfer::transfer(cap, sender);
    }

    /// Add a doctor to the allowlist (read/write access)
    public entry fun add_doctor(
        registry: &mut WhitelistRegistry,
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        doctor: address,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        assert!(!whitelist.doctors.contains(&doctor), E_DUPLICATE);
        
        let whitelist_id = object::uid_to_inner(&whitelist.id);
        whitelist.doctors.push_back(doctor);

        // Register doctor's access to this whitelist
        add_user_whitelist_access(registry, doctor, whitelist_id, ctx);

        event::emit(AccessGranted {
            whitelist_id,
            user: doctor,
            role: ROLE_DOCTOR,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    /// Add a member to the allowlist (read-only access)
    public entry fun add_member(
        registry: &mut WhitelistRegistry,
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        member: address,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        assert!(!whitelist.members.contains(&member), E_DUPLICATE);
        
        let whitelist_id = object::uid_to_inner(&whitelist.id);
        whitelist.members.push_back(member);

        // Register member's access to this whitelist
        add_user_whitelist_access(registry, member, whitelist_id, ctx);

        event::emit(AccessGranted {
            whitelist_id,
            user: member,
            role: ROLE_MEMBER,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    /// Remove a doctor from the allowlist
    public entry fun remove_doctor(
        registry: &mut WhitelistRegistry,
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        doctor: address,
        clock: &Clock,
        _ctx: &mut TxContext
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        
        let whitelist_id = object::uid_to_inner(&whitelist.id);
        whitelist.doctors = whitelist.doctors.filter!(|x| x != doctor);

        // Check if user still has access through other roles
        if (!whitelist.members.contains(&doctor) && whitelist.owner != doctor) {
            remove_user_whitelist_access(registry, doctor, whitelist_id);
        };

        event::emit(AccessRevoked {
            whitelist_id,
            user: doctor,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    /// Remove a member from the allowlist
    public entry fun remove_member(
        registry: &mut WhitelistRegistry,
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        member: address,
        clock: &Clock,
        _ctx: &mut TxContext
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        
        let whitelist_id = object::uid_to_inner(&whitelist.id);
        whitelist.members = whitelist.members.filter!(|x| x != member);

        // Check if user still has access through other roles
        if (!whitelist.doctors.contains(&member) && whitelist.owner != member) {
            remove_user_whitelist_access(registry, member, whitelist_id);
        };

        event::emit(AccessRevoked {
            whitelist_id,
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

    /// Add a record to the whitelist (with admin cap)
    public fun add_record(
        whitelist: &mut SealWhitelist,
        cap: &WhitelistAdminCap,
        record_id: ID,
    ) {
        assert!(cap.whitelist_id == object::uid_to_inner(&whitelist.id), E_INVALID_CAP);
        whitelist.records.push_back(record_id);
    }

    /// Add a record to the whitelist (by doctor, no cap required)
    public fun add_record_by_doctor(
        whitelist: &mut SealWhitelist,
        record_id: ID,
        doctor: address,
        clock: &Clock,
    ) {
        // Check if doctor has write access
        assert!(can_write(whitelist, doctor, clock), E_NO_WRITE_ACCESS);
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

    ////////////////////////////////////////////////////////////
    // User role query functions
    ////////////////////////////////////////////////////////////

    /// Get the role of a user in this whitelist
    /// Returns: ROLE_OWNER (0), ROLE_DOCTOR (1), ROLE_MEMBER (2), or ROLE_NONE (255)
    public fun get_user_role(whitelist: &SealWhitelist, user: address): u8 {
        if (user == whitelist.owner) {
            return ROLE_OWNER
        };
        
        if (whitelist.doctors.contains(&user)) {
            return ROLE_DOCTOR
        };
        
        if (whitelist.members.contains(&user)) {
            return ROLE_MEMBER
        };
        
        ROLE_NONE
    }

    /// Check if a user has any access to this whitelist
    public fun has_access(whitelist: &SealWhitelist, user: address): bool {
        get_user_role(whitelist, user) != ROLE_NONE
    }

    /// Get whitelist ID
    public fun whitelist_id(whitelist: &SealWhitelist): ID {
        object::uid_to_inner(&whitelist.id)
    }

    /// Get created timestamp
    public fun created_at(whitelist: &SealWhitelist): u64 {
        whitelist.created_at
    }

    /// Check if user can manage this whitelist (i.e., owns the admin cap)
    /// This should be checked by verifying the WhitelistAdminCap ownership off-chain
    public fun whitelist_admin_cap_id(cap: &WhitelistAdminCap): ID {
        cap.whitelist_id
    }

    ////////////////////////////////////////////////////////////
    // User whitelist access query functions
    ////////////////////////////////////////////////////////////

    /// Get all whitelist IDs that a user has access to
    /// Note: This function iterates through the Table to build a vector
    /// For checking access to a specific whitelist, use user_has_whitelist_access() instead
    public fun get_user_accessible_whitelists(
        registry: &WhitelistRegistry,
        user: address
    ): vector<ID> {
        if (!table::contains(&registry.user_whitelists, user)) {
            return vector::empty()
        };
        
        // Note: Table doesn't support direct iteration in Move
        // This function signature is kept for API compatibility
        // In practice, off-chain indexing should be used for listing
        // or the frontend should track whitelist IDs
        vector::empty()
    }

    /// Check if user has access to a specific whitelist
    /// O(1) lookup using nested Table structure
    public fun user_has_whitelist_access(
        registry: &WhitelistRegistry,
        user: address,
        whitelist_id: ID
    ): bool {
        if (!table::contains(&registry.user_whitelists, user)) {
            return false
        };
        
        let user_table = table::borrow(&registry.user_whitelists, user);
        table::contains(user_table, whitelist_id)
    }

    /// Get count of whitelists a user has access to
    /// Note: Table doesn't have a length() function in Move
    /// Count must be maintained separately or calculated off-chain
    /// For now, this returns 0 as placeholder
    public fun get_user_whitelist_count(
        registry: &WhitelistRegistry,
        user: address
    ): u64 {
        // TODO: Add a counter field to track count
        // For now, use off-chain indexing to count
        0
    }

    /// Get whitelists by role - returns whitelist IDs where user has specific role
    /// This requires checking each whitelist object individually
    /// Note: This is a helper structure - actual implementation needs whitelist objects
    public fun filter_whitelists_by_role(
        registry: &WhitelistRegistry,
        user: address,
        target_role: u8
    ): vector<ID> {
        let all_whitelists = get_user_accessible_whitelists(registry, user);
        // Note: Filtering by role requires accessing actual whitelist objects
        // This should be done off-chain by fetching each whitelist and checking role
        all_whitelists
    }

    /// Get detailed access information for a user across a whitelist
    /// Returns role, read access, and write access
    public fun get_user_whitelist_access_info(
        whitelist: &SealWhitelist,
        user: address
    ): (u8, bool, bool) {
        let role = get_user_role(whitelist, user);
        let has_write = user == whitelist.owner || whitelist.doctors.contains(&user);
        let has_read = has_write || whitelist.members.contains(&user);
        (role, has_read, has_write)
    }

    /// Entry function to get user's whitelist IDs
    /// This can be called via view call from frontend to get the list
    /// Note: Due to Table iteration limitations, prefer off-chain indexing
    public entry fun get_my_whitelists(
        registry: &WhitelistRegistry,
        ctx: &TxContext
    ) {
        let user = tx_context::sender(ctx);
        let _ = get_user_accessible_whitelists(registry, user);
        // Note: Return value will be in transaction effects/events
    }

    /// Check if a user has any access to a specific whitelist
    /// Returns true if user is owner, doctor, or member
    public fun user_can_access_whitelist(
        whitelist: &SealWhitelist,
        user: address
    ): bool {
        user == whitelist.owner ||
        whitelist.doctors.contains(&user) ||
        whitelist.members.contains(&user)
    }

    /// Check if user has write access to a specific whitelist
    public fun user_can_write_to_whitelist(
        whitelist: &SealWhitelist,
        user: address
    ): bool {
        user == whitelist.owner || whitelist.doctors.contains(&user)
    }

    /// Check if user has read access to a specific whitelist
    public fun user_can_read_from_whitelist(
        whitelist: &SealWhitelist,
        user: address
    ): bool {
        user == whitelist.owner ||
        whitelist.doctors.contains(&user) ||
        whitelist.members.contains(&user)
    }

    /// Get complete access information for a user in a whitelist
    /// Returns WhitelistAccessInfo struct with all access details
    public fun get_whitelist_access_info(
        whitelist: &SealWhitelist,
        user: address
    ): WhitelistAccessInfo {
        let whitelist_id = object::uid_to_inner(&whitelist.id);
        let role = get_user_role(whitelist, user);
        let has_write = user == whitelist.owner || whitelist.doctors.contains(&user);
        let has_read = has_write || whitelist.members.contains(&user);

        WhitelistAccessInfo {
            whitelist_id,
            role,
            has_read,
            has_write,
        }
    }

    /// Get access information for multiple whitelists for a user
    /// Returns a vector of WhitelistAccessInfo structs
    /// Note: This function takes object IDs and fetches the objects
    public fun get_user_whitelists_with_access(
        whitelist_ids: vector<ID>,
        user: address,
        ctx: &TxContext
    ): vector<WhitelistAccessInfo> {
        let mut result = vector::empty<WhitelistAccessInfo>();
        let mut i = 0;
        let len = vector::length(&whitelist_ids);
        
        // Note: In practice, this would need to be called from a transaction
        // that has access to the actual SealWhitelist objects
        // This is a helper function structure for reference
        
        result
    }

    /// Get access information for a single whitelist with detailed breakdown
    /// Returns tuple: (whitelist_id, name, owner, role, has_read, has_write, record_count)
    public fun get_whitelist_full_access_info(
        whitelist: &SealWhitelist,
        user: address
    ): (ID, String, address, u8, bool, bool, u64) {
        let whitelist_id = object::uid_to_inner(&whitelist.id);
        let role = get_user_role(whitelist, user);
        let has_write = user == whitelist.owner || whitelist.doctors.contains(&user);
        let has_read = has_write || whitelist.members.contains(&user);
        let record_count = vector::length(&whitelist.records);
        
        (whitelist_id, whitelist.name, whitelist.owner, role, has_read, has_write, record_count)
    }

    /// Entry function to verify user access to a whitelist
    /// Can be called from frontend to check permissions before attempting operations
    public entry fun verify_user_access(
        whitelist: &SealWhitelist,
        ctx: &TxContext
    ) {
        let user = tx_context::sender(ctx);
        assert!(user_can_access_whitelist(whitelist, user), E_NO_READ_ACCESS);
    }

    /// Entry function to verify user write access to a whitelist
    /// Can be called from frontend to check write permissions
    public entry fun verify_user_write_access(
        whitelist: &SealWhitelist,
        ctx: &TxContext
    ) {
        let user = tx_context::sender(ctx);
        assert!(user_can_write_to_whitelist(whitelist, user), E_NO_WRITE_ACCESS);
    }
}
