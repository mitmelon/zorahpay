// SPDX-License-Identifier: MIT
// ZorahPay Protocol v1.0 - Vault (Card) Contract
// Individual payment card with ZK-proof PIN security, multi-currency support, and intelligent swap routing

#[starknet::contract]
mod ZorahVault {
    // yield removed
    use core::num::traits::Zero;
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp,
        get_contract_address, ClassHash
    };
    use starknet::syscalls::library_call_syscall;
    use starknet::storage::Map;
    use openzeppelin::security::reentrancyguard::ReentrancyGuardComponent;
    use openzeppelin::upgrades::UpgradeableComponent;
    use openzeppelin::upgrades::interface::IUpgradeable;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // ============================================================================
    // COMPONENTS
    // ============================================================================
    
    component!(path: ReentrancyGuardComponent, storage: reentrancy, event: ReentrancyEvent);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    impl ReentrancyGuardInternalImpl = ReentrancyGuardComponent::InternalImpl<ContractState>;
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    // ============================================================================
    // CONSTANTS
    // ============================================================================

    const MAX_FAILED_ATTEMPTS: u8 = 3;
    const LOCKOUT_DURATION: u64 = 3600; // 1 hour
    const CHARGE_COOLDOWN: u64 = 30; // 30 seconds
    const MERCHANT_REQUEST_LIMIT: u8 = 10; // per hour
    const APPROVAL_LIMIT: u8 = 20; // per hour
    const RECURRING_INTERVAL: u64 = 2592000; // 30 days (non-leap)
    const RECURRING_INTERVAL_LEAP: u64 = 2592000; // Adjusted for leap years
    const RATE_LIMIT_WINDOW: u64 = 3600; // 1 hour
    const MAX_SLIPPAGE: u16 = 1000; // 10%
    const BASIS_POINTS: u256 = 10000;
    const SECONDS_PER_DAY: u64 = 86400;

    // ============================================================================
    // STORAGE
    // ============================================================================

    #[storage]
    struct Storage {
        // Components
        #[substorage(v0)]
        reentrancy: ReentrancyGuardComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,

        // Card identity
        owner: ContractAddress,
        admin: ContractAddress,
        authorized_relayer: ContractAddress,
        factory: ContractAddress,
        
        // Card status
        status: CardStatus,
        created_at: u64,
        
        // PIN security (ZK-proof based)
        pin_commitment: felt252,
        used_proof_nonces: Map<felt252, bool>,
        failed_attempts: u8,
        lockout_until: u64,
        
        // Currency configuration
        default_token: ContractAddress,
        accepted_currencies: Map<u32, ContractAddress>,
        currency_count: u32,
        is_currency_accepted: Map<ContractAddress, bool>,
        payment_mode: PaymentMode,
        slippage_tolerance_bps: u16,
        
        // Balance tracking
        token_balances: Map<ContractAddress, u256>,
        // cashback_balance removed; cashback is now credited directly to token_balances
        last_balance_sync: Map<ContractAddress, u64>,
        
        // Transaction limits
        max_transaction_amount: u256,
        daily_transaction_limit: u16,
        daily_spend_limit: u256,
        
        // Daily tracking
        daily_transaction_count: u16,
        daily_spend_amount: u256,
        last_daily_reset: u64,
        
        // Payment requests
        request_counter: u64,
        payment_requests: Map<u64, PaymentRequest>,
        request_status: Map<u64, RequestStatus>,
        
        // Merchant management
        merchant_blacklist: Map<ContractAddress, bool>,
        merchant_blacklist_reason: Map<ContractAddress, ByteArray>,
        merchant_whitelist: Map<ContractAddress, bool>,
        merchant_interactions: Map<ContractAddress, bool>, // Track unique merchants
        
        // Rate limiting
        merchant_request_timestamps: Map<(ContractAddress, u8), u64>,
        merchant_request_count: Map<ContractAddress, u8>,
        merchant_last_request_reset: Map<ContractAddress, u64>,
        
        approval_timestamps: Map<u8, u64>,
        approval_count: u8,
        approval_last_reset: u64,
        
        last_charge_timestamp: u64,
        
        // Transaction history
        transaction_counter: u64,
        transactions: Map<u64, TransactionRecord>,
        
        // Yield management removed
        
        // Credit scoring
        credit_score: u16, // 0-1000
        total_payments_made: u64,
        total_volume_processed: u256,
        on_time_payment_count: u64,
        
        // Fraud detection
        fraud_alerts: Map<u64, FraudAlert>,
        fraud_alert_count: u64,
        // Plugin registry: map plugin_id -> implementation class hash (multi-function plugins)
        plugin_registry: Map<felt252, ClassHash>,
    }

    // ============================================================================
    // EVENTS
    // ============================================================================

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ReentrancyEvent: ReentrancyGuardComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
        
        // Card lifecycle
        CardInitialized: CardInitialized,
        CardFrozen: CardFrozen,
        CardUnfrozen: CardUnfrozen,
        CardBurned: CardBurned,
        
        // PIN management
        PINUpdated: PINUpdated,
        
        // Currency management
        CurrencyAdded: CurrencyAdded,
        CurrencyRemoved: CurrencyRemoved,
        PaymentModeUpdated: PaymentModeUpdated,
        SlippageToleranceUpdated: SlippageToleranceUpdated,
        
        // Payment requests
        PaymentRequestSubmitted: PaymentRequestSubmitted,
        PaymentRequestApproved: PaymentRequestApproved,
        PaymentRequestRejected: PaymentRequestRejected,
        PaymentApprovalRevoked: PaymentApprovalRevoked,
        
        // Payments
        CardCharged: CardCharged,
        RecurringPaymentCharged: RecurringPaymentCharged,
        SwapExecuted: SwapExecuted,
        
        // Funds management
        FundsDeposited: FundsDeposited,
        FundsWithdrawn: FundsWithdrawn,
        CashbackWithdrawn: CashbackWithdrawn,
        
        // Merchant management
        MerchantBlacklisted: MerchantBlacklisted,
        MerchantUnblacklisted: MerchantUnblacklisted,
        MerchantWhitelisted: MerchantWhitelisted,
        
        // Yield (moved to plugin)
        
        // Security
        RateLimitExceeded: RateLimitExceeded,
        FraudAlertTriggered: FraudAlertTriggered,
        
        // Configuration
        LimitsUpdated: LimitsUpdated,
        CreditScoreUpdated: CreditScoreUpdated,
        // Plugin lifecycle
        PluginRegistered: PluginRegistered,
        PluginUnregistered: PluginUnregistered,
        PluginCalled: PluginCalled,
    }

    #[derive(Drop, starknet::Event)]
    struct CardInitialized {
        #[key]
        owner: ContractAddress,
        default_token: ContractAddress,
        payment_mode: PaymentMode,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CardFrozen {
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CardUnfrozen {
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CardBurned {
        owner: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PINUpdated {
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CurrencyAdded {
        token: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CurrencyRemoved {
        token: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentModeUpdated {
        old_mode: PaymentMode,
        new_mode: PaymentMode,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SlippageToleranceUpdated {
        old_tolerance: u16,
        new_tolerance: u16,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentRequestSubmitted {
        #[key]
        request_id: u64,
        #[key]
        merchant: ContractAddress,
        amount: u256,
        token: ContractAddress,
        is_recurring: bool,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentRequestApproved {
        #[key]
        request_id: u64,
        #[key]
        merchant: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentRequestRejected {
        #[key]
        request_id: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentApprovalRevoked {
        #[key]
        request_id: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CardCharged {
        #[key]
        request_id: u64,
        #[key]
        merchant: ContractAddress,
        #[key]
        payout_wallet: ContractAddress,
        amount: u256,
        token_in: ContractAddress,
        token_out: ContractAddress,
        swap_occurred: bool,
        swap_fee: u256,
        transaction_fee: u256,
        cashback: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct RecurringPaymentCharged {
        #[key]
        request_id: u64,
        #[key]
        merchant: ContractAddress,
        charge_number: u32,
        amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SwapExecuted {
        token_in: ContractAddress,
        token_out: ContractAddress,
        amount_in: u256,
        amount_out: u256,
        swap_fee: u256,
        price_impact: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct FundsDeposited {
        #[key]
        token: ContractAddress,
        amount: u256,
        depositor: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct FundsWithdrawn {
        #[key]
        token: ContractAddress,
        amount: u256,
        timestamp: u64,
    }

    // CashbackWithdrawn event removed

    #[derive(Drop, starknet::Event)]
    struct MerchantBlacklisted {
        #[key]
        merchant: ContractAddress,
        reason: ByteArray,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MerchantUnblacklisted {
        #[key]
        merchant: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MerchantWhitelisted {
        #[key]
        merchant: ContractAddress,
        timestamp: u64,
    }

    // Yield events removed; yield handled by plugin.

    #[derive(Drop, starknet::Event)]
    struct RateLimitExceeded {
        limit_type: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct FraudAlertTriggered {
        #[key]
        alert_id: u64,
        #[key]
        request_id: u64,
        alert_type: felt252,
        severity: u8,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct LimitsUpdated {
        max_transaction_amount: u256,
        daily_transaction_limit: u16,
        daily_spend_limit: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CreditScoreUpdated {
        old_score: u16,
        new_score: u16,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PluginRegistered {
        #[key]
        plugin_id: felt252,
        class_hash: ClassHash,
    }

    #[derive(Drop, starknet::Event)]
    struct PluginUnregistered {
        #[key]
        plugin_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct PluginCalled {
        #[key]
        plugin_id: felt252,
        #[key]
        selector: felt252,
        caller: ContractAddress,
    }

    // ============================================================================
    // DATA STRUCTURES
    // ============================================================================

    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
    enum CardStatus {
        Active,
        Frozen,
        Burned,
    }

    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
    enum PaymentMode {
        MerchantTokenOnly,
        AnyAcceptedToken,
        DefaultTokenOnly,
    }

    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
    enum RequestStatus {
        Pending,
        Approved,
        Rejected,
        Charged,
        Revoked,
    }

    #[derive(Drop, Serde, starknet::Store)]
    struct PaymentRequest {
        request_id: u64,
        merchant: ContractAddress,
        amount: u256,
        token: ContractAddress,
        is_recurring: bool,
        status: RequestStatus,
        description: ByteArray,
        metadata: ByteArray,
        created_at: u64,
        approved_at: u64,
        last_charged_at: u64,
        charge_count: u32,
        balance_validated: bool,
    }

    #[derive(Drop, Serde, starknet::Store)]
    struct TransactionRecord {
        transaction_id: u64,
        request_id: u64,
        merchant: ContractAddress,
        payout_wallet: ContractAddress,
        amount: u256,
        token_in: ContractAddress,
        token_out: ContractAddress,
        swap_occurred: bool,
        swap_fee: u256,
        slippage_paid: u256,
        transaction_fee: u256,
        cashback_amount: u256,
        timestamp: u64,
        transaction_type: felt252,
    }

    #[derive(Drop, Serde)]
    struct ZKProof {
        proof_a: Span<felt252>,
        proof_b: Span<felt252>,
        proof_c: Span<felt252>,
        public_inputs: Span<felt252>,
    }

    // YieldPosition removed; yield functionality moved to plugins

    #[derive(Drop, Serde, starknet::Store)]
    struct FraudAlert {
        alert_id: u64,
        request_id: u64,
        merchant: ContractAddress,
        alert_type: felt252,
        severity: u8,
        message: ByteArray,
        timestamp: u64,
        auto_blocked: bool,
    }

    #[derive(Drop, Serde)]
    struct FraudScore {
        risk_level: u8,
        flags: Span<felt252>,
        recommendation: felt252,
    }

    #[derive(Drop, Serde)]
    struct CardConfig {
        max_transaction_amount: u256,
        daily_transaction_limit: u16,
        daily_spend_limit: u256,
        slippage_tolerance_bps: u16,
    }

    #[derive(Drop, Serde)]
    struct CardInfo {
        card_address: ContractAddress,
        owner: ContractAddress,
        default_token: ContractAddress,
        is_frozen: bool,
        is_burned: bool,
        created_at: u64,
        payment_mode: PaymentMode,
        slippage_tolerance_bps: u16,
    }

    #[derive(Drop, Serde)]
    struct RateLimitStatus {
        is_locked: bool,
        failed_attempts: u8,
        lockout_until: u64,
        requests_submitted_last_hour: u8,
        approvals_last_hour: u8,
        charges_last_hour: u8,
        last_charge_timestamp: u64,
        cooldown_remaining: u64,
    }

    #[derive(Drop, Serde)]
    struct TokenBalance {
        token: ContractAddress,
        balance: u256,
        is_default: bool,
        last_updated: u64,
    }

    #[derive(Drop, Serde)]
    struct BalanceSummary {
        balances: Span<TokenBalance>,
        // cashback_balance removed; cashback is now part of balances
        total_value_usd: u256,
    }

    #[derive(Drop, Serde)]
    struct TransactionSummary {
        total_spent: u256,
        total_received: u256,
        total_cashback_earned: u256,
        total_swap_fees_paid: u256,
        total_tx_fees_charged: u256,
        transaction_count: u64,
        unique_merchants: u32,
        transactions: Span<TransactionRecord>,
    }

    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        admin: ContractAddress,
        authorized_relayer: ContractAddress,
        default_token: ContractAddress,
        pin_commitment: felt252,
        accepted_currencies: Span<ContractAddress>,
        payment_mode: PaymentMode,
        initial_config: CardConfig,
    ) {
        // Validate inputs
        assert(!owner.is_zero(), 'Invalid owner');
        assert(!admin.is_zero(), 'Invalid admin');
        assert(!default_token.is_zero(), 'Invalid default token');
        assert(pin_commitment != 0, 'Invalid PIN commitment');
        assert(accepted_currencies.len() > 0, 'No currencies');
        
        // Set card identity
        self.owner.write(owner);
        self.admin.write(admin);
        self.authorized_relayer.write(authorized_relayer);
        self.factory.write(get_caller_address()); // Factory is deployer
        
        // Set card status
        self.status.write(CardStatus::Active);
        let timestamp = get_block_timestamp();
        self.created_at.write(timestamp);
        
        // Set PIN commitment (ZK-proof based)
        self.pin_commitment.write(pin_commitment);
        
        // Set currency configuration
        self.default_token.write(default_token);
        self.payment_mode.write(payment_mode);
        self.slippage_tolerance_bps.write(initial_config.slippage_tolerance_bps);
        
        // Add accepted currencies
        let mut i: u32 = 0;
        loop {
            if i >= accepted_currencies.len() {
                break;
            }
            let token = *accepted_currencies.at(i);
            assert(!token.is_zero(), 'Invalid currency');
            
                self.accepted_currencies.entry(i).write(token);
                self.is_currency_accepted.entry(token).write(true);
            i += 1;
        };
        self.currency_count.write(i);
        
        // Ensure default token is in accepted list
        if !self.is_currency_accepted.entry(default_token).read() {
                self.accepted_currencies.entry(i).write(default_token);
                self.is_currency_accepted.entry(default_token).write(true);
            self.currency_count.write(i + 1);
        }
        
        // Set transaction limits
        self.max_transaction_amount.write(initial_config.max_transaction_amount);
        self.daily_transaction_limit.write(initial_config.daily_transaction_limit);
        self.daily_spend_limit.write(initial_config.daily_spend_limit);
        
        // Initialize daily tracking
        self.last_daily_reset.write(timestamp);
        
        // Initialize credit score at 500 (50%)
        self.credit_score.write(500);
        
        // Emit initialization event
        self.emit(CardInitialized {
            owner,
            default_token,
            payment_mode,
            timestamp,
        });
    }

    // ============================================================================
    // EXTERNAL FUNCTIONS
    // ============================================================================

    #[abi(embed_v0)]
    impl ZorahVaultImpl of super::IZorahVault<ContractState> {

        /// Returns the current credit score for the card/user.
        fn get_credit_score(self: @ContractState) -> u16 {
            self.credit_score.read()
        }
        
        // ========================================================================
        // A. CARD INITIALIZATION & PIN MANAGEMENT
        // ========================================================================

        fn update_pin(
            ref self: ContractState,
            old_pin_proof: ZKProof,
            new_pin_commitment: felt252,
            proof_nonce: felt252,
        ) {
            self._assert_owner_or_relayer();
            self._assert_not_burned();
            self._check_rate_limit();
            
            // Verify old PIN
            self._verify_zkproof(old_pin_proof, proof_nonce);
            
            // Update PIN commitment
            self.pin_commitment.write(new_pin_commitment);
            
            self.emit(PINUpdated {
                timestamp: get_block_timestamp(),
            });
        }

        // ========================================================================
        // B. CURRENCY CONFIGURATION
        // ========================================================================

        fn add_accepted_currency(
            ref self: ContractState,
            token: ContractAddress,
            pin_proof: Option<ZKProof>,
            proof_nonce: felt252,
        ) {
            self._assert_not_burned();
            assert(!token.is_zero(), 'Invalid token');
            
            let caller = get_caller_address();
            if caller == self.owner.read() {
                // Owner must provide ZK-proof
                assert(pin_proof.is_some(), 'PIN proof required');
                self._verify_zkproof(pin_proof.unwrap(), proof_nonce);
            } else if caller == self.authorized_relayer.read() {
                // Relayer doesn't need proof
            } else {
                panic(array!['Unauthorized']);
            }
            
            // Add currency if not already accepted
            if !self.is_currency_accepted.entry(token).read() {
                let count = self.currency_count.read();
                self.accepted_currencies.entry(count).write(token);
                self.is_currency_accepted.entry(token).write(true);
                self.currency_count.write(count + 1);
                
                self.emit(CurrencyAdded {
                    token,
                    timestamp: get_block_timestamp(),
                });
            }
        }

        fn remove_accepted_currency(
            ref self: ContractState,
            token: ContractAddress,
            pin_proof: Option<ZKProof>,
            proof_nonce: felt252,
        ) {
            self._assert_not_burned();
            
            let caller = get_caller_address();
            if caller == self.owner.read() {
                self._verify_zkproof(pin_proof.unwrap(), proof_nonce);
            } else if caller != self.authorized_relayer.read() {
                panic(array!['Unauthorized']);
            }
            
            // Cannot remove default token
            assert(token != self.default_token.read(), 'Cannot remove default');
            
            // Remove currency
                self.is_currency_accepted.entry(token).write(false);
            
            self.emit(CurrencyRemoved {
                token,
                timestamp: get_block_timestamp(),
            });
        }

        fn update_payment_mode(
            ref self: ContractState,
            new_mode: PaymentMode,
            pin_proof: Option<ZKProof>,
            proof_nonce: felt252,
        ) {
            self._assert_not_burned();
            
            let caller = get_caller_address();
            if caller == self.owner.read() {
                self._verify_zkproof(pin_proof.unwrap(), proof_nonce);
            } else if caller != self.authorized_relayer.read() {
                panic(array!['Unauthorized']);
            }
            
            let old_mode = self.payment_mode.read();
            self.payment_mode.write(new_mode);
            
            self.emit(PaymentModeUpdated {
                old_mode,
                new_mode,
                timestamp: get_block_timestamp(),
            });
        }

        fn set_slippage_tolerance(
            ref self: ContractState,
            tolerance_bps: u16,
            pin_proof: Option<ZKProof>,
            proof_nonce: felt252,
        ) {
            self._assert_not_burned();
            assert(tolerance_bps <= MAX_SLIPPAGE, 'Slippage too high');
            
            let caller = get_caller_address();
            if caller == self.owner.read() {
                self._verify_zkproof(pin_proof.unwrap(), proof_nonce);
            } else if caller != self.authorized_relayer.read() {
                panic(array!['Unauthorized']);
            }
            
            let old_tolerance = self.slippage_tolerance_bps.read();
            self.slippage_tolerance_bps.write(tolerance_bps);
            
            self.emit(SlippageToleranceUpdated {
                old_tolerance,
                new_tolerance: tolerance_bps,
                timestamp: get_block_timestamp(),
            });
        }

        fn get_accepted_currencies(self: @ContractState) -> Span<ContractAddress> {
            let count = self.currency_count.read();
            let mut currencies = ArrayTrait::new();
            
            let mut i: u32 = 0;
            loop {
                if i >= count {
                    break;
                }
                currencies.append(self.accepted_currencies.entry(i).read());
                i += 1;
            };
            
            currencies.span()
        }

        fn get_default_token(self: @ContractState) -> ContractAddress {
            self.default_token.read()
        }

        fn get_payment_mode(self: @ContractState) -> PaymentMode {
            self.payment_mode.read()
        }

        fn is_currency_accepted(self: @ContractState, token: ContractAddress) -> bool {
            self.is_currency_accepted.entry(token).read()
        }

        // ========================================================================
        // C. PAYMENT REQUEST MANAGEMENT
        // ========================================================================

        fn submit_payment_request(
            ref self: ContractState,
            merchant: ContractAddress,
            amount: u256,
            token: ContractAddress,
            is_recurring: bool,
            description: ByteArray,
            metadata: ByteArray,
        ) -> u64 {
            self.reentrancy.start();
            self._assert_not_frozen();
            
            let timestamp = get_block_timestamp();
            
            // CRITICAL: Verify merchant is registered with factory
            let factory = IZorahFactoryDispatcher { contract_address: self.factory.read() };
            assert(factory.is_merchant_registered(merchant), 'Merchant not registered');
            assert(!factory.is_merchant_globally_blacklisted(merchant), 'Merchant globally blocked');
            
            // Check merchant not blacklisted on this card
            assert(!self.merchant_blacklist.entry(merchant).read(), 'Merchant blacklisted');

            // Check merchant request rate limit
            self._check_merchant_request_limit(merchant);

            // Check merchant reputation (require minimum score to submit requests)
            let reputation = factory.get_merchant_reputation(merchant);
            assert(reputation.reputation_score >= 200, 'Low reputation score');
            
            // CRITICAL: Validate currency accepted
            assert(self.is_currency_accepted.entry(token).read(), 'Currency not accepted');
            
            // CRITICAL: Validate balance based on payment mode
            let payment_mode = self.payment_mode.read();
            let balance_valid = self._validate_balance_for_request(amount, token, payment_mode);
            assert(balance_valid, 'Insufficient balance');
            
            // Create payment request
            let request_id = self.request_counter.read() + 1;
            self.request_counter.write(request_id);
            
            let request = PaymentRequest {
                request_id,
                merchant,
                amount,
                token,
                is_recurring,
                status: RequestStatus::Pending,
                description: description.clone(),
                metadata,
                created_at: timestamp,
                approved_at: 0,
                last_charged_at: 0,
                charge_count: 0,
                balance_validated: true,
            };
            
            self.payment_requests.entry(request_id).write(request);
            self.request_status.entry(request_id).write(RequestStatus::Pending);
            
            // Track merchant interaction
            if !self.merchant_interactions.entry(merchant).read() {
                self.merchant_interactions.entry(merchant).write(true);
            }
            
            self.emit(PaymentRequestSubmitted {
                request_id,
                merchant,
                amount,
                token,
                is_recurring,
                timestamp,
            });
            
            self.reentrancy.end();
            request_id
        }

        fn approve_payment_request(
            ref self: ContractState,
            request_id: u64,
            pin_proof: ZKProof,
            proof_nonce: felt252,
        ) {
            self._assert_not_frozen();
            self._assert_owner_or_relayer();
            self._check_approval_rate_limit();
            
            // Verify PIN via ZK-proof
            self._verify_zkproof(pin_proof, proof_nonce);
            
            // Get request
            let mut request = self.payment_requests.entry(request_id).read();
            assert(request.request_id != 0, 'Request not found');
            assert(request.status == RequestStatus::Pending, 'Request not pending');
            
            // Re-validate balance
            let balance_valid = self._validate_balance_for_request(
                request.amount,
                request.token,
                self.payment_mode.read()
            );
            assert(balance_valid, 'Insufficient balance');
            
            // Check fraud score
            let fraud_score = self._check_fraud_score(request_id);
            if fraud_score.risk_level > 80 {
                // High risk - create alert
                self._create_fraud_alert(
                    request_id,
                    request.merchant,
                    'high_risk_score',
                    8,
                    "High fraud risk detected",
                    false
                );
            }
            
            // Approve request
            let timestamp = get_block_timestamp();
            request.status = RequestStatus::Approved;
            request.approved_at = timestamp;
            self.payment_requests.entry(request_id).write(request);
            self.request_status.entry(request_id).write(RequestStatus::Approved);
            
            self.emit(PaymentRequestApproved {
                request_id,
                merchant: request.merchant,
                timestamp,
            });
        }

        fn approve_multiple_requests(
            ref self: ContractState,
            request_ids: Span<u64>,
            pin_proof: ZKProof,
            proof_nonce: felt252,
        ) {
            self._assert_not_frozen();
            self._assert_owner_or_relayer();
            
            assert(request_ids.len() <= 10, 'Max 10 requests');
            
            // Single ZK-proof verification for all
            self._verify_zkproof(pin_proof, proof_nonce);
            
            let timestamp = get_block_timestamp();
            let mut i = 0;
            loop {
                if i >= request_ids.len() {
                    break;
                }
                
                let request_id = *request_ids.at(i);
                let mut request = self.payment_requests.entry(request_id).read();
                
                if request.request_id != 0 && request.status == RequestStatus::Pending {
                    request.status = RequestStatus::Approved;
                    request.approved_at = timestamp;
                    self.payment_requests.entry(request_id).write(request);
                    self.request_status.entry(request_id).write(RequestStatus::Approved);
                    
                    self.emit(PaymentRequestApproved {
                        request_id,
                        merchant: request.merchant,
                        timestamp,
                    });
                }
                
                i += 1;
            };
        }

        fn reject_payment_request(
            ref self: ContractState,
            request_id: u64,
            pin_proof: ZKProof,
            proof_nonce: felt252,
        ) {
            self._assert_owner_or_relayer();
            self._verify_zkproof(pin_proof, proof_nonce);
            
            let mut request = self.payment_requests.entry(request_id).read();
            assert(request.request_id != 0, 'Request not found');
            
            request.status = RequestStatus::Rejected;
            self.payment_requests.entry(request_id).write(request);
            self.request_status.entry(request_id).write(RequestStatus::Rejected);
            
            self.emit(PaymentRequestRejected {
                request_id,
                timestamp: get_block_timestamp(),
            });
        }

        fn revoke_payment_approval(
            ref self: ContractState,
            request_id: u64,
            pin_proof: ZKProof,
            proof_nonce: felt252,
        ) {
            self._assert_owner_or_relayer();
            self._verify_zkproof(pin_proof, proof_nonce);
            
            let mut request = self.payment_requests.entry(request_id).read();
            assert(request.request_id != 0, 'Request not found');
            assert(request.status == RequestStatus::Approved, 'Not approved');
            
            request.status = RequestStatus::Revoked;
            self.payment_requests.entry(request_id).write(request);
            self.request_status.entry(request_id).write(RequestStatus::Revoked);
            
            self.emit(PaymentApprovalRevoked {
                request_id,
                timestamp: get_block_timestamp(),
            });
        }

        fn get_pending_requests(
            self: @ContractState,
            offset: u64,
            limit: u8,
        ) -> Span<PaymentRequest> {
            self._assert_owner_or_relayer();
            
            let actual_limit = if limit > 100 { 100 } else { limit };
            let mut requests = ArrayTrait::new();
            let total = self.request_counter.read();
            
            let mut i = offset + 1;
            let mut count = 0_u8;
            loop {
                if i > total || count >= actual_limit {
                    break;
                }
                
                let status = self.request_status.entry(i).read();
                if status == RequestStatus::Pending {
                    requests.append(self.payment_requests.entry(i).read());
                    count += 1;
                }
                
                i += 1;
            };
            
            requests.span()
        }

        fn get_approved_requests(
            self: @ContractState,
            offset: u64,
            limit: u8,
        ) -> Span<PaymentRequest> {
            self._assert_owner_or_relayer();
            
            let actual_limit = if limit > 100 { 100 } else { limit };
            let mut requests = ArrayTrait::new();
            let total = self.request_counter.read();
            
            let mut i = offset + 1;
            let mut count = 0_u8;
            loop {
                if i > total || count >= actual_limit {
                    break;
                }
                
                let status = self.request_status.entry(i).read();
                if status == RequestStatus::Approved {
                    requests.append(self.payment_requests.entry(i).read());
                    count += 1;
                }
                
                i += 1;
            };
            
            requests.span()
        }

        fn get_request_details(self: @ContractState, request_id: u64) -> PaymentRequest {
            self._assert_owner_or_relayer();
            
            let request = self.payment_requests.entry(request_id).read();
            assert(request.request_id != 0, 'Request not found');
            request
        }

        fn get_request_status(self: @ContractState, request_id: u64) -> (RequestStatus, Option<TransactionRecord>) {
            // Public function for merchants to check their request status
            let request = self.payment_requests.entry(request_id).read();
            assert(request.request_id != 0, 'Request not found');

            let status = self.request_status.entry(request_id).read();
            
            // If charged, return transaction data
            if status == RequestStatus::Charged && request.charge_count > 0 {
                // Find the transaction for this request
                let total_txs = self.transaction_counter.read();
                let mut i = 1_u64;
                loop {
                    if i > total_txs {
                        break;
                    }
                    
                    let tx = self.transactions.entry(i).read();
                    if tx.request_id == request_id {
                        return (status, Option::Some(tx));
                    }
                    
                    i += 1;
                };
            }
            
            (status, Option::None)
        }

        // ========================================================================
        // D. PAYMENT EXECUTION WITH INTELLIGENT SWAP ROUTING
        // ========================================================================

        fn charge_card(
            ref self: ContractState,
            request_id: u64,
            quote: Option<OffchainQuote>,
            slippage_tolerance_bps: u16,
            deadline: u64,
        ) {
            self.reentrancy.start();
            self._assert_not_frozen();
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            assert(timestamp <= deadline, 'Deadline passed');
            let last_charge = self.last_charge_timestamp.read();
            assert(timestamp >= last_charge + CHARGE_COOLDOWN, 'Cooldown active');

            let mut request = self.payment_requests.entry(request_id).read();
            assert(request.request_id != 0, 'Request not found');
            assert(request.status == RequestStatus::Approved, 'Not approved');
            assert(!request.is_recurring, 'Use charge_recurring');

            let is_owner = caller == self.owner.read();
            let is_relayer = caller == self.authorized_relayer.read();
            let is_merchant = caller == request.merchant;
            assert(is_owner || is_relayer || is_merchant, 'Unauthorized');

            let factory = IZorahFactoryDispatcher { contract_address: self.factory.read() };
            assert(factory.is_merchant_registered(request.merchant), 'Merchant not registered');
            assert(!factory.is_merchant_globally_blacklisted(request.merchant), 'Merchant blocked');
            assert(!self.merchant_blacklist.entry(request.merchant).read(), 'Merchant blacklisted');

            let reputation = factory.get_merchant_reputation(request.merchant);
            assert(reputation.reputation_score >= 200, 'Low reputation score');

            let fraud_score = self._check_fraud_score(request_id);
            assert(fraud_score.risk_level < 90, 'Fraud risk too high');

            let payout_wallet = factory.get_merchant_payout_wallet(request.merchant);
            assert(!payout_wallet.is_zero(), 'Invalid payout wallet');

            // === DETERMINE IF SWAP IS NEEDED ===
            let source_token = self._determine_source_token(request.token, request.amount);
            let swap_needed = source_token != request.token;

            let mut transaction_fee: u256 = 0;
            let mut cashback: u256 = 0;
            let mut transaction_fee: u256 = 0;
            let mut cashback: u256 = 0;
            let (swap_occurred, actual_swap_fee, final_token_in) = if swap_needed {
                // Swap required → quote MUST be provided
                assert(quote.is_some(), 'Quote required for swap');
                let q = quote.unwrap();

                // Validate quote matches intent
                assert(q.buy_token_address == request.token, 'Quote output mismatch');
                assert(q.sell_token_address == source_token, 'Quote input mismatch');

                // Execute swap: leave output tokens in the vault, we'll deduct fees and then pay the payout wallet
                let res = self._execute_swap_with_quote(
                    request.amount,
                    request.token,
                    q,
                    slippage_tolerance_bps,
                    deadline
                );

                // After swap, deduct fees from the vault balance and transfer net to payout
                let (tf, cb) = self._apply_transaction_fee(request.amount, request.token, request.merchant);
                transaction_fee = tf;
                cashback = cb;
                let admin_share = transaction_fee - cashback;
                let net = request.amount - transaction_fee;

                // Ensure swap produced expected output and vault has enough to cover payout + admin share
                let out_dispatcher = IERC20Dispatcher { contract_address: request.token };
                let card = get_contract_address();
                let final_balance = out_dispatcher.balance_of(card);
                assert(final_balance >= request.amount, 'Insufficient output after swap');

                let total_to_send = net + admin_share;
                assert(final_balance >= total_to_send, 'Insufficient for payout+fee');

                let sent_net = out_dispatcher.transfer(payout_wallet, net);
                assert(sent_net, 'Send to merchant failed');

                if admin_share > 0 {
                    let config = factory.get_protocol_config();
                    let admin_wallet = config.admin_wallet;
                    let sent_admin = out_dispatcher.transfer(admin_wallet, admin_share);
                    assert(sent_admin, 'Admin transfer failed');
                }

                // Update internal tracked balance for token_out
                let remaining = out_dispatcher.balance_of(card);
                self.token_balances.entry(request.token).write(remaining);

                res
            } else {
                // Direct transfer → no quote needed
                assert(quote.is_none(), 'Quote not needed for direct transfer');
                // Compute fee and deduct from payout
                let (tf, cb) = self._apply_transaction_fee(request.amount, request.token, request.merchant);
                transaction_fee = tf;
                cashback = cb;
                let admin_share = transaction_fee - cashback;
                let net = request.amount - transaction_fee;

                    let balance = self.token_balances.entry(request.token).read();
                let total_to_send = net + admin_share;
                assert(balance >= total_to_send, 'Insufficient for payout+fee');

                // Update internal balance and transfer out net + admin share
                self.token_balances.entry(request.token).write(balance - total_to_send);
                let dispatcher = IERC20Dispatcher { contract_address: request.token };
                let success = dispatcher.transfer(payout_wallet, net);
                assert(success, 'Transfer failed');

                if admin_share > 0 {
                    let config = factory.get_protocol_config();
                    let sent_admin = dispatcher.transfer(config.admin_wallet, admin_share);
                    assert(sent_admin, 'Admin transfer failed');
                }

                (false, 0_u256, request.token)
            };

            // transaction_fee and cashback set by the branch above

            request.status = RequestStatus::Charged;
            request.last_charged_at = timestamp;
            request.charge_count = 1;
            self.payment_requests.entry(request_id).write(request);
            self.request_status.entry(request_id).write(RequestStatus::Charged);

            self._record_transaction(
                request_id,
                request.merchant,
                payout_wallet,
                request.amount,
                final_token_in,
                request.token,
                swap_occurred,
                actual_swap_fee,
                transaction_fee,
                cashback,
                'charge_one_time'
            );

            self.last_charge_timestamp.write(timestamp);
            self._update_daily_tracking(request.amount);
            self._update_credit_score(true, request.amount);

            factory.update_merchant_reputation(
                request.merchant,
                get_contract_address(),
                request.amount,
                true
            );

            self.emit(CardCharged {
                request_id,
                merchant: request.merchant,
                payout_wallet,
                amount: request.amount,
                token_in: final_token_in,
                token_out: request.token,
                swap_occurred,
                swap_fee: actual_swap_fee,
                transaction_fee,
                cashback,
                timestamp,
            });
            self.reentrancy.end();
        }

        fn charge_recurring(
            ref self: ContractState,
            request_id: u64,
            quote: Option<OffchainQuote>,
            slippage_tolerance_bps: u16,
            deadline: u64,
        ) {
            self.reentrancy.start();
            self._assert_not_frozen();
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            assert(timestamp <= deadline, 'Deadline passed');
            let last_charge = self.last_charge_timestamp.read();
            assert(timestamp >= last_charge + CHARGE_COOLDOWN, 'Cooldown active');

            let mut request = self.payment_requests.entry(request_id).read();
            assert(request.request_id != 0, 'Request not found');
            assert(request.status == RequestStatus::Approved, 'Not approved');
            assert(request.is_recurring, 'Not recurring');

            let is_merchant = caller == request.merchant;
            assert(is_merchant, 'Only merchant can charge');

            if request.last_charged_at > 0 {
                let interval = self._calculate_recurring_interval(request.last_charged_at, timestamp);
                assert(timestamp >= request.last_charged_at + interval, 'Too soon for recurring');
            }

            let factory = IZorahFactoryDispatcher { contract_address: self.factory.read() };
            assert(factory.is_merchant_registered(request.merchant), 'Merchant not registered');
            assert(!factory.is_merchant_globally_blacklisted(request.merchant), 'Merchant blocked');
            assert(!self.merchant_blacklist.entry(request.merchant).read(), 'Merchant blacklisted');

            let reputation = factory.get_merchant_reputation(request.merchant);
            assert(reputation.reputation_score >= 200, 'Low reputation score');

            let payout_wallet = factory.get_merchant_payout_wallet(request.merchant);
            assert(!payout_wallet.is_zero(), 'Invalid payout wallet');

            let source_token = self._determine_source_token(request.token, request.amount);
            let swap_needed = source_token != request.token;

            let (swap_occurred, actual_swap_fee, final_token_in) = if swap_needed {
                assert(quote.is_some(), 'Quote required for swap');
                let q = quote.unwrap();
                assert(q.buy_token_address == request.token, 'Quote output mismatch');
                assert(q.sell_token_address == source_token, 'Quote input mismatch');
                let res = self._execute_swap_with_quote(
                    request.amount,
                    request.token,
                    q,
                    slippage_tolerance_bps,
                    deadline
                );

                // Compute fee and perform payout/admin transfers from vault
                let (tf, cb) = self._apply_transaction_fee(request.amount, request.token, request.merchant);
                transaction_fee = tf;
                cashback = cb;
                let admin_share = transaction_fee - cashback;
                let net = request.amount - transaction_fee;

                let out_dispatcher = IERC20Dispatcher { contract_address: request.token };
                let card = get_contract_address();
                let final_balance = out_dispatcher.balance_of(card);

                //Stop payment here to avoid merchant getting less fee.
                assert(final_balance >= request.amount, 'Insufficient output after swap');

                let total_to_send = net + admin_share;
                assert(final_balance >= total_to_send, 'Insufficient for payout+fee');

                let sent_net = out_dispatcher.transfer(payout_wallet, net);
                assert(sent_net, 'Send to merchant failed');

                if admin_share > 0 {
                    let config = factory.get_protocol_config();
                    let admin_wallet = config.admin_wallet;
                    let sent_admin = out_dispatcher.transfer(admin_wallet, admin_share);
                    assert(sent_admin, 'Admin transfer failed');
                }

                let remaining = out_dispatcher.balance_of(card);
                self.token_balances.entry(request.token).write(remaining);

                res
            } else {
                assert(quote.is_none(), 'Quote not needed');

                // Compute fee and deduct before payout
                let (tf, cb) = self._apply_transaction_fee(request.amount, request.token, request.merchant);
                transaction_fee = tf;
                cashback = cb;
                let admin_share = transaction_fee - cashback;
                let net = request.amount - transaction_fee;

                let balance = self.token_balances.entry(request.token).read();
                let total_to_send = net + admin_share;
                assert(balance >= total_to_send, 'Insufficient for payout+fee');

                self.token_balances.entry(request.token).write(balance - total_to_send);
                let dispatcher = IERC20Dispatcher { contract_address: request.token };
                let success = dispatcher.transfer(payout_wallet, net);
                assert(success, 'Transfer failed');

                if admin_share > 0 {
                    let config = factory.get_protocol_config();
                    let sent_admin = dispatcher.transfer(config.admin_wallet, admin_share);
                    assert(sent_admin, 'Admin transfer failed');
                }

                (false, 0_u256, request.token)
            };

            // transaction_fee and cashback set by branch above

            request.last_charged_at = timestamp;
            request.charge_count += 1;
            self.payment_requests.entry(request_id).write(request);

            self._record_transaction(
                request_id,
                request.merchant,
                payout_wallet,
                request.amount,
                final_token_in,
                request.token,
                swap_occurred,
                actual_swap_fee,
                transaction_fee,
                cashback,
                'charge_recurring'
            );

            self.last_charge_timestamp.write(timestamp);
            self._update_daily_tracking(request.amount);
            self._update_credit_score(true, request.amount);

            factory.update_merchant_reputation(
                request.merchant,
                get_contract_address(),
                request.amount,
                true
            );

            self.emit(RecurringPaymentCharged {
                request_id,
                merchant: request.merchant,
                charge_number: request.charge_count,
                amount: request.amount,
                timestamp,
            });
            self.reentrancy.end();
        }

        // ========================================================================
        // E. FUNDS MANAGEMENT
        // ========================================================================

        fn deposit_funds(
            ref self: ContractState,
            token: ContractAddress,
            amount: u256,
        ) {
            self._assert_not_frozen();
            assert(self.is_currency_accepted.entry(token).read(), 'Currency not accepted');
            assert(amount > 0, 'Invalid amount');
            
            let caller = get_caller_address();
            let card = get_contract_address();
            
            // Transfer tokens to card
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            let success = token_dispatcher.transfer_from(caller, card, amount);
            assert(success, 'Transfer failed');
            
            // Update balance
            let current_balance = self.token_balances.entry(token).read();
            self.token_balances.entry(token).write(current_balance + amount);
            
            self.emit(FundsDeposited {
                token,
                amount,
                depositor: caller,
                timestamp: get_block_timestamp(),
            });
        }

        fn withdraw_funds(
            ref self: ContractState,
            token: ContractAddress,
            amount: u256,
            pin_proof: ZKProof,
            proof_nonce: felt252,
        ) {
            self.reentrancy.start();
            self._assert_not_frozen();
            self._assert_owner();
            
            // Verify PIN
            self._verify_zkproof(pin_proof, proof_nonce);
            
            assert(amount > 0, 'Invalid amount');
            
            // Check balance
            let balance = self.token_balances.entry(token).read();
            assert(balance >= amount, 'Insufficient balance');
            
            // Update balance
            self.token_balances.entry(token).write(balance - amount);
            
            // Transfer to owner
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            let success = token_dispatcher.transfer(self.owner.read(), amount);
            assert(success, 'Transfer failed');
            
            self.emit(FundsWithdrawn {
                token,
                amount,
                timestamp: get_block_timestamp(),
            });
            
            self.reentrancy.end();
        }

        // withdraw_cashback removed; cashback is now credited directly to token_balances

        fn sync_balances(ref self: ContractState, tokens: Span<ContractAddress>) {
            let card = get_contract_address();
            let mut i = 0;
            
            loop {
                if i >= tokens.len() {
                    break;
                }
                
                let token = *tokens.at(i);
                let token_dispatcher = IERC20Dispatcher { contract_address: token };
                let actual_balance = token_dispatcher.balance_of(card);
                
                self.token_balances.entry(token).write(actual_balance);
                self.last_balance_sync.entry(token).write(get_block_timestamp());
                
                i += 1;
            };
        }

        // ========================================================================
        // F. MERCHANT & FRAUD MANAGEMENT
        // ========================================================================

        fn add_merchant_to_blacklist(
            ref self: ContractState,
            merchant: ContractAddress,
            reason: ByteArray,
            pin_proof: Option<ZKProof>,
            proof_nonce: felt252,
        ) {
            let caller = get_caller_address();
            
            if caller == self.owner.read() {
                self._verify_zkproof(pin_proof.unwrap(), proof_nonce);
            } else if caller != self.authorized_relayer.read() {
                panic(array!['Unauthorized']);
            }
            
            self.merchant_blacklist.entry(merchant).write(true);
            self.merchant_blacklist_reason.entry(merchant).write(reason.clone());
            
            // Auto-reject all pending requests from merchant
            let total = self.request_counter.read();
            let mut i = 1_u64;
            loop {
                if i > total {
                    break;
                }
                
                    let mut request = self.payment_requests.entry(i).read();
                    if request.merchant == merchant && request.status == RequestStatus::Pending {
                        request.status = RequestStatus::Rejected;
                        self.payment_requests.entry(i).write(request);
                        self.request_status.entry(i).write(RequestStatus::Rejected);
                    }
                
                i += 1;
            };
            
            // Notify factory
            let factory = IZorahFactoryDispatcher { contract_address: self.factory.read() };
            factory.increment_merchant_blacklist_count(merchant);
            
            self.emit(MerchantBlacklisted {
                merchant,
                reason,
                timestamp: get_block_timestamp(),
            });
        }

        fn remove_merchant_from_blacklist(
            ref self: ContractState,
            merchant: ContractAddress,
            pin_proof: Option<ZKProof>,
            proof_nonce: felt252,
        ) {
            let caller = get_caller_address();
            
            if caller == self.owner.read() {
                self._verify_zkproof(pin_proof.unwrap(), proof_nonce);
            } else if caller != self.authorized_relayer.read() {
                panic(array!['Unauthorized']);
            }
            
            self.merchant_blacklist.entry(merchant).write(false);
            
            self.emit(MerchantUnblacklisted {
                merchant,
                timestamp: get_block_timestamp(),
            });
        }

        fn add_merchant_to_whitelist(
            ref self: ContractState,
            merchant: ContractAddress,
        ) {
            self._assert_owner_or_relayer();
            
            self.merchant_whitelist.entry(merchant).write(true);
            
            self.emit(MerchantWhitelisted {
                merchant,
                timestamp: get_block_timestamp(),
            });
        }

        fn is_merchant_blacklisted(self: @ContractState, merchant: ContractAddress) -> bool {
            self.merchant_blacklist.entry(merchant).read()
        }

        // ========================================================================
        // G. CARD CONTROL & LIFECYCLE
        // ========================================================================

        fn freeze_card(
            ref self: ContractState,
            pin_proof: Option<ZKProof>,
            proof_nonce: felt252,
        ) {
            let caller = get_caller_address();
            
            if caller == self.owner.read() {
                self._verify_zkproof(pin_proof.unwrap(), proof_nonce);
            } else if caller != self.authorized_relayer.read() {
                panic(array!['Unauthorized']);
            }
            
            self.status.write(CardStatus::Frozen);
            
            self.emit(CardFrozen {
                timestamp: get_block_timestamp(),
            });
        }

        fn unfreeze_card(
            ref self: ContractState,
            pin_proof: Option<ZKProof>,
            proof_nonce: felt252,
        ) {
            let caller = get_caller_address();
            
            if caller == self.owner.read() {
                self._verify_zkproof(pin_proof.unwrap(), proof_nonce);
            } else if caller != self.authorized_relayer.read() {
                panic(array!['Unauthorized']);
            }
            
            assert(self.status.read() == CardStatus::Frozen, 'Card not frozen');
            
            self.status.write(CardStatus::Active);
            
            self.emit(CardUnfrozen {
                timestamp: get_block_timestamp(),
            });
        }

        fn burn_card(
            ref self: ContractState,
            pin_proof: Option<ZKProof>,
            proof_nonce: felt252,
        ) {
            self.reentrancy.start();
            
            let caller = get_caller_address();
            
            if caller == self.owner.read() {
                self._verify_zkproof(pin_proof.unwrap(), proof_nonce);
            } else if caller != self.authorized_relayer.read() {
                panic(array!['Unauthorized']);
            }
            
            let owner = self.owner.read();
            
            // Get burn fee from factory
            let factory = IZorahFactoryDispatcher { contract_address: self.factory.read() };
            let config = factory.get_protocol_config();
            let burn_fee = config.burn_fee;
            
            // Find a token with sufficient balance for burn fee
            let mut fee_paid = false;
            let count = self.currency_count.read();
            let mut i: u32 = 0;
            loop {
                if i >= count || fee_paid {
                    break;
                }
                
                let token = self.accepted_currencies.entry(i).read();
                let balance = self.token_balances.entry(token).read();
                
                if balance >= burn_fee {
                    // Transfer burn fee to admin
                    let token_dispatcher = IERC20Dispatcher { contract_address: token };
                    let success = token_dispatcher.transfer(config.admin_wallet, burn_fee);
                    if success {
                        self.token_balances.entry(token).write(balance - burn_fee);
                        fee_paid = true;
                    }
                }
                
                i += 1;
            };
            
            assert(fee_paid, 'No balance for burn fee');
            
            // Withdraw all remaining balances to owner
            let mut j: u32 = 0;
            loop {
                if j >= count {
                    break;
                }
                
                let token = self.accepted_currencies.entry(j).read();
                let balance = self.token_balances.entry(token).read();
                
                if balance > 0 {
                    let token_dispatcher = IERC20Dispatcher { contract_address: token };
                    token_dispatcher.transfer(owner, balance);
                    self.token_balances.entry(token).write(0);
                }
                
                j += 1;
            };
            
            // Withdraw cashback removed; cashback is now part of token_balances
            
            // Clear all data
            self.owner.write(Zero::zero());
            self.status.write(CardStatus::Burned);
            self.pin_commitment.write(0);
            
            self.emit(CardBurned {
                owner,
                timestamp: get_block_timestamp(),
            });
            
            self.reentrancy.end();
        }

        fn update_spending_limits(
            ref self: ContractState,
            max_transaction_amount: u256,
            daily_transaction_limit: u16,
            daily_spend_limit: u256,
            pin_proof: Option<ZKProof>,
            proof_nonce: felt252,
        ) {
            let caller = get_caller_address();
            
            if caller == self.owner.read() {
                self._verify_zkproof(pin_proof.unwrap(), proof_nonce);
            } else if caller != self.authorized_relayer.read() {
                panic(array!['Unauthorized']);
            }
            
            self.max_transaction_amount.write(max_transaction_amount);
            self.daily_transaction_limit.write(daily_transaction_limit);
            self.daily_spend_limit.write(daily_spend_limit);
            
            self.emit(LimitsUpdated {
                max_transaction_amount,
                daily_transaction_limit,
                daily_spend_limit,
                timestamp: get_block_timestamp(),
            });
        }

        // ========================================================================
        // H. YIELD MANAGEMENT
        // ========================================================================

        // Yield functionality removed from vault and moved to plugin implementations.

        // ========================================================================
        // I. TRANSACTION PRIVACY & REPORTING (VIEW + ZK-PROTECTED)
        // ========================================================================

        fn get_transaction_summary(
            ref self: ContractState,
            pin_proof: ZKProof,
            proof_nonce: felt252,
            start_timestamp: u64,
            end_timestamp: u64,
            offset: u64,
            limit: u8,
        ) -> TransactionSummary {
            self._assert_owner_or_relayer();
            self._verify_zkproof(pin_proof, proof_nonce);

            let actual_limit = if limit > 100 { 100 } else { limit };
            let mut summary = TransactionSummary {
                total_spent: 0,
                total_received: 0,
                total_cashback_earned: 0,
                total_swap_fees_paid: 0,
                total_tx_fees_charged: 0,
                transaction_count: 0,
                unique_merchants: 0_u32,
                transactions: ArrayTrait::new().span(),
            };

            let total = self.transaction_counter.read();
            let mut i = offset + 1;
            let mut count = 0_u8;
            let mut merchant_set = ArrayTrait::new();
            loop {
                if i > total || count >= actual_limit {
                    break;
                }
                let tx = self.transactions.entry(i).read();
                if tx.timestamp >= start_timestamp && tx.timestamp <= end_timestamp {
                    summary.total_spent = summary.total_spent + tx.amount;
                    summary.total_cashback_earned = summary.total_cashback_earned + tx.cashback_amount;
                    summary.total_tx_fees_charged = summary.total_tx_fees_charged + tx.transaction_fee;
                    summary.transaction_count += 1;
                    if !merchant_set.contains(tx.merchant) {
                        merchant_set.append(tx.merchant);
                    }
                    ArrayTrait::from_span(summary.transactions).append(tx);
                    count += 1;
                }
                i += 1;
            };

            summary.unique_merchants = merchant_set.len() as u32;
            summary
        }

        fn get_balance_summary(
            ref self: ContractState,
            pin_proof: ZKProof,
            proof_nonce: felt252,
        ) -> BalanceSummary {
            self._assert_owner_or_relayer();
            self._verify_zkproof(pin_proof, proof_nonce);

            let mut balances = ArrayTrait::new();
            let count = self.currency_count.read();
            let mut i: u32 = 0;
            let mut total_value_usd: u256 = 0;
            loop {
                if i >= count {
                    break;
                }
                let token = self.accepted_currencies.entry(i).read();
                let bal = self.token_balances.entry(token).read();
                balances.append(TokenBalance { token, balance: bal, is_default: token == self.default_token.read(), last_updated: self.last_balance_sync.entry(token).read() });
                i += 1;
            };

            BalanceSummary { balances: balances.span(), total_value_usd }
        }

        fn get_fraud_alerts(
            ref self: ContractState,
            pin_proof: ZKProof,
            proof_nonce: felt252,
        ) -> Span<FraudAlert> {
            self._assert_owner_or_relayer();
            self._verify_zkproof(pin_proof, proof_nonce);

            let mut alerts = ArrayTrait::new();
            let total = self.fraud_alert_count.read();
            let mut i: u64 = 1;
            loop {
                if i > total {
                    break;
                }
                alerts.append(self.fraud_alerts.entry(i).read());
                i += 1;
            };

            alerts.span()
        }

        fn get_card_info(self: @ContractState) -> CardInfo {
            CardInfo {
                card_address: get_contract_address(),
                owner: self.owner.read(),
                default_token: self.default_token.read(),
                is_frozen: self.status.read() == CardStatus::Frozen,
                is_burned: self.status.read() == CardStatus::Burned,
                created_at: self.created_at.read(),
                payment_mode: self.payment_mode.read(),
                slippage_tolerance_bps: self.slippage_tolerance_bps.read(),
            }
        }

        fn is_proof_nonce_used(self: @ContractState, nonce: felt252) -> bool {
            self.used_proof_nonces.entry(nonce).read()
        }

        fn get_card_status(self: @ContractState) -> CardStatus {
            self.status.read()
        }

        fn get_rate_limit_status(self: @ContractState) -> RateLimitStatus {
            let failed = self.failed_attempts.read();
            let lock_until = self.lockout_until.read();
            let mut requests_last_hour: u8 = 0;
            RateLimitStatus {
                is_locked: lock_until > get_block_timestamp(),
                failed_attempts: failed,
                lockout_until: lock_until,
                requests_submitted_last_hour: requests_last_hour,
                approvals_last_hour: self.approval_count.read(),
                charges_last_hour: 0_u8,
                last_charge_timestamp: self.last_charge_timestamp.read(),
                cooldown_remaining: if self.last_charge_timestamp.read() + CHARGE_COOLDOWN > get_block_timestamp() { (self.last_charge_timestamp.read() + CHARGE_COOLDOWN) - get_block_timestamp() } else { 0_u64 },
            }
        }

        // ========================================================================
        // K. PLUGIN MANAGEMENT (selector -> class_hash registry)
        // ========================================================================
        
        fn register_plugin(
            ref self: ContractState,
            plugin_id: felt252,
            class_hash: ClassHash,
        ) {
            self._assert_owner_or_relayer();
            assert(self.plugin_registry.entry(plugin_id).read().is_zero(), 'ALREADY_EXISTS');
            self.plugin_registry.entry(plugin_id).write(class_hash);
            self.emit(PluginRegistered { plugin_id, class_hash });

        fn unregister_plugin(
            ref self: ContractState,
            plugin_id: felt252,
        ) {
            self._assert_owner_or_relayer();
            self.plugin_registry.entry(plugin_id).write(0.into());
            self.emit(PluginUnregistered { plugin_id });
        }

        fn upgrade_plugin_by_id(
            ref self: ContractState,
            plugin_id: felt252,
            new_class_hash: ClassHash,
        ) {
            self._assert_owner_or_relayer();
            assert(!self.plugin_registry.entry(plugin_id).read().is_zero(), 'NOT_FOUND');
            self.plugin_registry.entry(plugin_id).write(new_class_hash);
            self.emit(PluginRegistered { plugin_id, class_hash: new_class_hash });
        }

        fn call_plugin(
            ref self: ContractState,
            plugin_id: felt252,
            function_selector: felt252,
            calldata: Span<felt252>,
        ) -> Span<felt252> {
            self._assert_owner_or_relayer();
            let class_hash = self.plugin_registry.entry(plugin_id).read();
            assert(!class_hash.is_zero(), 'PLUGIN_NOT_FOUND');
            self.emit(PluginCalled { plugin_id, selector: function_selector, caller: get_caller_address() });
            library_call_syscall(class_hash, function_selector, calldata).unwrap()
        }
    }

    // ============================================================================
    // INTERNAL HELPERS
    // ============================================================================

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _assert_owner(self: @ContractState) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'Unauthorized');
        }

        fn _assert_owner_or_relayer(self: @ContractState) {
            let caller = get_caller_address();
            let is_owner = caller == self.owner.read();
            let is_relayer = caller == self.authorized_relayer.read();
            assert(is_owner || is_relayer, 'Unauthorized');
        }

        fn _assert_not_frozen(self: @ContractState) {
            assert(self.status.read() != CardStatus::Frozen, 'Card is frozen');
        }

        fn _assert_not_burned(self: @ContractState) {
            assert(self.status.read() != CardStatus::Burned, 'Card is burned');
        }

        fn _check_rate_limit(self: @ContractState) {
            let now = get_block_timestamp();
            let lock_until = self.lockout_until.read();
            if now < lock_until {
                panic(array!['Locked out']);
            }
        }

        fn _check_merchant_request_limit(self: @ContractState, merchant: ContractAddress) {
            let now = get_block_timestamp();
            let last_reset = self.merchant_last_request_reset.entry(merchant).read();
            let mut count = self.merchant_request_count.entry(merchant).read();
            if now >= last_reset + RATE_LIMIT_WINDOW {
                count = 0_u8;
                self.merchant_request_count.entry(merchant).write(count);
                self.merchant_last_request_reset.entry(merchant).write(now);
            }
            count += 1_u8;
            assert(count <= MERCHANT_REQUEST_LIMIT, 'Merchant rate limit');
            self.merchant_request_count.entry(merchant).write(count);
        }

        fn _check_approval_rate_limit(self: @ContractState) {
            let now = get_block_timestamp();
            let last_reset = self.approval_last_reset.read();
            let mut count = self.approval_count.read();
            if now >= last_reset + RATE_LIMIT_WINDOW {
                count = 0_u8;
                self.approval_count.write(count);
                self.approval_last_reset.write(now);
            }
            count += 1_u8;
            assert(count <= APPROVAL_LIMIT, 'Approval rate limit');
            self.approval_count.write(count);
        }

        fn _validate_balance_for_request(self: @ContractState, amount: u256, token: ContractAddress, mode: PaymentMode) -> bool {
            if mode == PaymentMode::MerchantTokenOnly {
                let bal = self.token_balances.entry(token).read();
                return bal >= amount;
            } else if mode == PaymentMode::DefaultTokenOnly {
                let d = self.default_token.read();
                let bal = self.token_balances.entry(d).read();
                return bal >= amount;
            } else {
                let count = self.currency_count.read();
                let factory = IZorahFactoryDispatcher { contract_address: self.factory.read() };
                let avnu = factory.avnu_router;
                let slippage_bps = self.slippage_tolerance_bps.read();
                let mut i: u32 = 0;
                loop {
                    if i >= count {
                        break;
                    }
                    let t = self.accepted_currencies.entry(i).read();
                    let bal = self.token_balances.entry(t).read();
                    if bal == 0 {
                        i += 1;
                        continue;
                    }
                    if t == token {
                        if bal >= amount { return true; }
                    } else {
                        if avnu.is_zero() { i += 1; continue; }
                        let avnu_dispatcher = IZorahAVNURouterDispatcher { contract_address: avnu };
                        let (expected_out, swap_fee, price_impact, _gas) = avnu_dispatcher.get_best_quote(t, token, amount);
                        if expected_out == 0 { i += 1; continue; }
                        if price_impact > 1000 { i += 1; continue; }
                        let slippage_fee = (amount * (slippage_bps.into())) / BASIS_POINTS;
                        let total_needed = amount + swap_fee + slippage_fee;
                        if bal >= total_needed { return true; }
                    }
                    i += 1;
                };
                return false;
            }
        }

        fn _calculate_recurring_interval(self: @ContractState, last: u64, now: u64) -> u64 {
            // Base interval = 30 days
            let mut interval = RECURRING_INTERVAL;

            // If the 30-day window crosses a Feb 29 (leap day), add one day
            // Convert timestamps to days since epoch
            let last_day = last / SECONDS_PER_DAY;
            let now_day = now / SECONDS_PER_DAY;

            // If same day or last >= now, return base interval
            if now_day <= last_day {
                return interval;
            }

            // Convert days to civil year/month/day to get year range
            let (mut y_last, _m_last, _d_last) = self._civil_from_days(last_day);
            let (mut y_now, _m_now, _d_now) = self._civil_from_days(now_day);

            // Iterate years between last and now (inclusive) and check for Feb 29
            let mut y = y_last;
            loop {
                if y > y_now {
                    break;
                }

                // Check if year is leap
                    if self._is_leap_year(y) {
                    // Get timestamp for Feb 29 of year y
                    let feb29_days = self._days_from_civil(y, 2, 29);
                    let feb29_ts = feb29_days * SECONDS_PER_DAY;
                    if feb29_ts > last && feb29_ts <= now {
                        interval = interval + SECONDS_PER_DAY;
                        return interval;
                    }
                }

                y = y + 1;
            };

            interval
        }

        fn _is_leap_year(self: @ContractState, year: u64) -> bool {
            // Leap year: divisible by 4 and (not divisible by 100 unless divisible by 400)
            let by4 = year % 4 == 0;
            let by100 = year % 100 == 0;
            let by400 = year % 400 == 0;
            (by4 && (!by100 || by400))
        }

        fn _civil_from_days(self: @ContractState, z: u64) -> (u64, u64, u64) {
            // Convert days since epoch (1970-01-01) to civil date (year, month, day)
            // Using algorithm adapted from Howard Hinnant's civil_from_days
            let mut z_adj = z + 719468;
            let era = if z_adj >= 0 { (z_adj / 146097) } else { ((z_adj - 146096) / 146097) };
            let doe = z_adj - era * 146097; // [0, 146096]
            let yoe = ((doe - doe/1460 + doe/36524 - doe/146096) / 365); // [0,399]
            let mut y = yoe + era * 400;
            let doy = doe - (365 * yoe + yoe/4 - yoe/100);
            let mp = (5 * doy + 2) / 153; // [0,11]
            let d = (doy - (153 * mp + 2)/5 + 1);
            let m = (mp + (if mp < 10 { 3 } else { -9 }));
            y = y + (if m <= 2 { 1 } else { 0 });

            // Cast back to u64 (dates here are modern, safe)
            (y, m, d)
        }

        fn _days_from_civil(self: @ContractState, y_in: u64, m_in: u64, d_in: u64) -> u64 {
            // Convert civil date to days since epoch using Hinnant's algorithm
            let mut y = y_in;
            let m = m_in;
            let d = d_in;
            y = y - (if m <= 2 { 1 } else { 0 });
            let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
            let yoe = y - era * 400;                                   // [0, 399]
            let mp = (m + (if m > 2 { -3 } else { 9 }));        // [0,11]
            let doy = (153 * mp + 2)/5 + d - 1;            // [0, 365]
            let doe = yoe * 365 + yoe/4 - yoe/100 + doy;       // [0, 146096]
            let days = era * 146097 + doe - 719468;
            days
        }

        fn _verify_zkproof(self: @ContractState, proof: ZKProof, proof_nonce: felt252) {
            assert(!self.used_proof_nonces.entry(proof_nonce).read(), 'Nonce already used');
            assert(proof.public_inputs.len() >= 2, 'Invalid proof inputs');
            let commitment = self.pin_commitment.read();
            let provided_commitment = *proof.public_inputs.at(0);
            let provided_nonce = *proof.public_inputs.at(1);
            if provided_commitment == commitment && provided_nonce == proof_nonce {
                self.used_proof_nonces.entry(proof_nonce).write(true);
                self.failed_attempts.write(0_u8);
            } else {
                let mut fails = self.failed_attempts.read();
                fails += 1_u8;
                self.failed_attempts.write(fails);
                if fails >= MAX_FAILED_ATTEMPTS {
                    let until = get_block_timestamp() + LOCKOUT_DURATION;
                    self.lockout_until.write(until);
                }
                panic(array!['Invalid proof']);
            }
        }
        
        fn _determine_source_token(self: @ContractState, target_token: ContractAddress, amount: u256) -> ContractAddress {
            let mode = self.payment_mode.read();
            if mode == PaymentMode::MerchantTokenOnly {
                return target_token;
            } else if mode == PaymentMode::DefaultTokenOnly {
                return self.default_token.read();
            } else {
                // AnyAcceptedToken: prefer direct if possible
                let bal = self.token_balances.entry(target_token).read();
                if bal >= amount {
                    return target_token;
                }
                // Otherwise, pick first token with balance
                let count = self.currency_count.read();
                let mut i: u32 = 0;
                loop {
                    if i >= count { break; }
                    let t = self.accepted_currencies.entry(i).read();
                    if self.token_balances.entry(t).read() > 0 {
                        return t;
                    }
                    i += 1;
                };
                panic(array!['No balance']);
            }
        }

        fn _execute_direct_transfer(
            ref self: ContractState,
            amount: u256,
            token: ContractAddress,
            payout_wallet: ContractAddress,
        ) {
            let balance = self.token_balances.entry(token).read();
            assert(balance >= amount, 'Insufficient');
            self.token_balances.entry(token).write(balance - amount);
            let dispatcher = IERC20Dispatcher { contract_address: token };
            let success = dispatcher.transfer(payout_wallet, amount);
            assert(success, 'Transfer failed');
        }

        fn _execute_swap_with_quote(
            ref self: ContractState,
            amount_out_requested: u256,
            token_out: ContractAddress,
            quote: OffchainQuote,
            slippage_tolerance_bps: u16,
            deadline: u64,
        ) -> (bool, u256, ContractAddress) {
            let source_token = quote.sell_token_address;
            let total_sell_amount = quote.sell_amount; // Includes fees
            let swap_fee = quote.fee.avnu_fees;

            let balance = self.token_balances.entry(source_token).read();
            assert(balance >= total_sell_amount, 'Insufficient swap');

            // Approve AVNU
            let factory = IZorahFactoryDispatcher { contract_address: self.factory.read() };
            let avnu_router = factory.get_protocol_config().avnu_router;
            assert(!avnu_router.is_zero(), 'Swap not set');

            let token_dispatcher = IERC20Dispatcher { contract_address: source_token };
            let approve_ok = token_dispatcher.approve(avnu_router, total_sell_amount);
            assert(approve_ok, 'Swap failed');

            // Execute swap: output tokens are left in the vault. Caller will deduct fees
            let avnu = IAvnuExchangeDispatcher { contract_address: avnu_router };
            let min_amount_out = quote.buy_amount - (quote.buy_amount * (slippage_tolerance_bps.into()) / 10000_u256);
            let success = avnu.multi_route_swap(
                source_token,
                total_sell_amount,
                token_out,
                quote.buy_amount,
                min_amount_out,
                get_contract_address(),
                quote.fee.integrator_fees_bps,
                Zero::zero(),
                quote.routes.span(),
            );
            assert(success, 'Swap failed');

            // Update source token balance after burning/using sell amount
            self.token_balances.entry(source_token).write(balance - total_sell_amount);

            return (true, swap_fee, source_token);
        }

        fn _apply_transaction_fee(
            self: @ContractState,
            amount: u256,
            token: ContractAddress,
            merchant: ContractAddress,
        ) -> (u256, u256) {
            // Compute fee, apply merchant discount and compute cashback.
            let factory = IZorahFactoryDispatcher { contract_address: self.factory.read() };
            let config = factory.get_protocol_config();
            let percent = config.transaction_fee_percent;
            let cap = config.transaction_fee_cap;
            let cashback_percent = config.user_cashback_percent;

            let mut fee = (amount * (percent.into())) / 10000u256;
            if fee > cap { fee = cap; }

            let discount_bps = factory.get_merchant_discount(merchant);
            if discount_bps > 0_u16 {
                let discount = (fee * (discount_bps.into())) / 10000u256;
                fee = fee - discount;
            }

            let cashback = (fee * (cashback_percent.into())) / 100u8;

            if cashback > 0 {
                let bal = self.token_balances.entry(token).read();
                self.token_balances.entry(token).write(bal + cashback);
            }

            (fee, cashback)
        }

        fn _record_transaction(
            self: @ContractState,
            request_id: u64,
            merchant: ContractAddress,
            payout_wallet: ContractAddress,
            amount: u256,
            token_in: ContractAddress,
            token_out: ContractAddress,
            swap_occurred: bool,
            swap_fee: u256,
            transaction_fee: u256,
            cashback: u256,
            tx_type: felt252,
        ) {
            let tx_id = self.transaction_counter.read() + 1;
            self.transaction_counter.write(tx_id);
            let rec = TransactionRecord {
                transaction_id: tx_id,
                request_id,
                merchant,
                payout_wallet,
                amount,
                token_in,
                token_out,
                swap_occurred,
                swap_fee,
                slippage_paid: 0,
                transaction_fee,
                cashback_amount: cashback,
                timestamp: get_block_timestamp(),
                transaction_type: tx_type,
            };
            self.transactions.entry(tx_id).write(rec);
        }

        fn _update_daily_tracking(self: @ContractState, amount: u256) {
            let now = get_block_timestamp();
            let last = self.last_daily_reset.read();
            if now >= last + SECONDS_PER_DAY {
                self.daily_transaction_count.write(0_u16);
                self.daily_spend_amount.write(0_u256);
                self.last_daily_reset.write(now);
            }
            let mut cnt = self.daily_transaction_count.read();
            cnt += 1_u16;
            self.daily_transaction_count.write(cnt);
            let spent = self.daily_spend_amount.read() + amount;
            self.daily_spend_amount.write(spent);

            let limit_cnt = self.daily_transaction_limit.read();
            if limit_cnt > 0u16 {
                assert(cnt <= limit_cnt, 'Daily tx limit exceeded');
            }
            let limit_spend = self.daily_spend_limit.read();
            if limit_spend > 0u256 {
                assert(spent <= limit_spend, 'Daily spend limit exceeded');
            }
        }

        fn _update_credit_score(self: @ContractState, on_time: bool, amount: u256) {
            let mut score = self.credit_score.read();
            self.total_payments_made.write(self.total_payments_made.read() + 1);
            self.total_volume_processed.write(self.total_volume_processed.read() + amount);
            if on_time {
                self.on_time_payment_count.write(self.on_time_payment_count.read() + 1);
                if score < 1000 { score += 5; }
            } else {
                if score > 0 { score -= 10; }
            }
            self.credit_score.write(score);
            self.emit(CreditScoreUpdated {
                old_score: 0, // Not tracked
                new_score: score,
                timestamp: get_block_timestamp(),
            });
        }

        fn _check_fraud_score(self: @ContractState, request_id: u64) -> FraudScore {
            let mut flags = ArrayTrait::new();
            let mut risk: u8 = 0_u8;
            let request = self.payment_requests.entry(request_id).read();
            let factory = IZorahFactoryDispatcher { contract_address: self.factory.read() };
            if self.merchant_blacklist.entry(request.merchant).read() || factory.is_merchant_globally_blacklisted(request.merchant) {
                flags.append('blacklisted_merchant');
                risk += 50_u8;
            }
            
            let reputation = factory.get_merchant_reputation(request.merchant);
            if reputation.reputation_score < 300u16 {
                flags.append('new_merchant');
                risk += 20_u8;
            }

            let merchant_count = self.merchant_request_count.entry(request.merchant).read();
            if merchant_count > MERCHANT_REQUEST_LIMIT / 2_u8 {
                flags.append('velocity_high');
                risk += 15_u8;
            }

            let recommendation = if risk > 70_u8 { 'reject' } else if risk > 30_u8 { 'review' } else { 'approve' };
            FraudScore { risk_level: risk, flags: flags.span(), recommendation }
        }

        fn _create_fraud_alert(
            self: @ContractState,
            request_id: u64,
            merchant: ContractAddress,
            alert_type: felt252,
            severity: u8,
            message: ByteArray,
            auto_blocked: bool,
        ) {
            let id = self.fraud_alert_count.read() + 1;
            self.fraud_alert_count.write(id);
            let alert = FraudAlert { alert_id: id, request_id, merchant, alert_type, severity, message: message.clone(), timestamp: get_block_timestamp(), auto_blocked };
            self.fraud_alerts.entry(id).write(alert);
            self.emit(FraudAlertTriggered { alert_id: id, request_id, alert_type, severity, timestamp: get_block_timestamp() });
        }
    }

    // ============================================================================
    // EXTERNAL INTERFACES (AVNU, NOSTRA)
    // ============================================================================

    #[starknet::interface]
    trait IAvnuExchange<TContractState> {
        fn multi_route_swap(
            ref self: TContractState,
            sell_token_address: ContractAddress,
            sell_token_amount: u256,
            buy_token_address: ContractAddress,
            buy_token_amount: u256,
            buy_token_min_amount: u256,
            beneficiary: ContractAddress,
            integrator_fee_amount_bps: u128,
            integrator_fee_recipient: ContractAddress,
            routes: Array<Route>,
        ) -> bool;
    }

    #[derive(Drop, Serde, starknet::Store)]
    struct OffchainQuote {
        sell_token_address: ContractAddress,
        buy_token_address: ContractAddress,
        sell_amount: u256,
        buy_amount: u256,
        price_impact: u256,
        fee: AvnuFee,
        routes: Span<Route>,
    }

    #[derive(Drop, Serde, starknet::Store)]
    struct AvnuFee {
        fee_token: ContractAddress,
        avnu_fees: u256,
        avnu_fees_bps: u128,
        integrator_fees: u256,
        integrator_fees_bps: u128,
    }

    #[derive(Drop, Serde, starknet::Store)]
    struct Route {
        exchange: ContractAddress,
        Array<felt252>,
    }

    // INostraPool interface removed (yield removed)

    #[derive(Drop, Serde)]
    struct SwapRoute {
        protocol: felt252,
        pool: ContractAddress,
        token_from: ContractAddress,
        token_to: ContractAddress,
        amount_in: u256,
        amount_out: u256,
        percent: u8,
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._assert_owner_or_relayer();
            self.upgradeable.upgrade(new_class_hash);
        }
    }

}

//54.155.129.205
//source /root/.bashrc