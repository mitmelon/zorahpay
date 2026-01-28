// SPDX-License-Identifier: MIT
// ZorahPay Protocol v1.0 - Factory Contract
// Handles card deployment, merchant registry, and global protocol configuration

#[starknet::contract]
mod ZorahFactory {
    use core::num::traits::Zero;
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp, 
        ClassHash, syscalls::deploy_syscall, get_contract_address
    };
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::security::pausable::PausableComponent;
    use openzeppelin::upgrades::UpgradeableComponent;
    use openzeppelin::upgrades::interface::IUpgradeable;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // ============================================================================
    // COMPONENTS
    // ============================================================================
    
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: PausableComponent, storage: pausable, event: PausableEvent);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;
    
    #[abi(embed_v0)]
    impl PausableImpl = PausableComponent::PausableImpl<ContractState>;
    impl PausableInternalImpl = PausableComponent::InternalImpl<ContractState>;
    
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    // ============================================================================
    // STORAGE
    // ============================================================================

    #[storage]
    struct Storage {
        // Components
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        pausable: PausableComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,

        // Protocol Configuration
        deployment_fee: u256,                              // $2 in USDC default
        transaction_fee_percent: u16,                      // 40 = 0.4%
        transaction_fee_cap: u256,                         // $10 in USDC default
        user_cashback_percent: u8,                         // 10% of tx fee
        burn_fee: u256,                                    // $1 in any token
        
        // Protocol Addresses
        authorized_relayer: ContractAddress,
        avnu_router: ContractAddress,
        admin_wallet: ContractAddress,                     // For fee collection
        deployment_fee_token: ContractAddress,             // Token required for deployment fee (STRK)
        
        // Deployment tracking
        vault_class_hash: ClassHash,                       // ZorahVault class hash
        total_cards_deployed: u64,
        card_exists: LegacyMap<ContractAddress, bool>,
        
        // Accepted deployment fee tokens (USDC, USDT, STRK, WBTC)
        accepted_fee_tokens: LegacyMap<ContractAddress, bool>,
        fee_token_count: u8,
        
        // Merchant Registry
        merchant_registered: LegacyMap<ContractAddress, bool>,
        merchant_info: LegacyMap<ContractAddress, MerchantInfo>,
        merchant_payout_wallet: LegacyMap<ContractAddress, ContractAddress>,
        merchant_discount: LegacyMap<ContractAddress, u16>,  // Basis points discount
        merchant_reputation: LegacyMap<ContractAddress, MerchantReputation>,
        total_merchants: u64,
        
        // Global merchant blacklist (across all cards)
        global_merchant_blacklist: LegacyMap<ContractAddress, bool>,
        blacklist_reason: LegacyMap<ContractAddress, ByteArray>,
    }

    // ============================================================================
    // EVENTS
    // ============================================================================

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        PausableEvent: PausableComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
        
        CardCreated: CardCreated,
        DeploymentFeeUpdated: DeploymentFeeUpdated,
        TransactionFeeUpdated: TransactionFeeUpdated,
        CashbackPercentUpdated: CashbackPercentUpdated,
        // YieldSplitUpdated removed
        RelayerUpdated: RelayerUpdated,
        AVNURouterUpdated: AVNURouterUpdated,
        // VesuPoolUpdated removed
        BurnFeeUpdated: BurnFeeUpdated,
        
        // Merchant Registry Events
        MerchantRegistered: MerchantRegistered,
        MerchantUpdated: MerchantUpdated,
        MerchantPayoutWalletUpdated: MerchantPayoutWalletUpdated,
        MerchantDiscountSet: MerchantDiscountSet,
        MerchantGloballyBlacklisted: MerchantGloballyBlacklisted,
        MerchantGloballyUnblacklisted: MerchantGloballyUnblacklisted,
        MerchantReputationUpdated: MerchantReputationUpdated,
    }

    #[derive(Drop, starknet::Event)]
    struct CardCreated {
        #[key]
        card_address: ContractAddress,
        #[key]
        owner: ContractAddress,
        default_token: ContractAddress,
        payment_mode: PaymentMode,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct DeploymentFeeUpdated {
        old_fee: u256,
        new_fee: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct TransactionFeeUpdated {
        old_percent: u16,
        new_percent: u16,
        old_cap: u256,
        new_cap: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CashbackPercentUpdated {
        old_percent: u8,
        new_percent: u8,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct RelayerUpdated {
        old_relayer: ContractAddress,
        new_relayer: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AVNURouterUpdated {
        old_router: ContractAddress,
        new_router: ContractAddress,
        timestamp: u64,
    }

    // YieldSplitUpdated and VesuPoolUpdated removed

    #[derive(Drop, starknet::Event)]
    struct BurnFeeUpdated {
        old_fee: u256,
        new_fee: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MerchantRegistered {
        #[key]
        merchant: ContractAddress,
        payout_wallet: ContractAddress,
        business_name: ByteArray,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MerchantUpdated {
        #[key]
        merchant: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MerchantPayoutWalletUpdated {
        #[key]
        merchant: ContractAddress,
        old_wallet: ContractAddress,
        new_wallet: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MerchantDiscountSet {
        #[key]
        merchant: ContractAddress,
        discount_bps: u16,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MerchantGloballyBlacklisted {
        #[key]
        merchant: ContractAddress,
        reason: ByteArray,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MerchantGloballyUnblacklisted {
        #[key]
        merchant: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MerchantReputationUpdated {
        #[key]
        merchant: ContractAddress,
        #[key]
        card: ContractAddress,
        total_transactions: u64,
        successful_transactions: u64,
        total_volume: u256,
        reputation_score: u16,
        timestamp: u64,
    }

    // ============================================================================
    // DATA STRUCTURES
    // ============================================================================

    #[derive(Copy, Drop, Serde, starknet::Store)]
    enum PaymentMode {
        MerchantTokenOnly,
        AnyAcceptedToken,
        DefaultTokenOnly,
    }

    #[derive(Drop, Serde, starknet::Store)]
    struct CardConfig {
        max_transaction_amount: u256,
        daily_transaction_limit: u16,
        daily_spend_limit: u256,
        slippage_tolerance_bps: u16,
    }

    #[derive(Drop, Serde, starknet::Store)]
    struct MerchantInfo {
        merchant_address: ContractAddress,
        payout_wallet: ContractAddress,
        business_name: ByteArray,
        contact_email: ByteArray,
        registered_at: u64,
        is_active: bool,
        kyc_verified: bool,
    }

    #[derive(Copy, Drop, Serde, starknet::Store)]
    struct MerchantReputation {
        total_transactions: u64,
        successful_transactions: u64,
        failed_transactions: u64,
        disputed_transactions: u64,
        total_volume: u256,
        blacklist_count: u32,           // Times blacklisted by users
        reputation_score: u16,          // 0-1000 (1000 = perfect)
        last_transaction: u64,
        cards_interacted: u32,          // Unique cards
    }

    #[derive(Drop, Serde)]
    struct ProtocolConfig {
        deployment_fee: u256,
        transaction_fee_percent: u16,
        transaction_fee_cap: u256,
        user_cashback_percent: u8,
        burn_fee: u256,
        authorized_relayer: ContractAddress,
        avnu_router: ContractAddress,
        admin_wallet: ContractAddress,
    }

    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        vault_class_hash: ClassHash,
        admin_wallet: ContractAddress,
        usdc_address: ContractAddress,
        usdt_address: ContractAddress,
        strk_address: ContractAddress,
        wbtc_address: ContractAddress,
    ) {
        // Initialize ownership
        self.ownable.initializer(owner);
        
        // Validate inputs
        assert(!vault_class_hash.is_zero(), 'Invalid vault class hash');
        assert(!admin_wallet.is_zero(), 'Invalid admin wallet');
        assert(!usdc_address.is_zero(), 'Invalid USDC address');
        
        // Set vault class hash
        self.vault_class_hash.write(vault_class_hash);
        
        // Set admin wallet
        self.admin_wallet.write(admin_wallet);
        
        // Set default protocol configuration
        self.deployment_fee.write(2_000000); // $2 in 6 decimals (USDC)
        self.transaction_fee_percent.write(40_u16); // 0.4%
        self.transaction_fee_cap.write(10_000000); // $10 in 6 decimals
        self.user_cashback_percent.write(10_u8); // 10%
        self.burn_fee.write(1_000000); // $1 in 6 decimals
        
        // Deployment fee must be paid in STRK only
        self.accepted_fee_tokens.entry(strk_address).write(true);
        self.fee_token_count.write(1_u8);

        // Store the required deployment fee token (STRK)
        self.deployment_fee_token.write(strk_address);
    }

    // ============================================================================
    // EXTERNAL FUNCTIONS - CARD DEPLOYMENT
    // ============================================================================

    #[abi(embed_v0)]
    impl ZorahFactoryImpl of super::IZorahFactory<ContractState> {
        /// Creates a new ZorahVault card instance
        /// Caller pays deployment fee in USDC, USDT, STRK, or WBTC

       /// @NOTE - Its adviced never to create a card without using ZorahPay SDK to ensure proper setup because the pin_commitment if not properly generated may lock the user out of their card or expose your card to an attacker.

        fn create_card(
            ref self: ContractState,
            pin_commitment: felt252,
            default_token: ContractAddress,
            accepted_currencies: Span<ContractAddress>,
            payment_mode: PaymentMode,
            initial_config: CardConfig,
            fee_token: ContractAddress,
        ) -> ContractAddress {
            // Check not paused
            self.pausable.assert_not_paused();
            
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();
            
            // Validate inputs
            assert(pin_commitment != 0, 'Invalid PIN commitment');
            assert(!default_token.is_zero(), 'Invalid default token');
            assert(accepted_currencies.len() > 0, 'No currencies provided');
            assert(initial_config.max_transaction_amount > 0, 'Invalid max tx amount');
            assert(initial_config.slippage_tolerance_bps <= 1000, 'Slippage too high'); // Max 10%
            
            // Validate fee token is the required deployment token (STRK)
            assert(fee_token == self.deployment_fee_token.read(), 'Deployment fee must be paid in STRK');
            
            // Collect deployment fee
            let deployment_fee = self.deployment_fee.read();
            let factory_address = get_contract_address();
            let admin_wallet = self.admin_wallet.read();
            
            let fee_token_dispatcher = IERC20Dispatcher { contract_address: fee_token };
            let success = fee_token_dispatcher.transfer_from(caller, admin_wallet, deployment_fee);
            assert(success, 'Fee transfer failed');
            
            // Prepare constructor calldata for ZorahVault
            let mut calldata = ArrayTrait::new();
            calldata.append(caller.into());                              // owner
            calldata.append(self.ownable.owner().into());                // admin
            calldata.append(self.authorized_relayer.read().into());      // relayer
            calldata.append(default_token.into());                       // default_token
            calldata.append(pin_commitment);                             // pin_commitment
            
            // Serialize accepted currencies
            Serde::serialize(@accepted_currencies.len(), ref calldata);
            let mut i = 0;
            loop {
                if i >= accepted_currencies.len() {
                    break;
                }
                calldata.append((*accepted_currencies.at(i)).into());
                i += 1;
            };
            
            // Serialize payment mode
            Serde::serialize(@payment_mode, ref calldata);
            
            // Serialize initial config
            Serde::serialize(@initial_config, ref calldata);
            
            // Deploy vault contract
            let (card_address, _) = deploy_syscall(
                self.vault_class_hash.read(),
                0, // salt
                calldata.span(),
                false
            ).expect('Card deployment failed');
            
            // Track deployment
            self.card_exists.entry(card_address).write(true);
            let count = self.total_cards_deployed.read();
            self.total_cards_deployed.write(count + 1);
            
            // Emit event
            self.emit(CardCreated {
                card_address,
                owner: caller,
                default_token,
                payment_mode,
                timestamp,
            });
            
            card_address
        }

        // ========================================================================
        // PROTOCOL CONFIGURATION (ADMIN ONLY)
        // ========================================================================

        fn set_deployment_fee(ref self: ContractState, new_fee: u256) {
            self.ownable.assert_only_owner();
            
            let old_fee = self.deployment_fee.read();
            self.deployment_fee.write(new_fee);
            
            self.emit(DeploymentFeeUpdated {
                old_fee,
                new_fee,
                timestamp: get_block_timestamp(),
            });
        }

        fn set_transaction_fee_percent(ref self: ContractState, new_percent: u16) {
            self.ownable.assert_only_owner();
            assert(new_percent <= 1000, 'Fee too high'); // Max 10%
            
            let old_percent = self.transaction_fee_percent.read();
            self.transaction_fee_percent.write(new_percent);
            
            self.emit(TransactionFeeUpdated {
                old_percent,
                new_percent,
                old_cap: self.transaction_fee_cap.read(),
                new_cap: self.transaction_fee_cap.read(),
                timestamp: get_block_timestamp(),
            });
        }

        fn set_transaction_fee_cap(ref self: ContractState, new_cap: u256) {
            self.ownable.assert_only_owner();
            
            let old_cap = self.transaction_fee_cap.read();
            self.transaction_fee_cap.write(new_cap);
            
            self.emit(TransactionFeeUpdated {
                old_percent: self.transaction_fee_percent.read(),
                new_percent: self.transaction_fee_percent.read(),
                old_cap,
                new_cap,
                timestamp: get_block_timestamp(),
            });
        }

        fn set_user_cashback_percent(ref self: ContractState, new_percent: u8) {
            self.ownable.assert_only_owner();
            assert(new_percent <= 100, 'Invalid percentage');
            
            let old_percent = self.user_cashback_percent.read();
            self.user_cashback_percent.write(new_percent);
            
            self.emit(CashbackPercentUpdated {
                old_percent,
                new_percent,
                timestamp: get_block_timestamp(),
            });
        }


        fn set_burn_fee(ref self: ContractState, new_fee: u256) {
            self.ownable.assert_only_owner();
            
            let old_fee = self.burn_fee.read();
            self.burn_fee.write(new_fee);
            
            self.emit(BurnFeeUpdated {
                old_fee,
                new_fee,
                timestamp: get_block_timestamp(),
            });
        }

        fn update_authorized_relayer(ref self: ContractState, new_relayer: ContractAddress) {
            self.ownable.assert_only_owner();
            assert(!new_relayer.is_zero(), 'Invalid relayer');
            
            let old_relayer = self.authorized_relayer.read();
            self.authorized_relayer.write(new_relayer);
            
            self.emit(RelayerUpdated {
                old_relayer,
                new_relayer,
                timestamp: get_block_timestamp(),
            });
        }

        fn set_avnu_router(ref self: ContractState, avnu_router: ContractAddress) {
            self.ownable.assert_only_owner();
            assert(!avnu_router.is_zero(), 'Invalid router');
            
            let old_router = self.avnu_router.read();
            self.avnu_router.write(avnu_router);
            
            self.emit(AVNURouterUpdated {
                old_router,
                new_router: avnu_router,
                timestamp: get_block_timestamp(),
            });
        }


        fn pause(ref self: ContractState) {
            self.ownable.assert_only_owner();
            self.pausable.pause();
        }

        fn unpause(ref self: ContractState) {
            self.ownable.assert_only_owner();
            self.pausable.unpause();
        }

        // ========================================================================
        // MERCHANT REGISTRY (ADMIN OR RELAYER ONLY)
        // ========================================================================

        /// Registers a new merchant - REQUIRED before merchant can submit payment requests
        fn register_merchant(
            ref self: ContractState,
            merchant: ContractAddress,
            payout_wallet: ContractAddress,
            business_name: ByteArray,
            contact_email: ByteArray,
            kyc_verified: bool,
        ) {
            self._assert_admin_or_relayer();
            
            assert(!merchant.is_zero(), 'Invalid merchant');
            assert(!payout_wallet.is_zero(), 'Invalid payout wallet');
            assert(!self.merchant_registered.entry(merchant).read(), 'Already registered');
            
            let timestamp = get_block_timestamp();
            
            // Create merchant info
            let info = MerchantInfo {
                merchant_address: merchant,
                payout_wallet,
                business_name: business_name.clone(),
                contact_email,
                registered_at: timestamp,
                is_active: true,
                kyc_verified,
            };
            
            self.merchant_info.entry(merchant).write(info);
            self.merchant_registered.entry(merchant).write(true);
            self.merchant_payout_wallet.entry(merchant).write(payout_wallet);
            
            // Initialize reputation
            let reputation = MerchantReputation {
                total_transactions: 0,
                successful_transactions: 0,
                failed_transactions: 0,
                disputed_transactions: 0,
                total_volume: 0,
                blacklist_count: 0,
                reputation_score: 500, // Start at 50%
                last_transaction: 0,
                cards_interacted: 0,
            };
            
            self.merchant_reputation.entry(merchant).write(reputation);
            
            // Update count
            let count = self.total_merchants.read();
            self.total_merchants.write(count + 1);
            
            self.emit(MerchantRegistered {
                merchant,
                payout_wallet,
                business_name,
                timestamp,
            });
        }

        /// Updates merchant payout wallet
        fn update_merchant_payout_wallet(
            ref self: ContractState,
            merchant: ContractAddress,
            new_payout_wallet: ContractAddress,
        ) {
            self._assert_admin_or_relayer();
            
            assert(self.merchant_registered.entry(merchant).read(), 'Merchant not registered');
            assert(!new_payout_wallet.is_zero(), 'Invalid wallet');
            
            let old_wallet = self.merchant_payout_wallet.entry(merchant).read();
            self.merchant_payout_wallet.entry(merchant).write(new_payout_wallet);

            // Update merchant info
            let mut info = self.merchant_info.entry(merchant).read();
            info.payout_wallet = new_payout_wallet;
            self.merchant_info.entry(merchant).write(info);
            
            self.emit(MerchantPayoutWalletUpdated {
                merchant,
                old_wallet,
                new_wallet: new_payout_wallet,
                timestamp: get_block_timestamp(),
            });
        }

        /// Sets transaction fee discount for specific merchant (in basis points)
        fn set_merchant_discount(
            ref self: ContractState,
            merchant: ContractAddress,
            discount_bps: u16,
        ) {
            self._assert_admin_or_relayer();
            
            assert(self.merchant_registered.entry(merchant).read(), 'Merchant not registered');
            assert(discount_bps <= 10000, 'Invalid discount'); // Max 100%
            
            self.merchant_discount.entry(merchant).write(discount_bps);
            
            self.emit(MerchantDiscountSet {
                merchant,
                discount_bps,
                timestamp: get_block_timestamp(),
            });
        }

        /// Removes merchant discount
        fn remove_merchant_discount(ref self: ContractState, merchant: ContractAddress) {
            self._assert_admin_or_relayer();
            
            self.merchant_discount.entry(merchant).write(0);
            
            self.emit(MerchantDiscountSet {
                merchant,
                discount_bps: 0,
                timestamp: get_block_timestamp(),
            });
        }

        /// Blacklists merchant globally (across all cards)
        fn globally_blacklist_merchant(
            ref self: ContractState,
            merchant: ContractAddress,
            reason: ByteArray,
        ) {
            self._assert_admin_or_relayer();
            
            self.global_merchant_blacklist.entry(merchant).write(true);
            self.blacklist_reason.entry(merchant).write(reason.clone());
            
            // Deactivate merchant
            let mut info = self.merchant_info.entry(merchant).read();
            info.is_active = false;
            self.merchant_info.entry(merchant).write(info);
            
            self.emit(MerchantGloballyBlacklisted {
                merchant,
                reason,
                timestamp: get_block_timestamp(),
            });
        }

        /// Removes merchant from global blacklist
        fn globally_unblacklist_merchant(ref self: ContractState, merchant: ContractAddress) {
            self._assert_admin_or_relayer();
            
            self.global_merchant_blacklist.entry(merchant).write(false);

            // Reactivate merchant
            let mut info = self.merchant_info.entry(merchant).read();
            info.is_active = true;
            self.merchant_info.entry(merchant).write(info);
            
            self.emit(MerchantGloballyUnblacklisted {
                merchant,
                timestamp: get_block_timestamp(),
            });
        }

        /// Updates merchant reputation after successful transaction
        /// Called by ZorahVault contracts
        fn update_merchant_reputation(
            ref self: ContractState,
            merchant: ContractAddress,
            card: ContractAddress,
            transaction_amount: u256,
            success: bool,
        ) {
            // Verify caller is a deployed card
            assert(self.card_exists.entry(get_caller_address()).read(), 'Unauthorized caller');

            let mut reputation = self.merchant_reputation.entry(merchant).read();
            
            // Update transaction counts
            reputation.total_transactions += 1;
            if success {
                reputation.successful_transactions += 1;
                reputation.total_volume += transaction_amount;
            } else {
                reputation.failed_transactions += 1;
            }
            
            reputation.last_transaction = get_block_timestamp();
            
            // Calculate reputation score (0-1000)
            // Formula: (successful / total) * 700 + volume_factor * 200 + recency_factor * 100
            let success_rate = if reputation.total_transactions > 0 {
                (reputation.successful_transactions * 700) / reputation.total_transactions
            } else {
                0
            };
            
            // Volume factor (normalized, capped)
            let volume_factor = if reputation.total_volume > 1000000_000000 { // $1M
                200
            } else {
                (reputation.total_volume * 200) / 1000000_000000
            };
            
            // Recency factor (bonus if active in last 30 days)
            let recency_factor = if get_block_timestamp() - reputation.last_transaction < 2592000 {
                100
            } else {
                0
            };
            
            // Penalty for blacklists
            let blacklist_penalty = reputation.blacklist_count * 50;
            
            let raw_score = success_rate + volume_factor + recency_factor;
            reputation.reputation_score = if raw_score > blacklist_penalty {
                (raw_score - blacklist_penalty).try_into().unwrap()
            } else {
                0
            };
            
            // Cap at 1000
            if reputation.reputation_score > 1000 {
                reputation.reputation_score = 1000;
            }
            
            self.merchant_reputation.entry(merchant).write(reputation);
            
            self.emit(MerchantReputationUpdated {
                merchant,
                card,
                total_transactions: reputation.total_transactions,
                successful_transactions: reputation.successful_transactions,
                total_volume: reputation.total_volume,
                reputation_score: reputation.reputation_score,
                timestamp: get_block_timestamp(),
            });
        }

        /// Increments merchant blacklist count (called by cards when user blacklists)
        fn increment_merchant_blacklist_count(ref self: ContractState, merchant: ContractAddress) {
            // Verify caller is a deployed card
            assert(self.card_exists.entry(get_caller_address()).read(), 'Unauthorized caller');

            let mut reputation = self.merchant_reputation.entry(merchant).read();
            reputation.blacklist_count += 1;
            
            // Recalculate reputation score with penalty
            let blacklist_penalty = reputation.blacklist_count * 50;
            if reputation.reputation_score > blacklist_penalty.into() {
                reputation.reputation_score -= blacklist_penalty.into();
            } else {
                reputation.reputation_score = 0;
            }
            
            self.merchant_reputation.entry(merchant).write(reputation);
        }

        /// Allows admin or authorized relayer to set merchant reputation score manually
        fn set_merchant_reputation(
            ref self: ContractState,
            merchant: ContractAddress,
            reputation_score: u16,
        ) {
            self._assert_admin_or_relayer();
            assert(self.merchant_registered.entry(merchant).read(), 'Merchant not registered');

            let mut reputation = self.merchant_reputation.entry(merchant).read();
            // Cap score at 1000
            let mut score = reputation_score;
            if score > 1000 {
                score = 1000;
            }
            reputation.reputation_score = score;
            self.merchant_reputation.write(merchant, reputation);

            self.emit(MerchantReputationUpdated {
                merchant,
                card: get_contract_address(),
                total_transactions: reputation.total_transactions,
                successful_transactions: reputation.successful_transactions,
                total_volume: reputation.total_volume,
                reputation_score: reputation.reputation_score,
                timestamp: get_block_timestamp(),
            });
        }

        // ========================================================================
        // VIEW FUNCTIONS
        // ========================================================================

        fn get_protocol_config(self: @ContractState) -> ProtocolConfig {
            ProtocolConfig {
                deployment_fee: self.deployment_fee.read(),
                transaction_fee_percent: self.transaction_fee_percent.read(),
                transaction_fee_cap: self.transaction_fee_cap.read(),
                user_cashback_percent: self.user_cashback_percent.read(),
                burn_fee: self.burn_fee.read(),
                authorized_relayer: self.authorized_relayer.read(),
                avnu_router: self.avnu_router.read(),
                admin_wallet: self.admin_wallet.read(),
            }
        }

        fn is_merchant_registered(self: @ContractState, merchant: ContractAddress) -> bool {
            self.merchant_registered.entry(merchant).read()
        }

        fn is_merchant_globally_blacklisted(self: @ContractState, merchant: ContractAddress) -> bool {
            self.global_merchant_blacklist.entry(merchant).read()
        }

        fn get_merchant_info(self: @ContractState, merchant: ContractAddress) -> MerchantInfo {
            assert(self.merchant_registered.entry(merchant).read(), 'Merchant not registered');
            self.merchant_info.entry(merchant).read()
        }

        fn get_merchant_payout_wallet(self: @ContractState, merchant: ContractAddress) -> ContractAddress {
            self.merchant_payout_wallet.entry(merchant).read()
        }

        fn get_merchant_discount(self: @ContractState, merchant: ContractAddress) -> u16 {
            self.merchant_discount.entry(merchant).read()
        }

        fn get_merchant_reputation(self: @ContractState, merchant: ContractAddress) -> MerchantReputation {
            self.merchant_reputation.entry(merchant).read()
        }

        fn is_card_deployed(self: @ContractState, card: ContractAddress) -> bool {
            self.card_exists.entry(card).read()
        }

        fn get_total_cards_deployed(self: @ContractState) -> u64 {
            self.total_cards_deployed.read()
        }

        fn get_total_merchants(self: @ContractState) -> u64 {
            self.total_merchants.read()
        }
    }

    // ============================================================================
    // UPGRADEABLE IMPLEMENTATION
    // ============================================================================

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.ownable.assert_only_owner();
            self.upgradeable.upgrade(new_class_hash);
        }
    }

    // ============================================================================
    // INTERNAL FUNCTIONS
    // ============================================================================

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Asserts caller is admin or authorized relayer
        fn _assert_admin_or_relayer(self: @ContractState) {
            let caller = get_caller_address();
            let is_owner = caller == self.ownable.owner();
            let is_relayer = caller == self.authorized_relayer.read();
            assert(is_owner || is_relayer, 'Unauthorized: admin/relayer only');
        }
    }
}

// ============================================================================
// INTERFACE
// ============================================================================

#[starknet::interface]
trait IZorahFactory<TContractState> {
    // Card deployment
    fn create_card(
        ref self: TContractState,
        pin_commitment: felt252,
        default_token: ContractAddress,
        accepted_currencies: Span<ContractAddress>,
        payment_mode: PaymentMode,
        initial_config: CardConfig,
        fee_token: ContractAddress,
    ) -> ContractAddress;

    // Protocol configuration
    fn set_deployment_fee(ref self: TContractState, new_fee: u256);
    fn set_transaction_fee_percent(ref self: TContractState, new_percent: u16);
    fn set_transaction_fee_cap(ref self: TContractState, new_cap: u256);
    fn set_user_cashback_percent(ref self: TContractState, new_percent: u8);
    // fn set_yield_split_percent(ref self: TContractState, admin_percent: u8);
    fn set_burn_fee(ref self: TContractState, new_fee: u256);
    fn update_authorized_relayer(ref self: TContractState, new_relayer: ContractAddress);
    fn set_avnu_router(ref self: TContractState, avnu_router: ContractAddress);
    // fn set_vesu_pool(ref self: TContractState, vesu_pool: ContractAddress);
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);

    // Merchant registry
    fn register_merchant(
        ref self: TContractState,
        merchant: ContractAddress,
        payout_wallet: ContractAddress,
        business_name: ByteArray,
        contact_email: ByteArray,
        kyc_verified: bool,
    );
    fn update_merchant_payout_wallet(
        ref self: TContractState,
        merchant: ContractAddress,
        new_payout_wallet: ContractAddress,
    );
    fn set_merchant_discount(ref self: TContractState, merchant: ContractAddress, discount_bps: u16);
    fn remove_merchant_discount(ref self: TContractState, merchant: ContractAddress);
    fn globally_blacklist_merchant(ref self: TContractState, merchant: ContractAddress, reason: ByteArray);
    fn globally_unblacklist_merchant(ref self: TContractState, merchant: ContractAddress);
    fn update_merchant_reputation(
        ref self: TContractState,
        merchant: ContractAddress,
        card: ContractAddress,
        transaction_amount: u256,
        success: bool,
    );
    fn increment_merchant_blacklist_count(ref self: TContractState, merchant: ContractAddress);
    fn set_merchant_reputation(ref self: TContractState, merchant: ContractAddress, reputation_score: u16);

    // View functions
    fn get_protocol_config(self: @TContractState) -> ProtocolConfig;
    fn is_merchant_registered(self: @TContractState, merchant: ContractAddress) -> bool;
    fn is_merchant_globally_blacklisted(self: @TContractState, merchant: ContractAddress) -> bool;
    fn get_merchant_info(self: @TContractState, merchant: ContractAddress) -> MerchantInfo;
    fn get_merchant_payout_wallet(self: @TContractState, merchant: ContractAddress) -> ContractAddress;
    fn get_merchant_discount(self: @TContractState, merchant: ContractAddress) -> u16;
    fn get_merchant_reputation(self: @TContractState, merchant: ContractAddress) -> MerchantReputation;
    fn is_card_deployed(self: @TContractState, card: ContractAddress) -> bool;
    fn get_total_cards_deployed(self: @TContractState) -> u64;
    fn get_total_merchants(self: @TContractState) -> u64;
}