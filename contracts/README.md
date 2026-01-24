# GurftronDB Smart Contract

A decentralized database system built on Starknet that combines on-chain data storage with community-driven validation, reputation scoring, and tokenized incentives. Think of it as a blockchain-native database where data quality is maintained through stake-based access and collective moderation.

## What Does It Do?

GurftronDB is an enhanced decentralized database that allows users to store, query, and manage structured data directly on the Starknet blockchain. Unlike traditional databases, every piece of data goes through a validation process powered by community voting before it becomes publicly accessible.

### Core Features

**Document Management**
- Create collections (similar to database tables) with indexed fields for efficient queries
- Insert, update, delete, and query documents with compressed data storage
- Each document includes metadata like creation time, creator address, and validation status
- Support for complex queries with multiple conditions

**Community Validation System**
- New documents enter a "pending" state and require community approval
- Users stake STRK tokens to gain voting rights
- Documents need a certain percentage of positive votes to be approved
- Rejected documents are filtered out of public queries
- Approved documents can later be flagged for removal through whitelist voting

**Reputation & Rewards**
- Users earn reputation points for contributing quality data
- Negative reputation for malicious behavior or rejected submissions
- Points awarded for insertions, updates, deletions, and voting
- Premium users get multiplied rewards
- Points can be converted to STRK token rewards

**Security Mechanisms**
- Stake-based access control (minimum stake required to write data)
- Time-locked stakes to prevent hit-and-run attacks
- Cooldown periods between actions to prevent spam
- Rate limiting on operations
- Admin and moderator roles for emergency interventions
- Slashing mechanism for malicious actors

**User Management**
- Account registration system with profile tracking
- Ban/unban capabilities for rule violators
- Premium status for trusted contributors
- Statistics tracking for accountability

## Architecture Overview

The contract is organized into several key components:

- **Storage Layer**: Documents, user profiles, stakes, and validation states
- **Access Control**: Admin, moderator, and stake-based permissions
- **Validation Engine**: Vote counting and consensus mechanisms
- **Reward System**: Point allocation and STRK token distribution
- **Query Engine**: Indexed searches and pagination support

## Building the Contract

### Prerequisites

You'll need to have Scarb installed. Scarb is the Cairo and Starknet development toolchain.

Install Scarb:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh
```

Verify installation:
```bash
scarb --version
```

### Building

Navigate to the contracts directory and build:

```bash
cd contracts
scarb build
```

This compiles the Cairo code and generates both Sierra (intermediate representation) and CASM (Cairo Assembly) artifacts in the `target` directory.

## Deployment Guide

### Prerequisites for Deployment

- **Starknet Foundry** (sncast tool): Install from [Starknet Foundry docs](https://foundry-rs.github.io/starknet-foundry/)
- **Test STRK tokens**: Get from Sepolia faucet
- **STRK token contract address**: Required as a constructor parameter

### Step 1: Create Your Deployment Account

Create a new account on Sepolia testnet:

```bash
sncast account create --network sepolia --name deployer
```

This generates a new account and provides you with:
- Account address
- Private key (keep this secure!)
- Instructions for funding

Fund your account with test ETH from the [Starknet Sepolia Faucet](https://starknet-faucet.vercel.app/).

### Step 2: Deploy the Account Contract

Once funded, deploy your account to the network:

```bash
sncast account deploy --network sepolia --name deployer
```

Wait for the transaction to be confirmed. This can take a minute or two.

### Step 3: (Alternative) Use an Existing Account

If you already have an account from another wallet like ArgentX or Braavos:

```bash
sncast account add --name deployer --address YOUR_ADDRESS --private-key YOUR_PRIVATE_KEY --type argent --network sepolia
```

Replace:
- `YOUR_ADDRESS` with your account address
- `YOUR_PRIVATE_KEY` with your private key
- `--type argent` (or `--type braavos` depending on your wallet)

### Step 4: Declare the Contract

Declaring uploads your contract class to the network:

```bash
sncast declare --network sepolia --contract-name GurftronDB
```

This outputs a **class hash**. Copy this value - you'll need it for deployment.

Example output:
```
Class hash: 0x1234...abcd
```

### Step 5: Deploy Your Contract Instance

Deploy an instance of your contract with the required constructor parameters:

```bash
sncast deploy --network sepolia --class-hash YOUR_CLASS_HASH --constructor-calldata ADMIN_ADDRESS STRK_TOKEN_ADDRESS
```

Replace:
- `YOUR_CLASS_HASH` with the hash from Step 4
- `ADMIN_ADDRESS` with the address that will control the contract (typically your account address)
- `STRK_TOKEN_ADDRESS` with the Sepolia STRK token contract address

Example:
```bash
sncast deploy --network sepolia --class-hash 0x1234...abcd --constructor-calldata 0x0576F...C2a9 0x04718...C03a
```

### Step 6: Verify Deployment

After successful deployment, you'll receive:
- **Contract address**: Use this to interact with your deployed database
- **Transaction hash**: Track deployment status

Check your contract on [Voyager](https://sepolia.voyager.online/) or [Starkscan](https://sepolia.starkscan.co/).

## Constructor Parameters

When deploying, you need to provide:

1. **Admin Address** (`ContractAddress`): The address that will have admin privileges. This account can:
   - Update system parameters
   - Add/remove moderators
   - Ban/unban users
   - Slash malicious stakes
   - Force approve/reject documents

2. **STRK Token Address** (`ContractAddress`): The ERC20 contract address for STRK tokens. Used for:
   - Staking requirements
   - Reward distributions
   - Transaction fees

## Post-Deployment Configuration

After deploying, you'll likely want to configure:

1. **Add moderators** (if needed):
   ```bash
   sncast invoke --network sepolia --contract-address YOUR_CONTRACT_ADDRESS --function add_moderator --calldata MODERATOR_ADDRESS
   ```

2. **Update security parameters** (optional):
   - Minimum stake amount
   - Stake lock period
   - Cooldown periods
   - Reputation thresholds

3. **Fund the contract** for rewards:
   - Transfer STRK tokens to the contract address so it can distribute rewards

## Interacting with the Contract

After deployment, users can:

1. **Register an account**
2. **Stake STRK tokens** to gain write access
3. **Create collections** for organizing data
4. **Insert documents** (enters pending validation)
5. **Vote on pending documents** to approve/reject
6. **Query approved data**
7. **Earn rewards** by contributing quality data

## Security Considerations

- Always keep your private keys secure
- Test thoroughly on testnet before mainnet deployment
- Ensure sufficient STRK tokens in the contract for rewards
- Monitor for malicious activity using the reporting system
- Regularly review pending validations to maintain data quality

## Contract Events

The contract emits comprehensive events for all major actions:
- Document lifecycle (insert, update, delete, approval)
- Voting activities
- Stake operations
- Reputation changes
- Security violations
- Reward claims

These events can be monitored off-chain for analytics and transparency.

## License

MIT License - See the contract header for full license text.

## Support

For issues or questions about the contract:
- Review the inline documentation in `lib.cairo`
- Check Starknet documentation at [docs.starknet.io](https://docs.starknet.io)
- Examine the event logs for debugging

---

**Note**: This contract is designed for decentralized data management with built-in quality control. The validation system ensures that only community-approved data is accessible through public queries, while maintaining transparency through on-chain voting and reputation tracking.
