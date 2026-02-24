// src/contracts/addresses.js
// Deployed contract addresses by network
// Update these after deploying contracts via Hardhat

import blockchainConfig from '../config/blockchain.config.js'

const addresses = {
    DID_REGISTRY: blockchainConfig.contracts.didRegistry,
    CREDENTIAL_REGISTRY: blockchainConfig.contracts.credentialRegistry,
    REVOCATION_REGISTRY: blockchainConfig.contracts.revocationRegistry,
}

export default addresses
