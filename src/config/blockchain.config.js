// src/config/blockchain.config.js
// Blockchain configuration — RPC URLs, network settings, contract addresses

const blockchainConfig = {
    // Network configuration
    network: {
        name: process.env.NETWORK_NAME || 'maticmum',
        chainId: parseInt(process.env.CHAIN_ID || '80001'),
        rpcUrl: process.env.POLYGON_RPC_URL || 'https://rpc-mumbai.maticvigil.com',
    },

    // Contract addresses (set after deployment)
    contracts: {
        didRegistry: process.env.DID_REGISTRY_ADDRESS,
        credentialRegistry: process.env.CREDENTIAL_REGISTRY_ADDRESS,
        revocationRegistry: process.env.REVOCATION_REGISTRY_ADDRESS,
    },

    // Issuer wallet (the backend's signing key)
    issuer: {
        privateKey: process.env.ISSUER_PRIVATE_KEY,
    },

    // Gas settings for Polygon
    gas: {
        maxFeePerGas: '50000000000',      // 50 gwei
        maxPriorityFeePerGas: '30000000000', // 30 gwei
    },
}

export default blockchainConfig
