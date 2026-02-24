// jest.config.js
export default {
    testEnvironment: 'node',
    transform: {},
    extensionsToTreatAsEsm: [],
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1',
    },
    testMatch: [
        '**/tests/**/*.test.js',
        '**/tests/**/*.spec.js',
    ],
    coverageDirectory: 'coverage',
    coveragePathIgnorePatterns: ['/node_modules/', '/tests/'],
    verbose: true,
    testTimeout: 15000,
}
