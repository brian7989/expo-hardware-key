/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleFileExtensions: ['ts', 'tsx', 'mts', 'js', 'mjs', 'cjs', 'jsx', 'json'],
  extensionsToTreatAsEsm: ['.ts'],
  transform: {
    '^.+\\.m?tsx?$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: {
          strict: true,
          esModuleInterop: true,
          module: 'ESNext',
          moduleResolution: 'bundler',
          allowJs: true,
          types: ['node', 'jest'],
        },
      },
    ],
    '^.+\\.m?js$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: {
          allowJs: true,
          module: 'ESNext',
          moduleResolution: 'bundler',
        },
      },
    ],
  },
  transformIgnorePatterns: [
    '/node_modules/(?!(@noble)/)',
  ],
  clearMocks: true,
};
