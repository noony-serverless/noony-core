module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: './src',
  testMatch: ['**/__tests__/**/*.test.ts', '**/__tests__/**/*.spec.ts'],
  collectCoverageFrom: [
    '**/*.ts',
    '!**/*.d.ts',
    '!**/__tests__/**',
    '!**/node_modules/**',
    '!**/dist/**',
  ],
  coverageDirectory: '../coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['./__tests__/setup.ts'],
  testTimeout: 30000,
  maxWorkers: 1, // Sequential execution for better test isolation
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/$1',
    '^@/config/(.*)$': '<rootDir>/config/$1',
    '^@/auth/(.*)$': '<rootDir>/auth/$1',
    '^@/middleware/(.*)$': '<rootDir>/middleware/$1',
    '^@/handlers/(.*)$': '<rootDir>/handlers/$1',
    '^@/services/(.*)$': '<rootDir>/services/$1',
    '^@/types/(.*)$': '<rootDir>/types/$1',
    '^@/utils/(.*)$': '<rootDir>/utils/$1',
  },
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        tsconfig: '../tsconfig.json',
      },
    ],
  },
};
