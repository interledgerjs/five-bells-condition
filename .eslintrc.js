module.exports = {
  extends: [
    'eslint:recommended',
    'standard',
    'plugin:node/recommended',
    'plugin:promise/recommended',
    'plugin:import/recommended'
  ],
  parser: '@babel/eslint-parser',
  parserOptions: { requireConfigFile: false },
  env: {
    browser: true,
    node: true
  },
  settings: {
    'import/ignore': ['node_modules', '.(scss|css)$', '.(jpe?g|png|gif|svg)']
  },
  rules: {
    'node/no-unsupported-features/es-syntax': 'off'
  }
}
