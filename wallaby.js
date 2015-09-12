module.exports = function (wallaby) {
  return {
    files: [
      'src/**/*.js',
      'schemas/*.json',
      'index.js'
    ],

    tests: [
      'test/*Spec.js'
    ],

    testFramework: 'mocha',

    env: {
      type: 'node',
      runner: 'node',
      params: {
        env: 'NODE_ENV=unit'
      }
    }
  }
}
