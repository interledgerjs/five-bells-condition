module.exports = function (karma) {
  karma.set({

    frameworks: [ 'browserify', 'mocha' ],
    files: ['test/*Spec.js'],
    preprocessors: {
      'test/*Spec.js': [ 'browserify' ]
    },

    browserify: {
      debug: true,
      transform: [ 'brfs', [ 'babelify', { presets: 'es2015' } ] ]
    },

    browsers: [ 'PhantomJS' ]
  })
}
