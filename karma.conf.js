module.exports = function (karma) {
  karma.set({
    frameworks: [ 'mocha' ],
    files: ['test/index.js'],
    preprocessors: {
      'test/index.js': [ 'webpack', 'sourcemap' ]
    },

    webpack: {
      devtool: 'inline-source-map',
      module: {
        loaders: [
          { test: /\.js$/, exclude: /node_modules|dist/, loader: 'babel' },
          { test: /\.json$/, loader: 'json-loader' }
        ],
        noParse: [
          /sinon/
        ]
      },
      resolve: {
        alias: { sinon: 'sinon/pkg/sinon' }
      },
      node: {
        fs: 'empty'
      }
    },

    webpackMiddleware: {
      stats: 'errors-only'
    },

    browsers: [ 'PhantomJS' ]
  })
}
