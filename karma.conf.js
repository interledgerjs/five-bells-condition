module.exports = function (karma) {
  karma.set({

    frameworks: [ 'mocha' ],
    files: ['test/*Spec.js'],
    preprocessors: {
      'test/*Spec.js': [ 'webpack' ]
    },

    webpack: {
      progress: true,
      module: {
        loaders: [
          { test: /\.js$/, exclude: /node_modules/, loader: 'babel'},
          { test: /\.json$/, loader: 'json-loader' }
        ],
        noParse: [
          /sinon/
        ],
      },
      node: {
        fs: "empty"
      },
      resolve: {
        alias: { sinon: 'sinon/pkg/sinon' }
      }
    },

    browsers: [ 'PhantomJS' ]
  })
}
