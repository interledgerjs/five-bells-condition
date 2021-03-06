const puppeteer = require('puppeteer')
process.env.CHROME_BIN = puppeteer.executablePath()

module.exports = function (karma) {
  karma.set({
    frameworks: ['mocha'],
    plugins: [
      'karma-webpack',
      'karma-mocha',
      'karma-sourcemap-loader',
      'karma-chrome-launcher'
    ],
    files: [
      { pattern: 'test/*Spec.js', watched: false }
    ],
    preprocessors: {
      'test/*Spec.js': ['webpack', 'sourcemap']
    },
    webpack: {
      devtool: 'inline-source-map',
      module: {
        rules: [
          {
            test: /\.js$/,
            exclude: /node_modules|dist/,
            loader: 'babel-loader'
          }
        ],
        noParse: [/sinon/]
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

    browsers: ['ChromeHeadless']
  })
}
