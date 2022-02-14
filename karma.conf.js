const puppeteer = require('puppeteer')
const { ProvidePlugin } = require('webpack')
process.env.CHROME_BIN = puppeteer.executablePath()

module.exports = function (karma) {
  karma.set({
    frameworks: ['mocha', 'webpack'],
    plugins: [
      'karma-webpack',
      'karma-mocha',
      'karma-sourcemap-loader',
      'karma-chrome-launcher'
    ],
    files: [{ pattern: 'test/*Spec.js', watched: false }],
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
        alias: { sinon: 'sinon/pkg/sinon' },
        fallback: {
          buffer: require.resolve('buffer/'),
          crypto: require.resolve('crypto-browserify'),
          fs: false,
          path: require.resolve('path-browserify'),
          process: require.resolve('process/browser'),
          querystring: require.resolve('querystring-es3'),
          stream: require.resolve('stream-browserify')
        }
      },
      plugins: [
        new ProvidePlugin({
          Buffer: ['buffer', 'Buffer']
        }),
        new ProvidePlugin({
          process: 'process/browser'
        })
      ],
      node: {
        global: true
      }
    },

    webpackMiddleware: {
      stats: 'errors-only'
    },

    browsers: ['ChromeHeadless']
  })
}
