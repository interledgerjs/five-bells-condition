/* eslint-disable strict, no-console, object-shorthand */

'use strict'

const { ProvidePlugin } = require('webpack')
const { paths } = require('./webpack.parts.js')

module.exports = {
  entry: paths.entry,
  mode: 'none',
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              [
                '@babel/preset-env',
                {
                  targets: [
                    '> 0.25%, not dead',
                    'not IE 11',
                    'maintained node versions'
                  ]
                }
              ]
            ]
          }
        }
      }
    ]
  },
  optimization: {
    minimize: true,
    emitOnErrors: false
  },
  resolve: {
    extensions: ['.js'],
    modules: ['node_modules'],
    fallback: {
      buffer: require.resolve('buffer/'),
      crypto: require.resolve('crypto-browserify'),
      fs: false,
      path: require.resolve('path-browserify'),
      querystring: require.resolve('querystring-es3'),
      stream: require.resolve('stream-browserify')
    }
  },
  plugins: [
    new ProvidePlugin({
      Buffer: ['buffer', 'Buffer']
    })
  ]
}
