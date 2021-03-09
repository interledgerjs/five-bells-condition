/* eslint-disable strict, no-console, object-shorthand */

'use strict'

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
    noEmitOnErrors: true
  },
  resolve: {
    extensions: ['.js'],
    modules: ['node_modules']
  }
}
